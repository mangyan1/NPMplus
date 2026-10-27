import errs from "../lib/error.js";
import { assertPrivilegedNginxFields } from "../lib/nginx-privilege.js";
import { global as logger } from "../logger.js";
import streamModel from "../models/stream.js";
import internalAuditLog from "./audit-log.js";
import internalCertificate from "./certificate.js";
import internalNginx from "./nginx.js";

/**
 * A stream port must be a single valid port, must not collide with the ports
 * NPMplus listens on itself and must not be taken by another stream
 * @param {String|Number} incomingPort
 * @param {Number} [ownId] id of the stream being updated, ignored when creating
 */
const validateIncomingPort = async (incomingPort, ownId) => {
	const port = Number.parseInt(incomingPort, 10);
	if (Number.isNaN(port) || String(port) !== String(incomingPort).trim() || port < 1 || port > 65535) {
		throw new errs.ValidationError("Incoming port must be a single port between 1 and 65535");
	}

	const reserved = [process.env.HTTP_PORT, process.env.HTTPS_PORT, process.env.NPM_PORT]
		.map((p) => Number.parseInt(p, 10))
		.filter((p) => p === port);
	if (reserved.length > 0) {
		throw new errs.ValidationError(`Incoming port ${port} is reserved for NPMplus itself`);
	}

	const rows = await streamModel.query().where("is_deleted", 0).select("id", "incoming_port");
	if (rows.some((row) => row.id !== ownId && Number.parseInt(row.incoming_port, 10) === port)) {
		throw new errs.ValidationError(`Incoming port ${port} is already used by another stream`);
	}
};

const cleanStreamData = (data, existingData) => {
	const combinedData = { ...existingData, ...data };

	if (!combinedData.tcp_forwarding && !combinedData.udp_forwarding) {
		throw new errs.ValidationError("TCP or UDP forwarding needs to be enabled");
	}

	if (combinedData.udp_forwarding) {
		combinedData.npmplus_proxy_tls = false;
		if (combinedData.npmplus_proxy_protocol_forwarding === 1) combinedData.npmplus_proxy_protocol_forwarding = 2;
		combinedData.certificate_id = 0;
	}

	if (combinedData.certificate_id === "new" && !combinedData.npmplus_dns_challenge) {
		throw new errs.ValidationError("New certificates for streams require the DNS challenge");
	}

	if (combinedData.certificate_id !== "new" && !(combinedData.certificate_id > 0)) {
		combinedData.npmplus_mtls_certificate_id = 0;
	}

	if (!(combinedData.npmplus_mtls_certificate_id > 0)) {
		combinedData.npmplus_mtls_verify_client_optional = false;
	}

	return combinedData;
};

const internalStream = {
	/**
	 * @param   {Access}  access
	 * @param   {Object}  data
	 * @returns {Promise}
	 */
	create: async (access, data) => {
		const thisData = cleanStreamData(data);
		const createCertificate = thisData.certificate_id === "new";

		if (createCertificate) {
			delete thisData.certificate_id;
		} else if (thisData.certificate_id > 0) {
			await internalCertificate.get(access, { id: thisData.certificate_id, mtls: false });
		}
		if (thisData.npmplus_mtls_certificate_id > 0) {
			await internalCertificate.get(access, { id: thisData.npmplus_mtls_certificate_id, mtls: true });
		}

		access.can("streams:manage");
		await assertPrivilegedNginxFields(access, thisData);

		await validateIncomingPort(thisData.incoming_port);

		thisData.owner_user_id = access.token.getUserId(1);

		if (createCertificate) {
			thisData.certificate_id = (await internalCertificate.createQuickCertificate(access, thisData)).id;
		}

		const createdRow = await streamModel.query().insertAndFetch(thisData);

		let savedRow;
		const finalize = async () => {
			savedRow = await internalStream.get(access, { id: createdRow.id });

			// Add to audit log
			await internalAuditLog.add(access, {
				action: "created",
				object_type: "stream",
				object_id: savedRow.id,
				meta: savedRow,
			});
		};
		try {
			const row = await internalStream.get(access, {
				id: createdRow.id,
				expand: ["certificate"],
			});

			// Configure nginx
			await internalNginx.configure(streamModel, "stream", row);
		} catch (operationError) {
			// the audit write must never replace the operation's own error
			try {
				await finalize();
			} catch (cleanupError) {
				logger.error(`Error auditing stream create ${createdRow.id}: ${cleanupError.message}`);
			}
			throw operationError;
		}
		await finalize();

		return savedRow;
	},

	/**
	 * @param  {Access}  access
	 * @param  {Object}  data
	 * @param  {Number}  data.id
	 * @return {Promise}
	 */
	update: async (access, data) => {
		const existingRow = await internalStream.get(access, { id: data.id });

		const thisData = cleanStreamData(data, existingRow);
		const createCertificate = thisData.certificate_id === "new";

		if (createCertificate) {
			delete thisData.certificate_id;
		} else if (thisData.certificate_id > 0) {
			await internalCertificate.get(access, { id: thisData.certificate_id, mtls: false });
		}
		if (thisData.npmplus_mtls_certificate_id > 0) {
			await internalCertificate.get(access, { id: thisData.npmplus_mtls_certificate_id, mtls: true });
		}

		access.can("streams:manage");

		if (typeof thisData.incoming_port !== "undefined") {
			await validateIncomingPort(thisData.incoming_port, thisData.id);
		}

		if (existingRow.id !== thisData.id) {
			// Sanity check that something crazy hasn't happened
			throw new errs.InternalValidationError(
				`Stream could not be updated, IDs do not match: ${existingRow.id} !== ${thisData.id}`,
			);
		}
		await assertPrivilegedNginxFields(access, thisData, existingRow);

		if (createCertificate) {
			const cert = await internalCertificate.createQuickCertificate(access, thisData);

			// update host with cert id
			thisData.certificate_id = cert.id;
		}

		await streamModel.query().where({ id: thisData.id }).patch(thisData);

		let savedRow;
		const finalize = async () => {
			savedRow = await internalStream.get(access, { id: thisData.id });

			// Add to audit log
			await internalAuditLog.add(access, {
				action: "updated",
				object_type: "stream",
				object_id: savedRow.id,
				meta: savedRow,
			});
		};
		try {
			const row = await internalStream.get(access, {
				id: thisData.id,
				expand: ["certificate"],
			});

			// No need to add nginx config if host is disabled
			if (row.enabled) {
				// Configure nginx
				await internalNginx.configure(streamModel, "stream", row);
			}
		} catch (operationError) {
			// the audit write must never replace the operation's own error
			try {
				await finalize();
			} catch (cleanupError) {
				logger.error(`Error auditing stream update ${thisData.id}: ${cleanupError.message}`);
			}
			throw operationError;
		}
		await finalize();

		return savedRow;
	},

	/**
	 * @param  {Access}   access
	 * @param  {Object}   data
	 * @param  {Number}   data.id
	 * @param  {Array}    [data.expand]
	 * @return {Promise}
	 */
	get: async (access, data) => {
		access.can("streams:view");

		const query = streamModel.query().where("id", data.id).allowGraph("[certificate]").first();

		if (access.visibility !== "all") {
			query.andWhere("owner_user_id", access.token.getUserId(1));
		}

		if (data.expand) query.withGraphFetched(`[${data.expand.join(", ")}]`);

		const row = await query;
		if (!row?.id) {
			throw new errs.ItemNotFoundError(data.id);
		}

		return row;
	},

	/**
	 * @param {Access}  access
	 * @param {Object}  data
	 * @param {Number}  data.id
	 * @param {String}  [data.reason]
	 * @returns {Promise}
	 */
	delete: async (access, data) => {
		access.can("streams:manage");

		const row = await internalStream.get(access, { id: data.id });

		await streamModel.query().deleteById(row.id);

		const finalize = async () => {
			// Add to audit log
			await internalAuditLog.add(access, {
				action: "deleted",
				object_type: "stream",
				object_id: row.id,
				meta: row,
			});
		};
		try {
			// Delete Nginx Config
			await internalNginx.deleteConfig("stream", row);
			await internalNginx.reload();
		} catch (operationError) {
			// the audit write must never replace the operation's own error
			try {
				await finalize();
			} catch (cleanupError) {
				logger.error(`Error auditing stream delete ${row.id}: ${cleanupError.message}`);
			}
			throw operationError;
		}
		await finalize();

		return row;
	},

	/**
	 * @param {Access}  access
	 * @param {Object}  data
	 * @param {Number}  data.id
	 * @param {String}  [data.reason]
	 * @returns {Promise}
	 */
	enable: async (access, data) => {
		access.can("streams:manage");

		const row = await internalStream.get(access, {
			id: data.id,
			expand: ["certificate"],
		});
		if (row.enabled) {
			throw new errs.ValidationError("Stream is already enabled");
		}

		row.enabled = 1;

		await streamModel.query().where("id", row.id).patch({
			enabled: 1,
			// pessimistic until configure reports otherwise: a failed enable
			// must not leave the previous online state on an enabled row
			npmplus_nginx_online: false,
			npmplus_nginx_err: "",
		});

		let savedRow;
		const finalize = async () => {
			savedRow = await internalStream.get(access, { id: row.id });

			// Add to audit log
			await internalAuditLog.add(access, {
				action: "enabled",
				object_type: "stream",
				object_id: row.id,
				meta: savedRow,
			});
		};
		try {
			// Configure nginx
			await internalNginx.configure(streamModel, "stream", row);
		} catch (operationError) {
			// the audit write must never replace the operation's own error
			try {
				await finalize();
			} catch (cleanupError) {
				logger.error(`Error auditing stream enable ${row.id}: ${cleanupError.message}`);
			}
			throw operationError;
		}
		await finalize();

		return savedRow;
	},

	/**
	 * @param {Access}  access
	 * @param {Object}  data
	 * @param {Number}  data.id
	 * @param {String}  [data.reason]
	 * @returns {Promise}
	 */
	disable: async (access, data) => {
		access.can("streams:manage");

		const row = await internalStream.get(access, { id: data.id });
		if (!row.enabled) {
			throw new errs.ValidationError("Stream is already disabled");
		}

		await streamModel.query().where("id", row.id).patch({
			enabled: 0,
		});

		let savedRow;
		const finalize = async () => {
			savedRow = await internalStream.get(access, { id: row.id });

			// Add to audit log
			await internalAuditLog.add(access, {
				action: "disabled",
				object_type: "stream",
				object_id: row.id,
				meta: savedRow,
			});
		};
		try {
			// Delete Nginx Config
			await internalNginx.deleteConfig("stream", row);
			await internalNginx.reload();
		} catch (operationError) {
			// the audit write must never replace the operation's own error
			try {
				await finalize();
			} catch (cleanupError) {
				logger.error(`Error auditing stream disable ${row.id}: ${cleanupError.message}`);
			}
			throw operationError;
		}
		await finalize();

		return savedRow;
	},

	/**
	 * All Streams
	 *
	 * @param   {Access}  access
	 * @param   {Array}   [expand]
	 * @returns {Promise}
	 */
	getAll: (access, expand) => {
		access.can("streams:view");

		const query = streamModel
			.query()
			.groupBy("id")
			.allowGraph("[owner,certificate]")
			.orderBy("incoming_port", "ASC");

		if (access.visibility !== "all") {
			query.andWhere("owner_user_id", access.token.getUserId(1));
		}

		if (expand) query.withGraphFetched(`[${expand.join(", ")}]`);

		return query;
	},

	/**
	 * Report use
	 *
	 * @param   {Number}  user_id
	 * @param   {String}  visibility
	 * @returns {Promise}
	 */
	getCount: (user_id, visibility) => {
		const query = streamModel.query();

		if (visibility !== "all") {
			query.andWhere("owner_user_id", user_id);
		}

		return query.resultSize();
	},
};

export default internalStream;
