import _ from "lodash";
import errs from "../lib/error.js";
import { castJsonIfNeed } from "../lib/helpers.js";
import utils from "../lib/utils.js";
import streamModel from "../models/stream.js";
import internalAuditLog from "./audit-log.js";
import internalCertificate from "./certificate.js";
import internalHost from "./host.js";
import internalNginx from "./nginx.js";

const omissions = () => ["is_deleted", "owner.is_deleted", "certificate.is_deleted"];

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

const internalStream = {
	/**
	 * @param   {Access}  access
	 * @param   {Object}  data
	 * @returns {Promise}
	 */
	create: async (access, data) => {
		const thisData = data;
		const createCertificate = thisData.certificate_id === "new";

		if (createCertificate) {
			delete thisData.certificate_id;
		}

		await access.can("streams:create", thisData);

		await validateIncomingPort(thisData.incoming_port);

		thisData.owner_user_id = access.token.getUserId(1);

		const createdRow = utils.omitRow(omissions())(await streamModel.query().insertAndFetch(thisData));

		if (createCertificate) {
			const cert = await internalCertificate.createQuickCertificate(access, thisData);

			// update host with cert id
			await internalStream.update(access, {
				id: createdRow.id,
				certificate_id: cert.id,
			});
		}

		const row = await internalStream.get(access, {
			id: createdRow.id,
			expand: ["certificate", "owner"],
		});

		// Configure nginx
		await internalNginx.configure(streamModel, "stream", row);

		// Add to audit log
		thisData.meta = { ...thisData.meta, ...row.meta };
		await internalAuditLog.add(access, {
			action: "created",
			object_type: "stream",
			object_id: row.id,
			meta: thisData,
		});

		return row;
	},

	/**
	 * @param  {Access}  access
	 * @param  {Object}  data
	 * @param  {Number}  data.id
	 * @return {Promise}
	 */
	update: async (access, data) => {
		const thisData = data;
		const createCertificate = thisData.certificate_id === "new";

		if (createCertificate) {
			delete thisData.certificate_id;
		}

		await access.can("streams:update", thisData.id);

		if (typeof thisData.incoming_port !== "undefined") {
			await validateIncomingPort(thisData.incoming_port, thisData.id);
		}

		const existingRow = await internalStream.get(access, { id: thisData.id });
		if (existingRow.id !== thisData.id) {
			// Sanity check that something crazy hasn't happened
			throw new errs.InternalValidationError(
				`Stream could not be updated, IDs do not match: ${existingRow.id} !== ${thisData.id}`,
			);
		}

		if (createCertificate) {
			const cert = await internalCertificate.createQuickCertificate(access, {
				domain_names: thisData.domain_names || existingRow.domain_names,
				meta: { ...existingRow.meta, ...thisData.meta },
			});

			// update host with cert id
			thisData.certificate_id = cert.id;
		}

		await streamModel.query().where({ id: thisData.id }).patch(thisData);

		// Add to audit log
		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "stream",
			object_id: existingRow.id,
			meta: thisData,
		});

		const row = await internalStream.get(access, {
			id: thisData.id,
			expand: ["certificate", "owner"],
		});

		if (!row.enabled) {
			// No need to add nginx config if host is disabled
			return _.omit(internalHost.cleanRowCertificateMeta(row), omissions());
		}

		// Configure nginx
		row.meta = await internalNginx.configure(streamModel, "stream", row);

		return _.omit(internalHost.cleanRowCertificateMeta(row), omissions());
	},

	/**
	 * @param  {Access}   access
	 * @param  {Object}   data
	 * @param  {Number}   data.id
	 * @param  {Array}    [data.expand]
	 * @param  {Array}    [data.omit]
	 * @return {Promise}
	 */
	get: async (access, data) => {
		const thisData = data || {};

		const accessData = await access.can("streams:get", thisData.id);

		const query = streamModel
			.query()
			.where("is_deleted", 0)
			.andWhere("id", thisData.id)
			.allowGraph(streamModel.defaultAllowGraph)
			.first();

		if (accessData.permission_visibility !== "all") {
			query.andWhere("owner_user_id", access.token.getUserId(1));
		}

		if (typeof thisData.expand !== "undefined" && thisData.expand !== null) {
			query.withGraphFetched(`[${thisData.expand.join(", ")}]`);
		}

		const row = utils.omitRow(omissions())(await query);
		if (!row?.id) {
			throw new errs.ItemNotFoundError(thisData.id);
		}

		const thisRow = internalHost.cleanRowCertificateMeta(row);

		// Custom omissions
		if (typeof thisData.omit !== "undefined" && thisData.omit !== null) {
			return _.omit(thisRow, thisData.omit);
		}

		return thisRow;
	},

	/**
	 * @param {Access}  access
	 * @param {Object}  data
	 * @param {Number}  data.id
	 * @param {String}  [data.reason]
	 * @returns {Promise}
	 */
	delete: async (access, data) => {
		await access.can("streams:delete", data.id);

		const row = await internalStream.get(access, { id: data.id });
		if (!row?.id) {
			throw new errs.ItemNotFoundError(data.id);
		}

		await streamModel.query().where("id", row.id).patch({
			is_deleted: 1,
		});

		// Delete Nginx Config
		await internalNginx.deleteConfig("stream", row);
		await internalNginx.reload();

		// Add to audit log
		await internalAuditLog.add(access, {
			action: "deleted",
			object_type: "stream",
			object_id: row.id,
			meta: _.omit(row, omissions()),
		});

		return true;
	},

	/**
	 * @param {Access}  access
	 * @param {Object}  data
	 * @param {Number}  data.id
	 * @param {String}  [data.reason]
	 * @returns {Promise}
	 */
	enable: async (access, data) => {
		await access.can("streams:update", data.id);

		const row = await internalStream.get(access, {
			id: data.id,
			expand: ["certificate", "owner"],
		});
		if (!row?.id) {
			throw new errs.ItemNotFoundError(data.id);
		}
		if (row.enabled) {
			throw new errs.ValidationError("Stream is already enabled");
		}

		row.enabled = 1;

		await streamModel.query().where("id", row.id).patch({
			enabled: 1,
		});

		// Configure nginx
		await internalNginx.configure(streamModel, "stream", row);

		// Add to audit log
		await internalAuditLog.add(access, {
			action: "enabled",
			object_type: "stream",
			object_id: row.id,
			meta: _.omit(row, omissions()),
		});

		return true;
	},

	/**
	 * @param {Access}  access
	 * @param {Object}  data
	 * @param {Number}  data.id
	 * @param {String}  [data.reason]
	 * @returns {Promise}
	 */
	disable: async (access, data) => {
		await access.can("streams:update", data.id);

		const row = await internalStream.get(access, { id: data.id });
		if (!row?.id) {
			throw new errs.ItemNotFoundError(data.id);
		}
		if (!row.enabled) {
			throw new errs.ValidationError("Stream is already disabled");
		}

		row.enabled = 0;

		await streamModel.query().where("id", row.id).patch({
			enabled: 0,
		});

		// Delete Nginx Config
		await internalNginx.deleteConfig("stream", row);
		await internalNginx.reload();

		// Add to audit log
		await internalAuditLog.add(access, {
			action: "disabled",
			object_type: "stream",
			object_id: row.id,
			meta: _.omit(row, omissions()),
		});

		return true;
	},

	/**
	 * All Streams
	 *
	 * @param   {Access}  access
	 * @param   {Array}   [expand]
	 * @param   {String}  [searchQuery]
	 * @returns {Promise}
	 */
	getAll: async (access, expand, searchQuery) => {
		const accessData = await access.can("streams:list");

		const query = streamModel
			.query()
			.where("is_deleted", 0)
			.groupBy("id")
			.allowGraph(streamModel.defaultAllowGraph)
			.orderBy("incoming_port", "ASC");

		if (accessData.permission_visibility !== "all") {
			query.andWhere("owner_user_id", access.token.getUserId(1));
		}

		// Query is used for searching
		if (typeof searchQuery === "string" && searchQuery.length > 0) {
			query.where(function () {
				this.where(castJsonIfNeed("incoming_port"), "like", `%${searchQuery}%`)
					.orWhere(castJsonIfNeed("forwarding_port"), "like", `%${searchQuery}%`)
					.orWhere("forwarding_host", "like", `%${searchQuery}%`)
					.orWhere("npmplus_description", "like", `%${searchQuery}%`);
			});
		}

		if (typeof expand !== "undefined" && expand !== null) {
			query.withGraphFetched(`[${expand.join(", ")}]`);
		}

		const rows = utils.omitRows(omissions())(await query);
		if (typeof expand !== "undefined" && expand !== null && expand.indexOf("certificate") !== -1) {
			return internalHost.cleanAllRowsCertificateMeta(rows);
		}

		return rows;
	},

	/**
	 * Report use
	 *
	 * @param   {Number}  user_id
	 * @param   {String}  visibility
	 * @returns {Promise}
	 */
	getCount: async (user_id, visibility) => {
		const query = streamModel.query().count("id as count").where("is_deleted", 0);

		if (visibility !== "all") {
			query.andWhere("owner_user_id", user_id);
		}

		const row = await query.first();

		return Number.parseInt(row.count, 10);
	},
};

export default internalStream;
