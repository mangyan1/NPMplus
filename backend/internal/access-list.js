import { appendFile, rm, writeFile } from "node:fs/promises";
import bcrypt from "bcryptjs";
import _ from "lodash";
import { serializeAccessListUpdate, snapshotAccessListFiles } from "../lib/access-list-recovery.js";
import errs from "../lib/error.js";
import { access as logger } from "../logger.js";
import accessListModel from "../models/access_list.js";
import accessListAuthModel from "../models/access_list_auth.js";
import accessListClientModel from "../models/access_list_client.js";
import proxyHostModel from "../models/proxy_host.js";
import internalAuditLog from "./audit-log.js";
import internalNginx from "./nginx.js";
import internalProxyHostAccessList from "./proxy-host-access-list.js";

// biome-ignore lint/suspicious/noControlCharactersInRegex: reject htpasswd record delimiters and control bytes
const invalidUsername = /[:\u0000-\u001f\u007f]/;

const omissions = () => ["is_deleted", "owner.is_deleted"];

const internalAccessList = {
	/**
	 * @param   {Access}  access
	 * @param   {Object}  data
	 * @returns {Promise}
	 */
	create: async (access, data) => {
		access.can("access_lists:manage");
		const row = await accessListModel.query().insertAndFetch({
			name: data.name,
			satisfy_any: data.satisfy_any,
			pass_auth: data.pass_auth,
			owner_user_id: access.token.getUserId(1),
		});

		data.id = row.id;

		// Items
		await Promise.all(
			(data.items ?? []).map(async (item) =>
				accessListAuthModel.query().insert({
					access_list_id: row.id,
					username: item.username,
					password: await bcrypt.hash(item.password, 6),
				}),
			),
		);

		// Clients
		await Promise.all(
			(data.clients ?? []).map((client) =>
				accessListClientModel.query().insert({
					access_list_id: row.id,
					address: client.address,
					directive: client.directive,
				}),
			),
		);

		// re-fetch with expansions
		const freshRow = await internalAccessList.get(access, {
			id: data.id,
			expand: ["items", "clients"],
		});

		const finalize = async () => {
			// Add to audit log
			await internalAuditLog.add(access, {
				action: "created",
				object_type: "access-list",
				object_id: freshRow.id,
				meta: freshRow,
			});
		};
		try {
			await internalAccessList.build(freshRow);
		} catch (operationError) {
			// the audit write must never replace the operation's own error
			try {
				await finalize();
			} catch (cleanupError) {
				logger.error(`Error auditing access list create ${freshRow.id}: ${cleanupError.message}`);
			}
			throw operationError;
		}
		await finalize();

		return freshRow;
	},

	/**
	 * @param  {Access}  access
	 * @param  {Object}  data
	 * @param  {Integer} data.id
	 * @param  {String}  [data.name]
	 * @param  {String}  [data.items]
	 * @return {Promise}
	 */
	update: (access, data) =>
		serializeAccessListUpdate(async () => {
			access.can("access_lists:manage");
			const row = await internalAccessList.get(access, {
				id: data.id,
				expand: ["items", "clients", "proxy_hosts.[certificate,access_lists.[clients,items]]"],
			});
			const existingUsernames = new Set((row.items || []).map((item) => item.username));
			if ((data.items || []).some((item) => !item.password && !existingUsernames.has(item.username))) {
				throw Object.assign(
					new errs.ValidationError("A password is required for new or renamed access-list users"),
					{ message_i18n: "error.access.password-required" },
				);
			}
			const patch = {};
			if (typeof data.name !== "undefined" && data.name) patch.name = data.name;
			if (typeof data.satisfy_any !== "undefined") patch.satisfy_any = data.satisfy_any;
			if (typeof data.pass_auth !== "undefined") patch.pass_auth = data.pass_auth;
			const newItems = [];
			for (const item of data.items || []) {
				if (item.password)
					newItems.push({
						access_list_id: data.id,
						username: item.username,
						password: await bcrypt.hash(item.password, 6),
					});
			}
			const restoreFiles = await snapshotAccessListFiles(
				row,
				(row.proxy_hosts || []).filter((host) => host.enabled),
			);
			let filesChanged = false;
			try {
				return await accessListModel.transaction(async (trx) => {
					if (Object.keys(patch).length > 0) await accessListModel.query(trx).findById(data.id).patch(patch);
					if (data.items) {
						const kept = data.items.filter((item) => !item.password).map((item) => item.username);
						const deletion = accessListAuthModel.query(trx).delete().where("access_list_id", data.id);
						if (kept.length > 0) deletion.whereNotIn("username", kept);
						await deletion;
						for (const item of newItems) await accessListAuthModel.query(trx).insert(item);
					}
					if (data.clients) {
						await accessListClientModel.query(trx).delete().where("access_list_id", data.id);
						for (const client of data.clients.filter((entry) => entry.address)) {
							await accessListClientModel.query(trx).insert({
								access_list_id: data.id,
								address: client.address,
								directive: client.directive,
							});
						}
					}
					const freshRow = await internalAccessList.get(
						access,
						{
							id: data.id,
							expand: ["items", "clients", "proxy_hosts.[certificate,access_lists.[clients,items]]"],
						},
						trx,
					);
					filesChanged = true;
					await internalAccessList.build(freshRow);
					for (const host of (freshRow.proxy_hosts || []).filter((entry) => entry.enabled)) {
						const populated = await internalProxyHostAccessList.populateLocationAccessLists(
							internalProxyHostAccessList.cleanAccessListTypes(host),
							trx,
						);
						await internalProxyHostAccessList.build("proxy_host", populated);
						await internalNginx.generateConfig("proxy_host", populated);
						await rm(`${internalNginx.getConfigName("proxy_host", host.id)}.err`, { force: true });
						await proxyHostModel
							.query(trx)
							.findById(host.id)
							.patch({ npmplus_nginx_online: true, npmplus_nginx_err: "" });
					}
					// Validation and reload must succeed before either the policy or audit commits.
					await internalNginx.test();
					await internalNginx.reload();
					const savedRow = { ...freshRow, proxy_hosts: undefined };
					await internalAuditLog.add(
						access,
						{ action: "updated", object_type: "access-list", object_id: data.id, meta: savedRow },
						trx,
					);
					return savedRow;
				});
			} catch (operationError) {
				if (filesChanged) {
					try {
						await restoreFiles();
						await internalNginx.reload();
					} catch (recoveryError) {
						logger.error(`Access list ${data.id} recovery failed: ${recoveryError.message}`);
						throw new AggregateError(
							[operationError, recoveryError],
							"Access-list update and recovery failed",
						);
					}
				}
				throw operationError;
			}
		}),

	/**
	 * @param  {Access}   access
	 * @param  {Object}   data
	 * @param  {Integer}  data.id
	 * @param  {Array}    [data.expand]
	 * @return {Promise}
	 */
	get: async (access, data, transaction) => {
		const thisData = data || {};
		access.can("access_lists:view");

		const query = accessListModel
			.query(transaction)
			.select("access_list.*", accessListModel.raw("COUNT(DISTINCT proxy_host.id) as proxy_host_count"))
			.leftJoin(
				"npmplus_proxy_host_access_list",
				"npmplus_proxy_host_access_list.access_list_id",
				"access_list.id",
			)
			.leftJoin("proxy_host", function () {
				this.on("proxy_host.id", "=", "npmplus_proxy_host_access_list.proxy_host_id").andOn(
					"proxy_host.is_deleted",
					"=",
					0,
				);
			})
			.where("access_list.is_deleted", 0)
			.andWhere("access_list.id", thisData.id)
			.groupBy("access_list.id")
			.allowGraph("[items,clients,proxy_hosts.[certificate,access_lists.[clients,items]]]")
			.first();

		if (access.visibility !== "all") {
			query.andWhere("access_list.owner_user_id", access.token.getUserId(1));
		}

		if (typeof thisData.expand !== "undefined" && thisData.expand !== null) {
			query.withGraphFetched(`[${thisData.expand.join(", ")}]`);
		}

		const row = await query;

		if (!row?.id) {
			throw new errs.ItemNotFoundError(thisData.id);
		}

		return row;
	},

	/**
	 * @param   {Access}  access
	 * @param   {Object}  data
	 * @param   {Integer} data.id
	 * @param   {String}  [data.reason]
	 * @returns {Promise}
	 */
	delete: async (access, data) => {
		access.can("access_lists:manage");
		const row = await internalAccessList.get(access, {
			id: data.id,
			expand: ["proxy_hosts.[certificate, access_lists.[clients,items]]", "items", "clients"],
		});

		if (!row?.id) {
			throw new errs.ItemNotFoundError(data.id);
		}
		// 1. update row to be deleted
		// 2. update any proxy hosts that were using it (ignoring permissions)
		// 3. reconfigure those hosts
		// 4. audit log

		// 1. update row to be deleted
		await accessListModel.query().where("id", row.id).patch({
			is_deleted: 1,
		});

		// 2. update any proxy hosts that were using it (ignoring permissions)
		const affectedHosts = (row.proxy_hosts || []).map((host) => {
			const updatedHost = { ...host };
			// check in case something crazy happened. This should never be the case, but safeguard
			if (!Array.isArray(updatedHost.npmplus_access_list_ids)) {
				updatedHost.npmplus_access_list_ids = [];
			}
			updatedHost.npmplus_access_list_ids = updatedHost.npmplus_access_list_ids.filter((id) => id !== row.id);

			// update the access_lists object (separate from the access_lists_ids)
			if (!Array.isArray(updatedHost.access_lists)) {
				updatedHost.access_lists = [];
			}
			updatedHost.access_lists = updatedHost.access_lists.filter((acl) => acl.id !== row.id);

			if (updatedHost.npmplus_access_list_ids.length === 0) {
				updatedHost.npmplus_access_list_type = "public";
			}
			if (!Array.isArray(updatedHost.locations)) {
				throw new errs.ConfigurationError("Invalid location structure. Expected an array");
			}
			updatedHost.locations = updatedHost.locations.map((location) => {
				const updatedLocation = { ...location };
				if (!Array.isArray(updatedLocation.npmplus_access_list_ids)) {
					updatedLocation.npmplus_access_list_ids = [];
				}
				updatedLocation.npmplus_access_list_ids = updatedLocation.npmplus_access_list_ids.filter(
					(id) => id !== row.id,
				);
				if (
					updatedLocation.npmplus_access_list_ids.length === 0 &&
					updatedLocation.npmplus_access_list_type === "custom"
				) {
					updatedLocation.npmplus_access_list_type = "global";
				}
				return updatedLocation;
			});
			return updatedHost;
		});
		const deletedRow = { ...row, proxy_hosts: undefined };

		const finalize = async () => {
			// 4. audit log
			await internalAuditLog.add(access, {
				action: "deleted",
				object_type: "access-list",
				object_id: row.id,
				meta: deletedRow,
			});
		};
		try {
			// 3. Write the changes to the database and the config
			if (affectedHosts.length > 0) {
				await proxyHostModel.transaction(async (trx) => {
					await Promise.all(
						affectedHosts.map(async (host) => {
							await proxyHostModel.query(trx).patchAndFetchById(host.id, {
								npmplus_access_list_ids: host.npmplus_access_list_ids,
								npmplus_access_list_type: host.npmplus_access_list_type,
								locations: host.locations,
							});

							return internalProxyHostAccessList.syncAccessListRelations(trx, host.id, host);
						}),
					);
				});
				row.proxy_hosts = affectedHosts;
				// step 4. Regenerate configs and htpasswd files
				// locations don't have accessList objects, only IDs, so populate it with the object itself
				row.proxy_hosts = await Promise.all(
					(row.proxy_hosts || []).map((host) => {
						const cleanedHost = internalProxyHostAccessList.cleanAccessListTypes(host);
						return internalProxyHostAccessList.populateLocationAccessLists(cleanedHost);
					}),
				);
				await internalNginx.bulkGenerateConfigs(proxyHostModel, "proxy_host", row.proxy_hosts);
			}

			await internalNginx.reload();

			// delete the htpasswd file
			await rm(internalAccessList.getFilename(row), { force: true });
		} catch (operationError) {
			// the audit write must never replace the operation's own error
			try {
				await finalize();
			} catch (cleanupError) {
				logger.error(`Error auditing access list delete ${row.id}: ${cleanupError.message}`);
			}
			throw operationError;
		}
		await finalize();
		return deletedRow;
	},

	/**
	 * All Lists
	 *
	 * @param   {Access}  access
	 * @param   {Array}   [expand]
	 * @param   {String}  [searchQuery]
	 * @returns {Promise}
	 */
	getAll: async (access, expand, searchQuery) => {
		access.can("access_lists:view");

		const query = accessListModel
			.query()
			.select("access_list.*", accessListModel.raw("COUNT(DISTINCT proxy_host.id) as proxy_host_count"))
			.leftJoin(
				"npmplus_proxy_host_access_list",
				"npmplus_proxy_host_access_list.access_list_id",
				"access_list.id",
			)
			.leftJoin("proxy_host", function () {
				this.on("proxy_host.id", "=", "npmplus_proxy_host_access_list.proxy_host_id").andOn(
					"proxy_host.is_deleted",
					"=",
					0,
				);
			})
			.where("access_list.is_deleted", 0)
			.groupBy("access_list.id")
			.allowGraph("[owner,items,clients]")
			.orderBy("access_list.name", "ASC");

		if (access.visibility !== "all") {
			query.andWhere("access_list.owner_user_id", access.token.getUserId(1));
		}

		// Query is used for searching
		if (typeof searchQuery === "string") {
			query.where(function () {
				this.where("name", "like", `%${searchQuery}%`);
			});
		}

		if (typeof expand !== "undefined" && expand !== null) {
			query.withGraphFetched(`[${expand.join(", ")}]`);
		}

		return await query;
	},

	/**
	 * Count is used in reports
	 *
	 * @param   {Integer} userId
	 * @param   {String}  visibility
	 * @returns {Promise}
	 */
	getCount: async (userId, visibility) => {
		const query = accessListModel.query().count("id as count").where("is_deleted", 0);

		if (visibility !== "all") {
			query.andWhere("owner_user_id", userId);
		}

		const row = await query.first();
		return Number.parseInt(row.count, 10);
	},

	maskItems: (list) => {
		if (!list) {
			return list;
		}
		return { ..._.omit(list, omissions()), items: list.items?.map((item) => ({ ...item, password: "" })) };
	},

	/**
	 * @param   {Object}  list
	 * @param   {Integer} list.id
	 * @returns {String}
	 */
	getFilename: (list) => `/data/access/${list.id}`,

	/**
	 *
	 * @param {*} htpasswdFile
	 * @param {*} items
	 */
	writeData: async (htpasswdFile, items) => {
		await writeFile(htpasswdFile, "", { encoding: "utf8" });

		if (items?.length > 0) {
			for (const item of items) {
				// Legacy rows also reach this writer during nginx regeneration.
				// Drop invalid records, keeping the auth file present and fail-closed.
				if (
					typeof item.username !== "string" ||
					invalidUsername.test(item.username) ||
					item.username.length > 255
				) {
					continue;
				}
				if (item.username?.length > 0 && item.password?.length > 0) {
					logger.info(`Adding: ${item.username}`);

					try {
						await appendFile(htpasswdFile, `${item.username}:${item.password}\n`, {
							encoding: "utf8",
						});
					} catch (err) {
						logger.error(err);
						throw err;
					}
				}
			}
		}
	},

	/**
	 * @param   {Object}  list
	 * @param   {Integer} list.id
	 * @param   {String}  list.name
	 * @param   {Array}   list.items
	 * @returns {Promise}
	 */
	build: async (list) => {
		logger.info(`Building Access file #${list.id} for: ${list.name}`);

		const htpasswdFile = internalAccessList.getFilename(list);

		await rm(htpasswdFile, { force: true });
		await internalAccessList.writeData(htpasswdFile, list.items);

		logger.success(`Built Access file #${list.id} for: ${list.name}`);
	},
};

export default internalAccessList;
