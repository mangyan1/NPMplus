import { readFile, rm, stat, writeFile } from "node:fs/promises";
import errs from "../lib/error.js";
import { nginx as logger } from "../logger.js";
import settingModel from "../models/setting.js";
import internalAuditLog from "./audit-log.js";
import internalNginx from "./nginx.js";

let pendingDefaultUpdate = Promise.resolve();

const snapshotFile = async (filename) => {
	try {
		return { filename, content: await readFile(filename), mode: (await stat(filename)).mode % 0o1000 };
	} catch (err) {
		if (err.code === "ENOENT") return { filename, content: null };
		throw err;
	}
};

const restoreFiles = async (snapshots) => {
	const results = await Promise.allSettled(
		snapshots.map(({ filename, content, mode }) =>
			content === null ? rm(filename, { force: true }) : writeFile(filename, content, { mode }),
		),
	);
	const failures = results.filter((result) => result.status === "rejected").map((result) => result.reason);
	if (failures.length > 0) throw new AggregateError(failures, "Failed to restore default-site files");
};

const updateDefaultSite = async (access, data) => {
	const existingRow = await internalSetting.get(access, { id: data.id });
	const candidate = { ...existingRow.toJSON(), ...data };
	const snapshots = await Promise.all([
		snapshotFile(internalNginx.getConfigName("default")),
		snapshotFile("/data/html/index.html"),
	]);
	try {
		// Preserve the last serving state until the candidate passes nginx validation.
		await internalNginx.generateConfig("default", candidate);
		await internalNginx.test();
		if (candidate.value === "html") await writeFile("/data/html/index.html", candidate.meta.html, "utf8");
		await internalNginx.reload();
		return await settingModel.transaction(async (transaction) => {
			const row = await settingModel.query(transaction).patchAndFetchById(data.id, data);
			await internalAuditLog.add(access, { action: "updated", object_type: "setting", meta: row }, transaction);
			return row;
		});
	} catch (applyError) {
		try {
			await restoreFiles(snapshots);
			await internalNginx.reload();
		} catch (restoreError) {
			throw new Error("Failed to restore previous default-site configuration", {
				cause: new AggregateError([applyError, restoreError], "Default-site update and recovery failed"),
			});
		}
		logger.warn("Default-site update rejected; previous state restored", applyError);
		throw new errs.ValidationError("Could not reconfigure Nginx. Please check logs.");
	}
};

const internalSetting = {
	/**
	 * @param  {Access}  access
	 * @param  {Object}  data
	 * @param  {String}  data.id
	 * @return {Promise}
	 */
	update: async (access, data) => {
		access.canAdmin();
		if (data.id === "default-site") {
			// Concurrent administrators must not restore another update's candidate.
			const update = pendingDefaultUpdate.then(() => updateDefaultSite(access, data));
			pendingDefaultUpdate = update.catch(() => {});
			return update;
		}

		const existingRow = await internalSetting.get(access, { id: data.id });
		if (existingRow.id !== data.id) {
			// Sanity check that something crazy hasn't happened
			throw new errs.InternalValidationError(
				`Setting could not be updated, IDs do not match: ${existingRow.id} !== ${data.id}`,
			);
		}

		await settingModel.query().where({ id: data.id }).patch(data);

		const row = await internalSetting.get(access, {
			id: data.id,
		});

		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "setting",
			meta: row,
		});
		return row;
	},

	/**
	 * @param  {Access}   access
	 * @param  {Object}   data
	 * @param  {String}   data.id
	 * @return {Promise}
	 */
	get: async (access, data) => {
		access.canAdmin();

		const row = await settingModel.query().where("id", data.id).first();
		if (row) {
			return row;
		}
		throw new errs.ItemNotFoundError(data.id);
	},

	/**
	 * All settings
	 *
	 * @param   {Access}  access
	 * @returns {Promise}
	 */
	getAll: (access) => {
		access.canAdmin();
		return settingModel.query().orderBy("description", "ASC");
	},
};

export default internalSetting;
