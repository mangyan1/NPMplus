import { migrate as logger } from "../logger.js";

const migrateName = "oidc-identity-unique";

const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.alterTable("auth", (table) => {
		table.unique(["type", "secret"], { indexName: "auth_type_secret_unique" });
	});
};

const down = async (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);
	await knex.schema.alterTable("auth", (table) => {
		table.dropUnique(["type", "secret"], "auth_type_secret_unique");
	});
};

export { down, up };
