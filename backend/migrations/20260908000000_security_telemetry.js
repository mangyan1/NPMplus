export const up = async (knex) => {
	await knex.schema.createTable("security_telemetry", (table) => {
		table.string("source", 16).notNullable();
		table.bigInteger("bucket").notNullable();
		table.text("data", "mediumtext").notNullable();
		table.primary(["source", "bucket"]);
	});
};
export const down = async (knex) => {
	await knex.schema.dropTable("security_telemetry");
};
