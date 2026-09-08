export const up = async (knex) => {
	await knex.schema.createTable("anubis_sample", (table) => {
		table.string("id", 64).primary();
		table.bigInteger("time").notNullable().index();
		table.text("data", "mediumtext").notNullable();
	});
	await knex.schema.createTable("anubis_event", (table) => {
		table.string("id", 64).primary();
		table.bigInteger("time").notNullable().index();
		table.string("ip", 45).notNullable();
		table.string("kind", 16).notNullable();
	});
};
export const down = async (knex) => {
	await knex.schema.dropTable("anubis_event");
	await knex.schema.dropTable("anubis_sample");
};
