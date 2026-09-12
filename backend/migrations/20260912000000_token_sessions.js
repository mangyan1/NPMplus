export const up = async (knex) => {
	await knex.schema.createTable("npmplus_token_session", (table) => {
		table.string("id", 64).primary();
		table.bigInteger("expires_at").notNullable().index();
	});
};

export const down = async (knex) => {
	await knex.schema.dropTable("npmplus_token_session");
};
