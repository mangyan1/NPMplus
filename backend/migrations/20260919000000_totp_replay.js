// Keep replay state outside MFA metadata so backup-code updates cannot reset it.
export const up = (knex) =>
	knex.schema.alterTable("auth", (table) => {
		table.bigInteger("npmplus_totp_last_used_step").nullable();
	});

export const down = (knex) =>
	knex.schema.alterTable("auth", (table) => {
		table.dropColumn("npmplus_totp_last_used_step");
	});
