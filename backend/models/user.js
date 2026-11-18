// Objection Docs:
// http://vincit.github.io/objection.js/

import { Model } from "objection";
import db from "../db.js";
import { convertBoolFieldsToInt, convertIntFieldsToBool } from "../lib/helpers.js";
import now from "./now_helper.js";
import UserPermission from "./user_permission.js";

Model.knex(db());

const boolFields = ["is_disabled", "npmplus_is_admin"];

class User extends Model {
	$beforeInsert() {
		this.created_on = now();
		this.modified_on = now();
	}

	$beforeUpdate() {
		this.modified_on = now();
	}

	$parseDatabaseJson(json) {
		const { is_deleted, nickname, roles, ...thisJson } = super.$parseDatabaseJson(json);
		return convertIntFieldsToBool(thisJson, boolFields);
	}

	$formatDatabaseJson(json) {
		const thisJson = convertBoolFieldsToInt(json, boolFields);
		return super.$formatDatabaseJson(thisJson);
	}

	// serialization-only strip: lib/access.js and lib/token.js read the
	// revocation cutoff from raw model instances, but it never belongs in an
	// API response or audit metadata
	$formatJson(json) {
		const { npmplus_token_valid_after, ...thisJson } = super.$formatJson(json);
		return thisJson;
	}

	static tableName = "user";

	static get relationMappings() {
		return {
			permissions: {
				relation: Model.HasOneRelation,
				modelClass: UserPermission,
				join: {
					from: "user.id",
					to: "user_permission.user_id",
				},
			},
		};
	}
}

export default User;
