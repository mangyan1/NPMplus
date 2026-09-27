// Objection Docs:
// http://vincit.github.io/objection.js/

import { Model } from "objection";
import db from "../db.js";
import now from "./now_helper.js";

Model.knex(db());

class UserPermission extends Model {
	$beforeInsert() {
		this.created_on = now();
		this.modified_on = now();
	}

	$beforeUpdate() {
		this.modified_on = now();
	}

	// responses and audit metadata expose the access fields only, never the
	// permission row internals
	$formatJson(json) {
		const { id, user_id, created_on, modified_on, ...thisJson } = super.$formatJson(json);
		return thisJson;
	}

	static get name() {
		return "UserPermission";
	}

	static get tableName() {
		return "user_permission";
	}
}

export default UserPermission;
