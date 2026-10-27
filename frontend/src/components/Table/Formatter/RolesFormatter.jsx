import { T } from "src/locale";

export function RolesFormatter({ roles }) {
	return (
		<>
			{(roles.length ? roles : ["standard-user"]).map((role) => (
				<span key={role} className="badge bg-yellow-lt me-1">
					<T id={`role.${role}`} />
				</span>
			))}
		</>
	);
}
