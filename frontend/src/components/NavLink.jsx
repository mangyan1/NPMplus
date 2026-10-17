import { useLocation, useNavigate } from "react-router";

export function NavLink({ children, to, href, isDropdownItem, active, onClick }) {
	const navigate = useNavigate();
	const location = useLocation();
	const isActive = Boolean(to && location.pathname === to);

	if (href) {
		return (
			<a
				className={isDropdownItem ? "dropdown-item" : "nav-link"}
				href={href}
				target="_blank"
				rel="noopener noreferrer"
				onClick={onClick}
			>
				{children}
			</a>
		);
	}

	return (
		<a
			className={`${isDropdownItem ? "dropdown-item" : "nav-link"}${active ? " active" : ""}`}
			href={to}
			aria-current={isActive ? "page" : undefined}
			onClick={(e) => {
				e.preventDefault();
				if (onClick) {
					onClick();
				}
				void navigate(to);
			}}
		>
			{children}
		</a>
	);
}
