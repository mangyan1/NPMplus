import { useLocation, useNavigate } from "react-router";

interface Props {
	children: React.ReactNode;
	to?: string;
	href?: string;
	isDropdownItem?: boolean;
	onClick?: () => void;
}
export function NavLink({ children, to, href, isDropdownItem, onClick }: Props) {
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
			className={isDropdownItem ? "dropdown-item" : `nav-link${isActive ? " active" : ""}`}
			href={to}
			aria-current={isActive ? "page" : undefined}
			onClick={(e) => {
				e.preventDefault();
				if (onClick) {
					onClick();
				}
				if (to) {
					navigate(to);
				}
			}}
		>
			{children}
		</a>
	);
}
