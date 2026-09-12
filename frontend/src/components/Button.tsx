import cn from "clsx";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import styles from "./Button.module.css";

interface Props extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "color" | "onClick"> {
	children: ReactNode;
	className?: string;
	type?: "button" | "submit";
	actionType?: "primary" | "secondary" | "success" | "warning" | "danger" | "info" | "light" | "dark";
	variant?: "ghost" | "outline" | "pill" | "square" | "action";
	size?: "sm" | "md" | "lg" | "xl";
	fullWidth?: boolean;
	isLoading?: boolean;
	disabled?: boolean;
	color?:
		| "blue"
		| "azure"
		| "indigo"
		| "purple"
		| "pink"
		| "red"
		| "orange"
		| "yellow"
		| "lime"
		| "green"
		| "teal"
		| "cyan";
	onClick?: () => void;
}
function Button({
	children,
	className,
	onClick,
	type,
	actionType,
	variant,
	size,
	color,
	fullWidth,
	isLoading,
	disabled,
	...buttonProps
}: Props) {
	const myOnClick = () => {
		if (!isLoading) onClick?.();
	};

	const cns = cn(
		"btn",
		className,
		variant === "outline" && styles.outline,
		variant === "outline" || variant === "ghost"
			? `btn-${variant}-${color || actionType || "secondary"}`
			: actionType && `btn-${actionType}`,
		variant && variant !== "outline" && variant !== "ghost" && `btn-${variant}`,
		size && `btn-${size}`,
		color && variant !== "outline" && variant !== "ghost" && `btn-${color}`,
		fullWidth && "w-100",
		isLoading && "btn-loading",
	);

	return (
		<button
			{...buttonProps}
			type={type || "button"}
			className={cns}
			onClick={myOnClick}
			disabled={disabled || isLoading}
		>
			{children}
		</button>
	);
}

export { Button };
