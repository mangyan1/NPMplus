import cn from "clsx";
import styles from "./Button.module.css";

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
}) {
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
