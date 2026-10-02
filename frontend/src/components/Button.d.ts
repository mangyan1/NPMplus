import type { ButtonHTMLAttributes, ReactElement } from "react";

interface ButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "onClick"> {
	// Button.jsx invokes the callback without passing a DOM event.
	onClick?: () => unknown;
	actionType?: string;
	variant?: string;
	size?: string;
	color?: string;
	fullWidth?: boolean;
	isLoading?: boolean;
}

export function Button(props: ButtonProps): ReactElement;
