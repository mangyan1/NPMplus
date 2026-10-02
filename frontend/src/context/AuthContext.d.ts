import type { ReactElement, ReactNode } from "react";

interface AuthState {
	authenticated: boolean;
	totpChallenge: boolean;
	login: (identity: string, secret: string) => Promise<void>;
	submitTotp: (code: string) => Promise<void>;
	cancelTotp: () => void;
	logout: () => Promise<void>;
	logoutEverywhere: () => Promise<void>;
}

export function AuthProvider(props: { children: ReactNode; tokenRefreshInterval?: number }): ReactElement;
export function useAuthState(): AuthState;
