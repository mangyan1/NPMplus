import { useQueryClient } from "@tanstack/react-query";
import { createContext, useContext, useEffect, useState } from "react";
import { useIntervalWhen } from "rooks";
import { deleteToken, getToken, refreshToken, revokeSessions, verifyTotp } from "src/api/backend";
import AuthStore from "src/modules/AuthStore";
import { getCookie } from "src/modules/Cookies";

const AuthContext = createContext(null);

function AuthProvider({ children, tokenRefreshInterval = 5 * 60 * 1000 }) {
	const queryClient = useQueryClient();
	const [authenticated, setAuthenticated] = useState(AuthStore.hasActiveToken());
	const [totpChallenge, setTotpChallenge] = useState(() => getCookie("__Host-npmplus_oidc_totp_required") === "true");

	const handleTokenUpdate = (response) => {
		AuthStore.set(response);
		setAuthenticated(true);
		setTotpChallenge(false);
	};

	const login = async (identity, secret) => {
		const response = await getToken(identity, secret);
		if (response.requiresTotp) {
			setTotpChallenge(true);
			return;
		}
		handleTokenUpdate(response);
	};

	const submitTotp = async (code) => {
		if (!totpChallenge) {
			throw new Error("No TOTP challenge pending");
		}
		const response = await verifyTotp(code);
		handleTokenUpdate(response);
	};

	const cancelTotp = () => {
		setTotpChallenge(false);
	};

	const logout = async () => {
		await deleteToken();
		AuthStore.clear();
		setAuthenticated(false);
		queryClient.clear();
	};

	const logoutEverywhere = async () => {
		await revokeSessions("me");
		AuthStore.clear();
		setAuthenticated(false);
		queryClient.clear();
	};

	const refresh = async (reload = true) => {
		const response = await refreshToken(reload);
		handleTokenUpdate(response);
	};

	// biome-ignore lint/correctness/useExhaustiveDependencies: the refresh must fire once per auth-state change, not on every render (theme/locale switches re-render and would burn the login rate limit)
	useEffect(() => {
		if (!authenticated) {
			if (totpChallenge) {
				window.cookieStore.delete("__Host-npmplus_oidc_totp_required");
				return;
			}
			// false means the 401 path in processResponse just throws instead of
			// clearing + reloading; a dead session must show the login form
			// rather than burning the /tokens rate limit in a reload loop.
			refresh(false).catch(() => {});
		}
	}, [authenticated, totpChallenge]);

	useIntervalWhen(
		() => {
			if (authenticated) {
				// A rejected cookie logs out through processResponse (401 ->
				// clear localStorage + one reload, then the login form shows).
				// Network errors (backend restarting during an update) must NOT
				// log out: the cookie is still valid, so skip this cycle and let
				// the next interval retry once the container is back.
				refresh().catch(() => {});
			}
		},
		tokenRefreshInterval,
		true,
	);

	const value = {
		authenticated,
		totpChallenge,
		login,
		submitTotp,
		cancelTotp,
		logout,
		logoutEverywhere,
	};

	return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

function useAuthState() {
	const context = useContext(AuthContext);
	if (!context) {
		throw new Error("useAuthState must be used within a AuthProvider");
	}
	return context;
}

export { AuthProvider, useAuthState };
