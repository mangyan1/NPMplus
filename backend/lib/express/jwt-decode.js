import Access from "../access.js";

export default () => {
	return async (req, res, next) => {
		const cookieName = "__Host-Http-token";
		const token = req.signedCookies?.[cookieName];
		const hasCookie =
			Object.hasOwn(req.signedCookies || {}, cookieName) || Object.hasOwn(req.cookies || {}, cookieName);

		try {
			res.locals.access = null;
			// cookie-parser uses false for a rejected signature and leaves unsigned
			// cookies in req.cookies. Neither is an anonymous request.
			if (hasCookie && (typeof token !== "string" || !token)) throw new Error("Invalid session cookie");
			const access = new Access(token || null);
			await access.load();
			res.locals.access = access;
			next();
		} catch {
			res.clearCookie("__Host-Http-token", {
				httpOnly: true,
				secure: true,
				sameSite: "Strict",
			});
			// 401, not 403: a rejected or expired session is an authentication
			// failure and the frontend treats 401 as "log in again", while 403
			// is reserved for authenticated users hitting a permission wall.
			// Sending 403 here stranded the UI in a ghost session: localStorage
			// still claimed a valid login while every request was rejected.
			res.cookie("__Host-npmplus_oidc_no_redirect", "true", {
				secure: true,
				sameSite: "Strict",
				maxAge: 60 * 60 * 1000,
			});
			return res.status(401).json({
				error: {
					message: "Invalid or expired token",
				},
			});
		}
	};
};
