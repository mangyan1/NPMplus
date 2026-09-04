import Access from "../access.js";

export default () => {
	return async (req, res, next) => {
		const token = req.signedCookies?.["__Host-Http-token"] || null;

		//if (!token) {
		//	return res.status(401).json({
		//		error: {
		//			message: "Missing token",
		//		},
		//	});
		//}

		try {
			res.locals.access = null;
			const access = new Access(token);
			await access.load();
			res.locals.access = access;
			next();
		} catch {
			res.clearCookie("__Host-Http-token", {
				httpOnly: true,
				secure: true,
				sameSite: "Strict",
			});
			// 401, not 403: a dead/expired/absent session is an authentication
			// failure and the frontend treats 401 as "log in again", while 403
			// is reserved for authenticated users hitting a permission wall.
			// Sending 403 here stranded the UI in a ghost session: localStorage
			// still claimed a valid login while every request was rejected.
			return res.status(401).json({
				error: {
					message: "Invalid or expired token",
				},
			});
		}
	};
};
