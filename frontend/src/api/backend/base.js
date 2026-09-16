import { QueryClient } from "@tanstack/react-query";
import queryString from "query-string";
import AuthStore from "src/modules/AuthStore";
import { camelizeKeys, decamelize, decamelizeKeys } from "./caseConvert";
import { deleteToken } from "./deleteToken";

export const queryClient = new QueryClient();
const contentTypeHeader = "Content-Type";

// call sites pass either an AbortController or a bare AbortSignal
const getAbortSignal = (source) => (source && "signal" in source ? source.signal : source);

function decamelizeParams(params) {
	if (!params) {
		return;
	}
	const result = {};
	for (const [key, value] of Object.entries(params)) {
		result[decamelize(key)] = value;
	}

	return result;
}

function buildUrl({ url, params }) {
	const endpoint = url.replace(/^\/|\/$/g, "");
	const baseUrl = `/api/${endpoint}`;
	const apiUrl = queryString.stringifyUrl({
		url: baseUrl,
		query: decamelizeParams(params),
	});
	return apiUrl;
}

function buildBody(data) {
	if (data) {
		return JSON.stringify(decamelizeKeys(data));
	}
}

async function processResponse(response, reload = true) {
	// Session status must be handled even when a proxy returns an HTML error page.
	if (response.status === 401 && reload) {
		// Invalid or expired session: log out. Refresh attempts (reload=false)
		// only throw, so a logged-out visitor does not fire token deletes or
		// burn requests from the login rate limit on every render.
		// 403 is an expected answer for restricted users, not a logout.
		AuthStore.clear();
		queryClient.clear();
		await deleteToken().catch(() => {});
		window.location.reload();
	}
	const payload = await response.json().catch((error) => {
		if (response.ok) throw error;
		return null;
	});
	if (!response.ok) {
		const error = new Error(
			payload?.error?.message_i18n || payload?.error?.message || `Request failed (HTTP ${response.status})`,
		);
		error.status = response.status;
		error.payload = payload;
		throw error;
	}
	return camelizeKeys(payload);
}

async function baseGet({ url, params }, abortSource) {
	const apiUrl = buildUrl({ url, params });
	const method = "GET";
	const signal = getAbortSignal(abortSource);
	const response = await fetch(apiUrl, { method, signal });
	return response;
}

export async function get(args, abortSource) {
	return processResponse(await baseGet(args, abortSource), args.reload);
}

export async function download({ url, params }, filename = "download.file") {
	const res = await fetch(buildUrl({ url, params }));
	if (!res.ok) await processResponse(res);
	const bl = await res.blob();
	const u = window.URL.createObjectURL(bl);
	const a = document.createElement("a");
	a.href = u;
	a.download = filename;
	a.click();
	window.URL.revokeObjectURL(u);
}

export async function post({ url, params, data, headers: extraHeaders }, abortSource) {
	const apiUrl = buildUrl({ url, params });
	const method = "POST";

	let headers = { ...extraHeaders };

	let body;
	// Check if the data is an instance of FormData
	// If data is FormData, let the browser set the Content-Type header
	if (data instanceof FormData) {
		body = data;
	} else {
		// If data is JSON, set the Content-Type header to 'application/json'
		headers = {
			...extraHeaders,
			[contentTypeHeader]: "application/json",
		};
		body = buildBody(data);
	}

	const signal = getAbortSignal(abortSource);
	const response = await fetch(apiUrl, { method, headers, body, signal });
	return processResponse(response);
}

export async function put({ url, params, data }, abortSource) {
	const apiUrl = buildUrl({ url, params });
	const method = "PUT";
	const headers = {
		[contentTypeHeader]: "application/json",
	};
	const signal = getAbortSignal(abortSource);
	const body = buildBody(data);
	const response = await fetch(apiUrl, { method, headers, body, signal });
	return processResponse(response);
}

export async function del({ url, params }, abortSource) {
	const apiUrl = buildUrl({ url, params });
	const method = "DELETE";
	const signal = getAbortSignal(abortSource);
	const response = await fetch(apiUrl, { method, signal });
	return processResponse(response);
}
