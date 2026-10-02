import type { QueryClient } from "@tanstack/react-query";

export interface ApiError extends Error {
	status: number;
	payload: unknown;
}

interface RequestOptions {
	url: string;
	params?: Record<string, unknown>;
	reload?: boolean;
}

interface WriteOptions extends RequestOptions {
	data?: unknown;
	headers?: Record<string, string>;
}

type AbortSource = AbortSignal | AbortController;

// Responses are camelized by base.js. Typed endpoint wrappers supply their
// response contracts; an untyped direct call must narrow unknown itself.
export function get<T = unknown>(options: RequestOptions, abortSource?: AbortSource): Promise<T>;
export function post<T = unknown>(options: WriteOptions, abortSource?: AbortSource): Promise<T>;
export function put<T = unknown>(options: WriteOptions, abortSource?: AbortSource): Promise<T>;
export function del<T = unknown>(options: RequestOptions, abortSource?: AbortSource): Promise<T>;
export function download(options: RequestOptions, filename?: string): Promise<void>;
export const queryClient: QueryClient;
