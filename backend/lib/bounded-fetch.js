const DEFAULT_TIMEOUT_MS = 10_000;

export const fetchWithTimeout = (url, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) => {
	const timeoutSignal = AbortSignal.timeout(timeoutMs);
	const signal = options.signal ? AbortSignal.any([options.signal, timeoutSignal]) : timeoutSignal;
	return fetch(url, { redirect: "error", ...options, signal });
};

export const readBoundedBuffer = async (response, maxBytes) => {
	const declaredLength = Number.parseInt(response.headers.get("content-length") || "0", 10);
	if (declaredLength > maxBytes) throw new Error(`Response exceeds ${maxBytes} bytes`);
	if (!response.body) return Buffer.alloc(0);

	const reader = response.body.getReader();
	const chunks = [];
	let total = 0;
	while (true) {
		const { done, value } = await reader.read();
		if (done) break;
		total += value.byteLength;
		if (total > maxBytes) {
			await reader.cancel();
			throw new Error(`Response exceeds ${maxBytes} bytes`);
		}
		chunks.push(Buffer.from(value));
	}
	return Buffer.concat(chunks, total);
};

export const readBoundedText = async (response, maxBytes) =>
	(await readBoundedBuffer(response, maxBytes)).toString("utf8");

export const readBoundedJson = async (response, maxBytes) => JSON.parse(await readBoundedText(response, maxBytes));
