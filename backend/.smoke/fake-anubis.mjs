// fake anubis upstream for smoke testing the container probe in the anubis
// route. mimics the real deployment: the main :8923 listener answers the
// auth_request probe with a policy response (401 here - a challenge would be
// 200 with html). any http response must count as "serving".
import http from "node:http";

let answering = true;

const server = http.createServer((req, res) => {
	if (!answering) {
		// simulate a hung container: accept the connection, never answer
		return;
	}
	res.writeHead(401, { "Content-Type": "text/html" });
	res.end("<html>challenge</html>");
});

const start = async () => {
	await new Promise((resolve) => server.listen(18081, "127.0.0.1", resolve));
	console.log("fake anubis on 18081");
};

const setAnswering = (value) => {
	answering = value;
};

const stop = () =>
	new Promise((resolve) => {
		server.closeAllConnections?.();
		server.close(resolve);
	});

export { setAnswering, start, stop };