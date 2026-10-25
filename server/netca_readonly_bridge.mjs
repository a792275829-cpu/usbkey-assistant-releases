// Compatibility entrypoint: importing it does not start the server or read TLS.
import { pathToFileURL } from "node:url";
import { createBridgeServer } from "./websocket-server.mjs";
import { port, parentPid, audit, bridgeVersion, allowedOrigins, logPath } from "./runtime.mjs";
export * from "./rpc.mjs";
export { createBridgeServer };

if (process.argv[1] != null &&
    import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = createBridgeServer();
  server.listen(port, "127.0.0.1", () => {
    audit("server_start", {
      bridgeVersion,
      address: `wss://127.0.0.1:${port}`,
      allowedOrigins: [...allowedOrigins],
      mode: "ft3000gm-signing",
      logPath,
    });
  });
  if (Number.isInteger(parentPid) && parentPid > 1) {
    const parentMonitor = setInterval(() => {
      try {
        process.kill(parentPid, 0);
      } catch {
        audit("parent_process_gone", { parentPid });
        server.close(() => process.exit(0));
        setTimeout(() => process.exit(0), 1000).unref();
      }
    }, 1000);
    parentMonitor.unref();
  }
}
