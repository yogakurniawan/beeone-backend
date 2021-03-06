#!/usr/bin/env node

/**
 * Module dependencies.
 */

const app = require("../app");
const { normalizePort, onError, onListening } = require("../helpers/utility");
const debug = require("debug")("beeone-backend:server");
const http = require("http");

/**
 * Get port from environment and store in Express.
 */
const port = normalizePort(process.env.PORT || "5000");
app.set("port", port);

/**
 * Create HTTP server.
 */

const server = http.createServer(app);

/**
 * Listen on provided port, on all network interfaces.
 */

server.listen(port);
server.on("error", onError);
server.on("listening", () => {
  console.log(debug);
  onListening(server, debug);
});
