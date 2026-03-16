# WebSocket Authentication

## DO

- **Authenticate on the initial HTTP upgrade request** — validate the JWT or session token in the handshake before upgrading the connection.
```javascript
// ws (Node.js)
wss.on("connection", (ws, req) => {
  const token = new URL(req.url, "http://localhost").searchParams.get("token");
  const user = verifyJwt(token);
  if (!user) return ws.close(4401, "Unauthorized");
  ws.userId = user.id;
});
```
- **Validate origin headers** — check `Origin` or `Sec-WebSocket-Origin` against an allowlist to prevent cross-site WebSocket hijacking.
- **Re-validate tokens on long-lived connections** — if a JWT expires during an open connection, enforce disconnection or require re-auth via an in-band message.
- **Apply per-message authorization** for sensitive operations — connection-level auth is not sufficient when different messages require different permission levels.
- **Set idle connection timeouts** — close connections that have been inactive beyond a threshold (e.g., 5 minutes) to prevent resource exhaustion.
- **Rate limit messages per connection** — prevent a single client from flooding the server. Track message count per time window.
- **Use `wss://` (TLS)** exclusively in production — unencrypted WebSocket traffic is trivially interceptable.

## DON'T

- Pass tokens in the URL path for production use — URLs appear in logs, Referer headers, and browser history. Use a short-lived token or authenticate via the first message.
- Rely on cookie-based auth alone without origin validation — cross-site WebSocket hijacking sends cookies automatically.
- Trust `userId` sent in WebSocket messages — derive identity from the authenticated connection, not from message payloads.
- Keep connections open indefinitely without heartbeats — stale connections consume memory and file descriptors.
- Broadcast messages to all connections without per-user authorization — validate that each recipient is permitted to see each message.
- Use `ws://` in production — all WebSocket traffic should be encrypted with TLS.

## Common AI Mistakes

- Building a WebSocket server with no authentication — accepting all connections and trusting `userId` from message payloads.
- Using `socket.io` without configuring `allowedOrigins` — defaults to accepting all origins.
- Generating chat applications where the connection authenticates once but never re-validates expired tokens.
- Passing long-lived JWTs as URL query parameters instead of using a short-lived connection ticket pattern.
- Implementing "rooms" without checking if the user is authorized to join that room.
- Forgetting to handle the `close` event for cleanup — orphaned connections leak memory and state.
