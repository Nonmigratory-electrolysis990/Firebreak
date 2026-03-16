# gRPC Security

## DO

- **Use mTLS for service-to-service communication**. Both client and server present certificates. Use `grpc.ssl_channel_credentials` with client cert/key.
- **Implement auth interceptors** (unary and stream) that validate tokens before the handler executes. Extract auth metadata from `grpc.Metadata`.
- **Validate all input fields** in protobuf messages. Proto3 defaults (0, "", false) are valid values — check for required fields explicitly.
- **Set deadlines on every RPC call** (`context.WithTimeout` in Go, `deadline` in Python). Propagate deadlines downstream to prevent cascading hangs.
- **Use per-RPC credentials** for user-facing calls. Attach bearer tokens via `grpc.WithPerRPCCredentials` or metadata interceptors.
- **Enable keepalive parameters** to detect dead connections: `keepalive_time_ms`, `keepalive_timeout_ms`, `permit_without_stream`.
- **Limit message sizes** with `grpc.max_receive_message_length` and `grpc.max_send_message_length` to prevent memory exhaustion.

## DON'T

- Use insecure channels (`grpc.insecure_channel`) in production — all traffic is plaintext.
- Trust client-supplied metadata without validation — metadata is user-controlled, like HTTP headers.
- Skip deadline propagation — a downstream service without a deadline can hang forever, exhausting connection pools.
- Use reflection service in production without auth — it exposes your entire API schema.
- Return detailed error messages with stack traces in `StatusException`. Use error codes and sanitized messages.
- Allow unlimited message sizes — a malicious client can send a multi-GB message and OOM the server.

## Common AI Mistakes

- Generating gRPC servers with `server.addInsecurePort("0.0.0.0:50051")` and no TLS.
- Forgetting deadline propagation — setting a deadline on the gateway but not passing context to downstream calls.
- Implementing auth in the handler instead of an interceptor, leading to inconsistent enforcement.
- Not validating proto3 default values (e.g., treating `0` as a valid ID when it means "not set").
- Using server reflection in production without access control, leaking the full API surface.
