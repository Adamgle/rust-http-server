# Rust HTTP Server

A lightweight asynchronous HTTP server built on Tokio, featuring routing, middleware, caching, and an experimental database integration.  
This project is still in development and serves as both a learning exercise and a foundation for future projects.

---

## Motivation

Created to gain experience with:

- Rust.
- Async programming in Rust with Futures.
- Tokio runtime.
- TCP protocol and network programming.
- Various crates used in the Rust ecosystem.

---

## Features

- **Logging**  
  Integrated with `env_logger` and the `log` crate. Supports logging to files and maintaining a log history for later analysis.

- **Asynchronous runtime**  
  Built on top of `tokio`.

- **Domain redirection**  
  Supports redirecting requests for specific domains.

- **Custom database**  
  Bundled with a simple database originally written for this project (now isolated into a separate repository). While basic, it demonstrates persistence and integration.

- **Router**

  - Register static request handlers at build time, resolving at runtime to async closures behind pinned pointers.
  - Support abstracted, custom routes that do not resolve to the file system.
  - Handles path normalization and validation.
  - Supports routes, middleware handlers, and middleware segments that resolve on wildcards.
  - Likely the most stable, abstract, and performant part of the system.

- **HTTP abstraction**  
  Provides abstractions over the HTTP lifecycle for structured reading, writing, parsing, and validation

  - Request and Response abstraction.
  - Headers with separate APIs for request and response headers.
  - Request lines, methods, and protocols
  - Response start lines, status codes, and status texts

    _(Implementation is not yet fully complete.)_

- **Public directory structure**  
  Serves static files from dedicated folders (`pages`, `client`, `assets`, `styles`).  
  File resolution is based on extension, or defaults to a directory path resolving to pages/.../index.html

- **Server-side caching**  
  Caches routes, middleware, and middleware segments registered in the router for faster lookups.
  Handles caching of `AppController` wrapper methods that also abstract database operations. This mitigates some performance issues with the database.

---

## Issues

- **Error handling**  
  Currently relies on `Box<dyn Error + Send + Sync>`. While functional, it lacks type specificity. A more structured approach (e.g., using `anyhow`) would improve maintainability. Ideally typed error messages based on status codes should be implemented.

- **Lack of testing**  
  No formal unit tests have been implemented. Only ad-hoc testing with Python scripts for HTTP parsing and basic performance.

- **Excessive use of `Mutex`**  
  Mutexes ensure thread safety but may degrade performance. In some cases, `RwLock` or other concurrency primitives may be more appropriate.

- **Config file inconsistency**  
  The `domain` field in the config technically represents a `Host` header. It is fine to keep it as a domain, but provide some abstracted getter
  that builds the `Host` header based on that and keep it persisted in the struct. Currently it exposes the function to transform it.

- **Header typing**  
  Header names and certain values (e.g., `Content-Type`) should be strongly typed and validated against MIME types.

- **File handling**  
  No support for serving files without extensions. File type inference based on file header might be a good move.

- **Async/futures usage**  
  Some async code may block I/O (e.g., file reads) or include unnecessary `await` points, potentially hurting performance.
  There may be some heavy misuse of the Tokio runtime, degrading performance.

---

## Notes

The repository includes a simple demo CRUD application with API based on this server, it features:

- Basic authentication (sign-in/out).
- User roles and user-specific data.
- Uses middleware and middleware segments to pre-process requests
- Exposes basic API to communicate with the database with dynamically resolved endpoints.
- Very minimal and not production-ready.

---

## TODO

- Write **unit tests** for HTTP message parsing and server-side path resolution (critical for security).
- Add **password hashing** in the database.
- Make **session storage configurable** (currently fixed to 1 year).
- Extend **domain redirection** to allow per-request rules instead of relying only on static config.
- Add **limits on HTTP message sizes** to prevent abuse.
- Add **limits on cache size** to avoid memory bloat.
- Expose **CLI arguments** for utility tasks (e.g., parsing log files into history). Currently, log parsing impacts only startup performance, not runtime.
- Validate the **route existence for middleware** as currently there is a way to register middleware handler or middleware segment for route that does not exist.
  This is not an issue in practice (if the route handler does not resolve, neither can the middleware), but it wastes memory.
- Implement **Transfer-Encoding: chunked** for large payloads.
- Generate **default config file** when server starts up.

---
