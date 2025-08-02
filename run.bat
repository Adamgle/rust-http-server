@REM start powershell -Command "tsc --watch"
cmd /c "set RUST_LOG=rust_http_server && cargo run -- 127.0.0.1:5000"