# Ampritude-proxy

A reverse proxy in front of amplitude and umami. It redacts some data and annotates requests with other data.

## Implementation notes
There's several green threads by tokio running different bits of the program.
They should fail at the same time.
Experimentation with `panic!` in one service confirms that they do.

The above also holds true when tested w/`loop { ... }`.

## Development
Configured dev-env requires:
1. Nix (flake supported)
1. Rust configured IDE of choice

#### How to run locally:
TODO: Fix/specify how to change ports, currently hardcoded
1. Start an echo server:
   ```
   socat -v -d -d tcp-l:1234,crlf,reuseaddr,fork system:"
   echo HTTP/1.1 200 OK;
   echo Content-Type\: text/plain;
   echo;
   echo \"Server: \$SOCAT_SOCKADDR:\$SOCAT_SOCKPORT\";
   echo \"Client: \$SOCAT_PEERADDR:\$SOCAT_PEERPORT\";
   "
   ```
   `socat -v tcp-l:1234,fork exec:"'$(realpath cat)'"`
1. Start the program:
   `cargo watch -qx 'run'` or just `cargo run`
1. Perform http request towards it:
   1. Liveness probe: `curl -v localhost:6969/is_alive`
   1. Proxied http request: `curl -v -H'user-agent: nav-developer' 'localhost:6191/nav123456/abcdef123456/test654321/a1b2c3d4e5?regularstring=123456&anotherString=12345'`
      This should print the following string in the `socat` terminal:
      `GET /nav123456/[redacted]/test654321/[redacted]?regularstring=[redacted]&anotherString=12345 HTTP/1.1\r`
