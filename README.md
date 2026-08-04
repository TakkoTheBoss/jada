<p align="center">
  <img src="jada-logo.png" alt="Jada project logo" width="40%">
</p>

# Jada

Jada is a Kademlia-based distributed hash table with single key/value operations, grouped data storage, an authenticated UDP RPC layer, a framed JSON TCP API, and an interactive client.

The executable is driven by Hachi. Hachi owns command-line mode selection, the interactive client, command validation, JSON request construction, target switching, local node orchestration, and user-facing help. The native C++ core remains responsible for sockets, cryptography, routing, concurrency, storage, snapshots, and the binary RPC protocol.

The CLI and node are independent components, but they can also run together in the same process. A CLI can attach to an already-running node, start a managed local node for live testing, stop or restart that managed node, or switch between local and remote targets without leaving the REPL.

Jada is named in memory of Jada, a resilient and unbreakable dog who survived cancer, multiple surgeries, and repeated recoveries with remarkable strength.

Post-quantum support is experimental and disabled by default.

***

## Project layout

- `jada.hachi` contains the application layer and executable entry point.
- `native/jada_native.cpp` contains the native Kademlia and transport core.
- `json.hpp` is the bundled nlohmann/json single-header library.
- `config.example.json` contains a complete example node configuration.
- `tests/smoke.sh` exercises the CLI, API, key/value operations, and group operations.

The Hachi layer calls a narrow native bridge:

- `jada_native::run_node()` starts a standalone node process.
- `jada_native::start_local_node()` starts a managed node inside the current CLI process.
- `jada_native::stop_local_node()` stops the managed node.
- `jada_native::local_node_status()` reports managed-node state.
- `jada_native::local_node_target()` returns the managed node API target.
- `jada_native::exchange()` sends one JSON request to a local or remote node.

Command parsing, mode selection, request construction, and REPL behavior remain in Hachi.

***

## Features

- Kademlia XOR-distance routing
- 128-bit or 160-bit NodeIDs
- User-supplied or randomly generated NodeIDs
- Text keys and hexadecimal keys
- Time-limited and infinite values
- Native `put` and `get` operations
- Native `group.put` and `group.get` operations
- Periodic republishing and routing refresh
- JSON snapshots for routing and stored values
- HMAC-SHA256 authenticated RPC messages
- Interactive Hachi CLI
- Independent CLI-only and node-only operation
- Combined node and CLI operation
- Managed local node start, stop, restart, status, and target selection from the REPL
- Domain, URL, IPv4, and bracketed IPv6 parsing for CLI targets
- Multi-line JSON request framing
- Experimental liboqs integration for post-quantum signatures

***

## Requirements

- Hachi 0.5.4 or a compatible newer release
- A C++20 compiler
- OpenSSL development headers and libraries
- POSIX sockets
- `json.hpp` in the project root
- Optional liboqs development files for experimental post-quantum builds

On Debian or Ubuntu, the core build dependencies can usually be installed with:

```bash
sudo apt install clang libssl-dev
```

Install Hachi separately and make sure the `hachi` executable is available in your `PATH`.

***

## Building

Build Jada through Hachi:

```bash
hachi jada.hachi -cf "-std=c++20 -O2 -I. -lssl -lcrypto" -build jada
```

This produces an executable named `jada`.

Build with experimental post-quantum support:

```bash
hachi jada.hachi -cf "-std=c++20 -O2 -I. -DWITH_OQS -lssl -lcrypto -loqs" -build jada
```

Post-quantum mode is still under test. Keep `pq_sign` set to `false` unless you are specifically testing that code path.

***

## Operating modes

Jada supports three operating patterns. The CLI does not automatically start a node, and starting a node does not automatically open the CLI unless both modes are explicitly requested.

### CLI only

Run Jada without node flags:

```bash
./jada
```

The CLI connects to `127.0.0.1:8080` by default. This is useful when a node is already running in another terminal, under a service manager, in a container, or on another machine.

Connect directly to another target:

```bash
./jada --cli 192.168.1.50:8080
./jada --cli node.example.net:8080
./jada --cli http://node.example.net:8080/path
```

The URL scheme and path are ignored. Jada uses the host and port to establish a raw TCP connection to the JSON API. This is not an HTTP request.

### Node only

Run a node with a configuration file:

```bash
./jada --config config.json
```

Run node mode with the default `config.json` path:

```bash
./jada --daemon
```

The `--daemon` flag selects node mode. It does not fork or detach the process from the terminal. Use systemd, another service manager, `nohup`, or a container runtime for background operation.

A separate CLI can attach to that node at any time:

```bash
./jada --cli 127.0.0.1:8080
```

Exiting that separate CLI does not stop the node.

### Node and CLI together

Start a node and open a CLI attached to its configured API port:

```bash
./jada --config config.json --cli
```

The node is started first. Jada reads `api_port` from the configuration and automatically sets the CLI target to `127.0.0.1:<api_port>`.

An explicit CLI target overrides the automatic local target:

```bash
./jada --config config.json --cli node.example.net:8080
```

This starts the local managed node while directing the CLI at the supplied target.

When the combined CLI exits, the managed in-process node is stopped before the process ends. Run the node separately when it must continue after the CLI closes.

### Help and version

```bash
./jada -h
./jada --help
./jada --version
```

***

## Interactive CLI

A CLI session begins with:

```text
🐶 Jada 0.1.0
CLI target: 127.0.0.1:8080
Type 'help' for commands. Type 'exit' or 'quit' to leave.
jada>
```

Available commands:

```text
put <key> <value> [ttl=SECONDS] [infinite=true|false]
get <key>
group.put <group> <key=value> [key=value ...] [ttl=SECONDS] [infinite=true|false]
group.get <group>
nearest <hex_target>
cli [host[:port]|url]
node.start [config]
node.stop
node.restart [config]
node.status
node.use
help
exit
quit
```

Quoted keys and values are supported:

```text
jada> put "system name" "Defiant Network" ttl=3600
jada> get "system name"
```

Change the target during a session:

```text
jada> cli node.example.net:8080
CLI target set to: node.example.net:8080
```

Display the current target:

```text
jada> cli
CLI target: node.example.net:8080
```

### Managed local node commands

Start a node from inside the CLI:

```text
jada> node.start config.json
Managed local node started: id=0123456789abcdef0123456789abcdef01234567 rpc=5555 api=8080 config=config.json
CLI target set to managed local node: 127.0.0.1:8080
```

When no path is supplied, `node.start` uses `config.json`:

```text
jada> node.start
```

Inspect the managed node:

```text
jada> node.status
Managed local node: running id=0123456789abcdef0123456789abcdef01234567 rpc=5555 api=8080 config=config.json
```

Stop or restart it:

```text
jada> node.stop
jada> node.restart config.json
```

Return the CLI target to the managed node after temporarily connecting elsewhere:

```text
jada> node.use
CLI target set to managed local node: 127.0.0.1:8080
```

These commands control only the node managed inside the current Jada process. They do not send remote shutdown commands and cannot stop a separately running or remote node. `node.status` reports the managed local node, not the health of the current remote CLI target.

A node started with `node.start` is stopped when its CLI process exits. Start the node in a separate process when it must outlive the CLI.

***

## Key/value operations

Store a value:

```text
jada> put alpha bravo ttl=3600
```

Retrieve it:

```text
jada> get alpha
```

Store without expiration:

```text
jada> put permanent value infinite=true
```

Text keys are hashed with SHA-256 and truncated to the configured NodeID width. A key containing only hexadecimal characters is interpreted as a hexadecimal key and left-padded when shorter than the configured width.

***

## Group operations

Groups provide a collection abstraction over individual DHT records.

```text
jada> group.put dns a1=1.2.3.4 a2=1.2.3.5 ttl=86400
jada> group.get dns
```

Each group member remains an independent key/value record. Jada stores a derived group index containing the member keys. The group index key is derived from `SHA-256("group:" + groupName)` and truncated to the configured NodeID width.

Values containing spaces can be quoted:

```text
jada> group.put services api="primary service" db="database service"
```

The current CLI treats `ttl=` and `infinite=` as group options. They are not inserted as group members.

***

## JSON API

The TCP API accepts complete JSON objects. Requests may be formatted on one line or across multiple lines.

Store a value directly:

```bash
printf '%s\n' '{"op":"put","key":"alpha","value":"bravo","ttl":3600,"infinite":false}' | nc -q 1 127.0.0.1 8080
```

Retrieve a value:

```bash
printf '%s\n' '{"op":"get","key":"alpha"}' | nc -q 1 127.0.0.1 8080
```

Store a group:

```bash
printf '%s\n' '{"op":"group.put","group":"dns","items":[{"key":"a1","value":"1.2.3.4"},{"key":"a2","value":"1.2.3.5"}],"ttl":86400,"infinite":false}' | nc -q 1 127.0.0.1 8080
```

Retrieve a group:

```bash
printf '%s\n' '{"op":"group.get","group":"dns"}' | nc -q 1 127.0.0.1 8080
```

Find known nodes nearest to a target:

```bash
printf '%s\n' '{"op":"nearest","target":"0123456789abcdef0123456789abcdef01234567"}' | nc -q 1 127.0.0.1 8080
```

***

## Configuration

Copy the example configuration:

```bash
cp config.example.json config.json
```

Example:

```json
{
  "rpc_port": 5555,
  "api_port": 8080,
  "secret": "replace-with-a-long-random-shared-secret",
  "K": 20,
  "ALPHA": 3,
  "request_timeout_ms": 3000,
  "republish_period_sec": 3600,
  "value_ttl_sec": 86400,
  "snapshot_period_sec": 300,
  "snapshot_path": "jada_snapshot.json",
  "bootstrap": [],
  "node_id": "0123456789abcdef0123456789abcdef01234567",
  "id_bits": 160,
  "pq_sign": false,
  "pq_scheme": "DILITHIUM_2"
}
```

### Configuration fields

- `rpc_port` is the UDP port used by the DHT protocol.
- `api_port` is the TCP port used by the JSON API.
- `secret` is the shared HMAC secret used by participating nodes.
- `K` is the Kademlia bucket size and replication target.
- `ALPHA` is the parallel lookup width.
- `request_timeout_ms` is the UDP RPC timeout.
- `republish_period_sec` controls publisher republishing.
- `value_ttl_sec` is the default value lifetime.
- `snapshot_period_sec` controls snapshot frequency.
- `snapshot_path` is the destination for JSON snapshots.
- `bootstrap` contains bootstrap peers in `IPv4:port` form.
- `node_id` is an optional fixed hexadecimal NodeID.
- `id_bits` must be `128` or `160`. Other values fall back to `160`.
- `pq_sign` enables the experimental post-quantum path when compiled with liboqs.
- `pq_scheme` selects the liboqs signature mechanism.

Nodes in the same overlay must use compatible NodeID widths and the same shared secret.

***

## Networking

The current node listeners use IPv4 sockets and bind to all local interfaces.

- The DHT RPC service uses UDP.
- The JSON API uses TCP.
- LAN and public Internet operation require routable addresses and open firewall rules.
- NAT traversal and automatic hole punching are not implemented.
- Public nodes usually require UDP port forwarding for `rpc_port`.
- The JSON API has no separate client authentication layer. Restrict `api_port` with a firewall, VPN, reverse proxy, or local bind policy when appropriate.
- Bootstrap entries currently use numeric IPv4 addresses.

The CLI resolver accepts domains, IPv4 addresses, URLs, and bracketed IPv6 targets. Successful connection still depends on the remote API listener and network path.

***

## Snapshots

When `snapshot_path` is configured, Jada periodically writes:

- NodeID and configured ID width
- Routing buckets and known contacts
- Stored key/value records
- Infinite-value markers

Snapshots are currently diagnostic output. Automatic restoration at startup is not yet implemented.

***

## Testing

Build Jada, then run:

```bash
./tests/smoke.sh
```

The smoke test verifies both lifecycle models:

- Starting and stopping a managed node from the Hachi CLI
- Automatic CLI attachment to a managed node
- Attaching a separate CLI to an independently running node
- Single key/value storage and retrieval
- Multi-member group storage and retrieval

***

## Current boundaries

The refactor moves the application layer into Hachi while retaining the native systems layer.

Hachi currently handles:

- Process mode selection
- CLI argument handling
- Help and version output
- REPL lifecycle
- Combined node and CLI orchestration
- Managed local node command dispatch
- CLI target switching
- Quoted command tokenization bridge usage
- Command validation
- JSON escaping and request construction
- Group command option handling

C++ currently handles:

- UDP and TCP sockets
- DNS resolution for CLI targets
- Managed node lifetime and thread shutdown primitives
- Kademlia routing and lookup
- Routing buckets
- Thread pools and synchronization
- HMAC and SHA-256
- Optional liboqs calls
- Binary RPC encoding
- Local storage and TTL enforcement
- Group index persistence
- Snapshots

The tokenization helper remains an embedded native block because Hachi 0.5.4 does not yet provide a dynamic string-list parser with the ownership behavior needed by this REPL.

***

## Post-quantum status

Post-quantum signing is experimental. It is not part of the validated core path and should not be treated as production-ready authentication. The default build and example configuration leave it disabled.

***

## License

Jada is licensed under the Apache License, Version 2.0. See `LICENSE` and `NOTICE`.

Bundled and linked dependencies retain their respective licenses and notices.
