![Jada Mascot](jada-logo.png "Jada!!")

# Jada

Jada is a resilient, Kademlia-based distributed hash table (DHT) that supports both single key/value operations and grouped data storage. It includes an embedded JSON API server and a built-in CLI for interacting with nodes locally or remotely. Optional post-quantum cryptography is still under testing.

***
## Features

- Kademlia-based distributed hash table
- Single and group key/value operations
- Lightweight JSON API server (TCP)
- CLI for local or remote interaction
- Configurable node identity and key size
- Optional post-quantum (PQ) crypto (experimental)
- Built to run indefinitely
- Fully namespaced for Hachi integration

***

## File Overview

|File|Purpose|
|---|---|
|`jada.cpp`|Main implementation of the Jada DHT and CLI logic. All functions live under the `jada` namespace.|
|`jada.hachi`|Entry point for compiling and running Jada with the Hachi compiler.|

***

## Building with Hachi

To build Jada using the Hachi compiler:

```
hachi jada.hachi -cf "-std=c++20 -O2 -I. -lssl -lcrypto" -build jada
```

This produces an executable named `jada`.

If you want to enable experimental post-quantum features, and your environment has liboqs installed:

```
hachi jada.hachi -cf "-std=c++20 -O2 -I. -DWITH_OQS -I. -lssl -lcrypto -loqs" -build jada
```

***

## Modes

Jada operates in two distinct modes:

|Mode|Command Example|Description|
|---|---|---|
|CLI mode|`jada` or `jada --cli <host:port>`|Starts the interactive shell for a local or remote Jada node. No node instance is launched.|
|Node mode|`jada --config config.json` or `jada --daemon --config config.json`|Runs the node service using the provided configuration file. RPC, API, and background threads start automatically.|

***

## CLI Usage

```
$ jada
🐶 Jada 0.1.0
CLI target: 127.0.0.1:8080
Type 'help' for commands. Ctrl-D or 'exit' to quit.
jada>
```

Available commands:

```
help
put <key> <value> [ttl=SECONDS] [infinite=true|false]
get <key>
group.put <group> <k=v> [k=v ...] [ttl=SECONDS] [infinite=true|false]
group.get <group>
nearest <hex_target>
cli [host[:port]|url]      # View or change CLI target
exit | quit                # Exit the CLI
```

Example session:

```
jada> put alpha bravo ttl=3600
{"ok":true,"msg":"stored","key":"alpha","value":"bravo"}

jada> get alpha
{"ok":true,"value":"bravo"}

jada> group.put dns a1=1.2.3.4 a2=1.2.3.5 infinite=true
{"ok":true,"stored_group":"dns"}

jada> group.get dns
{"ok":true,"group":"dns","items":[{"key":"a1","value":"1.2.3.4"},{"key":"a2","value":"1.2.3.5"}]}
```

***

## Node Configuration

Example `config.json`:

```json
{
  "node_id_bits": 160,
  "rpc_port": 5555,
  "api_port": 8080,
  "snapshot_path": "snapshot.json",
  "bootstrap": ["192.168.1.10:5555", "node.example.net:5555"],
  "secret": "your-hmac-secret",
  "pq_enabled": false
}
```

Start the node:

```
./jada --config config.json
```

Or run as a service:

```
./jada --daemon --config config.json
```

Expected output:

```
[node] started id=0123456789abcdef... (160b)
rpc_port=5555 api_port=8080 pq=off
[api] listening on 8080 (framed JSON; multiline OK)
[boot] 127.0.0.1:5555 -> ok
```

***

## Networking Notes

- Works across localhost, LAN, WAN, and public Internet if reachable
- Requires UDP/TCP ports open or forwarded (rpc_port, api_port)
- Supports domain names, IPv4, and IPv6
- No NAT traversal or hole punching
- Safe for indefinite runtime; threads self-maintain routing and TTLs

***

## Status

Post-quantum signature functionality is still being validated.  
Core Kademlia, JSON API, and group features are stable.

***

## License

Apache License  
No GPL or restrictive dependencies.  
Uses nlohmann/json under MIT and OpenSSL for cryptography. liboqs is optional.
