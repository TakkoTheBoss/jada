<p align="center">
  <img src="jada-logo.png" alt="Jada project logo" title="Jada" width="40%">
</p>

Jada

Jada is a resilient, Kademlia-based distributed hash table that supports individual key/value records, grouped data storage, local and remote operation, an authenticated UDP RPC layer, a framed JSON TCP API, and an interactive command-line client.

Jada is written as a Hachi application backed by a native C++ systems core. The refactor moves the application logic, command handling, mode selection, and CLI behavior into Hachi while keeping networking, cryptography, routing, storage, and concurrency in the native layer.

Jada is named in memory of a deeply resilient dog. She rarely became sick, then faced cancer and multiple surgeries with extraordinary strength, recovering again and again. She was unbreakable, and this project carries her name in that spirit.

Post-quantum support is experimental and disabled by default.



Figure 1. Simple Kademlia peering subtree



Figure 2. XOR distance lookup

Features

Kademlia XOR-distance routing

128-bit or 160-bit NodeIDs

User-supplied or randomly generated NodeIDs

Text keys and hexadecimal keys

Individual put and get operations

Native group.put and group.get operations

Time-limited and infinite records

Periodic republishing and routing refresh

HMAC-SHA256 authenticated RPC messages

JSON snapshots of routing and stored values

Framed JSON TCP API with multi-line request support

Built-in CLI for local or remote interaction

Independent CLI-only and node-only operation

Combined node and CLI operation

Local node start, stop, restart, status, and selection from the CLI

Domain, URL, IPv4, and bracketed IPv6 parsing for CLI targets

Optional liboqs integration for experimental post-quantum signatures

Designed for long-running operation

Design Overview

Jada extends the Kademlia distributed hash table model with a small application layer for direct key/value storage and grouped collections.

Routing

Every node has a NodeID. Jada measures distance between NodeIDs and keys using XOR distance, then maintains contacts in Kademlia-style routing buckets. Lookups query multiple peers in parallel and move toward the nodes closest to the target.

Key Storage

Jada accepts both text keys and hexadecimal keys.

Text keys are hashed with SHA-256 and truncated to the configured NodeID width.

Keys containing only hexadecimal characters are interpreted as hexadecimal keys.

Records may use a time-to-live or be marked as infinite.

Locally published records are periodically republished to nearby peers.

Group Operations

A group is a collection of independently stored key/value records associated with a shared name.

For a group named dns, Jada derives a group index key from:

SHA-256("group:" + groupName)

The index contains the keys belonging to the group. Each member remains an ordinary DHT record, so it can still be retrieved individually.

This provides a collection abstraction without replacing or complicating the underlying Kademlia routing model.

RPC Security

Jada uses HMAC-SHA256 to authenticate RPC messages between nodes that share the same secret. This protects the DHT protocol from unauthenticated messages and unauthorized storage requests within a configured overlay.

The JSON API is a separate TCP interface. It does not currently include its own client authentication mechanism, so it should be restricted with local binding, firewall rules, a VPN, or another trusted network boundary when exposed beyond localhost.

Post-Quantum Support

Jada includes an optional liboqs integration for post-quantum signature testing. This path is experimental, disabled by default, and is not part of the validated core operation.

Project Files

File

Purpose

jada.hachi

Jada application entry point, CLI, mode selection, request construction, and node lifecycle controls

native/jada_native.cpp

Native Kademlia engine, sockets, routing, cryptography, storage, RPC protocol, threading, and snapshots

json.hpp

Bundled nlohmann/json single-header library

config.example.json

Example Jada node configuration

tests/smoke.sh

Basic lifecycle, key/value, and group operation tests

ARCHITECTURE.md

Additional notes about the Hachi and native boundary

Requirements

Hachi 0.5.4 or a compatible newer version

A C++20 compiler

OpenSSL development headers and libraries

POSIX sockets

Optional liboqs development files for post-quantum testing

On Debian or Ubuntu, the core native dependencies can usually be installed with:

sudo apt install clang libssl-dev

Install Hachi separately and make sure the hachi executable is available in your PATH.

Building with Hachi

<p align="center">
  <img src="hachi+Jada.png" alt="Hachi and Jada" title="Hachi and Jada" width="55%">
</p>

Build Jada with:

hachi jada.hachi -cf "-std=c++20 -O2 -I. -lssl -lcrypto" -build jada

This produces an executable named jada.

Build with experimental post-quantum support:

hachi jada.hachi -cf "-std=c++20 -O2 -I. -DWITH_OQS -lssl -lcrypto -loqs" -build jada

Keep pq_sign set to false unless you are specifically testing the post-quantum path.

Operating Jada

The CLI and node are independent. Starting the CLI does not silently start a node, and starting a node does not force open a CLI. They can also run together when explicitly requested.

CLI Only

Open the CLI and target the default local API at 127.0.0.1:8080:

./jada

Connect directly to an existing node:

./jada --cli 192.168.1.50:8080
./jada --cli node.example.net:8080
./jada --cli http://node.example.net:8080/path

The URL scheme and path are ignored. Jada uses the resolved host and port for its raw TCP JSON API connection. It does not send an HTTP request.

Node Only

Start a node with a configuration file:

./jada --config config.json

Start node mode with the default config.json path:

./jada --daemon

The --daemon option selects node mode. It does not fork or detach the process. Use systemd, another service manager, nohup, or a container runtime when the process must run in the background.

A separate CLI can attach to the running node at any time:

./jada --cli 127.0.0.1:8080

Exiting that CLI does not stop the separately running node.

Node and CLI Together

Start a node and open a CLI attached to it:

./jada --config config.json --cli

Jada reads api_port from the configuration and targets the managed local node automatically.

An explicit target may also be supplied:

./jada --config config.json --cli node.example.net:8080

This starts the managed local node while directing the CLI at the supplied target.

When a combined CLI session exits, the node managed inside that process is stopped cleanly. Start the node in a separate process when it must continue after the CLI closes.

Help and Version

./jada -h
./jada --help
./jada --version

CLI Usage

A CLI session begins with:

🐶 Jada 0.1.0
CLI target: 127.0.0.1:8080
Type 'help' for commands. Type 'exit' or 'quit' to leave.
jada>

Available commands:

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

Key/Value Examples

Store a value:

jada> put alpha bravo ttl=3600

Retrieve it:

jada> get alpha

Store a record without expiration:

jada> put permanent value infinite=true

Quoted keys and values are supported:

jada> put "system name" "Defiant Network" ttl=3600
jada> get "system name"

Group Examples

Store several related records:

jada> group.put dns a1=1.2.3.4 a2=1.2.3.5 ttl=86400

Retrieve the group:

jada> group.get dns

Values containing spaces can be quoted:

jada> group.put services api="primary service" db="database service"

The CLI recognizes ttl= and infinite= as group options. They are not stored as group members.

Switching Nodes

Show the current target:

jada> cli
CLI target: 127.0.0.1:8080

Switch to another node:

jada> cli node.example.net:8080
CLI target set to: node.example.net:8080

Managing a Local Node

Start a local node from the CLI:

jada> node.start config.json
Managed local node started: id=0123456789abcdef0123456789abcdef01234567 rpc=5555 api=8080 config=config.json
CLI target set to managed local node: 127.0.0.1:8080

When no path is supplied, Jada uses config.json:

jada> node.start

Check its status:

jada> node.status
Managed local node: running id=0123456789abcdef0123456789abcdef01234567 rpc=5555 api=8080 config=config.json

Stop or restart it:

jada> node.stop
jada> node.restart config.json

Return the CLI target to the managed node after connecting elsewhere:

jada> node.use
CLI target set to managed local node: 127.0.0.1:8080

These commands control only the node started inside the current CLI process. They do not stop a separately running or remote node.

JSON API

The TCP API accepts complete JSON objects on one line or across multiple lines.

Store a value:

printf '%s\n' '{"op":"put","key":"alpha","value":"bravo","ttl":3600,"infinite":false}' | nc -q 1 127.0.0.1 8080

Retrieve a value:

printf '%s\n' '{"op":"get","key":"alpha"}' | nc -q 1 127.0.0.1 8080

Store a group:

printf '%s\n' '{"op":"group.put","group":"dns","items":[{"key":"a1","value":"1.2.3.4"},{"key":"a2","value":"1.2.3.5"}],"ttl":86400,"infinite":false}' | nc -q 1 127.0.0.1 8080

Retrieve a group:

printf '%s\n' '{"op":"group.get","group":"dns"}' | nc -q 1 127.0.0.1 8080

Find known nodes nearest to a target:

printf '%s\n' '{"op":"nearest","target":"0123456789abcdef0123456789abcdef01234567"}' | nc -q 1 127.0.0.1 8080

Configuration

Copy the example configuration:

cp config.example.json config.json

Example:

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

Configuration Fields

rpc_port is the UDP port used by the DHT protocol.

api_port is the TCP port used by the JSON API.

secret is the shared HMAC secret used by participating nodes.

K is the routing bucket size and replication target.

ALPHA is the parallel lookup width.

request_timeout_ms is the UDP RPC timeout.

republish_period_sec controls publisher republishing.

value_ttl_sec is the default value lifetime.

snapshot_period_sec controls snapshot frequency.

snapshot_path is the destination for JSON snapshots.

bootstrap contains bootstrap peers in IPv4:port form.

node_id is an optional fixed hexadecimal NodeID.

id_bits must be 128 or 160. Other values fall back to 160.

pq_sign enables the experimental post-quantum path when compiled with liboqs.

pq_scheme selects the liboqs signature mechanism.

Nodes in the same overlay must use compatible NodeID widths and the same shared secret.

Networking Notes

Jada can operate across localhost, LAN, WAN, and the public Internet when the network path is reachable.

The DHT RPC service uses UDP.

The JSON API uses TCP.

Node listeners currently use IPv4 sockets and bind to all local interfaces.

LAN and public Internet operation require appropriate firewall rules.

Public nodes usually require UDP port forwarding for rpc_port.

NAT traversal and automatic hole punching are not implemented.

Bootstrap entries currently use numeric IPv4 addresses.

The CLI accepts domains, URLs, IPv4 addresses, and bracketed IPv6 targets.

The JSON API should not be exposed publicly without an appropriate access-control boundary.

Snapshots

When snapshot_path is configured, Jada periodically records:

The node identity and configured ID width

Routing buckets and known contacts

Stored key/value records

Infinite-value markers

Snapshots are currently diagnostic output. Automatic restoration at startup is not yet implemented.

Testing

Build Jada, then run:

./tests/smoke.sh

The smoke test covers:

Starting and stopping a managed node from the CLI

Automatic CLI attachment to a managed node

Attaching a separate CLI to an independently running node

Single key/value storage and retrieval

Multi-member group storage and retrieval

Status

The core Kademlia, JSON API, CLI, key/value, group, and local node lifecycle paths are working and smoke-tested.

Post-quantum signature functionality remains experimental and under active testing.

License

Jada is licensed under the Apache License, Version 2.0. See LICENSE and NOTICE.

Bundled and linked dependencies retain their respective licenses and notices. Jada uses nlohmann/json under the MIT License, OpenSSL for cryptography, and optional liboqs for experimental post-quantum support.
