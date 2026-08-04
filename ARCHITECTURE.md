# Jada architecture

Jada is built as one Hachi executable with a narrow native systems core.

## Hachi application layer

`jada.hachi` owns the application flow:

- Argument parsing
- CLI-only, node-only, and combined mode selection
- Help and version output
- Interactive command loop
- Managed local node command dispatch
- CLI target management
- Command validation
- JSON escaping
- JSON request construction
- Group option parsing

Hachi calls a narrow native bridge:

- `nativeRunNode`
- `nativeStartLocalNode`
- `nativeStopLocalNode`
- `nativeLocalNodeStatus`
- `nativeLocalNodeTarget`
- `nativeExchange`

## Native systems core

`native/jada_native.cpp` owns operations that currently require C++ and POSIX APIs:

- UDP RPC transport
- TCP JSON API server
- Kademlia routing
- Node and value lookup
- Contact buckets
- Replication and republishing
- TTL enforcement
- OpenSSL cryptography
- Experimental liboqs signatures
- Threading and synchronization
- Managed local node ownership and shutdown
- Snapshot output

## Execution model

CLI-only mode sends JSON requests to an existing local or remote node. It does not start a node unless the operator runs `node.start` inside the REPL.

Node-only mode starts the RPC service, API service, maintenance threads, and bootstrap process. It does not start an interactive shell.

Combined mode starts a managed local node and then opens the Hachi CLI. The CLI automatically targets the managed node unless an explicit target was supplied. When the combined CLI exits, the managed node is stopped cleanly.

A managed node uses the same native DHT engine as a standalone node. The difference is ownership. Its lifetime belongs to the current CLI process and can be controlled with `node.start`, `node.stop`, `node.restart`, `node.status`, and `node.use`.

## Data flow

1. The Hachi CLI parses a command.
2. Lifecycle commands are routed to the managed-node bridge.
3. Data commands are validated and converted into JSON requests.
4. `nativeExchange` resolves the selected target and opens a TCP connection.
5. The node API parses the JSON request.
6. The native DHT core performs the requested operation.
7. The API returns one JSON response.
8. Hachi prints the response.

## Group representation

A group is represented by:

- Independent DHT values for each member
- A derived group-index key
- A JSON index listing member keys

The group-index key is generated from `SHA-256("group:" + groupName)` and truncated to the active NodeID width.

## Compatibility

The native RPC and storage behavior remains based on the previous Jada implementation. The refactor changes the application boundary and corrects CLI construction of group options. It does not replace the DHT protocol with a new protocol.
