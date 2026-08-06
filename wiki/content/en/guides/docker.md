# Docker Chains and Demo

The `.docker/` directory provides a four-level nested network environment: a chain assertion test (one-shot) and a persistent demo (the host connects directly into the deepest network).

## Topology

```
tester ──public(172.28)──► node-root ──public──► node-mid ──mid(10.100)──► node-leaf ──leaf(10.120)──► node-deep ──deep(10.140)──► target
```

The tester can only reach root/mid; target (10.140.0.100) is reachable only from node-deep.
Data path: client(tester) → root → mid → leaf → deep → target.

## Chain Assertion Test

```bash
docker build -f .docker/Dockerfile -t anet:dev .
docker compose -f .docker/docker-compose.test.yaml up --abort-on-container-exit --exit-code-from tester
```

Assertion matrix (exit code 0 when all pass):

| Assertion | Description |
| --- | --- |
| T1 | SOCKS5 traversal across the four-level chain |
| T2 | Same target via HTTP CONNECT |
| T3 | ACL rejection: targets outside the rules must fail |
| T4 | Multi-node access: one client connected to root and mid simultaneously |
| T5 | Long-poll config hot update: newly added rules take effect on the client without reconnecting |
| T6 | Self-healing: kick mid → chain breaks → automatic reconnect and recovery |
| T7 | Management-plane traversal: handshake delivers the control endpoint → auto-discovery → ticket chain exchanged for a scoped management session (rules tier enforced) |

> On Windows, if the demo chain is running, first run
> `docker compose -f .docker/docker-compose.chain.yaml down` to release the subnets,
> then run the test.

## Persistent Demo

```bash
docker compose -f .docker/docker-compose.chain.yaml up -d
```

From the host you can connect to root directly with `anet-svc client` or anet-gui (via the
`127.0.0.1` port mappings) and experience the full path to 10.140.0.100 across the four-level chain.

## Custom Chains

Orchestration notes:

- Each node pre-provisions downstream tokens via `AGILE_RELAY_TOKENS` (idempotent by hash); the `psk_xxx|expose:rules` syntax exposes the control plane
- Set `AGILE_PUBLIC_HOST` to a name resolvable inside the container network, so that share links and tunnel endpoints are correct
- Mount the config file at `/etc/agile-net/node.toml`: `[listener]` opens the upstream-facing side, `[[connectors]]` connects to the upstream,
  and `advertise` announces the local segment (with multi-level setups, downstream links are included automatically)
