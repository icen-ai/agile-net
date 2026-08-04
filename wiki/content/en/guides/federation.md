# Federation: Delegated Issuance & E2E

The federation model keeps three parties sovereign — the public rendezvous (B), the resource
owner (C), and the consumer (A): B provides reachability only; accounts and grants always
belong to the resource owner.

Three ways to share, by trust tier:

| Mode | Use when | What B can see |
| --- | --- | --- |
| One-click adoption (P1) | You trust B's admin: C pushes policy groups, B's admin adopts and opens an account for A | Traffic content (hop-by-hop TLS) |
| Delegated issuance (P2, transparent) | C issues credentials to A directly — no work for B's admin | Traffic content |
| Delegated issuance + E2E groups (P3) | You don't trust B: content is end-to-end encrypted | Coarse routing hints only — no targets, no content |

## Delegated issuance (resource owner C)

Admin UI → **Fan-out** → **Delegation** tab → **Issue Delegation**:

1. **Registration targets (failover set)**: check the upstreams that accept this token
   (online v3+ upstreams are pre-checked). The token registers on every selected upstream;
   any online one accepts the consumer.
2. **Primary entry**: the link's first-connect address; the rest are failover backups the
   client rotates through in check order.
3. **Groups**: local groups the token may reach (multi-select). Groups with an `E2E` badge
   enforce end-to-end encryption.
4. Add a label and generate — you get a full link (or a downloadable `.anet` credential
   file, optionally PIN-encrypted).

Route advertisement needs no hand maintenance: a fan-out's pushed group rules are unioned
into the routes it declares upstream (offering implies reachability), and the E2E routing
hint is derived from that same set — the hint always lands within what the peer's route
table actually carries. Fill the advertise field only for extra segments beyond the pushed
groups.

**Trust semantics** (pinned in the dialog): in transparent tier the failover set is exactly
*who can see the traffic*; with E2E it is a pure availability set (upstreams only see
routing hints).

The list shows each token's per-upstream registration state (registered / registering /
offline / failure reason). **Revoke** takes effect immediately: every online upstream drops
the registration and kicks the token's live sessions.

## E2E-enforced groups (e2e_required)

Once a group is marked end-to-end encrypted:

- It may hang **only** on delegated tokens — never on local accounts, fan-in tokens or
  fan-out connectors (those principals have no E2E key; all four write paths enforce this).
- Every access to its targets must arrive E2E-sealed — a plaintext Open hitting the group is
  refused by C (fail-close: a flag-stripping attack degrades to denial of service, never to
  plaintext).
- Coarse advertisement + local fine-grained grants: C advertises only a coarse routing hint
  to B; fine rules (e.g. one exact database address) live in a local-only group that is never
  pushed — B stays oblivious while A reaches them through the grant.

## Consumer side (A)

Import the link (paste / .anet file / anet:// deep link) and connect:

- A delegated credential is a pure data-plane key — no API login; the client dials the
  primary relay entry directly.
- The link embeds the failover set and per-entry cert fingerprints: when the current entry
  drops, the client rotates to the next (in-flight connections retry at the application
  layer, as with any VPN). The credential card shows a **Delegated** badge and the live entry.
- When the link carries an E2E hint, every Open is sealed end-to-end automatically.

## Lifecycle & revocation

- Delegated tokens **live with the fan-out session**: when C goes offline the token lapses
  on every upstream (A couldn't reach C's resources anyway); on reconnect C re-registers
  automatically. Relays persist nothing.
- Revocation = C deletes the local record and sends a revoke frame to every online upstream;
  offline upstreams lapse by disconnect.
- A second session with the same node identity kicks the stale one (tolerates restart
  flapping); multiple fan-out links to the same upstream are forced into distinct
  `name#connector` identities and never evict each other.

## Honest limits

- Failover is **reconnect-level**: entries have different IPs, so in-flight TCP connections
  drop and retry — seamless roaming is physically impossible.
- v1 has no forward secrecy: recorded traffic plus a later token leak exposes history
  (a Noise_NK handshake with forward secrecy is planned as P3.5).
- Metadata (timings, volumes, routing hints) remains visible to B — this model targets
  sovereignty and reachability, not anonymity.
- The delegated token is the root of trust: guard it like any access credential; revoke on
  suspicion.

## See also

- Design: `docs/todo/federation.md` (federation model) · `docs/plan/federation-p2p3.md`
  (P2/P3 implementation record)
- API: Delegation `docs/api/delegation.md`
