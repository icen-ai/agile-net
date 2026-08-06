# Federation: Unified Issuance & E2E

The federation model keeps three parties sovereign — the public rendezvous (B), the resource
owner (C), and the consumer (A): B provides reachability only; tokens and grants always
belong to the resource owner. Consumer access has **no account layer** — C issues delegated
tokens directly, and the token is the only identity.

## The four dimensions of unified issuance

Admin UI → the **Issue** tab on the fan-in / fan-out page → **Issue**, then pick tiers by
trust and topology:

| Dimension | Tier | Semantics |
| --- | --- | --- |
| Entry | **Direct to this endpoint** (direct) | A dials C's own listener: TLS is already end-to-end, no relay involved, trust tier locked to plaintext; the token self-registers into C's local registry |
| Entry | **Via fan-out rendezvous** (relay) | Registered upstream over the disaster set: the token registers on every selected upstream; any online one accepts the consumer; registration lives with the session |
| Trust | **Plaintext** | Hop-by-hop TLS; B can see traffic content |
| Trust | **E2E** | With an E2E-enforced group attached: every Open is sealed end-to-end to C; B sees only the opaque routing word (`en_xxx`) |
| Trust | **E2E + management grant** | Additionally issues a bootstrap ticket over the E2E channel (never in relay plaintext): read-only / rules / full |
| Routing | **Dedicated** | The consumer routes its whole machine into the tunnel and never sees the rule vocabulary |
| Routing | **Split** | The vocabulary is delivered E2E-sealed; only authorized targets enter the tunnel (requires an E2E group) |
| Concurrency | **Single** | A new session with the same token kicks the old one (tolerates restart flapping) |
| Concurrency | **Multi** | Sessions coexist up to the max_sessions snapshot at issuance (the endpoint's `delegation_max_sessions` setting, default 8) |

The relay entry additionally picks the **disaster set** (the upstreams that accept the token)
and the **primary entry** (the link's first-connect address; the rest fail over in order).
Issuance produces a complete `anet://connect` link (or a downloadable `.anet` credential
file, optionally PIN-encrypted); the token plaintext is shown only once.

**Trust semantics**: in the plaintext tier the disaster set is exactly *who can see the
traffic*; with E2E it is a pure availability set (upstreams only see routing words).

The list shows each token's per-upstream registration state (registered / registering /
offline / failure reason). **Revoke** takes effect immediately: every online upstream drops
the registration and kicks the token's live sessions.

## One-click adoption (relay B)

Admin UI → **Groups** or **Rules** → **Adopt**: every pushed group, grouped by fan-in endpoint.
Adopting mirrors the group locally (`name@nodeID`) as a **read-only live mirror**: rule or E2E
changes on the source side follow within seconds; an offline source leaves the last snapshot
serving. To customize, hit **Copy** — a detached editable group is created while the mirror
keeps following. Deleting the mirror un-adopts it.

Route advertisement needs no hand maintenance: a fan-out's pushed group rules are unioned
into the routes it declares upstream (offering implies reachability). Fill the advertise
field only for extra segments beyond the pushed groups.

## E2E-enforced groups (e2e_required)

Once a group is marked end-to-end encrypted:

- It may hang **only** on delegated tokens — never on fan-in tokens or fan-out connectors
  (those principals have no E2E key; the write paths enforce this).
- Every access to its targets must arrive E2E-sealed — a plaintext Open hitting the group is
  refused by C (fail-close: a flag-stripping attack degrades to denial of service, never to
  plaintext).
- **Entrust zero-disclosure routing**: E2E tokens automatically carry an opaque
  `en_<token-hash prefix>` routing word — issuance **does not require** pushed groups or
  advertised routes: B only ever learns `en_xxx → C`, never a group name, a rule, or a subnet.

## Consumer side (A)

Import the link (paste / .anet file / anet:// deep link) and connect:

- A delegated credential is a pure data-plane key — no API login; the client dials the
  primary relay entry directly.
- The link embeds the failover set and per-entry cert fingerprints: when the current entry
  drops, the client rotates to the next (in-flight connections retry at the application
  layer, as with any VPN).
- When the link carries an E2E routing word, every Open is sealed end-to-end automatically.
- A management-tier link pulls a bootstrap ticket over the E2E config channel and can open
  the issuer's admin console (the full tier additionally unlocks transit management of the
  upstreams the issuer has discovered: consumer → E2E → issuer → fan-out session → upstream).

## Lifecycle & revocation

- Relay-entry delegated tokens **live with the fan-out session**: when C goes offline the
  token lapses on every upstream; on reconnect C re-registers automatically. Relays persist
  nothing. Direct-entry tokens register in C's local persistent registry.
- **Optional expiry & usage caps**: issuance accepts an expiry and a usage cap (unlimited by
  default); once expired or exhausted the registration sync stops offering the token (the
  list shows expired/exhausted) and the issuer's data plane refuses it outright. Fan-in
  tokens support the same optional validity window.
- Revocation = C deletes the local record and sends a revoke frame to every online upstream;
  offline upstreams lapse by disconnect.
- Concurrency enforcement: in single tier a second session with the same token kicks the
  stale one; in multi tier sessions coexist up to max_sessions, beyond which opens are
  refused. Multiple fan-out links to the same upstream are forced into distinct
  `name#connector` identities and never evict each other.

## Honest limits

- Failover is **reconnect-level**: entries have different IPs, so in-flight TCP connections
  drop and retry — seamless roaming is physically impossible.
- No forward secrecy yet: recorded traffic plus a later token leak exposes history
  (a Noise_NK handshake with forward secrecy remains on the roadmap).
- Metadata (timings, volumes, routing words) remains visible to B — this model targets
  sovereignty and reachability, not anonymity.
- The delegated token is the root of trust: guard it like any access credential; revoke on
  suspicion.

## See also

- API: Unified Issuance `docs/api/delegation.md`
