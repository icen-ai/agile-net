//! Deep Guard (trust profile G3) listener enforcement tests:
//! - advertise overlap: a guarded token's conflicting entry is rejected (+ AdvertiseConflict
//!   event), a non-guarded overlap keeps the union and only warns (once per episode)
//! - pushed groups of a guarded token stop auto-declaring routes (federation/adopt is the path)
//! - a guarded token's pending device is gated per Open even under a global allow policy

use agile_net_core::proto::message::{AuthKind, AuthRequest, PushedGroupMsg};
use agile_net_core::relay::connector::{ConnectionState, RelayConnector};
use agile_net_core::relay::listener::{
    AuthIdentity, DeviceGate, PeerEvent, RelayListener, TokenValidator,
};
use agile_net_core::error::Result;
use agile_net_core::tunnel::tls::TlsConfigBuilder;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn get_free_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

/// Port-allocation race guard (same contract as relay_test.rs).
static NET_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Validator mapping tokens to identity, with a per-token Deep Guard flag.
struct MapValidator {
    tokens: HashMap<String, bool>,
}

impl TokenValidator for MapValidator {
    fn validate(&self, auth: &AuthRequest) -> Option<AuthIdentity> {
        if auth.kind != AuthKind::Node {
            return None;
        }
        let guarded = *self.tokens.get(auth.token.as_str())?;
        Some(AuthIdentity::Node {
            node_id: auth.node_id.clone(),
            advertise: auth.advertise.clone(),
            groups: auth.groups.clone(),
            control: None,
            acl: None,
            display: None,
            guarded,
        })
    }
}

fn guarded_validator(
    entries: &[(&str, bool)],
) -> Result<(Arc<MapValidator>, tokio_rustls::TlsAcceptor)> {
    let tokens = entries.iter().map(|(t, g)| (t.to_string(), *g)).collect();
    let (server_config, _) = TlsConfigBuilder::new().build_server()?;
    Ok((Arc::new(MapValidator { tokens }), tokio_rustls::TlsAcceptor::from(server_config)))
}

async fn spawn_echo(addr: SocketAddr) {
    let echo = TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
}

/// Collect AdvertiseConflict events for a while (the broadcast channel is buffered).
async fn drain_conflicts(rx: &mut tokio::sync::broadcast::Receiver<PeerEvent>) -> Vec<(String, String, String, bool)> {
    let mut out = Vec::new();
    while let Ok(evt) = rx.try_recv() {
        if let PeerEvent::AdvertiseConflict {
            node_id,
            entry,
            existing_node,
            guarded,
        } = evt
        {
            out.push((node_id, entry, existing_node, guarded));
        }
    }
    out
}

/// G3-1: two downstreams advertise the same CIDR — the guarded LATER peer's entry is rejected
/// (the earlier claim keeps routing) and the conflict is reported as a guarded rejection.
#[tokio::test]
async fn guarded_advertise_overlap_rejected() -> Result<()> {
    let _net_guard = NET_TEST_LOCK.lock().await;
    let addr = get_free_addr();
    let (validator, tls) = guarded_validator(&[("psk_plain", false), ("psk_guard", true)])?;
    let listener = Arc::new(RelayListener::with_validator(addr, validator, tls));
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(60)).await;
    let mut events = listener.subscribe_events();

    let a = RelayConnector::new(addr, "node-a", "psk_plain")?
        .with_advertise(vec!["10.9.0.0/16".into(), "a.internal".into()]);
    a.connect().await?;
    tokio::time::sleep(Duration::from_millis(80)).await;

    // guarded later arrival: the conflicting CIDR is rejected, the unique entry still routes
    let b = RelayConnector::new(addr, "node-b", "psk_guard")?
        .with_advertise(vec!["10.9.0.0/16".into(), "b.internal".into()]);
    b.connect().await?;
    tokio::time::sleep(Duration::from_millis(120)).await;

    assert_eq!(listener.resolve_peer("10.9.0.1").as_deref(), Some("node-a"),
        "guarded later claim rejected — the earlier node keeps the route");
    assert_eq!(listener.resolve_peer("b.internal").as_deref(), Some("node-b"),
        "non-conflicting entries of the guarded peer still route");
    let conflicts = drain_conflicts(&mut events).await;
    assert!(
        conflicts.iter().any(|(later, entry, existing, guarded)| {
            later == "node-b" && entry == "10.9.0.0/16" && existing == "node-a" && *guarded
        }),
        "guarded conflict reported with both node ids: {conflicts:?}"
    );

    a.disconnect().await;
    b.disconnect().await;
    Ok(())
}

/// G3-1 (default tier): a non-guarded overlap keeps the union (both peers route — unchanged
/// behavior) and warns exactly once per episode; an unrelated rebuild does not re-warn.
#[tokio::test]
async fn unguarded_overlap_only_warns() -> Result<()> {
    let _net_guard = NET_TEST_LOCK.lock().await;
    let addr = get_free_addr();
    let (validator, tls) = guarded_validator(&[("psk_a", false), ("psk_b", false), ("psk_c", false)])?;
    let listener = Arc::new(RelayListener::with_validator(addr, validator, tls));
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(60)).await;
    let mut events = listener.subscribe_events();

    let a = RelayConnector::new(addr, "node-a", "psk_a")?.with_advertise(vec!["10.7.0.0/16".into()]);
    a.connect().await?;
    tokio::time::sleep(Duration::from_millis(80)).await;

    let b = RelayConnector::new(addr, "node-b", "psk_b")?.with_advertise(vec!["10.7.0.0/16".into()]);
    b.connect().await?;
    tokio::time::sleep(Duration::from_millis(120)).await;

    // union: the entry routes (either claimant — deterministically the later registration)
    let routed = listener.resolve_peer("10.7.0.1");
    assert!(routed == Some("node-a".into()) || routed == Some("node-b".into()),
        "non-guarded overlap stays routed (union, unchanged default)");
    let conflicts = drain_conflicts(&mut events).await;
    assert_eq!(conflicts.len(), 1, "one warn per episode (no flooding): {conflicts:?}");
    assert!(!conflicts[0].3, "non-guarded conflicts are warn-only");

    // an unrelated third peer reconnect re-runs rebuild_routes — the same pair must NOT re-warn
    let c = RelayConnector::new(addr, "node-c", "psk_c")?.with_advertise(vec!["10.8.0.0/16".into()]);
    c.connect().await?;
    tokio::time::sleep(Duration::from_millis(120)).await;
    let more = drain_conflicts(&mut events).await;
    assert!(more.is_empty(), "unrelated rebuild re-arms nothing: {more:?}");

    // the conflict clears (b leaves) and comes back (b reconnects) — a NEW episode warns again
    b.disconnect().await;
    tokio::time::sleep(Duration::from_millis(120)).await;
    let b2 = RelayConnector::new(addr, "node-b", "psk_b")?.with_advertise(vec!["10.7.0.0/16".into()]);
    b2.connect().await?;
    tokio::time::sleep(Duration::from_millis(120)).await;
    let again = drain_conflicts(&mut events).await;
    assert_eq!(again.len(), 1, "a fresh episode warns exactly once: {again:?}");

    a.disconnect().await;
    b2.disconnect().await;
    c.disconnect().await;
    Ok(())
}

/// G3-3: a guarded token's device is forced through approval — under a gate that would
/// globally allow pending devices, every open (both directions) fails closed until certified.
#[tokio::test]
async fn guarded_token_forces_device_approval() -> Result<()> {
    let _net_guard = NET_TEST_LOCK.lock().await;
    let echo_addr = get_free_addr();
    spawn_echo(echo_addr).await;
    let addr = get_free_addr();
    let (validator, tls) = guarded_validator(&[("psk_plain", false), ("psk_guard", true)])?;

    // global "allow" policy shape: the gate answers Pending for unknown devices, mirroring
    // DeviceGateCache under device_pending_policy=allow — except the listener turns Pending into
    // Allow for non-guarded sessions and keeps it blocking for guarded ones.
    let gate = Arc::new(|_fp: &str| (DeviceGate::Pending, None::<String>));
    let listener = Arc::new(
        RelayListener::with_validator(addr, validator, tls).with_device_gate(gate),
    );
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(60)).await;

    // guarded peer authenticates (a pending device is never auth-rejected) but is gated per Open
    let b = RelayConnector::new(addr, "node-g", "psk_guard")?
        .with_advertise(vec!["10.9.0.0/16".into()]);
    b.connect().await?;
    assert_eq!(b.state(), ConnectionState::Connected, "pending device still authenticates");
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(
        listener
            .open_channel("node-g", &echo_addr.ip().to_string(), echo_addr.port())
            .await
            .is_err(),
        "relay-initiated open toward a guarded pending device fails closed"
    );

    // non-guarded peer with the SAME gate: the identical Pending decision does not gate
    // (the deep-guard override is what turns it blocking, not the gate alone)
    let a = RelayConnector::new(addr, "node-p", "psk_plain")?
        .with_advertise(vec!["10.9.0.0/16".into()]);
    a.connect().await?;
    tokio::time::sleep(Duration::from_millis(80)).await;
    let mut ch = listener
        .open_channel("node-p", &echo_addr.ip().to_string(), echo_addr.port())
        .await
        .expect("non-guarded open flows under the global allow policy");
    ch.write_all(b"ping").await?;
    let mut buf = vec![0u8; 8];
    ch.read(&mut buf).await?;
    assert_eq!(&buf[..4], b"ping");

    a.disconnect().await;
    b.disconnect().await;
    Ok(())
}

/// G3-2: a guarded token's pushed groups stop auto-declaring routes — entries the connector
/// derived from its pushed groups (effective_advertise union) are stripped at the listener;
/// the groups still pool for manual federation/adopt.
#[tokio::test]
async fn guarded_pushed_groups_not_auto_effective() -> Result<()> {
    let _net_guard = NET_TEST_LOCK.lock().await;
    let addr = get_free_addr();
    let (validator, tls) = guarded_validator(&[("psk_plain", false), ("psk_guard", true)])?;
    let listener = Arc::new(RelayListener::with_validator(addr, validator, tls));
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(60)).await;

    // the connector pushes a group AND advertises its rules (exactly what effective_advertise
    // unions today: manual + pushed-group rules ride the same wire field)
    let push = Arc::new(arc_swap::ArcSwap::from_pointee(vec![PushedGroupMsg {
        name: "db".into(),
        remark: String::new(),
        rules: vec!["10.8.0.0/16".into(), "db.internal".into()],
        e2e_required: false,
    }]));
    let b = RelayConnector::new(addr, "node-g", "psk_guard")?
        .with_push_groups(push.clone())
        .with_advertise(vec!["10.8.0.0/16".into(), "db.internal".into(), "manual.internal".into()]);
    b.connect().await?;
    tokio::time::sleep(Duration::from_millis(120)).await;

    assert_eq!(listener.resolve_peer("manual.internal").as_deref(), Some("node-g"),
        "manual advertise entries of a guarded peer still route");
    assert!(listener.resolve_peer("10.8.0.1").is_none(),
        "pushed-group CIDR of a guarded peer does not auto-declare a route");
    assert!(listener.resolve_peer("db.internal").is_none(),
        "pushed-group domain of a guarded peer does not auto-declare a route");
    // the offer still pools — federation/adopt stays the manual path
    let offers = listener.peer_offers();
    let o = offers.iter().find(|o| o.node_id == "node-g").expect("offer pooled");
    assert_eq!(o.groups.len(), 1, "pushed groups still pool for adoption");
    assert_eq!(o.groups[0].name, "db");

    // same shape on a non-guarded token: pushed-group rules auto-declare as before (default tier)
    let a = RelayConnector::new(addr, "node-p", "psk_plain")?
        .with_push_groups(push)
        .with_advertise(vec!["10.8.0.0/16".into(), "db.internal".into()]);
    a.connect().await?;
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert_eq!(listener.resolve_peer("10.8.0.1").as_deref(), Some("node-p"),
        "non-guarded pushed-group rules keep auto-declaring (unchanged default)");

    a.disconnect().await;
    b.disconnect().await;
    Ok(())
}
