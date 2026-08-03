//! Bidirectional data bridging

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

/// Bridge two async streams bidirectionally until either side closes.
/// Returns (bytes transferred a->b, bytes transferred b->a).
pub async fn bridge<A, B>(a: A, b: B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (bytes_ab, bytes_ba) = tokio::io::copy_bidirectional(&mut { a }, &mut { b }).await?;
    debug!(a_to_b = bytes_ab, b_to_a = bytes_ba, "bridge closed");
    Ok((bytes_ab, bytes_ba))
}
