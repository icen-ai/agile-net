//! 双向数据桥接

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

/// 将两个异步流双向桥接，直到任一方关闭。
/// 返回 (a→b 传输字节数, b→a 传输字节数)。
pub async fn bridge<A, B>(a: A, b: B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (bytes_ab, bytes_ba) = tokio::io::copy_bidirectional(&mut { a }, &mut { b }).await?;
    debug!(a_to_b = bytes_ab, b_to_a = bytes_ba, "bridge closed");
    Ok((bytes_ab, bytes_ba))
}
