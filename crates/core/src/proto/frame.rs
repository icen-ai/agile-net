//! 帧编解码
//!
//! TLS 之上的自定义帧格式：
//! ```text
//! ┌──────────┬──────────┬──────────────┬──────────┐
//! │ Len (u32)│ Type (u8)│ Channel (u32)│ Payload  │
//! └──────────┴──────────┴──────────────┴──────────┘
//! ```

use bytes::{BufMut, Bytes, BytesMut};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 帧头长度：4 (len) + 1 (type) + 4 (channel) = 9 字节
pub const HEADER_LEN: usize = 9;

/// 最大帧负载：16 MB
const MAX_PAYLOAD: u32 = 16 * 1024 * 1024;

/// 帧类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Auth = 0x01,
    AuthOk = 0x02,
    AuthFail = 0x03,
    Open = 0x10,
    OpenOk = 0x11,
    OpenFail = 0x12,
    Data = 0x20,
    DataFin = 0x21,
    Ping = 0x30,
    Pong = 0x31,
    Close = 0x40,
}

impl FrameType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Auth),
            0x02 => Some(Self::AuthOk),
            0x03 => Some(Self::AuthFail),
            0x10 => Some(Self::Open),
            0x11 => Some(Self::OpenOk),
            0x12 => Some(Self::OpenFail),
            0x20 => Some(Self::Data),
            0x21 => Some(Self::DataFin),
            0x30 => Some(Self::Ping),
            0x31 => Some(Self::Pong),
            0x40 => Some(Self::Close),
            _ => None,
        }
    }
}

/// 一个完整的帧。
#[derive(Debug, Clone)]
pub struct Frame {
    pub frame_type: FrameType,
    pub channel_id: u32,
    pub payload: Bytes,
}

impl Frame {
    /// 创建新帧。
    pub fn new(frame_type: FrameType, channel_id: u32, payload: impl Into<Bytes>) -> Self {
        Self {
            frame_type,
            channel_id,
            payload: payload.into(),
        }
    }

    /// 创建无负载帧。
    pub fn empty(frame_type: FrameType, channel_id: u32) -> Self {
        Self::new(frame_type, channel_id, Bytes::new())
    }

    /// 编码为字节序列。
    pub fn encode(&self) -> Bytes {
        let payload_len = self.payload.len() as u32;
        // len 字段 = type(1) + channel(4) + payload(N)
        let len = 1 + 4 + payload_len;
        let mut buf = BytesMut::with_capacity(4 + len as usize);
        buf.put_u32(len);
        buf.put_u8(self.frame_type as u8);
        buf.put_u32(self.channel_id);
        buf.extend_from_slice(&self.payload);
        buf.freeze()
    }

    /// 从异步流中读取一帧。
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        // 读 length
        let len = reader.read_u32().await?;
        if len < 5 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too short",
            ));
        }
        let payload_len = len - 5;
        if payload_len > MAX_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }

        // 读 type
        let type_byte = reader.read_u8().await?;
        let frame_type = FrameType::from_u8(type_byte).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown frame type: {type_byte:#x}"),
            )
        })?;

        // 读 channel
        let channel_id = reader.read_u32().await?;

        // 读 payload
        let mut payload = vec![0u8; payload_len as usize];
        if !payload.is_empty() {
            reader.read_exact(&mut payload).await?;
        }

        Ok(Self {
            frame_type,
            channel_id,
            payload: Bytes::from(payload),
        })
    }

    /// 写一帧到异步流。
    pub async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        let encoded = self.encode();
        writer.write_all(&encoded).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let frame = Frame::new(FrameType::Data, 42, Bytes::from("hello world"));
        let encoded = frame.encode();
        let mut cursor = io::Cursor::new(encoded.to_vec());

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let decoded = rt.block_on(Frame::read_from(&mut cursor)).unwrap();

        assert_eq!(decoded.frame_type, FrameType::Data);
        assert_eq!(decoded.channel_id, 42);
        assert_eq!(decoded.payload.as_ref(), b"hello world");
    }

    #[test]
    fn empty_frame_roundtrip() {
        let frame = Frame::empty(FrameType::Ping, 0);
        let encoded = frame.encode();
        let mut cursor = io::Cursor::new(encoded.to_vec());

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let decoded = rt.block_on(Frame::read_from(&mut cursor)).unwrap();

        assert_eq!(decoded.frame_type, FrameType::Ping);
        assert_eq!(decoded.channel_id, 0);
        assert!(decoded.payload.is_empty());
    }
}
