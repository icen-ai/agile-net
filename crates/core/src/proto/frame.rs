//! Frame codec
//!
//! Custom frame format on top of TLS:
//! ```text
//! ┌──────────┬──────────┬──────────────┬──────────┐
//! │ Len (u32)│ Type (u8)│ Channel (u32)│ Payload  │
//! └──────────┴──────────┴──────────────┴──────────┘
//! ```

use bytes::{BufMut, Bytes, BytesMut};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Frame header length: 4 (len) + 1 (type) + 4 (channel) = 9 bytes
pub const HEADER_LEN: usize = 9;

/// Max payload for control frames (Auth/Open/Ping/Close etc.): 64 KB.
/// Control frames are tiny; anything larger is malicious or a bug.
const MAX_CONTROL_PAYLOAD: u32 = 64 * 1024;

/// Max payload for data frames (Data/DataFin): 256 KB.
/// `MuxChannel` chunks at 16 KB on the normal path; larger frames are anomalous.
const MAX_DATA_PAYLOAD: u32 = 256 * 1024;

/// Data frame chunk size (write path).
pub const DATA_CHUNK_SIZE: usize = 16 * 1024;

/// Frame type
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
    /// Flow-control window update (payload = u32 BE, bytes consumed by the peer)
    WindowUpdate = 0x22,
    Ping = 0x30,
    Pong = 0x31,
    Close = 0x40,
    /// Session control plane (protocol v3): JSON payload on channel 0, e.g. delegated-token
    /// register/revoke (federation P2). Unknown to v1/v2 peers — never sent to them.
    Ctrl = 0x04,
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
            0x22 => Some(Self::WindowUpdate),
            0x30 => Some(Self::Ping),
            0x31 => Some(Self::Pong),
            0x40 => Some(Self::Close),
            0x04 => Some(Self::Ctrl),
            _ => None,
        }
    }
}

/// A complete frame.
#[derive(Debug, Clone)]
pub struct Frame {
    pub frame_type: FrameType,
    pub channel_id: u32,
    pub payload: Bytes,
}

impl Frame {
    /// Create a new frame.
    pub fn new(frame_type: FrameType, channel_id: u32, payload: impl Into<Bytes>) -> Self {
        Self {
            frame_type,
            channel_id,
            payload: payload.into(),
        }
    }

    /// Create a frame without payload.
    pub fn empty(frame_type: FrameType, channel_id: u32) -> Self {
        Self::new(frame_type, channel_id, Bytes::new())
    }

    /// Encode to bytes.
    pub fn encode(&self) -> Bytes {
        let payload_len = self.payload.len() as u32;
        // len field = type(1) + channel(4) + payload(N)
        let len = 1 + 4 + payload_len;
        let mut buf = BytesMut::with_capacity(4 + len as usize);
        buf.put_u32(len);
        buf.put_u8(self.frame_type as u8);
        buf.put_u32(self.channel_id);
        buf.extend_from_slice(&self.payload);
        buf.freeze()
    }

    /// Read one frame from an async stream.
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        // read length
        let len = reader.read_u32().await?;
        if len < 5 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too short",
            ));
        }
        let payload_len = len - 5;

        // read type
        let type_byte = reader.read_u8().await?;
        let frame_type = FrameType::from_u8(type_byte).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown frame type: {type_byte:#x}"),
            )
        })?;

        // cap payload by frame type so a peer cannot exhaust memory with a huge declared len (DoS)
        let max_payload = match frame_type {
            FrameType::Data | FrameType::DataFin => MAX_DATA_PAYLOAD,
            _ => MAX_CONTROL_PAYLOAD,
        };
        if payload_len > max_payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame too large: {payload_len} > {max_payload}"),
            ));
        }

        // read channel
        let channel_id = reader.read_u32().await?;

        // read payload
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

    /// Write one frame to an async stream.
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

    fn decode_blocking(bytes: Vec<u8>) -> io::Result<Frame> {
        let mut cursor = io::Cursor::new(bytes);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(Frame::read_from(&mut cursor))
    }

    #[test]
    fn reject_oversized_control_frame() {
        // an Auth frame declaring 64KB+1 must be rejected
        let frame = Frame::new(FrameType::Auth, 0, vec![0u8; 65 * 1024]);
        let err = decode_blocking(frame.encode().to_vec()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn reject_oversized_data_frame() {
        // a Data frame declaring 256KB+1 must be rejected
        let frame = Frame::new(FrameType::Data, 1, vec![0u8; 257 * 1024]);
        let err = decode_blocking(frame.encode().to_vec()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn reject_truncated_len() {
        // len < 5 is rejected outright
        let mut buf = Vec::new();
        buf.extend_from_slice(&4u32.to_be_bytes());
        buf.extend_from_slice(&[0x01, 0, 0, 0, 0]);
        let err = decode_blocking(buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn reject_unknown_type() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u32.to_be_bytes());
        buf.push(0x7f); // unknown type
        buf.extend_from_slice(&0u32.to_be_bytes());
        let err = decode_blocking(buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn accept_max_control_frame() {
        let frame = Frame::new(FrameType::Open, 7, vec![1u8; 64 * 1024]);
        let decoded = decode_blocking(frame.encode().to_vec()).unwrap();
        assert_eq!(decoded.payload.len(), 64 * 1024);
    }
}
