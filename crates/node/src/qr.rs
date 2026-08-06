//! QR image decoding (universal import wizard `agimport.js`): one implementation shared by the
//! admin API (`POST /api/v1/admin/tool/qr-decode`) and the desktop `qr_pick_decode` command.
//! PNG/JPEG screenshots of an anet:// link QR decode back to the link text; pure Rust (rqrr).

/// Decode the first QR code found in an image (PNG/JPEG bytes) into its text payload.
/// Errors are user-facing Chinese strings (no QR found / unreadable image / empty payload).
pub fn decode_qr_image(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() > 20 * 1024 * 1024 {
        return Err("图片过大（限 20MB）".into());
    }
    let img = image::load_from_memory(bytes).map_err(|e| format!("无法读取图片：{e}"))?;
    let gray = img.to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(gray);
    let grids = prepared.detect_grids();
    let Some(grid) = grids.first() else {
        return Err("图片中未识别到二维码".into());
    };
    let (_, text) = grid.decode().map_err(|_| "二维码内容损坏，无法解码".to_string())?;
    let text = text.trim().to_string();
    if text.is_empty() {
        return Err("二维码内容为空".into());
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// qrcode (generation, already a dependency) -> PNG -> rqrr decode roundtrip.
    #[test]
    fn qr_roundtrip_png() {
        let link = "anet://connect?server=relay.example.com&port=59090&account=d:alice&password=psk_x&fp=ab12";
        let code = qrcode::QrCode::new(link.as_bytes()).unwrap();
        let img = code
            .render::<image::Luma<u8>>()
            .min_dimensions(240, 240)
            .build();
        let mut buf = std::io::Cursor::new(Vec::new());
        img.write_to(&mut buf, image::ImageFormat::Png).unwrap();
        assert_eq!(decode_qr_image(buf.get_ref()).unwrap(), link);
    }

    #[test]
    fn qr_rejects_non_image() {
        assert!(decode_qr_image(b"not an image").is_err());
    }

    #[test]
    fn qr_rejects_image_without_code() {
        // a blank 64x64 gray PNG carries no grid
        let img = image::GrayImage::from_pixel(64, 64, image::Luma([200u8]));
        let mut buf = std::io::Cursor::new(Vec::new());
        img.write_to(&mut buf, image::ImageFormat::Png).unwrap();
        let e = decode_qr_image(buf.get_ref()).unwrap_err();
        assert!(e.contains("未识别"));
    }
}
