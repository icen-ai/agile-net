//! QR image decoding + generation (universal import wizard `agimport.js` + phone-QR sync):
//! one implementation shared by the admin API and the desktop Tauri commands.
//! PNG/JPEG screenshots of an anet:// link QR decode back to the link text; pure Rust (rqrr +
//! qrcode crate, both workspace deps).

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

/// Generate a QR code PNG from a text payload (typically an `anet://connect?...` URL for
/// phone-sync). Error-correction level M (suitable for scanning from a phone camera at
/// desktop-screen distance). Returns PNG bytes.
/// Errors are user-facing Chinese strings (payload too large for QR capacity / encoding failure).
pub fn generate_qr_png(url: &str) -> Result<Vec<u8>, String> {
    if url.len() > 1000 {
        return Err("内容过长，超出二维码容量上限".into());
    }
    let code = qrcode::QrCode::with_error_correction_level(url.as_bytes(), qrcode::EcLevel::M)
        .map_err(|e| format!("生成二维码失败：{e}"))?;
    let img = code
        .render::<image::Luma<u8>>()
        .min_dimensions(280, 280)
        .build();
    let mut buf = std::io::Cursor::new(Vec::new());
    img.write_to(&mut buf, image::ImageFormat::Png)
        .map_err(|e| format!("编码 PNG 失败：{e}"))?;
    Ok(buf.into_inner())
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
