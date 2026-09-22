use data_encoding::BASE32_NOPAD;
use rand::RngCore;
use totp_lite::{totp_custom, Sha1, DEFAULT_STEP};

const SECRET_LEN: usize = 20;

pub fn generate_secret() -> String {
    let mut raw = [0u8; SECRET_LEN];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    BASE32_NOPAD.encode(&raw)
}

pub fn otpauth_url(secret: &str) -> String {
    format!(
        "otpauth://totp/MDM%20Panel:admin?secret={secret}&issuer=MDM%20Panel&algorithm=SHA1&digits=6&period=30"
    )
}

pub fn otpauth_qr_data_uri(secret: &str) -> Option<String> {
    use base64::Engine;
    use qrcode::render::svg;
    use qrcode::QrCode;
    let url = otpauth_url(secret);
    let code = QrCode::new(url.as_bytes()).ok()?;
    let svg = code
        .render::<svg::Color<'_>>()
        .min_dimensions(180, 180)
        .dark_color(svg::Color("#0f172a"))
        .light_color(svg::Color("#ffffff"))
        .build();
    let b64 = base64::engine::general_purpose::STANDARD.encode(svg.as_bytes());
    Some(format!("data:image/svg+xml;base64,{b64}"))
}

pub fn verify(secret_b32: &str, code: &str, now_unix: u64) -> bool {
    let digits: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 6 {
        return false;
    }
    let Ok(raw) = BASE32_NOPAD.decode(secret_b32.as_bytes()) else {
        return false;
    };
    if raw.is_empty() {
        return false;
    }
    for skew in [-1i64, 0, 1] {
        let t = now_unix.saturating_add_signed(skew * DEFAULT_STEP as i64);
        let expected = totp_custom::<Sha1>(DEFAULT_STEP, 6, &raw, t);
        if expected == digits {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secret_round_trips() {
        let secret = generate_secret();
        let now = 1_700_000_000u64;
        let raw = BASE32_NOPAD.decode(secret.as_bytes()).unwrap();
        let code = totp_custom::<Sha1>(DEFAULT_STEP, 6, &raw, now);
        assert!(verify(&secret, &code, now));
        assert!(verify(&secret, &code, now + 20));
        assert!(!verify(&secret, "000000", now));
        assert!(!verify(&secret, "abc", now));
    }

    #[test]
    fn otpauth_contains_secret() {
        let url = otpauth_url("MFRGGZDFMZTWQ2LK");
        assert!(url.starts_with("otpauth://totp/"));
        assert!(url.contains("secret=MFRGGZDFMZTWQ2LK"));
        assert!(!url.contains("TrustTunnel"));
        let qr = otpauth_qr_data_uri("MFRGGZDFMZTWQ2LK").expect("qr");
        assert!(qr.starts_with("data:image/svg+xml;base64,"));
        assert!(qr.len() > 100);
    }
}
