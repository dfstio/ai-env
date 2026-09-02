//! Bech32 (BIP-173, classic constant 1) decoding for age recipient strings.
//!
//! Hand-rolled (~80 lines) instead of pulling the `bech32` crate: we only
//! ever *decode*, and only three HRPs. Checksum-verified, mixed-case
//! rejected, tested against real plugin/keygen output.
use crate::ParseError;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// A decoded age recipient ai-env can reason about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    /// `age1tag1…` — tagged Secure-Enclave/P-256 recipient (33-byte compressed point).
    Tag([u8; 33]),
    /// `age1se1…` — legacy age-plugin-se recipient (33-byte compressed point).
    Se([u8; 33]),
    /// `age1…` — native X25519 recipient (32 bytes).
    X25519([u8; 32]),
}

impl Recipient {
    /// The compressed P-256 point for tagged kinds (what tag derivations use).
    #[must_use]
    pub fn p256_point(&self) -> Option<&[u8; 33]> {
        match self {
            Recipient::Tag(p) | Recipient::Se(p) => Some(p),
            Recipient::X25519(_) => None,
        }
    }
}

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3B6A_57B2, 0x2650_8E6D, 0x1EA1_19FA, 0x3D42_33DD, 0x2A14_62B3];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = (chk & 0x01FF_FFFF) << 5 ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    out.push(0);
    out.extend(hrp.bytes().map(|b| b & 31));
    out
}

/// Strict bech32 decode: returns (hrp, 8-bit data). Classic constant only.
fn bech32_decode(s: &str) -> Result<(String, Vec<u8>), ParseError> {
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(ParseError::Malformed("mixed-case bech32"));
    }
    let s = s.to_ascii_lowercase();
    let pos = s.rfind('1').ok_or(ParseError::Malformed("bech32: no separator"))?;
    if pos == 0 || pos + 7 > s.len() || s.len() > 1024 {
        return Err(ParseError::Malformed("bech32: bad layout"));
    }
    let (hrp, data_part) = (&s[..pos], &s[pos + 1..]);
    let mut data = Vec::with_capacity(data_part.len());
    for c in data_part.bytes() {
        let v = CHARSET
            .iter()
            .position(|&x| x == c)
            .ok_or(ParseError::Malformed("bech32: invalid character"))?;
        data.push(v as u8);
    }
    let mut check = hrp_expand(hrp);
    check.extend_from_slice(&data);
    if polymod(&check) != 1 {
        return Err(ParseError::Malformed("bech32: bad checksum"));
    }
    data.truncate(data.len() - 6); // strip checksum

    // 5-bit -> 8-bit regroup (strict: no leftover bits set).
    let mut out = Vec::with_capacity(data.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for v in data {
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    if bits >= 5 || (acc & ((1 << bits) - 1)) != 0 {
        return Err(ParseError::Malformed("bech32: invalid padding"));
    }
    Ok((hrp.to_owned(), out))
}

/// Decode an age recipient string (`age1…`, `age1se1…`, `age1tag1…`).
pub fn decode_recipient(s: &str) -> Result<Recipient, ParseError> {
    let (hrp, bytes) = bech32_decode(s.trim())?;
    match hrp.as_str() {
        "age1tag" | "age1se" => {
            let point: [u8; 33] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| ParseError::Malformed("recipient: expected 33 bytes"))?;
            if point[0] != 0x02 && point[0] != 0x03 {
                return Err(ParseError::Malformed("recipient: not a compressed P-256 point"));
            }
            Ok(if hrp == "age1tag" { Recipient::Tag(point) } else { Recipient::Se(point) })
        }
        "age" => {
            let key: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| ParseError::Malformed("recipient: expected 32 bytes"))?;
            Ok(Recipient::X25519(key))
        }
        _ => Err(ParseError::Malformed("unknown recipient type")),
    }
}
