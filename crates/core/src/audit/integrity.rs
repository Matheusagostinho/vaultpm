//! Tarball integrity verification.
//!
//! npm publishes a Subresource-Integrity string (`sha512-<base64>`) in the
//! `dist.integrity` field, and a legacy `dist.shasum` (SHA-1 hex). We verify
//! whichever is available, preferring SHA-512.

use crate::error::{Result, VaultError};
use base64::Engine;
use sha1::Sha1;
use sha2::{Digest, Sha512};

/// Verify `bytes` against the registry-provided integrity metadata.
///
/// Returns `Ok(())` on success or a [`VaultError::Integrity`] describing the
/// mismatch. If neither hash is present we treat it as a hard failure: a
/// package with no integrity metadata cannot be trusted.
pub fn verify(
    name: &str,
    version: &str,
    bytes: &[u8],
    integrity: Option<&str>,
    shasum: Option<&str>,
) -> Result<()> {
    let sha512 = Sha512::digest(bytes);
    let sha1 = Sha1::digest(bytes);
    verify_precomputed(name, version, &sha512, &sha1, integrity, shasum)
}

/// Like [`verify`] but for digests already computed while streaming the tarball
/// to disk — so we never have to hold the whole `.tgz` in memory. The check is
/// still **fail-closed and happens before extraction**.
pub fn verify_precomputed(
    name: &str,
    version: &str,
    sha512: &[u8],
    sha1: &[u8],
    integrity: Option<&str>,
    shasum: Option<&str>,
) -> Result<()> {
    if let Some(sri) = integrity {
        return verify_sri(name, version, sha512, sri);
    }
    if let Some(sha1_hex) = shasum {
        let actual = hex::encode(sha1);
        if actual.eq_ignore_ascii_case(sha1_hex) {
            return Ok(());
        }
        return Err(VaultError::Integrity {
            name: name.into(),
            version: version.into(),
            expected: sha1_hex.into(),
            actual,
        });
    }
    Err(VaultError::Integrity {
        name: name.into(),
        version: version.into(),
        expected: "<registry provided no integrity hash>".into(),
        actual: "<none>".into(),
    })
}

/// Compare a precomputed SHA-512 digest against an SRI string (`sha512-<b64>`).
fn verify_sri(name: &str, version: &str, sha512: &[u8], sri: &str) -> Result<()> {
    // Take the first algorithm token (`sha512-...`); npm always emits sha512.
    let token = sri.split_whitespace().next().unwrap_or(sri);
    let (algo, b64) = token.split_once('-').ok_or_else(|| VaultError::Integrity {
        name: name.into(),
        version: version.into(),
        expected: sri.into(),
        actual: "<malformed SRI>".into(),
    })?;

    let expected = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| VaultError::Integrity {
            name: name.into(),
            version: version.into(),
            expected: sri.into(),
            actual: "<invalid base64 in SRI>".into(),
        })?;

    if algo != "sha512" {
        return Err(VaultError::Integrity {
            name: name.into(),
            version: version.into(),
            expected: format!("unsupported integrity algorithm `{algo}`"),
            actual: "<none>".into(),
        });
    }

    if sha512 == expected.as_slice() {
        Ok(())
    } else {
        Err(VaultError::Integrity {
            name: name.into(),
            version: version.into(),
            expected: sri.into(),
            actual: format!(
                "sha512-{}",
                base64::engine::general_purpose::STANDARD.encode(sha512)
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha512_sri_roundtrip() {
        let data = b"vault integrity test";
        let digest = Sha512::digest(data);
        let sri = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(digest)
        );
        assert!(verify("pkg", "1.0.0", data, Some(&sri), None).is_ok());
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let digest = Sha512::digest(b"original");
        let sri = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(digest)
        );
        assert!(verify("pkg", "1.0.0", b"tampered", Some(&sri), None).is_err());
    }

    #[test]
    fn missing_metadata_is_rejected() {
        assert!(verify("pkg", "1.0.0", b"x", None, None).is_err());
    }
}
