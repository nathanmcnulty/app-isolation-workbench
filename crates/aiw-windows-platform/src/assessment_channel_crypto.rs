//! Ephemeral CNG ECDSA-P256 keys; no private export/import or persistence.
//! Callers must separately establish the approved execution/verification anchor.
use windows::Win32::{
    Foundation::NTSTATUS,
    Security::Cryptography::{
        BCRYPT_ALG_HANDLE, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM,
        BCRYPT_ECDSA_PUBLIC_P256_MAGIC, BCRYPT_FLAGS, BCRYPT_KEY_HANDLE,
        BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        BCryptCloseAlgorithmProvider, BCryptDestroyKey, BCryptExportKey, BCryptFinalizeKeyPair,
        BCryptGenRandom, BCryptGenerateKeyPair, BCryptImportKeyPair, BCryptOpenAlgorithmProvider,
        BCryptSignHash, BCryptVerifySignature, MS_PRIMITIVE_PROVIDER,
    },
};

pub const PUBLIC_KEY_BYTES: usize = 72;
pub const SIGNATURE_BYTES: usize = 64;
type Result<T> = std::result::Result<T, String>;

fn check(status: NTSTATUS, stage: &str) -> Result<()> {
    status
        .ok()
        .map_err(|_| format!("assessment channel {stage}: NTSTATUS 0x{:08x}", status.0))
}

struct Algorithm(BCRYPT_ALG_HANDLE);
impl Algorithm {
    fn open() -> Result<Self> {
        let mut algorithm = BCRYPT_ALG_HANDLE::default();
        // SAFETY: valid output pointer, fixed algorithm and Microsoft provider.
        check(
            unsafe {
                BCryptOpenAlgorithmProvider(
                    &mut algorithm,
                    BCRYPT_ECDSA_P256_ALGORITHM,
                    MS_PRIMITIVE_PROVIDER,
                    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
                )
            },
            "open ECDSA-P256 provider",
        )?;
        Ok(Self(algorithm))
    }

    fn close(&mut self) -> Result<()> {
        if !self.0.0.is_null() {
            // SAFETY: exclusive successfully opened handle, retained on failure.
            check(
                unsafe { BCryptCloseAlgorithmProvider(self.0, 0) },
                "close provider",
            )?;
            self.0 = BCRYPT_ALG_HANDLE::default();
        }
        Ok(())
    }
}
impl Drop for Algorithm {
    fn drop(&mut self) {
        // Best-effort fallback; callers needing an observed release use close.
        let _ = self.close();
    }
}

struct Key {
    handle: BCRYPT_KEY_HANDLE,
    // The algorithm provider outlives key destruction, including error paths.
    _algorithm: Algorithm,
}
impl Key {
    fn close(&mut self) -> Result<()> {
        if !self.handle.0.is_null() {
            // SAFETY: exclusive key ownership; provider is still held.
            check(unsafe { BCryptDestroyKey(self.handle) }, "destroy key")?;
            self.handle = BCRYPT_KEY_HANDLE::default();
        }
        self._algorithm.close()
    }
}
impl Drop for Key {
    fn drop(&mut self) {
        // Best-effort fallback; explicit close reports native cleanup failures.
        let _ = self.close();
    }
}

/// Neither Clone nor Debug: the only exported key material is public.
pub struct AssessmentSigningKey(Key);
impl AssessmentSigningKey {
    /// Consume the signer and observe CNG key/provider release. An error must
    /// fail the channel; Drop retries cleanup but does not prove release.
    /// Success is an OS API observation, not physical-memory zeroization proof.
    pub fn destroy(mut self) -> Result<()> {
        self.0.close()
    }

    pub fn generate() -> Result<Self> {
        let algorithm = Algorithm::open()?;
        let mut handle = BCRYPT_KEY_HANDLE::default();
        // SAFETY: fixed 256-bit curve and valid output pointer.
        check(
            unsafe { BCryptGenerateKeyPair(algorithm.0, &mut handle, 256, 0) },
            "generate key",
        )?;
        let key = Key {
            handle,
            _algorithm: algorithm,
        };
        // SAFETY: generated owned key; failure drops both native handles.
        check(
            unsafe { BCryptFinalizeKeyPair(key.handle, 0) },
            "finalize key",
        )?;
        Ok(Self(key))
    }

    pub fn public_key(&self) -> Result<[u8; PUBLIC_KEY_BYTES]> {
        let mut bytes = [0; PUBLIC_KEY_BYTES];
        let mut written = 0;
        // SAFETY: fixed public-only blob type and exactly sized output buffer.
        check(
            unsafe {
                BCryptExportKey(
                    self.0.handle,
                    None,
                    BCRYPT_ECCPUBLIC_BLOB,
                    Some(&mut bytes),
                    &mut written,
                    0,
                )
            },
            "export public key",
        )?;
        if written as usize != PUBLIC_KEY_BYTES || !public_key_shape(&bytes) {
            return Err("assessment channel public key encoding refused".into());
        }
        Ok(bytes)
    }

    /// Sign an already domain-separated SHA-256 digest from the closed protocol.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; SIGNATURE_BYTES]> {
        let mut bytes = [0; SIGNATURE_BYTES];
        let mut written = 0;
        // SAFETY: finalized owned P256 key, exact hash/output sizes, no padding.
        check(
            unsafe {
                BCryptSignHash(
                    self.0.handle,
                    None,
                    digest,
                    Some(&mut bytes),
                    &mut written,
                    BCRYPT_FLAGS(0),
                )
            },
            "sign digest",
        )?;
        if written as usize != SIGNATURE_BYTES {
            return Err("assessment channel signature size refused".into());
        }
        Ok(bytes)
    }
}

fn public_key_shape(bytes: &[u8; PUBLIC_KEY_BYTES]) -> bool {
    bytes[..4] == BCRYPT_ECDSA_PUBLIC_P256_MAGIC.to_le_bytes()
        && bytes[4..8] == 32_u32.to_le_bytes()
}

/// A successful cryptographic check does not authenticate a self-chosen key.
/// The caller must supply the independently latched execution key.
pub fn verify_digest(
    public_key: &[u8; PUBLIC_KEY_BYTES],
    digest: &[u8; 32],
    signature: &[u8; SIGNATURE_BYTES],
) -> Result<()> {
    if !public_key_shape(public_key) {
        return Err("assessment channel public key encoding refused".into());
    }
    let algorithm = Algorithm::open()?;
    let mut handle = BCRYPT_KEY_HANDLE::default();
    // SAFETY: fixed public-only blob; flags zero retain CNG key validation.
    check(
        unsafe {
            BCryptImportKeyPair(
                algorithm.0,
                None,
                BCRYPT_ECCPUBLIC_BLOB,
                &mut handle,
                public_key,
                0,
            )
        },
        "import public key",
    )?;
    let mut key = Key {
        handle,
        _algorithm: algorithm,
    };
    // SAFETY: imported P256 key and exact hash/signature slices; no padding.
    let verification = check(
        unsafe { BCryptVerifySignature(key.handle, None, digest, signature, BCRYPT_FLAGS(0)) },
        "verify digest",
    );
    let cleanup = key.close();
    match (verification, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; {cleanup}")),
    }
}

/// Public per-execution nonce. Does not persist state or generate a key.
pub fn generate_nonce() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    // SAFETY: exact mutable buffer and the system-preferred CSPRNG.
    check(
        unsafe { BCryptGenRandom(None, &mut bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG) },
        "generate nonce",
    )?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn native_verification_matches_rfc6979_p256_sha256_public_vector() {
        // RFC 6979 A.2.5, message "sample": public verification only.
        // https://www.rfc-editor.org/rfc/rfc6979#appendix-A.2.5
        // No private vector key is imported; signing need not be deterministic.
        let mut public = [0; PUBLIC_KEY_BYTES];
        public[..4].copy_from_slice(&BCRYPT_ECDSA_PUBLIC_P256_MAGIC.to_le_bytes());
        public[4..8].copy_from_slice(&32_u32.to_le_bytes());
        hex::decode_to_slice(
            concat!(
                "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
                "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
            ),
            &mut public[8..],
        )
        .unwrap();
        let mut signature = [0; SIGNATURE_BYTES];
        hex::decode_to_slice(
            concat!(
                "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
                "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"
            ),
            &mut signature,
        )
        .unwrap();
        let digest: [u8; 32] = Sha256::digest(b"sample").into();
        verify_digest(&public, &digest, &signature).unwrap();
        let other_digest: [u8; 32] = Sha256::digest(b"test").into();
        assert!(verify_digest(&public, &other_digest, &signature).is_err());
        let mut reversed_signature = signature;
        reversed_signature[..32].reverse();
        reversed_signature[32..].reverse();
        assert!(verify_digest(&public, &digest, &reversed_signature).is_err());
    }

    #[test]
    fn native_round_trip_rejects_changed_digest_signature_and_foreign_key() {
        let key = AssessmentSigningKey::generate().unwrap();
        let public = key.public_key().unwrap();
        let digest = [7; 32];
        let signature = key.sign_digest(&digest).unwrap();
        verify_digest(&public, &digest, &signature).unwrap();
        let mut changed_digest = digest;
        changed_digest[0] ^= 1;
        assert!(verify_digest(&public, &changed_digest, &signature).is_err());
        let mut changed_signature = signature;
        changed_signature[0] ^= 1;
        assert!(verify_digest(&public, &digest, &changed_signature).is_err());
        let other = AssessmentSigningKey::generate().unwrap();
        assert!(verify_digest(&other.public_key().unwrap(), &digest, &signature).is_err());
        // Public verification does not depend on retaining the private handle.
        key.destroy().unwrap();
        verify_digest(&public, &digest, &signature).unwrap();
    }

    #[test]
    fn native_verification_rejects_wrong_curve_encoding_and_invalid_point() {
        let key = AssessmentSigningKey::generate().unwrap();
        let public = key.public_key().unwrap();
        let digest = [11; 32];
        let signature = key.sign_digest(&digest).unwrap();
        let mut wrong_magic = public;
        wrong_magic[0] ^= 1;
        assert!(verify_digest(&wrong_magic, &digest, &signature).is_err());
        let mut wrong_size = public;
        wrong_size[4] = 48;
        assert!(verify_digest(&wrong_size, &digest, &signature).is_err());
        let mut invalid_point = public;
        invalid_point[8..].fill(0);
        assert!(verify_digest(&invalid_point, &digest, &signature).is_err());
        assert!(verify_digest(&public, &digest, &[0; SIGNATURE_BYTES]).is_err());
    }

    #[test]
    fn native_system_rng_produces_independent_execution_nonces() {
        let first = generate_nonce().unwrap();
        let second = generate_nonce().unwrap();
        assert_ne!(first, second);
    }
}
