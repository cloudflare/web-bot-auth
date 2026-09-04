use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{VerifyingKey, ed25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Errors that may be thrown by this module
/// when importing a JWK key.
#[derive(Debug)]
pub enum KeyringError {
    /// JWK key specified an unsupported algorithm
    UnsupportedAlgorithm,
    /// The contained parameters could not be
    /// parsed correctly
    ParsingError(base64::DecodeError),
    /// The bytes found could not be cast to
    /// a valid public key
    ConversionError(ed25519::Error),
    /// The key already exists in our keyring
    KeyAlreadyExists,
}

/// Errors that may occur when modifying a keyring.
#[derive(Debug)]
pub enum OperationError {
    /// The old key is not present.
    KeyNotPresent,
    /// The new key identifier is already occupied.
    KeyOccupied,
}

/// Represents a public key to be consumed during the verification.
pub type PublicKey = Vec<u8>;

/// Subset of [HTTP signature algorithm](https://www.iana.org/assignments/http-message-signature/http-message-signature.xhtml)
/// implemented in this module. In the future, we may support more.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// [The `ed25519` algorithm](https://www.rfc-editor.org/rfc/rfc9421#name-eddsa-using-curve-edwards25)
    Ed25519,
    /// [The `rsa-pss-sha512` algorithm](https://www.rfc-editor.org/rfc/rfc9421.html#name-rsassa-pss-using-sha-512)
    RsaPssSha512,
    /// [The `rsa-v1_5-sha256` algorithm](https://www.rfc-editor.org/rfc/rfc9421.html#name-rsassa-pkcs1-v1_5-using-sha)
    RsaV1_5Sha256,
    /// [The `hmac-sha256` algorithm](https://www.rfc-editor.org/rfc/rfc9421.html#name-hmac-using-sha-256)
    HmacSha256,
    /// [The `ecdsa-p256-sha256` algorithm](https://www.rfc-editor.org/rfc/rfc9421.html#name-ecdsa-using-curve-p-256-dss)
    EcdsaP256Sha256,
    /// [The `ecdsa-p384-sha384` algorithm](https://www.rfc-editor.org/rfc/rfc9421.html#name-ecdsa-using-curve-p-384-dss)
    EcdsaP384Sha384,
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Algorithm::Ed25519 => write!(f, "ed25519"),
            Algorithm::RsaPssSha512 => write!(f, "rsa-pss-sha512"),
            Algorithm::RsaV1_5Sha256 => write!(f, "rsa-pss-sha512"),
            Algorithm::HmacSha256 => write!(f, "hmac-sha256"),
            Algorithm::EcdsaP256Sha256 => write!(f, "ecdsa-p256-sha256"),
            Algorithm::EcdsaP384Sha384 => write!(f, "ecdsa-p384-sha384"),
        }
    }
}

/// Represents a JSON Web Key containing the bare minimum that
/// can be thumbprinted per [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html)
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum Thumbprintable {
    /// An elliptic curve key
    EC {
        /// Corresponding crv
        crv: String,
        /// Corresponding x
        x: String,
        /// Corresponding y
        y: String,
    },
    /// An OKP key, supporting Ed25519 keys
    OKP {
        /// Corresponding crv
        crv: String,
        /// Corresponding x
        x: String,
    },
    /// An RSA key
    RSA {
        /// Corresponding e
        e: String,
        /// Corresponding n
        n: String,
    },
    /// A symmetric key
    #[serde(rename = "oct")]
    OCT {
        /// Corresponding k
        k: String,
    },
}

/// Representation of a JSON Web Key Set
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct JSONWebKeySet {
    /// List of keys contained in the set.
    pub keys: Vec<Thumbprintable>,
}

impl Thumbprintable {
    /// Calculate the base64-encoded URL safe JWK thumbprint associated with the key
    pub fn b64_thumbprint(&self) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(match self {
            Thumbprintable::EC { crv, x, y } => {
                format!("{{\"crv\":\"{crv}\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}")
            }
            Thumbprintable::OKP { crv, x } => {
                format!("{{\"crv\":\"{crv}\",\"kty\":\"OKP\",\"x\":\"{x}\"}}")
            }
            Thumbprintable::RSA { e, n } => {
                format!("{{\"e\":\"{e}\",\"kty\":\"RSA\",\"n\":\"{n}\"}}")
            }
            Thumbprintable::OCT { k } => format!("{{\"k\":\"{k}\",\"kty\":\"oct\"}}"),
        }))
    }

    /// Attempt to cast into a public key.
    ///
    /// # Errors
    ///
    /// Today we only support importing ed25519 keys. Errors may
    /// be thrown when decoding or converting the JSON web key
    /// into an ed25519 public key.
    pub fn public_key(&self) -> Result<Vec<u8>, KeyringError> {
        match self {
            Thumbprintable::OKP { crv, x } => match crv.as_str() {
                "Ed25519" => {
                    let decoded = general_purpose::URL_SAFE_NO_PAD
                        .decode(x)
                        .map_err(KeyringError::ParsingError)?;
                    VerifyingKey::try_from(decoded.as_slice())
                        .map(|key| key.to_bytes().to_vec())
                        .map_err(KeyringError::ConversionError)
                }
                _ => Err(KeyringError::UnsupportedAlgorithm),
            },
            _ => Err(KeyringError::UnsupportedAlgorithm),
        }
    }

    /// Attempt to extract algorithm.
    ///
    /// # Errors
    ///
    /// Today we only support extracting the algorithm of an ed25519 key.
    pub fn algorithm(&self) -> Result<Algorithm, KeyringError> {
        match self {
            Thumbprintable::OKP { crv, .. } => match crv.as_str() {
                "Ed25519" => Ok(Algorithm::Ed25519),
                _ => Err(KeyringError::UnsupportedAlgorithm),
            },
            _ => Err(KeyringError::UnsupportedAlgorithm),
        }
    }
}

/// A keyring that maps identifiers to public keys. Used in web-bot-auth to retrieve
/// verifying keys for verificiation.
#[derive(Default, Debug, Clone)]
pub struct KeyRing {
    ring: HashMap<String, KeyEntry>,
}

/// A keyring entry: the raw key material backing the public `get` API, plus
/// verification state prepared once at insertion time.
#[derive(Debug, Clone)]
struct KeyEntry {
    raw: (Algorithm, PublicKey),
    prepared: PreparedKey,
}

/// Verification state prepared when an entry is created, so that verification
/// does not pay for key reconstruction on every request.
#[derive(Debug, Clone)]
pub(crate) enum PreparedKey {
    /// `Some` when the raw bytes yielded a valid `VerifyingKey` at import time.
    /// `None` preserves the historical behavior of deferring the
    /// `InvalidKeyLength` error to verification.
    Ed25519(Option<VerifyingKey>),
    /// No preparation is possible for algorithms we do not yet verify.
    Unsupported,
}

impl From<(Algorithm, PublicKey)> for KeyEntry {
    fn from(raw: (Algorithm, PublicKey)) -> KeyEntry {
        let prepared = match &raw {
            (Algorithm::Ed25519, public_key) => {
                PreparedKey::Ed25519(VerifyingKey::try_from(public_key.as_slice()).ok())
            }
            _ => PreparedKey::Unsupported,
        };
        KeyEntry { raw, prepared }
    }
}

impl FromIterator<(String, (Algorithm, PublicKey))> for KeyRing {
    fn from_iter<T: IntoIterator<Item = (String, (Algorithm, PublicKey))>>(iter: T) -> KeyRing {
        KeyRing {
            ring: HashMap::from_iter(iter.into_iter().map(|(id, raw)| (id, raw.into()))),
        }
    }
}

impl KeyRing {
    /// Insert a raw public key under a known identifier. If an identifier is already
    /// known, it will *not* be updated and this method will return false.
    pub fn import_raw(
        &mut self,
        identifier: String,
        algorithm: Algorithm,
        public_key: Vec<u8>,
    ) -> bool {
        !self.ring.contains_key(&identifier)
            && self
                .ring
                .insert(identifier, (algorithm, public_key).into())
                .is_none()
    }

    /// Rename a public key from `old_identifier` to `new_identifier`.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError::KeyNotPresent`] if the old key is absent, or
    /// [`OperationError::KeyOccupied`] if the new identifier belongs to another key.
    pub fn try_rename_key(
        &mut self,
        old_identifier: String,
        new_identifier: String,
    ) -> Result<(), OperationError> {
        if !self.ring.contains_key(&old_identifier) {
            return Err(OperationError::KeyNotPresent);
        }
        if old_identifier == new_identifier {
            return Ok(());
        }
        if self.ring.contains_key(&new_identifier) {
            return Err(OperationError::KeyOccupied);
        }

        let value = self
            .ring
            .remove(&old_identifier)
            .ok_or(OperationError::KeyNotPresent)?;
        let replaced = self.ring.insert(new_identifier, value);
        debug_assert!(replaced.is_none());
        Ok(())
    }

    /// Rename a public key from `old_identifier` to `new_identifier`.
    ///
    /// This method does not safely handle destination conflicts. Use [`Self::try_rename_key`]
    /// instead.
    #[deprecated(note = "does not safely handle destination conflicts; use `try_rename_key`")]
    pub fn rename_key(&mut self, old_identifier: String, new_identifier: String) -> bool {
        match self.ring.remove(&old_identifier) {
            Some(value) => self.ring.insert(new_identifier, value).is_none(),
            None => false,
        }
    }

    /// Retrieve a key. Semantics are identical to `HashMap::get`.
    pub fn get(&self, identifier: &String) -> Option<&(Algorithm, Vec<u8>)> {
        self.ring.get(identifier).map(|entry| &entry.raw)
    }

    /// Retrieve the algorithm and prepared verification state for a key.
    /// Used by verification to avoid reconstructing verifying keys per request.
    pub(crate) fn get_prepared(&self, identifier: &String) -> Option<(&Algorithm, &PreparedKey)> {
        self.ring
            .get(identifier)
            .map(|entry| (&entry.raw.0, &entry.prepared))
    }

    /// Import a single JSON Web Key. This method is fallible.
    ///
    /// # Errors
    ///
    /// Unsupported keys will not be imported, as will keys that failed to
    /// be inserted
    pub fn try_import_jwk(&mut self, jwk: &Thumbprintable) -> Result<(), KeyringError> {
        let thumbprint = jwk.b64_thumbprint();
        let public_key = jwk.public_key()?;
        let algorithm = jwk.algorithm()?;
        if !self.import_raw(thumbprint, algorithm, public_key) {
            return Err(KeyringError::KeyAlreadyExists);
        }
        Ok(())
    }

    /// Import a JSON Web Key Set on a best-effort basis. This method returns a vector indicating
    /// whether or not the corresponding key in the key set could be imported.
    pub fn import_jwks(&mut self, jwks: JSONWebKeySet) -> Vec<Option<KeyringError>> {
        jwks.keys
            .iter()
            .map(|jwk| self.try_import_jwk(jwk).err())
            .collect::<Vec<_>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_rename_key_does_not_replace_existing_destination() {
        let mut keyring = KeyRing::default();
        let source_key = vec![1; 32];
        let destination_key = vec![2; 32];
        assert!(keyring.import_raw("source".to_string(), Algorithm::Ed25519, source_key.clone()));
        assert!(keyring.import_raw(
            "destination".to_string(),
            Algorithm::Ed25519,
            destination_key.clone(),
        ));

        assert!(matches!(
            keyring.try_rename_key("source".to_string(), "destination".to_string()),
            Err(OperationError::KeyOccupied)
        ));
        assert_eq!(
            keyring.get(&"source".to_string()),
            Some(&(Algorithm::Ed25519, source_key))
        );
        assert_eq!(
            keyring.get(&"destination".to_string()),
            Some(&(Algorithm::Ed25519, destination_key))
        );
    }

    #[test]
    fn try_rename_key_to_same_identifier_reports_whether_key_exists() {
        let mut keyring = KeyRing::default();
        assert!(matches!(
            keyring.try_rename_key("missing".to_string(), "missing".to_string()),
            Err(OperationError::KeyNotPresent)
        ));

        let public_key = vec![1; 32];
        assert!(keyring.import_raw(
            "existing".to_string(),
            Algorithm::Ed25519,
            public_key.clone(),
        ));

        assert!(
            keyring
                .try_rename_key("existing".to_string(), "existing".to_string())
                .is_ok()
        );
        assert_eq!(
            keyring.get(&"existing".to_string()),
            Some(&(Algorithm::Ed25519, public_key))
        );
    }

    #[test]
    fn try_rename_key_with_missing_source_takes_precedence() {
        let mut keyring = KeyRing::default();
        let public_key = vec![1; 32];
        assert!(keyring.import_raw(
            "existing".to_string(),
            Algorithm::Ed25519,
            public_key.clone(),
        ));

        assert!(matches!(
            keyring.try_rename_key("missing".to_string(), "existing".to_string()),
            Err(OperationError::KeyNotPresent)
        ));
        assert_eq!(
            keyring.get(&"existing".to_string()),
            Some(&(Algorithm::Ed25519, public_key))
        );
    }

    #[test]
    fn test_importing_ed25519_key_from_jwks() {
        let mut keyring = KeyRing::default();
        let jwks: JSONWebKeySet = serde_json::from_str(r#"{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"test-key-ed25519","d":"n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]}"#).unwrap();
        for (index, result) in keyring.import_jwks(jwks).into_iter().enumerate() {
            assert_eq!(index, 0);
            assert!(result.is_none());
        }
        assert!(
            keyring
                .get(&String::from("poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"))
                .is_some()
        );
        assert!(
            keyring
                .try_rename_key(
                    String::from("poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"),
                    String::from("test-key-ed25519")
                )
                .is_ok()
        );
        assert!(keyring.get(&String::from("test-key-ed25519")).is_some());
    }
}
