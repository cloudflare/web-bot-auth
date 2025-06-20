use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{VerifyingKey, ed25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

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
    ring: HashMap<String, (Algorithm, PublicKey)>,
}

impl FromIterator<(String, (Algorithm, PublicKey))> for KeyRing {
    fn from_iter<T: IntoIterator<Item = (String, (Algorithm, PublicKey))>>(iter: T) -> KeyRing {
        KeyRing {
            ring: HashMap::from_iter(iter),
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
                .insert(identifier, (algorithm, public_key))
                .is_none()
    }

    /// Rename a public key from `old_identifier` to `new_identifier`. Returns `false` if the old
    /// key was not present.
    pub fn rename_key(&mut self, old_identifier: String, new_identifier: String) -> bool {
        match self.ring.remove(&old_identifier) {
            Some(value) => self.ring.insert(new_identifier, value).is_none(),
            None => false,
        }
    }

    /// Retrieve a key. Semantics are identical to `HashMap::get`.
    pub fn get(&self, identifier: &String) -> Option<&(Algorithm, Vec<u8>)> {
        self.ring.get(identifier)
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
        assert!(keyring.rename_key(
            String::from("poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"),
            String::from("test-key-ed25519")
        ));
        assert!(keyring.get(&String::from("test-key-ed25519")).is_some());
    }
}
