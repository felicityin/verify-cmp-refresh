//! Extended private keys, copy from 

use bip32::{
    ChildNumber, Error, ExtendedKey, ExtendedKeyAttrs, 
    KeyFingerprint, PrivateKey, PublicKey, Result, KEY_SIZE,
};
use core::{
    fmt::{self, Debug},
    str::FromStr,
};
use hmac::Mac;

type HmacSha512 = hmac::Hmac<sha2::Sha512>;

#[cfg(feature = "alloc")]
use {
    bip32::DerivationPath,
    alloc::string::{String, ToString},
    zeroize::Zeroizing,
};

/// Derivation domain separator for BIP39 keys.
const BIP39_DOMAIN_SEPARATOR: [u8; 12] = [
    0x42, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0x20, 0x73, 0x65, 0x65, 0x64,
];

/// Extended private secp256k1 ECDSA signing key.
// #[cfg(feature = "secp256k1")]
pub type XPrv = ExtendedPrivateKey1<k256::ecdsa::SigningKey>;

/// Extended private keys derived using BIP32.
///
/// Generic around a [`PrivateKey`] type. When the `secp256k1` feature of this
/// crate is enabled, the [`XPrv`] type provides a convenient alias for
/// extended ECDSA/secp256k1 private keys.
#[derive(Clone)]
pub struct ExtendedPrivateKey1<K: PrivateKey> {
    /// Derived private key
    pub private_key: K,

    /// Extended key attributes.
    pub attrs: ExtendedKeyAttrs,
}

impl<K> ExtendedPrivateKey1<K>
where
    K: PrivateKey,
{
    /// Derive a child key from the given [`DerivationPath`].
    #[cfg(feature = "alloc")]
    pub fn derive_from_path<S>(seed: S, path: &DerivationPath) -> Result<Self>
    where
        S: AsRef<[u8]>,
    {
        path.iter().fold(Self::new(seed), |maybe_key, child_num| {
            maybe_key.and_then(|key| key.derive_child(child_num))
        })
    }

    pub fn new(private_key: K, attrs: ExtendedKeyAttrs) -> Self {
        ExtendedPrivateKey1 { private_key, attrs }
    }

    /// Create the root extended key for the given seed value.
    pub fn new_from_seed<S>(seed: S) -> Result<Self>
    where
        S: AsRef<[u8]>,
    {
        if ![16, 32, 64].contains(&seed.as_ref().len()) {
            return Err(Error::SeedLength);
        }

        let mut hmac = HmacSha512::new_from_slice(&BIP39_DOMAIN_SEPARATOR)?;
        hmac.update(seed.as_ref());

        let result = hmac.finalize().into_bytes();
        let (secret_key, chain_code) = result.split_at(KEY_SIZE);
        let private_key = PrivateKey::from_bytes(secret_key.try_into()?)?;
        let attrs = ExtendedKeyAttrs {
            depth: 0,
            parent_fingerprint: KeyFingerprint::default(),
            child_number: ChildNumber::default(),
            chain_code: chain_code.try_into()?,
        };

        Ok(ExtendedPrivateKey1 { private_key, attrs })
    }

    /// Derive a child key for a particular [`ChildNumber`].
    pub fn derive_child(&self, child_number: ChildNumber) -> Result<Self> {
        let depth = self.attrs.depth.checked_add(1).ok_or(Error::Depth)?;

        let mut hmac =
            HmacSha512::new_from_slice(&self.attrs.chain_code).map_err(|_| Error::Crypto)?;

        if child_number.is_hardened() {
            hmac.update(&[0]);
            hmac.update(&self.private_key.to_bytes());
        } else {
            hmac.update(&self.private_key.public_key().to_bytes());
        }

        hmac.update(&child_number.to_bytes());

        let result = hmac.finalize().into_bytes();
        let (child_key, chain_code) = result.split_at(KEY_SIZE);

        // We should technically loop here if a `secret_key` is zero or overflows
        // the order of the underlying elliptic curve group, incrementing the
        // index, however per "Child key derivation (CKD) functions":
        // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-ckd-functions
        //
        // > "Note: this has probability lower than 1 in 2^127."
        //
        // ...so instead, we simply return an error if this were ever to happen,
        // as the chances of it happening are vanishingly small.
        let private_key = self.private_key.derive_child(child_key.try_into()?)?;

        let attrs = ExtendedKeyAttrs {
            parent_fingerprint: self.private_key.public_key().fingerprint(),
            child_number,
            chain_code: chain_code.try_into()?,
            depth,
        };

        Ok(ExtendedPrivateKey1 { private_key, attrs })
    }

    /// Borrow the derived private key value.
    pub fn private_key(&self) -> &K {
        &self.private_key
    }

    /// Serialize this key as a self-[`Zeroizing`] `String`.
    #[cfg(feature = "alloc")]
    pub fn to_string(&self, prefix: Prefix) -> Zeroizing<String> {
        Zeroizing::new(self.to_extended_key(prefix).to_string())
    }
}

impl<K> Debug for ExtendedPrivateKey1<K>
where
    K: PrivateKey,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO(tarcieri): use `finish_non_exhaustive` when stable
        f.debug_struct("ExtendedPrivateKey")
            .field("private_key", &"...")
            .field("attrs", &self.attrs)
            .finish()
    }
}

/// NOTE: uses [`ConstantTimeEq`] internally
// impl<K> Eq for ExtendedPrivateKey1<K> where K: PrivateKey {}

// /// NOTE: uses [`ConstantTimeEq`] internally
// impl<K> PartialEq for ExtendedPrivateKey1<K>
// where
//     K: PrivateKey,
// {
//     fn eq(&self, other: &Self) -> bool {
//         self.ct_eq(other).into()
//     }
// }

impl<K> FromStr for ExtendedPrivateKey1<K>
where
    K: PrivateKey,
{
    type Err = Error;

    fn from_str(xprv: &str) -> Result<Self> {
        ExtendedKey::from_str(xprv)?.try_into()
    }
}

impl<K> TryFrom<ExtendedKey> for ExtendedPrivateKey1<K>
where
    K: PrivateKey,
{
    type Error = Error;

    fn try_from(extended_key: ExtendedKey) -> Result<ExtendedPrivateKey1<K>> {
        if extended_key.prefix.is_private() && extended_key.key_bytes[0] == 0 {
            Ok(ExtendedPrivateKey1 {
                private_key: PrivateKey::from_bytes(extended_key.key_bytes[1..].try_into()?)?,
                attrs: extended_key.attrs.clone(),
            })
        } else {
            Err(Error::Crypto)
        }
    }
}
