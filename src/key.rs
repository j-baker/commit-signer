use base64::Engine;
use byteorder::{BigEndian, WriteBytesExt};
use core_foundation::dictionary::CFDictionary;
use eyre::{bail, ensure, eyre};
use log::info;
use picky_asn1::wrapper::IntegerAsn1;
use picky_asn1_der::from_bytes;
use security_framework::item::{
    ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult,
};
use security_framework::key::{
    access_control_flags, AccessControlCombinationMode, AccessControlFlag, Algorithm,
    GenerateKeyOptions, KeyType, SecKey, Token,
};
use serde::Deserialize;
use std::fs;
use std::path::{Path};

const CURVE_TYPE: &str = "ecdsa-sha2-nistp256";
const CURVE_IDENTIFIER: &str = "nistp256";

#[derive(Clone, Copy, Debug)]
pub enum KeyUsageTarget {
    Comms,
    Signing,
}

impl KeyUsageTarget {
    fn filename(&self) -> &'static str {
        match self {
            KeyUsageTarget::Signing => "signing_key.pub",
            KeyUsageTarget::Comms => "comms_key.pub",
        }
    }
}

#[derive(Clone)]
pub(crate) struct SepKey {
    /// Actual key reference
    pub(crate) key: SecKey,
    /// OpenSSH string format.
    pub(crate) pubkey_string: String,
    /// As expected by OpenSSH agent.
    pub(crate) pubkey_bytes: Vec<u8>,
    /// The canonical file, but as a string.
    pub(crate) pubkey_file: String,
}

impl SepKey {
    pub(crate) fn delete_all() -> eyre::Result<()> {
        Self::delete(KeyUsageTarget::Signing)?;
        Self::delete(KeyUsageTarget::Comms)?;
        Ok(())
    }

    fn delete(usage: KeyUsageTarget) -> eyre::Result<()> {
        if let Some(key) = get_key(usage)? {
            key.delete()?;
        }
        Ok(())
    }

    pub(crate) fn create(dir: &Path, usage: KeyUsageTarget) -> eyre::Result<SepKey> {
        let pubkey_file = dir.join(usage.filename());
        let key = key(usage)?;
        let key_bytes = pub_key_bytes(&key);
        let key_string = pub_key_string(&key);

        fs::write(&pubkey_file, &key_string)?;

        Ok(SepKey {
            key,
            pubkey_string: key_string,
            pubkey_bytes: key_bytes,
            pubkey_file: pubkey_file.to_str().unwrap().to_string(),
        })
    }

    pub(crate) fn sign(&self, data: &[u8]) -> eyre::Result<EcDsaSignature> {
        let sig = self
            .key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, data)
            .map_err(|err| eyre!("wrapped: {err:?}"))?;
        Ok(from_bytes(&sig)?)
    }

    pub fn curve_type(&self) -> &'static str {
        CURVE_TYPE
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct EcDsaSignature {
    pub(crate) r: IntegerAsn1,
    pub(crate) s: IntegerAsn1,
}

fn key(target: KeyUsageTarget) -> eyre::Result<SecKey> {
    match get_key(target)? {
        Some(key) => Ok(key),
        None => {
            info!("could not find key so generating a new one");
            generate_key(target)
        }
    }
}

fn generate_key(target: KeyUsageTarget) -> eyre::Result<SecKey> {
    let key_options = generate_key_options(target);
    let key = SecKey::generate(key_options).map_err(|err| eyre!("wrapped error: {err:?}"))?;
    Ok(key)
}

fn get_key(target: KeyUsageTarget) -> eyre::Result<Option<SecKey>> {
    let search = ItemSearchOptions::new()
        .class(ItemClass::key())
        .label(name(target))
        .load_refs(true)
        .key_class(KeyClass::private())
        .search_data_protection_keychain()
        .search()
        .ok();
    if let Some(mut results) = search {
        ensure!(
            results.len() == 1,
            "expected exactly 1 result, received {}",
            results.len()
        );
        let result = results.remove(0);
        match result {
            SearchResult::Ref(Reference::Key(key)) => Ok(Some(key)),
            _ => bail!("key had wrong type, was not a reference to a SecKey"),
        }
    } else {
        Ok(None)
    }
}

fn generate_key_options(target: KeyUsageTarget) -> CFDictionary {
    let access_control = match target {
        KeyUsageTarget::Signing => Some(access_control_flags(
            AccessControlCombinationMode::Or,
            &[AccessControlFlag::BiometryAny],
        )),
        KeyUsageTarget::Comms => None,
    };

    let opts = GenerateKeyOptions {
        key_type: Some(KeyType::ec()),
        size_in_bits: Some(256),
        label: Some(name(target).to_string()),
        token: Some(Token::SecureEnclave),
        location: Some(Location::DataProtectionKeychain),
        access_control,
    };
    opts.to_dictionary()
}

fn name(target: KeyUsageTarget) -> &'static str {
    match target {
        KeyUsageTarget::Comms => "code-signing-comms",
        KeyUsageTarget::Signing => "code-signing-signing",
    }
}

fn pub_key_string(key: &SecKey) -> String {
    format!(
        "ecdsa-sha2-nistp256 {}",
        base64::engine::general_purpose::STANDARD.encode(pub_key_bytes(key))
    )
}

fn pub_key_bytes(key: &SecKey) -> Vec<u8> {
    let curve_type = String::from(CURVE_TYPE);
    let identifier = String::from(CURVE_IDENTIFIER);

    let mut data = Vec::new();

    data.write_u32::<BigEndian>(curve_type.len() as u32)
        .unwrap();
    data.extend(curve_type.as_bytes());

    data.write_u32::<BigEndian>(identifier.len() as u32)
        .unwrap();
    data.extend(identifier.as_bytes());

    let key = key
        .public_key()
        .unwrap()
        .external_representation()
        .unwrap()
        .to_vec();
    data.write_u32::<BigEndian>(key.len() as u32).unwrap();
    data.extend(key);
    data
}
