use bip32::{Mnemonic, ChildNumber};
use k256::Scalar;
use rand_core::OsRng;
use crate::ckd::XPrv;

mod ckd;

fn main() {
    //================ old

    //---------------- first slice

    // Generate random Mnemonic using the default language (English)
    let mnemonic = Mnemonic::random(&mut OsRng, Default::default());

    // Derive a BIP39 seed value using the given password
    let seed = mnemonic.to_seed("password");

    let root_xprv1 = XPrv::new_from_seed(&seed).unwrap();

    let child_xprv1 = root_xprv1.derive_child(ChildNumber(0)).unwrap();

    //---------------- second slice

    let mnemonic = Mnemonic::random(&mut OsRng, Default::default());

    let seed = mnemonic.to_seed("password1");

    let root_xprv2 = XPrv::new_from_seed(&seed).unwrap();

    let child_xprv2 = root_xprv2.derive_child(ChildNumber(0)).unwrap();

    //================ new

    let mnemonic = Mnemonic::random(&mut OsRng, Default::default());

    let seed = mnemonic.to_seed("password2");

    let delta = XPrv::new_from_seed(&seed).unwrap().private_key().as_nonzero_scalar().to_owned();

    //---------------- first slice

    let root_xprv11 = XPrv::new(
        k256::ecdsa::SigningKey::from_bytes(&root_xprv1.private_key().as_nonzero_scalar().sub(&delta).to_bytes()).unwrap(), 
        root_xprv1.attrs.clone(),
    );
    let child_xprv11 = root_xprv11.derive_child(ChildNumber(0)).unwrap();

    //---------------- second slice

    let root_xprv22 = XPrv::new(
        k256::ecdsa::SigningKey::from_bytes(&root_xprv2.private_key().as_nonzero_scalar().add(&delta).to_bytes()).unwrap(), 
        root_xprv2.attrs.clone(),
    );
    let child_xprv22 = root_xprv22.derive_child(ChildNumber(0)).unwrap();

    //================ verify

    let root_priv1: Scalar = root_xprv1.private_key().as_nonzero_scalar().add(root_xprv2.private_key().as_nonzero_scalar());
    let root_priv2: Scalar = root_xprv11.private_key().as_nonzero_scalar().add(root_xprv22.private_key().as_nonzero_scalar());
    assert!(root_priv1.eq(&root_priv2));

    let child_priv1: Scalar = child_xprv1.private_key().as_nonzero_scalar().add(child_xprv2.private_key().as_nonzero_scalar());
    let child_priv2: Scalar = child_xprv11.private_key().as_nonzero_scalar().add(child_xprv22.private_key().as_nonzero_scalar());
    assert!(!child_priv1.eq(&child_priv2));

    println!("ok");
}
