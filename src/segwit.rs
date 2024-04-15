use std::str::FromStr;
use bitcoin::{CompressedPublicKey, EcdsaSighashType, Network, OutPoint, PrivateKey, PublicKey, WPubkeyHash};
use bitcoin::ecdsa::Signature;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::{All, SecretKey, Signing};
use crate::helpers::hex_decode;

pub(crate) fn new_private_key(priv_key: &str) -> PrivateKey {
    PrivateKey::from_slice(
        hex_decode(priv_key)
            .as_slice(), Network::Regtest).unwrap()
}

pub fn new_secret_key(priv_key: &PrivateKey) -> SecretKey {
    SecretKey::from_slice(priv_key.to_bytes().as_slice()).unwrap()
}

fn compressed_pk(secp: &Secp256k1<All>, private_key_2: &PrivateKey) -> Vec<u8> {
    let comp_pubkey_2 = CompressedPublicKey::from_private_key(&secp, &private_key_2)
        .unwrap()
        .to_bytes()
        .to_vec();
    comp_pubkey_2
}

fn player_keys<C: Signing>(secp: &Secp256k1<C>) -> (SecretKey, PublicKey, WPubkeyHash) {
    let sk = SecretKey::new(&mut rand::thread_rng());
    let pk = PublicKey::new(sk.public_key(secp));
    let wpkh = pk.wpubkey_hash().expect("key is compressed");

    (sk, pk, wpkh)
}

pub fn senders_keys<C: Signing>(secp: &Secp256k1<C>) -> Keypair {
    let sk = SecretKey::new(&mut rand::thread_rng());
    Keypair::from_secret_key(secp, &sk)
}

fn to_sig(signature_1: bitcoin::secp256k1::ecdsa::Signature) -> Signature {
    Signature {
        signature: signature_1,
        sighash_type: EcdsaSighashType::All,
    }
}

fn new_outpoint(txid: &str, vout: u32) -> OutPoint {
    let txid_vout = format!("{}:{}", txid, vout);
    let fund_utxo = OutPoint::from_str(txid_vout.as_str())
        .expect("error generating outpoint");
    fund_utxo
}

#[allow(unused_imports)]
#[cfg(test)]
mod test_segwit {
    use core::slice::SlicePattern;
    use std::io::Read;
    use std::ops::{Add, Sub};
    use std::str::FromStr;
    use bitcoin::{Address, Amount, CompressedPublicKey, EcdsaSighashType, Network, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence, TapNodeHash, TapSighashType, Transaction, Txid, TxIn, TxOut, Witness, WPubkeyHash};
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode;
    use bitcoin::ecdsa::Signature;
    use bitcoin::hashes::Hash;
    use bitcoin::hex::{Case, DisplayHex};
    use bitcoin::key::{Keypair, Secp256k1, TapTweak, TweakedKeypair, UntweakedPublicKey, Verification};
    use bitcoin::secp256k1::{All, Message, SecretKey, Signing};
    use bitcoin::sighash::{Prevouts, SighashCache};
    use bitcoin::transaction::Version;
    use btc_transaction_utils::multisig::RedeemScript;
    use btc_transaction_utils::{p2wsh, TxInRef};
    use btc_transaction_utils::test_data::btc_tx_from_hex;
    use crate::helpers::hex_decode;
    use crate::segwit::{compressed_pk, new_outpoint, new_private_key, new_secret_key, player_keys, to_sig};
    use crate::treepp::*;

    #[test]
    fn test_p2wsh_2x2_multisig() {
        // should choose the right TXID and VOUT to spend
        const TXID: &str = "dfdca5eefd976884193e4f72e5a018523aa567d713b98e1806681c21bfb17c36";
        const VOUT: u32 = 1;
        const SPEND_AMOUNT: Amount = Amount::from_sat(150_000_000); // 1.5 btc
        const CHANGE_AMOUNT: Amount = Amount::from_sat(50_000_000); // 0.5 btc
        const FUND_UTXO_AMOUNT: Amount = Amount::from_sat(200_100_000); // 2.001 btc

        let secp = bitcoin::secp256k1::Secp256k1::new();

        let private_key_1 =
            new_private_key("1111111111111111111111111111111111111111111111111111111111111111");
        let private_key_2 =
            new_private_key("2222222222222222222222222222222222222222222222222222222222222222");

        let comp_pubkey_1 = compressed_pk(&secp, &private_key_1);
        let comp_pubkey_2 = compressed_pk(&secp, &private_key_2);

        // 2 of 2 mulisig
        let p2wsh_witness_script = script! {
            OP_2
            <comp_pubkey_1>
            <comp_pubkey_2>
            OP_2
            OP_CHECKMULTISIG
        }; // unlocking script / redeem script

        println!("GENERATING P2WSH ADDRESS\n");

        let p2wsh_address = Address::p2wsh(&p2wsh_witness_script, Network::Regtest);
        let p2wsh_script_hash = p2wsh_witness_script.wscript_hash();
        let p2wsh_script_pubkey = ScriptBuf::new_p2wsh(&p2wsh_script_hash);

        println!("p2wsh_witness_script: {:?}", p2wsh_witness_script.clone().to_hex_string());
        println!("p2wsh_script_hash (256 bit hash): {:?}", p2wsh_script_hash);
        println!("p2wsh_address: {:?}", p2wsh_address);
        println!("p2wsh_script_pubkey: {:?}", p2wsh_script_pubkey.to_hex_string());

        println!("\n-------------------------------------------------------\n");

        println!("CREATING UNSIGNED TRANSACTION\n");

        // define inputs
        let input = TxIn {
            previous_output: new_outpoint(TXID, VOUT), // utxo to spend
            script_sig: Default::default(), // no script_sig if p2wsh
            sequence: Default::default(),
            witness: Default::default(), // will be signed later
        };

        // create a new keys for the receiver
        let receiver_priv_key = new_private_key("4444444444444444444444444444444444444444444444444444444444444444");
        let receiver_pub_key = CompressedPublicKey::from_private_key(&secp, &receiver_priv_key).unwrap();
        let receiver_address = Address::p2pkh(receiver_pub_key.pubkey_hash(), Network::Regtest);
        let receiver_script_pubkey = receiver_address.script_pubkey();

        println!("receiver_address: {:?}", receiver_address);
        println!("receiver_script_pubkey: {:?}", receiver_script_pubkey.to_hex_string());

        let hardcoded_spk =
            ScriptBuf::from_hex("512098642d71134586a2e4622228e4a5af95f8b4fc47ca6d7bf2545a859f79da8c22").unwrap();
        // we spend two outputs (one comes back to us)
        let output_spend = TxOut {
            value: SPEND_AMOUNT,
            script_pubkey: receiver_script_pubkey.clone()
            // script_pubkey: hardcoded_spk.clone()
        };
        let output_change = TxOut {
            value: CHANGE_AMOUNT,
            script_pubkey: receiver_script_pubkey.clone(), // change comes back to us :)
        };

        // we create an unsigned transaction with one input and two outputs
        let mut unsigned_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![input],
            output: vec![output_spend, output_change],
        };

        println!("unsigned_tx: {:?}", encode::serialize_hex(&unsigned_tx));

        println!("\n-------------------------------------------------------\n");

        println!("SIGNING TRANSACTION\n");

        let mut sighasher = SighashCache::new(&mut unsigned_tx);
        let input_index = 0; // index of the input to sign (there's only one)
        let tx_sighash = sighasher
            .p2wsh_signature_hash(
                input_index,
                &p2wsh_witness_script.as_script(),
                FUND_UTXO_AMOUNT,
                EcdsaSighashType::All
            )
            .expect("failed to create sighash");

        println!("tx_sighash: {:?}", tx_sighash);

        // Sign the sighash using the secp256k1 library (exported by rust-bitcoin).
        let msg_1 = Message::from(tx_sighash);
        let signature_1 = secp.sign_ecdsa(&msg_1, &new_secret_key(&private_key_1));

        let msg_2 = Message::from(tx_sighash);
        let signature_2  = secp.sign_ecdsa(&msg_2, &new_secret_key(&private_key_2));

        // now we create a witness with 2 of 2 signatures + witness script
        let mut w = Witness::new();
        // Add an extra "" for the CheckMultiSig bug
        // https://learn.saylor.org/mod/book/view.php?id=36369&chapterid=18956
        w.push(hex_decode("")); //
        w.push_ecdsa_signature(&to_sig(signature_1)); // push 1 of 2 signatures
        w.push_ecdsa_signature(&to_sig(signature_2)); // push 2 of 2 signatures
        w.push(p2wsh_witness_script.clone()); // push witness_script

        // update witness field
        *sighasher.witness_mut(input_index).unwrap() = w;

        // get the signed transaction.
        let tx = sighasher.into_transaction();
        let tx_hex = encode::serialize_hex(&tx);

        println!("\n-------------------------------------------------------\n");

        println!("TRANSACTION SIGNED AND READY TO BROADCAST (REMEMBER TO FUND THE ADDRESS FIRST!)\n");
        println!("tx_hex: {:?}", tx_hex);
    }
}

