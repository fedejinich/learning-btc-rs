use std::str::FromStr;

use bitcoin::{Address, Amount, Network, OutPoint, Txid, TxOut};
use bitcoin::key::Verification;

/// returns necessary objects to spend a utxo
fn utxo_to_spend(
    address: Address,
    utxo_amount: Amount,
    txid: &str,
    vout: u32,
) -> (OutPoint, TxOut) {
    let script_pubkey =  address.script_pubkey();

    let out_point = OutPoint {
        txid: Txid::from_str(txid).expect("coudln't get txid"),
        vout,
    };

    let utxo = TxOut { value: utxo_amount, script_pubkey };

    (out_point, utxo)
}

mod test_taproot {
    use std::str::FromStr;

    use bitcoin::{Address, Amount, Network, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode;
    use bitcoin::hashes::Hash;
    use bitcoin::key::{Keypair, Secp256k1, TapTweak, TweakedKeypair};
    use bitcoin::secp256k1::Message;
    use bitcoin::sighash::{Prevouts, SighashCache};
    use bitcoin::TapSighashType::All;
    use bitcoin::transaction::Version;

    use crate::segwit::{new_private_key, new_secret_key};
    use crate::taproot::utxo_to_spend;

    #[test]
    fn test_p2tr() {
        // this should be filled with blockchain data
        const TXID: &str = "505750e49f9148460e677c81a7ddfcdadbf4488c37f2707353f287de6f907680";
        const VOUT: u32 = 0;
        const RECEIVER_ADDR: &str =
            "bcrt1pnpjz6ugngkr29erzyg5wffd0jhutflz8efkhhuj5t2ze77w63s3qx5qxjc";
        const UTXO_TO_SPEND_AMOUNT: Amount = Amount::from_sat(200_100_000); // 2.001 btc
        const SPEND_AMOUNT: Amount = Amount::from_sat(150_000_000); // 1.5 btc
        const CHANGE_AMOUNT: Amount = Amount::from_sat(50_000_000); // 0.5 btc

        let secp = Secp256k1::new();
        let bitcoin_network = Network::Regtest;

        println!("GENERATING TAPROOT ADDRESS\n");

        let private_key =
            new_private_key("1111111111111111111111111111111111111111111111111111111111111111");

        // Get a keypair we control. In a real application these would come from a stored secret.
        let keypair = Keypair::from_secret_key(&secp, &new_secret_key(&private_key));
        let (internal_pubkey, _) = keypair.x_only_public_key();
        let tr_merkle_root = None; // as there's no taptree
        let tr_address= Address::p2tr(&secp, internal_pubkey, tr_merkle_root,
                                       bitcoin_network);

        println!("tr_address: {:?}", tr_address.clone());
        println!("tr_merkle_root: {:?}", tr_merkle_root);
        println!("tr_script_pubkey: {:?}", tr_address.clone().script_pubkey().to_hex_string());

        println!("\n-------------------------------------------------------\n");

        println!("CREATING UNSIGNED TRANSACTION\n");

        let (utxo_outpoint, utxo) =
            utxo_to_spend(tr_address.clone(), UTXO_TO_SPEND_AMOUNT, TXID, VOUT);

        // Get an address to send to
        let receiver_address = Address::from_str(RECEIVER_ADDR)
            .expect("a valid address")
            .require_network(bitcoin_network)
            .expect("couldn't get a valid address for regtest");
        let receiver_address_script_pubkey = receiver_address.script_pubkey();

        println!("receiver_address: {:?}", receiver_address);
        println!("receiver_address_script_pubkey: {:?}", receiver_address_script_pubkey.to_hex_string());

        // The input for the transaction we are constructing.
        let input = TxIn {
            previous_output: utxo_outpoint, // The dummy output we are spending.
            script_sig: ScriptBuf::default(), // For a p2tr script_sig is empty.
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(), // Filled in after signing.
        };

        // The spend output is locked to a key controlled by the receiver.
        let spend = TxOut { value: SPEND_AMOUNT, script_pubkey: receiver_address_script_pubkey };

        // The change output is locked to a key controlled by us.
        // let change_script_pubkey = ScriptBuf::new_p2tr(&secp, internal_pubkey,
        //                                                tr_merkle_root);
        let change_script_pubkey = tr_address.script_pubkey().clone();
        let change = TxOut {
            value: CHANGE_AMOUNT,
            script_pubkey: change_script_pubkey.clone(), // Change comes back to us.
        };

        println!("change_script_pubkey: {:?}", change_script_pubkey.to_hex_string());

        // The transaction we want to sign and broadcast.
        let mut unsigned_tx = Transaction {
            version: Version::TWO,  // Post BIP-68.
            lock_time: LockTime::ZERO, // Ignore the locktime.
            input: vec![input],                  // Input goes into index 0.
            output: vec![spend, change],         // Outputs, order does not matter.
        };

        println!("unsigned_tx: {:?}", encode::serialize_hex(&unsigned_tx));

        println!("\n-------------------------------------------------------\n");

        println!("SIGNING TRANSACTION\n");

        let input_index = 0;

        // Get the sighash to sign.
        let mut sighasher = SighashCache::new(&mut unsigned_tx);
        let sighash_type = All;
        let sighash = sighasher.taproot_key_spend_signature_hash(
            input_index, &Prevouts::All(vec![utxo].as_slice()), sighash_type)
            .expect("failed to construct sighash");

        println!("tx_key_sighash: {:?}", sighash.to_string());

        // Sign the sighash
        let tweaked: TweakedKeypair = keypair.tap_tweak(&secp, None);
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = secp.sign_schnorr(&msg, &tweaked.to_inner());

        // let msg = Message::from_digest(sighash.to_byte_array());
        // let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

        // verify
        // secp.verify_schnorr(&sig, &msg, &keypair.x_only_public_key().0)
        // let xp = bitcoin::key::XOnlyPublicKey::from_slice(&internal_pubkey.serialize()).expect("couldn't from slice");
        // secp.verify_schnorr(&sig, &msg, &xp.0)
        //     .expect("couldn't verify signature");

        // Update the witness stack.
        let signature = bitcoin::taproot::Signature { signature: sig, sighash_type };
        *sighasher.witness_mut(input_index).unwrap() = Witness::p2tr_key_spend(&signature);

        println!("\n-------------------------------------------------------\n");

        // Get the signed transaction.
        let tx = sighasher.into_transaction();
        let tx_hex = encode::serialize_hex(&tx);

        println!("TRANSACTION SIGNED AND READY TO BROADCAST (REMEMBER TO FUND THE ADDRESS FIRST!)\n");
        println!("signed_tx_hex: {:?}", tx_hex);
    }
}
