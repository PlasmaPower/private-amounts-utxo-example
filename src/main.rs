use bulletproofs::{BulletproofGens, PedersenGens};
use ed25519_dalek::Keypair;
use rand::thread_rng;
use sha2::Sha512;

mod ledger;
mod transaction;

use crate::ledger::{ChainConstants, Ledger};
use crate::transaction::{AbstractedOutput, Transaction};

const DOMAIN_NAME: &[u8] = b"PlasmaPower/private-amounts-utxo-example";
const PRIVATE_AMOUNT_BITS: usize = 64;

fn main() {
    let mut rng = thread_rng();
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(PRIVATE_AMOUNT_BITS, 256);

    println!("Initialized generators");

    let keys1 = Keypair::generate::<Sha512, _>(&mut rng);
    let keys2 = Keypair::generate::<Sha512, _>(&mut rng);
    let keys3 = Keypair::generate::<Sha512, _>(&mut rng);

    let consts = ChainConstants {
        bp_gens,
        pc_gens,
        private_amount_bits: PRIVATE_AMOUNT_BITS,
        domain_name: DOMAIN_NAME,
    };
    let mut ledger = Ledger::new(consts, keys1.public);

    // the genesis input
    let tx1_inputs = vec![([0u8; 32], 0)];
    let tx1_outputs = vec![
        AbstractedOutput {
            destination: keys2.public,
            amount: 20,
            private: false,
        },
        AbstractedOutput {
            destination: keys2.public,
            amount: 30,
            private: true,
        },
        AbstractedOutput {
            destination: keys3.public,
            amount: 20,
            private: false,
        },
        AbstractedOutput {
            destination: keys1.public,
            amount: u64::max_value() - 20 - 20 - 30,
            private: false,
        },
    ];
    let tx1 = Transaction::new(&ledger, keys1.secret, tx1_inputs, tx1_outputs)
        .expect("Failed to create tx1");
    let tx1_hash = tx1.hash();
    ledger.process(tx1).expect("Failed to process tx1");

    let tx2_inputs = vec![(tx1_hash, 0), (tx1_hash, 1)];
    let tx2_outputs = vec![AbstractedOutput {
        destination: keys3.public,
        amount: 50,
        private: true,
    }];
    let tx2 = Transaction::new(&ledger, keys2.secret, tx2_inputs, tx2_outputs)
        .expect("Failed to create tx2");
    let tx2_hash = tx2.hash();
    ledger.process(tx2).expect("Failed to process tx2");

    let tx3_inputs = vec![(tx1_hash, 2), (tx2_hash, 0)];
    let tx3_outputs = vec![AbstractedOutput {
        destination: keys1.public,
        amount: 70,
        private: false,
    }];
    let tx3 = Transaction::new(&ledger, keys3.secret, tx3_inputs, tx3_outputs)
        .expect("Failed to create tx3");
    ledger.process(tx3).expect("Failed to process tx3");
}
