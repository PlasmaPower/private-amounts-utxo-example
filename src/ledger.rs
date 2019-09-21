use crate::transaction::{Hash, InvalidTransaction, Output, OutputRef, Transaction};
use bulletproofs::BulletproofGens;
use bulletproofs::PedersenGens;
use ed25519_dalek::PublicKey;
use std::collections::HashMap;

pub struct Utxo {
    pub output: Output,
    /// Used for the amount privacy key exchange.
    /// See documentation on get_early_ref() for more details.
    pub early_ref: Hash,
    pub source_account: PublicKey,
}

pub struct ChainConstants {
    pub bp_gens: BulletproofGens,
    pub pc_gens: PedersenGens,
    pub private_amount_bits: usize,
    pub domain_name: &'static [u8],
}

pub struct Ledger {
    consts: ChainConstants,

    utxos: HashMap<(Hash, u8), Utxo>,
    total_private_balance: u64,
}

impl Ledger {
    pub fn new(consts: ChainConstants, genesis_acct: PublicKey) -> Ledger {
        let mut utxos = HashMap::new();
        utxos.insert(
            ([0u8; 32], 0),
            Utxo {
                output: Output::create_genesis(genesis_acct),
                early_ref: [0u8; 32],
                source_account: PublicKey::default(),
            },
        );
        Ledger {
            consts,
            utxos,
            total_private_balance: 0,
        }
    }

    pub fn consts(&self) -> &ChainConstants {
        &self.consts
    }

    pub fn get_utxo(&self, output_ref: &OutputRef) -> Option<&Utxo> {
        self.utxos.get(output_ref)
    }

    pub fn process(&mut self, transaction: Transaction) -> Result<(), InvalidTransaction> {
        transaction.validate(&self)?;
        if transaction.uses_privacy() {
            for input in transaction.get_inputs() {
                let utxo = self
                    .utxos
                    .get(input)
                    .expect("Failed to get input from utxos for validated transaction");
                if let Some(amount) = utxo.output.get_public_amount() {
                    self.total_private_balance = self
                        .total_private_balance
                        .checked_add(amount)
                        .expect(concat!(
                            "Total private balance exceeded maximum u64 ",
                            "(public transactions are broken?)"
                        ));
                }
            }
            for output in transaction.get_outputs() {
                if let Some(amount) = output.get_public_amount() {
                    self.total_private_balance = self
                        .total_private_balance
                        .checked_sub(amount)
                        .expect(concat!(
                            "More balance extracted from privacy pool than ",
                            "put in (privacy is broken!)"
                        ));
                }
            }
        }
        let hash = transaction.hash();
        let mut account = None;
        for input in transaction.get_inputs() {
            let utxo = self
                .utxos
                .remove(input)
                .expect("Validated transaction referenced non-existant UTXO");
            if let Some(account) = account {
                assert_eq!(account, utxo.output.destination);
            } else {
                account = Some(utxo.output.destination);
            }
        }
        let account = account.expect("Account unset while processing validated transaction");
        assert!(
            transaction.get_outputs().len() <= u8::max_value().into(),
            "too many outputs",
        );
        let tx_inner = transaction.into_inner();
        for (i, output) in tx_inner.outputs.into_iter().enumerate() {
            let i = i as u8;
            let output_ref = (hash, i);
            let early_ref = crate::transaction::get_early_ref(&tx_inner.inputs, i);
            self.utxos.insert(
                output_ref,
                Utxo {
                    output,
                    early_ref,
                    source_account: account,
                },
            );
        }
        Ok(())
    }
}
