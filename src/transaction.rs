use crate::ledger::Ledger;
use byteorder::{ByteOrder, LittleEndian};
use curve25519_dalek::{
    edwards::CompressedEdwardsY,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::VartimeMultiscalarMul,
};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature};
use merlin::Transcript;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use std::{collections::HashSet, convert::TryFrom};
use x25519_dalek as x25519;

pub type Commitment = CompressedRistretto;
pub type Hash = [u8; 32];
pub type OutputRef = (Hash, u8);

enum OutputAmount {
    Public(u64),
    Private {
        commitment: Commitment,
        /// Used by the receiver to get the amount.
        /// Not verified by the rest of the network.
        amount_memo: u64,
    },
}

pub struct Output {
    pub destination: PublicKey,
    amount: OutputAmount,
}

impl Output {
    pub(crate) fn create_genesis(destination: PublicKey) -> Output {
        Output {
            destination,
            amount: OutputAmount::Public(u64::max_value()),
        }
    }

    pub fn get_public_amount(&self) -> Option<u64> {
        match self.amount {
            OutputAmount::Public(amount) => Some(amount),
            OutputAmount::Private { .. } => None,
        }
    }
}

pub enum RangeProofWrapper {
    Bulletproof(bulletproofs::RangeProof),
    // This could be expanded in the future
}

pub struct PrivacyProofs {
    // If you didn't need ed25519 compatibility,
    // this could be merged into the regular signature.
    pub blinding_signature: (CompressedRistretto, Scalar),
    /// `None` if no outputs have privacy enabled
    pub range_proof: Option<RangeProofWrapper>,
}

/// Basic information that is hashed into the transaction.
pub struct TransactionBody {
    pub inputs: Vec<OutputRef>,
    pub outputs: Vec<Output>,
}

/// Information that does not affect the nature of the transaction,
/// except for simply if it is valid or not. Therefore, to prevent
/// malleability issues, it is not hashed into the transaction.
struct TransactionTail {
    signature: Signature,
    privacy_proofs: Option<PrivacyProofs>,
}

pub struct Transaction {
    inner: TransactionBody,
    tail: TransactionTail,
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum InvalidTransaction {
    InvalidCommitment,
    InvalidBulletproof(bulletproofs::ProofError),
    InvalidBlindingSignature,
    InvalidNumberOfInputs,
    InvalidNumberOfOutputs,
    UnknownInput,
    /// input - output != 0
    MismatchedAmounts,
    MissingPrivacyProofs,
    UnnecessaryPrivacyProofs,
    /// Could be supported in theory.
    MixedInputDestinations,
    InvalidSignature,
    DuplicateInputs,

    // The following are only returned from Transaction::new
    InputHasDifferentOwner,
    InvalidPrivateDestination,
    InvalidInputKeying,
}

impl ::std::fmt::Display for InvalidTransaction {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::std::fmt::Debug::fmt(&self, f)
    }
}

impl ::std::error::Error for InvalidTransaction {}

fn ristretto_sign(
    basepoint: &RistrettoPoint,
    message: &[u8],
    private_key: &Scalar,
) -> (CompressedRistretto, Scalar) {
    let mut randomness = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut randomness);
    let r_value = Scalar::from_hash(
        Sha512::default()
            .chain(private_key.as_bytes())
            .chain(message)
            // just in case
            .chain(randomness),
    );
    let rb_value = (r_value * basepoint).compress();

    let public_key = private_key * basepoint;
    let h = Scalar::from_hash(
        Sha512::default()
            .chain(rb_value.as_bytes())
            .chain(public_key.compress().as_bytes())
            .chain(message),
    );

    let s_value = r_value + h * private_key;
    (rb_value, s_value)
}

fn verify_ristretto_sig(
    basepoint: &RistrettoPoint,
    message: &[u8],
    public_key: &RistrettoPoint,
    signature: &(CompressedRistretto, Scalar),
) -> Result<(), ()> {
    let rb_value = &signature.0;
    let s_value = &signature.1;
    let negative_public_key = -public_key;

    let h = Scalar::from_hash(
        Sha512::default()
            .chain(rb_value.as_bytes())
            .chain(public_key.compress().as_bytes())
            .chain(message),
    );

    let scalars = &[h, *s_value];
    let points = &[negative_public_key, *basepoint];
    let expected_rb = RistrettoPoint::vartime_multiscalar_mul(scalars, points);

    if &expected_rb.compress() == rb_value {
        Ok(())
    } else {
        Err(())
    }
}

/// An "early ref" is a hash of the inputs that can be calculated before
/// the transaction's outputs are created. This is needed for the blinding
/// key exchange to work (each blinding key should be unique, but they're
/// needed to compute the outputs).
pub fn get_early_ref(inputs: &[OutputRef], output_idx: u8) -> Hash {
    let mut hasher = Sha256::default();
    assert!(inputs.len() <= u8::max_value().into(), "too many inputs",);
    hasher.input([inputs.len() as u8]);
    for (tx_hash, idx) in inputs {
        hasher.input(tx_hash);
        hasher.input([*idx]);
    }
    hasher.input([output_idx]);
    hasher.result().into()
}

fn key_exchange(our_secret: &SecretKey, their_public: &PublicKey) -> Result<[u8; 32], ()> {
    // Hash the secret (clamping is the same as in ed25519)
    let mut our_secret_hash = [0u8; 32];
    our_secret_hash.copy_from_slice(&Sha512::digest(our_secret.as_bytes())[..32]);
    let our_secret = x25519::StaticSecret::from(our_secret_hash);
    // Convert from compressed edwards y representation to montgomery representation
    let their_public = CompressedEdwardsY(their_public.to_bytes())
        .decompress()
        .ok_or(())?
        .to_montgomery();
    let their_public = x25519::PublicKey::from(their_public.to_bytes());
    Ok(*our_secret.diffie_hellman(&their_public).as_bytes())
}

fn compute_blinding_secret(
    our_secret: &SecretKey,
    their_public: &PublicKey,
    early_ref: Hash,
) -> Result<Scalar, ()> {
    Ok(Scalar::from_hash(
        Sha512::default()
            .chain(key_exchange(our_secret, their_public)?)
            .chain(&early_ref),
    ))
}

fn compute_amount_memo_mask(blinding_key: &Scalar) -> u64 {
    let blinding_hash = Sha256::digest(blinding_key.as_bytes());
    LittleEndian::read_u64(&blinding_hash)
}

fn pad_to_power_of_two<T: Default>(v: &mut Vec<T>) {
    let current_len = v.len();
    let new_len = current_len.next_power_of_two();
    v.reserve(new_len - current_len);
    for _ in current_len..new_len {
        v.push(T::default());
    }
}

pub struct AbstractedOutput {
    pub destination: PublicKey,
    pub amount: u64,
    pub private: bool,
}

impl TransactionBody {
    pub fn hash(&self) -> Hash {
        let mut hasher = Sha256::default();
        assert!(
            self.inputs.len() <= u8::max_value().into(),
            "too many inputs",
        );
        hasher.input([self.inputs.len() as u8]);
        for (tx_hash, idx) in &self.inputs {
            hasher.input(tx_hash);
            hasher.input([*idx]);
        }
        assert!(
            self.outputs.len() <= u8::max_value().into(),
            "too many outputs",
        );
        hasher.input([self.outputs.len() as u8]);
        for output in &self.outputs {
            hasher.input(output.destination.as_bytes());
            match output.amount {
                OutputAmount::Public(amount) => {
                    hasher.input([0]);
                    let mut buf = [0u8; 8];
                    LittleEndian::write_u64(&mut buf, amount);
                    hasher.input(buf);
                }
                OutputAmount::Private { commitment, .. } => {
                    hasher.input([1]);
                    hasher.input(commitment.as_bytes());
                }
            }
        }
        hasher.result().into()
    }
}

impl Transaction {
    pub fn hash(&self) -> Hash {
        self.inner.hash()
    }

    /// Warning: only guaranteed to be accurate if transaction is valid
    pub fn uses_privacy(&self) -> bool {
        self.tail.privacy_proofs.is_some()
    }

    pub fn get_inputs(&self) -> &[OutputRef] {
        &self.inner.inputs
    }

    pub fn get_outputs(&self) -> &[Output] {
        &self.inner.outputs
    }

    pub fn into_inner(self) -> TransactionBody {
        self.inner
    }

    pub fn validate(&self, ledger: &Ledger) -> Result<(), InvalidTransaction> {
        // This is an i128 because it needs to have the capacity of a u64 (not an i64),
        // but also be able to handle negatives. We could do a (u64, bool) but for for
        // this project I've deemed it not worth the code quality cost. This also
        // protects against overflows, though we still explicitly check for them.
        let mut total_public: i128 = 0;
        let mut total_private = RistrettoPoint::default();
        let mut uses_privacy = false;
        if self.inner.inputs.is_empty() || self.inner.inputs.len() > u8::max_value().into() {
            return Err(InvalidTransaction::InvalidNumberOfInputs);
        }
        let mut seen_inputs: HashSet<OutputRef> = HashSet::new();
        let mut destination = None;
        for input in &self.inner.inputs {
            if !seen_inputs.insert(input.clone()) {
                // Let's not have another BTC incident ;)
                return Err(InvalidTransaction::DuplicateInputs);
            }
            let utxo = ledger.get_utxo(input).ok_or(InvalidTransaction::UnknownInput)?;
            if let Some(destination) = destination {
                if utxo.output.destination != destination {
                    return Err(InvalidTransaction::MixedInputDestinations);
                }
            } else {
                destination = Some(utxo.output.destination);
            }
            match utxo.output.amount {
                OutputAmount::Public(amount) => {
                    total_public = total_public
                        .checked_add(amount.into())
                        .expect("Somehow managed to overflow public amount");
                }
                OutputAmount::Private { commitment, .. } => {
                    // We don't need to verify the range proof, because we should've
                    // done that when we added the output to the ChainState.
                    let commitment = commitment
                        .decompress()
                        .ok_or(InvalidTransaction::InvalidCommitment)?;
                    total_private += commitment;
                    uses_privacy = true;
                }
            }
        }
        if self.inner.outputs.is_empty() || self.inner.outputs.len() > u8::max_value().into() {
            return Err(InvalidTransaction::InvalidNumberOfOutputs);
        }
        let mut commitments_to_verify = Vec::new();
        for output in &self.inner.outputs {
            match output.amount {
                OutputAmount::Public(amount) => {
                    total_public = total_public
                        .checked_sub(amount.into())
                        .ok_or(InvalidTransaction::MismatchedAmounts)?;
                }
                OutputAmount::Private { commitment, .. } => {
                    commitments_to_verify.push(commitment);
                    let commitment = commitment
                        .decompress()
                        .ok_or(InvalidTransaction::InvalidCommitment)?;
                    total_private -= commitment;
                    uses_privacy = true;
                }
            }
        }
        let destination = destination
            .expect("Didn't set destination, but there should've been at least one input");
        if destination
            .verify::<Sha512>(&self.hash(), &self.tail.signature)
            .is_err()
        {
            return Err(InvalidTransaction::InvalidSignature);
        }
        if uses_privacy {
            let privacy_proofs = self
                .tail
                .privacy_proofs
                .as_ref()
                .ok_or(InvalidTransaction::MissingPrivacyProofs)?;
            if !commitments_to_verify.is_empty() {
                pad_to_power_of_two(&mut commitments_to_verify);
                match &privacy_proofs.range_proof {
                    Some(RangeProofWrapper::Bulletproof(proof)) => {
                        proof
                            .verify_multiple(
                                &ledger.consts().bp_gens,
                                &ledger.consts().pc_gens,
                                &mut Transcript::new(ledger.consts().domain_name),
                                commitments_to_verify.as_slice(),
                                ledger.consts().private_amount_bits,
                            )
                            .map_err(InvalidTransaction::InvalidBulletproof)?;
                    }
                    None => return Err(InvalidTransaction::MissingPrivacyProofs),
                }
            } else if privacy_proofs.range_proof.is_some() {
                return Err(InvalidTransaction::UnnecessaryPrivacyProofs);
            }
            // It seems a bit odd on the surface, but this verifies that
            // the private amounts commitment sum is a commitment to 0.
            // If this was wrapped into the main signature,
            // the message would be this transaction's hash.
            let total_public_negative = total_public.is_negative();
            let total_public = total_public
                .checked_abs()
                .ok_or(InvalidTransaction::MismatchedAmounts)?;
            let total_public =
                u64::try_from(total_public).map_err(|_| InvalidTransaction::MismatchedAmounts)?;
            let mut total_public = Scalar::from(total_public);
            if total_public_negative {
                total_public = -total_public;
            }
            total_private += total_public * ledger.consts().pc_gens.B;
            verify_ristretto_sig(
                &ledger.consts().pc_gens.B_blinding,
                &[],
                &total_private,
                &privacy_proofs.blinding_signature,
            )
            .map_err(|_| InvalidTransaction::InvalidBlindingSignature)?;
        } else {
            if self.tail.privacy_proofs.is_some() {
                return Err(InvalidTransaction::UnnecessaryPrivacyProofs);
            }
            if total_public != 0 {
                return Err(InvalidTransaction::MismatchedAmounts);
            }
            assert_eq!(total_private, RistrettoPoint::default());
            assert!(commitments_to_verify.is_empty());
        }
        Ok(())
    }

    pub fn new(
        ledger: &Ledger,
        secret_key: SecretKey,
        inputs: Vec<OutputRef>,
        mut abstracted_outputs: Vec<AbstractedOutput>,
    ) -> Result<Transaction, InvalidTransaction> {
        let public_key = PublicKey::from_secret::<Sha512>(&secret_key);
        let keypair = Keypair {
            secret: secret_key,
            public: public_key,
        };
        let mut running_amount: u64 = 0;
        let mut seen_inputs: HashSet<OutputRef> = HashSet::new();
        if inputs.is_empty() || inputs.len() > u8::max_value().into() {
            return Err(InvalidTransaction::InvalidNumberOfInputs);
        }
        let mut range_proof_values = Vec::new();
        let mut range_proof_blindings = Vec::new();
        let mut total_blindings = Scalar::default();
        let mut uses_privacy = false;
        for input in &inputs {
            if !seen_inputs.insert(input.clone()) {
                return Err(InvalidTransaction::DuplicateInputs);
            }
            let utxo = ledger.get_utxo(input).ok_or(InvalidTransaction::UnknownInput)?;
            if utxo.output.destination != public_key {
                return Err(InvalidTransaction::InputHasDifferentOwner);
            }
            match utxo.output.amount {
                OutputAmount::Public(amount) => {
                    running_amount = running_amount
                        .checked_add(amount)
                        .expect("Running amount overflow in tx generation");
                }
                OutputAmount::Private {
                    amount_memo,
                    commitment,
                } => {
                    uses_privacy = true;
                    let blinding_secret = compute_blinding_secret(
                        &keypair.secret,
                        &utxo.source_account,
                        utxo.early_ref,
                    )
                    .map_err(|_| InvalidTransaction::InvalidPrivateDestination)?;
                    let amount_memo_mask = compute_amount_memo_mask(&blinding_secret);
                    let real_amount = amount_memo ^ amount_memo_mask;
                    let expected_commitment = Scalar::from(real_amount)
                        * ledger.consts().pc_gens.B
                        + blinding_secret * ledger.consts().pc_gens.B_blinding;
                    if commitment != expected_commitment.compress() {
                        return Err(InvalidTransaction::InvalidInputKeying);
                    }
                    running_amount = running_amount
                        .checked_add(real_amount)
                        .expect("Running amount overflow in tx generation");
                    total_blindings += blinding_secret;
                }
            }
        }
        if abstracted_outputs.is_empty() || abstracted_outputs.len() > u8::max_value().into() {
            return Err(InvalidTransaction::InvalidNumberOfInputs);
        }
        for (i, abstracted_output) in abstracted_outputs.iter_mut().enumerate() {
            let i = i as u8;
            running_amount = running_amount
                .checked_sub(abstracted_output.amount)
                .ok_or(InvalidTransaction::MismatchedAmounts)?;
            if abstracted_output.private {
                let early_ref = get_early_ref(&inputs, i);
                let destination = abstracted_output.destination;
                let blinding_secret =
                    compute_blinding_secret(&keypair.secret, &destination, early_ref)
                        .map_err(|_| InvalidTransaction::InvalidPrivateDestination)?;
                let amount_memo_mask = compute_amount_memo_mask(&blinding_secret);
                uses_privacy = true;
                total_blindings -= blinding_secret;
                range_proof_values.push(abstracted_output.amount);
                range_proof_blindings.push(blinding_secret);
                abstracted_output.amount ^= amount_memo_mask;
            }
        }
        let mut privacy_proofs = None;
        let mut commitments = Vec::new();
        if uses_privacy {
            let range_proof = if range_proof_blindings.is_empty() {
                None
            } else {
                pad_to_power_of_two(&mut range_proof_values);
                pad_to_power_of_two(&mut range_proof_blindings);
                let range_proof = bulletproofs::RangeProof::prove_multiple(
                    &ledger.consts().bp_gens,
                    &ledger.consts().pc_gens,
                    &mut Transcript::new(ledger.consts().domain_name),
                    &range_proof_values,
                    &range_proof_blindings,
                    ledger.consts().private_amount_bits,
                )
                .expect("Bulletproof generation failed");
                commitments = range_proof.1;
                commitments.reverse();
                Some(range_proof.0)
            };
            let blinding_signature =
                ristretto_sign(&ledger.consts().pc_gens.B_blinding, &[], &total_blindings);
            privacy_proofs = Some(PrivacyProofs {
                range_proof: range_proof.map(RangeProofWrapper::Bulletproof),
                blinding_signature,
            });
        }
        let mut real_outputs = Vec::with_capacity(abstracted_outputs.len());
        for abstracted_output in abstracted_outputs {
            // Warning: by this loop, private outputs' amounts have already been masked
            if abstracted_output.private {
                real_outputs.push(Output {
                    destination: abstracted_output.destination,
                    amount: OutputAmount::Private {
                        commitment: commitments
                            .pop()
                            .expect("Not enough commitments for private outputs"),
                        amount_memo: abstracted_output.amount,
                    },
                });
            } else {
                real_outputs.push(Output {
                    destination: abstracted_output.destination,
                    amount: OutputAmount::Public(abstracted_output.amount),
                });
            }
        }
        if running_amount != 0 {
            return Err(InvalidTransaction::MismatchedAmounts);
        }
        let inner = TransactionBody {
            inputs,
            outputs: real_outputs,
        };
        let hash = inner.hash();
        let signature = keypair.sign::<Sha512>(&hash);
        Ok(Transaction {
            inner,
            tail: TransactionTail {
                signature,
                privacy_proofs,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{key_exchange, ristretto_sign, verify_ristretto_sig};
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use ed25519_dalek::Keypair;
    use sha2::Sha512;

    #[test]
    fn test_key_exchange() {
        let mut rng = rand::thread_rng();
        let keys1 = Keypair::generate::<Sha512, _>(&mut rng);
        let keys2 = Keypair::generate::<Sha512, _>(&mut rng);
        assert_eq!(
            key_exchange(&keys1.secret, &keys2.public),
            key_exchange(&keys2.secret, &keys1.public),
        );
    }

    #[test]
    fn test_ristretto_sigs() {
        let mut rng = rand::thread_rng();
        let basepoint = RistrettoPoint::random(&mut rng);
        let secret = Scalar::random(&mut rng);
        let public = secret * basepoint;
        let message = b"hello world";
        let mut sig = ristretto_sign(&basepoint, message, &secret);
        assert_eq!(
            verify_ristretto_sig(&basepoint, message, &public, &sig),
            Ok(()),
        );
        sig.1 = Scalar::random(&mut rng);
        assert!(verify_ristretto_sig(&basepoint, message, &public, &sig).is_err());
    }
}
