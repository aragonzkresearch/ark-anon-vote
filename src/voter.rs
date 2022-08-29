use crate::ConstraintF;
use ark_crypto_primitives::signature::schnorr::{constraints::PublicKeyVar, PublicKey};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};
use ark_r1cs_std::bits::{uint32::UInt32, uint64::UInt64, ToBytesGadget};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};
use std::borrow::Borrow;

////////
// Index

#[derive(Hash, Eq, PartialEq, Copy, Clone, Ord, PartialOrd, Debug)]
pub struct Index(pub u32);

impl Index {
    pub fn to_bytes_le(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

#[derive(Clone, Debug)]
pub struct IndexVar(pub UInt32<ConstraintF>);

impl IndexVar {
    #[tracing::instrument(target = "r1cs", skip(self))]
    pub fn to_bytes_le(&self) -> Vec<UInt8<ConstraintF>> {
        // vec![self.0.clone()]
        self.0.to_bytes().unwrap()
    }
}

impl AllocVar<Index, ConstraintF> for IndexVar {
    #[tracing::instrument(target = "r1cs", skip(cs, f, mode))]
    fn new_variable<T: Borrow<Index>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        UInt32::new_variable(cs, || f().map(|u| u.borrow().0), mode).map(Self)
    }
}

////////
// Voter

pub type VoterPublicKey = PublicKey<EdwardsProjective>;
pub type VoterPublicKeyVar = PublicKeyVar<EdwardsProjective, EdwardsVar>;

#[derive(Hash, Eq, PartialEq, Copy, Clone, Ord, PartialOrd, Debug)]
pub struct ProcessId(pub u64);
#[derive(Clone, Debug)]
pub struct ProcessIdVar(pub UInt64<ConstraintF>);

impl AllocVar<ProcessId, ConstraintF> for ProcessIdVar {
    #[tracing::instrument(target = "r1cs", skip(cs, f, mode))]
    fn new_variable<T: Borrow<ProcessId>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        UInt64::new_variable(cs, || f().map(|u| u.borrow().0), mode).map(Self)
    }
}

impl ProcessIdVar {
    #[tracing::instrument(target = "r1cs", skip(self))]
    pub fn to_bytes_le(&self) -> Vec<UInt8<ConstraintF>> {
        self.0.to_bytes().unwrap()
    }
}

#[derive(Hash, Eq, PartialEq, Copy, Clone)]
pub struct Voter {
    pub public_key: VoterPublicKey,
    pub process_id: ProcessId,
}

impl Voter {
    pub fn to_bytes_le(&self) -> Vec<u8> {
        ark_ff::to_bytes![self.public_key, self.process_id.0.to_le_bytes()].unwrap()
    }
}

#[derive(Clone)]
pub struct VoterVar {
    pub public_key: VoterPublicKeyVar,
    pub process_id: ProcessIdVar,
}
impl VoterVar {
    #[tracing::instrument(target = "r1cs", skip(self))]
    pub fn to_bytes_le(&self) -> Vec<UInt8<crate::ConstraintF>> {
        self.public_key
            .to_bytes()
            .unwrap()
            .into_iter()
            .chain(self.process_id.to_bytes_le())
            .collect()
    }
}

impl AllocVar<Voter, ConstraintF> for VoterVar {
    #[tracing::instrument(target = "r1cs", skip(cs, f, mode))]
    fn new_variable<T: Borrow<Voter>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|voter| {
            let voter = voter.borrow();
            let cs = cs.into();
            let public_key =
                VoterPublicKeyVar::new_variable(cs.clone(), || Ok(&voter.public_key), mode)?;
            let process_id =
                ProcessIdVar::new_variable(cs.clone(), || Ok(&voter.process_id), mode)?;
            Ok(Self {
                public_key,
                process_id,
            })
        })
    }
}
