use crate::ConstraintF;
use ark_crypto_primitives::signature::schnorr::{constraints::PublicKeyVar, PublicKey};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};
use ark_r1cs_std::bits::{uint32::UInt32, uint64::UInt64, ToBytesGadget};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};
use std::borrow::Borrow;

use ark_r1cs_std::fields::fp::FpVar;

// use the same hash than merkletree
use crate::{LeafHash, LeafHashGadget};
use ark_crypto_primitives::crh::{CRHGadget, CRH};

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

// WIP
// #[derive(Hash, Eq, PartialEq, Copy, Clone, Ord, PartialOrd, Debug)]
// pub struct Vote(pub u8);

////////
// Voter

#[derive(Hash, Eq, PartialEq, Copy, Clone, Ord, PartialOrd, Debug)]
pub struct ProcessId(pub u64);
impl ProcessId {
    pub fn to_bytes_le(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

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

pub type SecretKey = ConstraintF;
pub type SecretKeyVar = FpVar<ConstraintF>;

pub type VoterPublicKey = PublicKey<EdwardsProjective>;
pub type VoterPublicKeyVar = PublicKeyVar<EdwardsProjective, EdwardsVar>;

pub type VotingKey = <LeafHash as CRH>::Output;
pub type VotingKeyVar = <LeafHashGadget as CRHGadget<LeafHash, ConstraintF>>::OutputVar;
pub type Nullifier = <LeafHash as CRH>::Output;
pub type NullifierVar = <LeafHashGadget as CRHGadget<LeafHash, ConstraintF>>::OutputVar;

#[derive(Hash, Eq, PartialEq, Copy, Clone, Debug)]
pub struct Voter {
    pub sk: SecretKey,
    pub voting_key: VotingKey,
}

impl Voter {
    pub fn new(leaf_crh_params: &<LeafHash as CRH>::Parameters, sk: SecretKey) -> Voter {
        let voting_key: VotingKey =
            <LeafHash as CRH>::evaluate(leaf_crh_params, &ark_ff::to_bytes![sk].unwrap()).unwrap();

        Voter { sk, voting_key }
    }

    pub fn nullifier(
        &self,
        leaf_crh_params: &<LeafHash as CRH>::Parameters,
        process_id: ProcessId,
    ) -> Nullifier {
        let n: VotingKey = <LeafHash as CRH>::evaluate(
            leaf_crh_params,
            &ark_ff::to_bytes![self.sk, process_id.0.to_le_bytes()].unwrap(),
        )
        .unwrap();
        n
    }

    pub fn to_bytes_le(&self) -> Vec<u8> {
        ark_ff::to_bytes![self.voting_key].unwrap()
    }
}

#[derive(Clone)]
pub struct VoterVar {
    pub sk: SecretKeyVar,
    pub voting_key: VotingKeyVar,
}
impl VoterVar {
    #[tracing::instrument(target = "r1cs", skip(self))]
    pub fn to_bytes_le(&self) -> Vec<UInt8<crate::ConstraintF>> {
        self.voting_key.to_bytes().unwrap()
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
            let sk = FpVar::new_variable(cs.clone(), || Ok(voter.sk), mode)?;
            let voting_key = FpVar::new_variable(cs, || Ok(voter.voting_key), mode)?;

            Ok(Self { sk, voting_key })
        })
    }
}
