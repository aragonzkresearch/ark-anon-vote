use crate::ConstraintF;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};
use std::borrow::Borrow;

use ark_r1cs_std::fields::fp::FpVar;

// use the same hash than merkletree
use crate::{LeafHash, LeafHashGadget};
use ark_crypto_primitives::crh::{CRHGadget, CRH};

pub type ProcessId = ConstraintF;
pub type ProcessIdVar = FpVar<ConstraintF>;

pub type SecretKey = ConstraintF;
pub type SecretKeyVar = FpVar<ConstraintF>;

pub type Vote = ConstraintF;
pub type VoteVar = FpVar<ConstraintF>;

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
            &ark_ff::to_bytes![self.sk, process_id].unwrap(),
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
