pub type ConstraintF = ark_bls12_381::Fr;

pub mod censustree;
use censustree::*;

pub mod voter;
use voter::*;

use std::borrow::Borrow;

// constraints
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError};

use ark_crypto_primitives::crh::{CRHGadget, TwoToOneCRH, CRH};

#[derive(Clone)]
pub struct Parameters {
    pub leaf_crh_params: <TwoToOneHash as CRH>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,
}
pub struct ParametersVar {
    pub leaf_crh_params: LeafHashParamsVar,
    pub two_to_one_crh_params: TwoToOneHashParamsVar,
}
impl AllocVar<Parameters, ConstraintF> for ParametersVar {
    #[tracing::instrument(target = "r1cs", skip(cs, f, _mode))]
    fn new_variable<T: Borrow<Parameters>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        f().and_then(|params| {
            let params: &Parameters = params.borrow();
            let leaf_crh_params =
                LeafHashParamsVar::new_constant(cs.clone(), &params.leaf_crh_params)?;
            let two_to_one_crh_params =
                TwoToOneHashParamsVar::new_constant(cs.clone(), &params.two_to_one_crh_params)?;
            Ok(Self {
                leaf_crh_params,
                two_to_one_crh_params,
            })
        })
    }
}

#[derive(Clone)]
pub struct AnonVote {
    pub parameters: Parameters,

    // public inputs
    pub root: Option<Root>,
    pub process_id: Option<ProcessId>,
    pub nullifier: Option<Nullifier>,
    pub vote: Option<u8>,

    // private inputs
    pub sk: Option<ConstraintF>,
    pub proof: Option<Proof>,
}

impl AnonVote {
    pub fn new_empty(parameters: Parameters) -> Self {
        Self {
            parameters,
            root: None,
            process_id: None,
            nullifier: None,
            vote: None,
            sk: None,
            proof: None,
        }
    }
}

impl ConstraintSynthesizer<ConstraintF> for AnonVote {
    #[tracing::instrument(target = "r1cs", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let parameters =
            ParametersVar::new_constant(ark_relations::ns!(cs, "parameters"), &self.parameters)?;

        // public inputs
        let root = RootVar::new_input(ark_relations::ns!(cs, "Root"), || {
            self.root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let process_id = ProcessIdVar::new_input(ark_relations::ns!(cs, "ProcessId"), || {
            self.process_id.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nullifier = NullifierVar::new_input(ark_relations::ns!(cs, "Nullifier"), || {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let proof = ProofVar::new_witness(ark_relations::ns!(cs, "Proof(path)"), || {
            self.proof.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let sk = SecretKeyVar::new_witness(ark_relations::ns!(cs, "SecretKey"), || {
            self.sk.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // TODO check vote value

        // check nullifier
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sk.to_bytes()?);
        hash_input.extend_from_slice(&process_id.to_bytes_le());
        let comp_nullifier = LeafHashGadget::evaluate(&parameters.leaf_crh_params, &hash_input)?;
        comp_nullifier.enforce_equal(&nullifier)?;

        // obtain voting_key from sk
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sk.to_bytes()?);
        let voting_key = LeafHashGadget::evaluate(&parameters.leaf_crh_params, &hash_input)?;

        // verify merkle proof
        proof
            .verify_membership(
                &parameters.leaf_crh_params,
                &parameters.two_to_one_crh_params,
                &root,
                &voting_key.to_bytes().unwrap().as_slice(),
            )?
            .enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::UniformRand;
    // use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    // use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn test_constraint_system() {
        let mut rng = ark_std::test_rng();
        let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

        let process_id: ProcessId = ProcessId(1);
        let n_voters = 10;
        // generate voters data
        let sk = ConstraintF::rand(&mut rng);

        let voter = Voter::new(&leaf_crh_params, sk);
        let nullifier = voter.nullifier(&leaf_crh_params, process_id);

        let vote = 0_u8.to_le_bytes();
        // TODO check vote validity

        let height = ark_std::log2(n_voters);
        let mut tree =
            CensusTree::blank(&leaf_crh_params, &two_to_one_crh_params, height as usize).unwrap();

        tree.update(0, &voter.to_bytes_le()).unwrap();

        let proof = tree.generate_proof(0).unwrap();
        let root = tree.root();

        // native proof verification
        assert!(proof
            .verify(
                &leaf_crh_params,
                &two_to_one_crh_params,
                &root,
                &voter.to_bytes_le()
            )
            .unwrap());

        // circuit verification
        let circuit = AnonVote {
            parameters: Parameters {
                leaf_crh_params,
                two_to_one_crh_params,
            },
            root: Some(root),
            process_id: Some(process_id),
            nullifier: Some(nullifier),
            vote: None,
            sk: Some(sk),
            proof: Some(proof),
        };

        // some boilerplate that helps with debugging
        // let mut layer = ConstraintLayer::default();
        // layer.mode = TracingMode::OnlyConstraints;
        // let subscriber = tracing_subscriber::Registry::default().with(layer);
        // let _guard = tracing::subscriber::set_default(subscriber);

        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(is_satisfied);
        println!(
            "n_voters={:?}, num_cnstraints={:?}",
            n_voters,
            cs.num_constraints()
        );
    }
}
