pub type ConstraintF = ark_bls12_381::Fr;

pub mod anonvote;
pub mod censustree;
pub mod voter;

use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

use ark_std::marker::PhantomData;

pub struct AnonVote<S> {
    _snark: PhantomData<S>, // WIP
    parameters: anonvote::Parameters,
}

impl<S: SNARK<ConstraintF>> AnonVote<S> {
    pub fn new(parameters: anonvote::Parameters) -> Self {
        Self {
            _snark: PhantomData,
            parameters,
        }
    }
    pub fn new_process_id(&self, pid: u16) -> voter::ProcessId {
        ConstraintF::from(pid)
    }
    pub fn new_voter<R: CryptoRng + RngCore>(&self, rng: &mut R) -> voter::Voter {
        // TODO determine which rng to use: Rng, RngCore, CryptoRng (also in the other methods)
        voter::Voter::new(&self.parameters.leaf_crh_params, rng)
    }
    pub fn new_vote(&self, v: u8) -> voter::Vote {
        ConstraintF::from(v)
    }
    pub fn new_censustree(
        &self,
        n_voters: usize,
    ) -> Result<censustree::CensusTree, censustree::Error> {
        let height = ark_std::log2(n_voters) as usize;
        censustree::CensusTree::blank(
            &self.parameters.leaf_crh_params,
            &self.parameters.two_to_one_crh_params,
            height,
        )
    }
    pub fn new_circuit_instance(
        self,
        root: censustree::Root,
        process_id: voter::ProcessId,
        nullifier: voter::Nullifier,
        vote: voter::Vote,
        sk: voter::SecretKey,
        proof: censustree::Proof,
    ) -> anonvote::AnonVoteCircuit {
        anonvote::AnonVoteCircuit {
            parameters: anonvote::Parameters {
                leaf_crh_params: self.parameters.leaf_crh_params,
                two_to_one_crh_params: self.parameters.two_to_one_crh_params,
            },
            root: Some(root),
            process_id: Some(process_id),
            nullifier: Some(nullifier),
            vote: Some(vote),
            sk: Some(sk),
            proof: Some(proof),
        }
    }
}

impl<S: SNARK<ConstraintF>> AnonVote<S> {
    pub fn circuit_setup<R: CryptoRng + RngCore>(
        rng: &mut R,
        circuit: anonvote::AnonVoteCircuit,
    ) -> Result<(S::ProvingKey, S::VerifyingKey), S::Error> {
        S::circuit_specific_setup(circuit, rng)
    }

    pub fn prove<R: CryptoRng + RngCore>(
        rng: &mut R,
        pk: S::ProvingKey,
        circuit: anonvote::AnonVoteCircuit,
    ) -> Result<S::Proof, S::Error> {
        S::prove(&pk, circuit, rng)
    }

    pub fn verify(
        vk: S::VerifyingKey,
        proof: S::Proof,
        public_input: Vec<ConstraintF>,
    ) -> Result<bool, S::Error> {
        S::verify(&vk, &public_input, &proof)
    }
}

#[cfg(test)]
mod test {
    use super::{
        anonvote::Parameters,
        voter::{ProcessId, Vote},
        AnonVote,
    };
    use ark_bls12_381::Bls12_381;
    use ark_groth16::Groth16;

    #[test]
    fn test_client_flow() {
        let mut rng = ark_std::test_rng();
        let parameters = Parameters::init(&mut rng);

        let av = AnonVote::<Groth16<Bls12_381>>::new(parameters.clone());
        let process_id: ProcessId = av.new_process_id(1 as u16);

        // client side
        let voter = av.new_voter(&mut rng);
        let nullifier = voter.nullifier(process_id);
        let vote: Vote = av.new_vote(1 as u8);

        // census creator side
        let n_voters: usize = 10;
        let mut census = av.new_censustree(n_voters).unwrap();

        // add voters to the census
        census.update(0, &voter.to_bytes_le()).unwrap();
        let censusproof = census.generate_proof(0).unwrap();
        let root = census.root();

        let circuit =
            av.new_circuit_instance(root, process_id, nullifier, vote, voter.sk, censusproof);

        let (pk, vk) =
            AnonVote::<Groth16<Bls12_381>>::circuit_setup(&mut rng, circuit.clone()).unwrap();
        let proof = AnonVote::<Groth16<Bls12_381>>::prove(&mut rng, pk, circuit.clone()).unwrap();

        let pub_inputs = circuit.public_inputs();

        let valid_proof = AnonVote::<Groth16<Bls12_381>>::verify(vk, proof, pub_inputs).unwrap();
        assert!(valid_proof);
    }
}
