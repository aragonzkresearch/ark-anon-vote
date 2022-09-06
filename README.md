# ark-anon-vote [![Test](https://github.com/aragonzkresearch/ark-anon-vote/workflows/Test/badge.svg)](https://github.com/aragonzkresearch/ark-anon-vote/actions?query=workflow%3ATest) [![Clippy](https://github.com/aragonzkresearch/ark-anon-vote/workflows/Clippy/badge.svg)](https://github.com/aragonzkresearch/ark-anon-vote/actions?query=workflow%3AClippy)

Experimental implementation of onchain anonymous voting using [arkworks](https://arkworks.rs), following a similar design done in [vocdoni/zk-franchise-proof](https://github.com/vocdoni/zk-franchise-proof-circuit) and [aragonzkresearch/oav](https://github.com/aragonzkresearch/ovote/blob/main/circuits/src/oav.circom) (which are done in Circom).


## Scheme
The main idea is that users send their vote + zk-proof to the smart contract, proving that they belong to the census (without revealing who they are) and that their vote has not been already casted.

Each user generates a random *SecretKey*, and computes the corresponding *VotingKey* by hashing it.
The census creator adds all the *VotingKeys* as leafs in the census tree, obtaining the *CensusRoot*:

![](ark-anon-vote-censustree.png)

Each user computes a zk-proof which will be verified onchain, proving that they know a *SecretKey* corresponding to a *VotingKey* (without revealing any of both), which is placed in some *CensusTree* leaf (without revealing which one) under the *CensusRoot*. Also proves that their *SecretKey* hashed together with the *ProcessId* leads to the given *Nullifier*, in order to prevent proof reusability.

Constraints system (grey background indicates public inputs):

![](ark-anon-vote-constraints.png)

## Usage
Import this lib:
```
ark-anon-vote = { git = "https://github.com/aragonzkresearch/ark-anon-vote" }
```

```rust
use ark_anon_vote::*;

// set the process_id
let process_id: ProcessId = ConstraintF::from(1);
// set number of max voters
let n_voters = 10;

// each voter generate voter's data
let sk = ConstraintF::rand(&mut rng);
let voter = Voter::new(&leaf_crh_params, sk);
let nullifier = voter.nullifier(&leaf_crh_params, process_id);
let vote: Vote = ConstraintF::from(1);
// do this for each voter

// create the CensusTree
let height = ark_std::log2(n_voters);
let mut tree =
      CensusTree::blank(&leaf_crh_params, &two_to_one_crh_params, height as usize).unwrap();

// add each voter VotingKey to the CensusTree
tree.update(0, &voter.to_bytes_le()).unwrap();
// [...]

// get Census Root
let root = tree.root();

// prepare Voter's inputs
let circuit = AnonVote {
   parameters: Parameters {
       leaf_crh_params,
       two_to_one_crh_params,
   },
   root: Some(root),
   process_id: Some(process_id),
   nullifier: Some(nullifier),
   vote: Some(vote),
   sk: Some(sk),
   proof: Some(tree.generate_proof(0).unwrap()),
};

// generate the zk-proof
let proof = Groth16::prove(&pk, circuit, &mut rng).unwrap();

// prepare the public inputs
let public_input = [
   circuit.root.unwrap(),
   circuit.process_id.unwrap(),
   circuit.nullifier.unwrap(),
   circuit.vote.unwrap(),
];

// verify the zk-proof for the given VerificationKey and public inputs
let valid_proof = Groth16::verify(&vk, &public_input, &proof).unwrap();
assert!(valid_proof);
```
Check [src/lib.rs](https://github.com/aragonzkresearch/ark-anon-vote/blob/main/src/lib.rs) for more details.
