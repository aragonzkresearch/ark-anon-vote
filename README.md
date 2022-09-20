# ark-anon-vote [![Test](https://github.com/aragonzkresearch/ark-anon-vote/workflows/Test/badge.svg)](https://github.com/aragonzkresearch/ark-anon-vote/actions?query=workflow%3ATest) [![Clippy](https://github.com/aragonzkresearch/ark-anon-vote/workflows/Clippy/badge.svg)](https://github.com/aragonzkresearch/ark-anon-vote/actions?query=workflow%3AClippy)

Experimental implementation of onchain anonymous voting using [arkworks](https://github.com/arkworks-rs), following a similar design done in [vocdoni/zk-franchise-proof](https://github.com/vocdoni/zk-franchise-proof-circuit) and [aragonzkresearch/oav](https://github.com/aragonzkresearch/ovote/blob/main/circuits/src/oav.circom) (which are done in Circom).


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

let parameters = Parameters::init(&mut rng);
let av = AnonVote::<Groth16<Bls12_381>>::new(parameters.clone());

// set the process_id
let process_id: ProcessId = av.new_process_id(1 as u16);
// set number of max voters
let n_voters = 10;

// each voter generate voter's data
let voter = av.new_voter(&mut rng);
let nullifier = voter.nullifier(process_id);
let vote: Vote = av.new_vote(1 as u8);
// do this for each voter

// create the CensusTree
let mut census = av.new_censustree(n_voters).unwrap();

// add each voter VotingKey to the CensusTree
tree.update(0, &voter.to_bytes_le()).unwrap();
// [...]

// get Census Root
let root = tree.root();
// get user's census proof (merkletree membership proof)
let censusproof = census.generate_proof(0).unwrap();

// prepare Voter's inputs
let circuit =
   av.new_circuit_instance(root, process_id, nullifier, vote, voter.sk, censusproof);
   
// generate circuit setup
let (pk, vk) =
   AnonVote::<Groth16<Bls12_381>>::circuit_setup(&mut rng, circuit.clone()).unwrap();

// generate the zk-proof
let proof = AnonVote::<Groth16<Bls12_381>>::prove(&mut rng, pk, circuit.clone()).unwrap();

// prepare the public inputs
let pub_inputs = circuit.public_inputs();

// verify the zk-proof for the given VerificationKey and public inputs
let valid_proof = AnonVote::<Groth16<Bls12_381>>::verify(vk, proof, pub_inputs).unwrap();
assert!(valid_proof);
```

Check [src/lib.rs](https://github.com/aragonzkresearch/ark-anon-vote/blob/main/src/lib.rs) for more details.
