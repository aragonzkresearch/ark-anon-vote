pub type ConstraintF = ark_bls12_381::Fr;

pub mod censustree;
use censustree::*;

pub mod voter;
use voter::*;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
