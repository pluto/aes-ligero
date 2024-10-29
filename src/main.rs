use arithmatic_circuits::read_constraint_system;
use ark_circom::{CircomBuilder, CircomConfig};
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::path::Path;
use ark_bn254::Fr as FrBN;


fn main() {
    // Reading an R1CS computing a Poseidon hash of rate 3.
    let cs: ConstraintSystem<FrBN> = read_constraint_system(
        "../aes-gctr-fold.r1cs",
        "../aes-gctr-fold.wasm",
    );

    let cfg = CircomConfig::<FrBN>::new(wasm_file, r1cs_file).unwrap();

    let builder = CircomBuilder::new(cfg);
    let circom = builder.setup();

    let cs = ConstraintSystem::<FrBN>::new_ref();
    circom.generate_constraints(cs.clone()).unwrap();
    cs.into_inner().unwrap()
}
