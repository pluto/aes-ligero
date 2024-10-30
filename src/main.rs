use arithmetic_circuits::{arithmetic_circuit::ArithmeticCircuit, read_constraint_system};
use ark_circom::{CircomBuilder, CircomConfig};
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::path::Path;
use ark_bn254::Fr as FrBN;
use ligero::{DEFAULT_SECURITY_LEVEL, ligero::LigeroCircuit};


fn main() -> () {
    // Reading an R1CS computing a Poseidon hash of rate 3.
    let cs: ConstraintSystem<FrBN> = read_constraint_system(
        "../aes-gctr-fold.r1cs",
        "../aes-gctr-fold.wasm",
    );

    // Compiling into an ArithmeticCircuit and then a LigeroCircuit
    let (circuit, outputs) = ArithmeticCircuit::from_constraint_system(&cs);
    let ligero = LigeroCircuit::new(circuit, outputs, DEFAULT_SECURITY_LEVEL);

    // Loading a valid witness produced by circom
    let cs_witness: Vec<F> = serde_json::from_str::<Vec<String>>(
        &std::fs::read_to_string("circom/poseidon/witness.json").unwrap(),
    ).unwrap().iter().map(|s| FrBN::from_str(s).unwrap()).collect();

    // Skipping the initial 1 in the R1CS witness
    let var_assignment = cs_witness.into_iter().enumerate().skip(1).collect_vec();

    // Proof system setup
    let mut sponge: PoseidonSponge<Fr> = test_sponge();
    let mt_params = LigeroMTTestParams::new();

    // Proving and verifying
    let proof = ligero.prove(var_assignment, &mt_params, &mut sponge.clone());
    assert!(ligero.verify(proof, &mt_params, &mut sponge));
}
