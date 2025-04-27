use std::sync::OnceLock;
use std::slice;
use std::os::raw::c_uchar;
use libc::size_t;
use ark_vrf::ring::{Prover, Verifier, RingCommitment};
use ark_vrf::reexports::ark_serialize::{self, CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::suites::bandersnatch;
use bandersnatch::{BandersnatchSha512Ell2, Input, Output, RingProofParams, RingProof, Public, Secret, PcsParams};

macro_rules! srs_file_path {
    () => {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/data/srs/bls12-381-srs-2-11-uncompressed-zcash.bin"
        )
    };
}

pub const RING_COMMITMENT_SIZE: usize = 144;
pub const PUBKEY_SIZE: usize = 32;
pub const SECRET_SIZE: usize = 32;
pub const RING_VRF_SIGNATURE_SIZE: usize = 784;
pub const OUTPUT_HASH_SIZE: usize = 32;

fn ring_size() -> usize {
    static RING_SIZE: OnceLock<usize> = OnceLock::new();
    // TODO: Make this ring size configurable from outer world (Golang size)
    // 1023 is current number of validators defined in Graypaper
    *RING_SIZE.get_or_init(|| 1023)
}

fn ring_proof_params() -> &'static RingProofParams {
    use std::sync::OnceLock;
    static PARAMS: OnceLock<RingProofParams> = OnceLock::new();
    PARAMS.get_or_init(|| {
        let buf: &[u8] = include_bytes!(srs_file_path!());
        let pcs_params =
            PcsParams::deserialize_uncompressed_unchecked(&mut &buf[..]).unwrap();
        RingProofParams::from_pcs_params(ring_size(), pcs_params)
            .unwrap()
    })
}

fn vrf_input_point(vrf_input_data: &[u8]) -> Input {
    Input::new(vrf_input_data).unwrap()
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct RingVrfSignature {
    output: Output,
    proof: RingProof,
}

#[no_mangle]
pub unsafe extern "C" fn new_secret_from_seed(
    seed_ptr: *const c_uchar,
    seed_len: size_t,
    secret_out_ptr: *mut c_uchar,
) -> bool {
    if seed_ptr.is_null() || secret_out_ptr.is_null() {
        return false;
    }

    let seed: &[u8] = slice::from_raw_parts(seed_ptr, seed_len as usize);
    let secret = Secret::from_seed(seed);
    let mut serialized = [0u8; SECRET_SIZE];
    match secret.serialize_compressed(&mut serialized[..]) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    std::ptr::copy_nonoverlapping(serialized.as_ptr(), secret_out_ptr, serialized.len());

    true
}

#[no_mangle]
pub unsafe extern "C" fn new_public_key_from_secret(
    secret_ptr: *const c_uchar,
    public_out_ptr: *mut c_uchar,
) -> bool {
    if secret_ptr.is_null() || public_out_ptr.is_null() {
        return false;
    }

    let secret: &[u8] = slice::from_raw_parts(secret_ptr, SECRET_SIZE);
    let secret = match Secret::deserialize_compressed(secret) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let public = secret.public();

    let mut serialized = [0u8; PUBKEY_SIZE];
    match public.serialize_compressed(&mut serialized[..]) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    std::ptr::copy_nonoverlapping(serialized.as_ptr(), public_out_ptr, serialized.len());

    true
}

#[no_mangle]
pub unsafe extern "C" fn new_ring_commitment(
    ring_ptr: *const [c_uchar; PUBKEY_SIZE],
    ring_len: size_t,
    commitment_out_ptr: *mut c_uchar,
) -> bool {
    if ring_ptr.is_null()
        || ring_len != ring_size()
        || commitment_out_ptr.is_null()
    {
        return false;
    }

    let ring_pubkeys: &[[u8; PUBKEY_SIZE]] = slice::from_raw_parts(ring_ptr, ring_len as usize);

    let padding_point = Public::from(RingProofParams::padding_point());
    let mut points = Vec::with_capacity(ring_pubkeys.len());
    for pubkey in ring_pubkeys.iter() {
        let point = match Public::deserialize_compressed(pubkey.as_slice()) {
            Ok(p) => p.0, // p.0 is type AffinePoint
            Err(_) => padding_point.0,
        };
        points.push(point);
    }

    let verifier_key = ring_proof_params().verifier_key(&points);
    let ring_commitment = verifier_key.commitment();

    let mut serialized = [0u8; RING_COMMITMENT_SIZE];
    match ring_commitment.serialize_compressed(&mut serialized[..]) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    std::ptr::copy_nonoverlapping(serialized.as_ptr(), commitment_out_ptr, serialized.len());

    true
}

#[no_mangle]
pub unsafe extern "C" fn ring_vrf_sign(
    ring_ptr: *const [c_uchar; PUBKEY_SIZE],
    ring_len: size_t,
    prover_idx: *const c_uchar,
    prover_secret_ptr: *const c_uchar,
    vrf_input_data_ptr: *const c_uchar,
    vrf_input_data_len: size_t,
    aux_data_ptr: *const c_uchar,
    aux_data_len: size_t,
    signature_out_ptr: *mut c_uchar,
) -> bool {
    if ring_ptr.is_null()
        || prover_idx.is_null()
        || prover_secret_ptr.is_null()
        || vrf_input_data_ptr.is_null()
        || aux_data_ptr.is_null()
        || signature_out_ptr.is_null()
    {
        return false;
    }

    if ring_len != ring_size() {
        return false;
    }

    let ring_pubkeys: &[[u8; PUBKEY_SIZE]] = slice::from_raw_parts(ring_ptr, ring_len as usize);
    let prover_idx = *prover_idx as usize;
    let prover_secret: &[u8] = slice::from_raw_parts(prover_secret_ptr, SECRET_SIZE);
    let prover_secret = match Secret::deserialize_compressed(prover_secret) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let vrf_input_data: &[u8] = slice::from_raw_parts(vrf_input_data_ptr, vrf_input_data_len as usize);
    let aux_data: &[u8] = slice::from_raw_parts(aux_data_ptr, aux_data_len as usize);

    let padding_point = Public::from(RingProofParams::padding_point());
    let mut points = Vec::with_capacity(ring_pubkeys.len());
    for pubkey in ring_pubkeys.iter() {
        let point = match Public::deserialize_compressed(pubkey.as_slice()) {
            Ok(p) => p.0, // p.0 is type AffinePoint
            Err(_) => padding_point.0,
        };
        points.push(point);
    }

    let input = vrf_input_point(vrf_input_data);
    let output = prover_secret.output(input);

    let params = ring_proof_params();
    let prover_key = params.prover_key(&points);
    let prover = params.prover(prover_key, prover_idx);
    let proof = prover_secret.prove(input, output, aux_data, &prover);

    let signature = RingVrfSignature { output, proof };

    let mut serialized = [0u8; RING_VRF_SIGNATURE_SIZE];
    match signature.serialize_compressed(&mut serialized[..]) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    std::ptr::copy_nonoverlapping(serialized.as_ptr(), signature_out_ptr, serialized.len());

    true
}

// Reference implementation
// https://github.com/davxy/bandersnatch-vrf-spec/blob/6b1ceba5b3cbc834201732bcdad1377e19e9283e/assets/example/src/main.rs#L143
#[no_mangle]
pub unsafe extern "C" fn ring_vrf_verify(
    vrf_input_data_ptr: *const c_uchar,
    vrf_input_data_len: size_t,
    aux_data_ptr: *const c_uchar,
    aux_data_len: size_t,
    ring_commitment_ptr: *const c_uchar,
    signature_ptr: *const c_uchar,
    output_hash_out_ptr: *mut c_uchar,
) -> bool {
    if vrf_input_data_ptr.is_null()
        || aux_data_ptr.is_null()
        || ring_commitment_ptr.is_null()
        || signature_ptr.is_null()
        || output_hash_out_ptr.is_null()
    {
        return false;
    }

    let (
        vrf_input_data,
        aux_data,
        ring_commitment,
        signature,
    ) = (
        slice::from_raw_parts(vrf_input_data_ptr, vrf_input_data_len as usize),
        slice::from_raw_parts(aux_data_ptr, aux_data_len as usize),
        slice::from_raw_parts(ring_commitment_ptr, RING_COMMITMENT_SIZE),
        slice::from_raw_parts(signature_ptr, RING_VRF_SIGNATURE_SIZE),
    );

    let ring_commitment = RingCommitment::<BandersnatchSha512Ell2>::deserialize_compressed(ring_commitment);
    if ring_commitment.is_err() {
        return false;
    }
    let ring_commitment = ring_commitment.unwrap();

    let signature = RingVrfSignature::deserialize_compressed(signature);
    if signature.is_err() {
        return false;
    }
    let signature = signature.unwrap();

    let input = vrf_input_point(vrf_input_data);
    let output = signature.output;

    let params = ring_proof_params();
    let verifier_key = params.verifier_key_from_commitment(ring_commitment);
    let verifier = params.verifier(verifier_key);
    if Public::verify(input, output, aux_data, &signature.proof, &verifier).is_err() {
        return false;
    }

    let mut output_hash = [0u8; OUTPUT_HASH_SIZE];
    output_hash.copy_from_slice(&output.hash()[..OUTPUT_HASH_SIZE]);

    std::ptr::copy_nonoverlapping(output_hash.as_ptr(), output_hash_out_ptr, output_hash.len());

    true
}
