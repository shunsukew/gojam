use ark_vrf::reexports::ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::suites::bandersnatch;
use bandersnatch::{RingProofParams, Public, PcsParams};
use std::sync::OnceLock;
use std::slice;
use std::os::raw::{c_uint, c_uchar};

macro_rules! srs_file_path {
    () => {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/data/srs/bls12-381-srs-2-11-uncompressed-zcash.bin"
        )
    };
}

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

#[no_mangle]
pub extern "C" fn new_ring_verifier_commitment(
    pubkeys_ptr: *const [c_uchar; 32],
    pubkeys_len: c_uint,
    out_ptr: *mut c_uchar,
) -> bool {
    let pubkeys: &[[u8; 32]] = unsafe { slice::from_raw_parts(pubkeys_ptr, pubkeys_len as usize) };

    let mut points = Vec::with_capacity(pubkeys.len());
    for pubkey in pubkeys.iter() {
        let point = match Public::deserialize_compressed(pubkey.as_slice()) {
            Ok(p) => p.0, // p.0 is type AffinePoint
            Err(_) => return false,
        };
        points.push(point);
    }

    let verifier_key = ring_proof_params().verifier_key(&points);
    let commitment = verifier_key.commitment();

    let mut serialized = [0u8; 144];
    match commitment.serialize_compressed(&mut serialized[..]) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    unsafe {
        std::ptr::copy_nonoverlapping(serialized.as_ptr(), out_ptr, serialized.len());
    }

    true
}
