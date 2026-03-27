use poseidon::poseidon2::Poseidon2;
use sha256::sha256_var;
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar,
    multi_scalar_mul,
};

global MAX_URL_LEN: u32 = 1024;

// -----------------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------------

// Verifies the secp256k1 signature and checks that each request URL starts with
// one of the allowed URLs. Returns the Poseidon2 hash of each matched allowed URL.
fn verify_sig_and_urls(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
) -> [Field; 2] {
    assert(std::ecdsa_secp256k1::verify_signature(public_key_x, public_key_y, signature, hash));

    let mut allowed_url_matches: [Field; 2] = [0; 2];
    for i in 0..2 {
        // Safety: find the allowed_url index unconstrained, then constrain it.
        let (found, url_index) = unsafe { get_allowed_url_index(request_urls[i], allowed_urls) };
        assert(found == true, "No allowed URL matches the request URL");
        let allowed_url = allowed_urls[url_index];
        for j in 0..MAX_URL_LEN {
            if j < allowed_url.len() {
                assert_eq(request_urls[i].storage()[j], allowed_url.storage()[j], "URL check failed");
            }
        }
        let mut hash_input: [Field; 1024] = [0; 1024];
        for j in 0..1024 {
            if j < allowed_url.len() {
                hash_input[j] = allowed_url.storage()[j] as Field;
            }
        }
        allowed_url_matches[i] = Poseidon2::hash(hash_input, 1024);
    }
    allowed_url_matches
}

// Verifies one keyName's commitment group via a batched MSM:
//   sum(msgs_chunks[i] * G + rnds[i] * H) == sum(coms[i])
// Call once per keyName to prevent cross-keyName swap attacks.
fn verify_commitment_group<let N: u32>(
    coms: BoundedVec<EmbeddedCurvePoint, N>,
    rnds: BoundedVec<Field, N>,
    msgs_chunks: BoundedVec<Field, N>,
    H: EmbeddedCurvePoint,
) {
    let G = EmbeddedCurvePoint::generator();
    let inf = EmbeddedCurvePoint::point_at_infinity();
    let zero_scalar = EmbeddedCurveScalar { lo: 0, hi: 0 };
    let one_scalar = EmbeddedCurveScalar { lo: 1, hi: 0 };
    let mut lhs_points: [EmbeddedCurvePoint; 2 * N] = [inf; 2 * N];
    let mut lhs_scalars: [EmbeddedCurveScalar; 2 * N] = [zero_scalar; 2 * N];
    let mut com_points: [EmbeddedCurvePoint; N] = [inf; N];
    let mut com_scalars: [EmbeddedCurveScalar; N] = [zero_scalar; N];

    for i in 0..N {
        if i < coms.len() {
            lhs_points[2 * i] = G;
            lhs_points[2 * i + 1] = H;
            lhs_scalars[2 * i] = EmbeddedCurveScalar::from_field(msgs_chunks.get(i));
            lhs_scalars[2 * i + 1] = EmbeddedCurveScalar::from_field(rnds.get(i));
            com_points[i] = coms.get(i);
            com_scalars[i] = one_scalar;
        }
    }

    assert(
        multi_scalar_mul(lhs_points, lhs_scalars) == multi_scalar_mul(com_points, com_scalars),
        "Commitment verification failed"
    );
}

// -----------------------------------------------------------------------------
// Public API - commitment-based (one variant per number of responseResolves)
// -----------------------------------------------------------------------------

pub fn verify_attestation_comm_1<let MAX_COMMS: u32>(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
    coms: BoundedVec<EmbeddedCurvePoint, MAX_COMMS>,
    rnds: BoundedVec<Field, MAX_COMMS>,
    msgs_chunks: BoundedVec<Field, MAX_COMMS>,
    H: EmbeddedCurvePoint,
) -> [Field; 2] {
    let allowed_url_matches = verify_sig_and_urls(
        public_key_x, public_key_y, hash, signature, request_urls, allowed_urls
    );
    verify_commitment_group(coms, rnds, msgs_chunks, H);
    allowed_url_matches
}

pub fn verify_attestation_comm_2<let MAX_COMMS_1: u32, let MAX_COMMS_2: u32>(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
    coms_1: BoundedVec<EmbeddedCurvePoint, MAX_COMMS_1>,
    rnds_1: BoundedVec<Field, MAX_COMMS_1>,
    msgs_chunks_1: BoundedVec<Field, MAX_COMMS_1>,
    coms_2: BoundedVec<EmbeddedCurvePoint, MAX_COMMS_2>,
    rnds_2: BoundedVec<Field, MAX_COMMS_2>,
    msgs_chunks_2: BoundedVec<Field, MAX_COMMS_2>,
    H: EmbeddedCurvePoint,
) -> [Field; 2] {
    let allowed_url_matches = verify_sig_and_urls(
        public_key_x, public_key_y, hash, signature, request_urls, allowed_urls
    );
    verify_commitment_group(coms_1, rnds_1, msgs_chunks_1, H);
    verify_commitment_group(coms_2, rnds_2, msgs_chunks_2, H);
    allowed_url_matches
}

pub fn verify_attestation_comm_3<let MAX_COMMS_1: u32, let MAX_COMMS_2: u32, let MAX_COMMS_3: u32>(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
    coms_1: BoundedVec<EmbeddedCurvePoint, MAX_COMMS_1>,
    rnds_1: BoundedVec<Field, MAX_COMMS_1>,
    msgs_chunks_1: BoundedVec<Field, MAX_COMMS_1>,
    coms_2: BoundedVec<EmbeddedCurvePoint, MAX_COMMS_2>,
    rnds_2: BoundedVec<Field, MAX_COMMS_2>,
    msgs_chunks_2: BoundedVec<Field, MAX_COMMS_2>,
    coms_3: BoundedVec<EmbeddedCurvePoint, MAX_COMMS_3>,
    rnds_3: BoundedVec<Field, MAX_COMMS_3>,
    msgs_chunks_3: BoundedVec<Field, MAX_COMMS_3>,
    H: EmbeddedCurvePoint,
) -> [Field; 2] {
    let allowed_url_matches = verify_sig_and_urls(
        public_key_x, public_key_y, hash, signature, request_urls, allowed_urls
    );
    verify_commitment_group(coms_1, rnds_1, msgs_chunks_1, H);
    verify_commitment_group(coms_2, rnds_2, msgs_chunks_2, H);
    verify_commitment_group(coms_3, rnds_3, msgs_chunks_3, H);
    allowed_url_matches
}

// -----------------------------------------------------------------------------
// Public API - hash-based
// -----------------------------------------------------------------------------

// N = number of responseResolves. Verifies sha256(contents[i]) == data_hashes[i] for each i.
pub fn verify_attestation_hashing<let N: u32, let MAX_CONTENT_LEN: u32>(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
    data_hashes: [[u8; 32]; N],
    contents: [BoundedVec<u8, MAX_CONTENT_LEN>; N],
) -> [Field; 2] {
    let allowed_url_matches = verify_sig_and_urls(
        public_key_x, public_key_y, hash, signature, request_urls, allowed_urls
    );
    for i in 0..N {
        let computed = sha256_var(contents[i].storage(), contents[i].len() as u64);
        assert(computed == data_hashes[i]);
    }
    allowed_url_matches
}

// -----------------------------------------------------------------------------
// Unconstrained URL helpers
// -----------------------------------------------------------------------------

unconstrained fn search(
    haystack: BoundedVec<u8, MAX_URL_LEN>,
    needle: BoundedVec<u8, MAX_URL_LEN>,
) -> (bool, u32) {
    let haystack_length: u32 = haystack.len();
    let needle_length: u32 = needle.len();
    assert(needle_length > 0, "needle length of size 0 not supported");
    assert(haystack_length > 0, "haystack length of size 0 not supported");
    let mut found = false;
    let mut found_index: u32 = 0;
    for i in 0..haystack_length - needle_length + 1 {
        if (found == true) {
            break;
        }
        for j in 0..needle_length {
            if haystack.get(i + j) != needle.get(j) {
                break;
            } else if (j == needle_length - 1) {
                found = true;
            }
            if (found == true) {
                found_index = i;
                break;
            }
        }
    }
    (found, found_index)
}

unconstrained fn get_allowed_url_index(
    request_url: BoundedVec<u8, MAX_URL_LEN>,
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
) -> (bool, u32) {
    let mut found = false;
    let mut index: u32 = 3050913689; // sentinel for "not found"
    for i in 0..allowed_urls.len() {
        let allowed_url = allowed_urls[i];
        if (allowed_url.len() <= request_url.len()) {
            let (result, match_position) = search(request_url, allowed_url);
            if result & (match_position == 0) & !found {
                found = true;
                index = i;
            }
        }
    }
    (found, index)
}
