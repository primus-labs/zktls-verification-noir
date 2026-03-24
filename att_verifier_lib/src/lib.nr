use poseidon::poseidon2::Poseidon2;
use sha256::sha256_var;
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar,
    multi_scalar_mul,
};

global MAX_URL_LEN: u32 = 1024;
global MAX_CONTENT_LEN: u32 = 1000;

pub fn verify_attestation_comm<let MAX_COMMS: u32>(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
    coms: BoundedVec<EmbeddedCurvePoint, MAX_COMMS>,
    rnds: BoundedVec<Field, MAX_COMMS>,
    msgs_chunks: BoundedVec<Field, MAX_COMMS>,
    H: EmbeddedCurvePoint, // G is fixed, H is fixed per business case
) -> [Field; 2] {
    // 1. Check signature
    assert(std::ecdsa_secp256k1::verify_signature(public_key_x, public_key_y, signature, hash));

    // 2. Check that the request_url starts with one of the allowed_urls
    let mut allowed_url_matches: [Field; 2] = [0; 2];
    for i in 0..2 {
        // Safety: Get the index of the url in allowed_urls that matches request_url (unconstrained) and then check it
        let (found, url_index) = unsafe { get_allowed_url_index(request_urls[i], allowed_urls) };
        assert(found == true, "No allowed URL matches the request URL");
        // Verify that the particular allowed_url is substring of the request_url
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

    let G = EmbeddedCurvePoint::generator();
    let inf = EmbeddedCurvePoint::point_at_infinity();
    let zero_scalar = EmbeddedCurveScalar { lo: 0, hi: 0 };
    let one_scalar = EmbeddedCurveScalar { lo: 1, hi: 0 };
    let mut lhs_points: [EmbeddedCurvePoint; 2 * MAX_COMMS] = [inf; 2 * MAX_COMMS];
    let mut lhs_scalars: [EmbeddedCurveScalar; 2 * MAX_COMMS] = [zero_scalar; 2 * MAX_COMMS];
    let mut com_points: [EmbeddedCurvePoint; MAX_COMMS] = [inf; MAX_COMMS];
    let mut com_scalars: [EmbeddedCurveScalar; MAX_COMMS] = [zero_scalar; MAX_COMMS];

    for i in 0..MAX_COMMS {
        if i < coms.len() {
            lhs_points[2 * i] = G;
            lhs_points[2 * i + 1] = H;
            lhs_scalars[2 * i] = EmbeddedCurveScalar::from_field(msgs_chunks.get(i));
            lhs_scalars[2 * i + 1] = EmbeddedCurveScalar::from_field(rnds.get(i));
            com_points[i] = coms.get(i);
            com_scalars[i] = one_scalar;
        }
    }

    assert(multi_scalar_mul(lhs_points, lhs_scalars) == multi_scalar_mul(com_points, com_scalars));

    allowed_url_matches
}

pub fn verify_attestation_hashing(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
    data_hashes: [[u8; 32]; 2],
    plain_json_response_contents: [BoundedVec<u8, MAX_CONTENT_LEN>; 2],
) -> [Field; 2] {
    // 1. Check signature
    assert(std::ecdsa_secp256k1::verify_signature(public_key_x, public_key_y, signature, hash));

    // 2. Check that the request_url starts with one of the allowed_urls
    let mut allowed_url_matches: [Field; 2] = [0; 2];
    for i in 0..2 {
        // Safety: Get the index of the url in allowed_urls that matches request_url (unconstrained) and then check it
        let (found, url_index) = unsafe { get_allowed_url_index(request_urls[i], allowed_urls) };
        assert(found == true, "No allowed URL matches the request URL");
        // Verify that the particular allowed_url is substring of the request_url
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

    // 3. Hash plain_json_responses and check with input hashes
    for i in 0..2 {
        let hash = sha256_var(
            plain_json_response_contents[i].storage(),
            plain_json_response_contents[i].len() as u64,
        );
        assert(hash == data_hashes[i]);
    }

    allowed_url_matches
}

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
    let mut index: u32 = 3050913689; // max u32 value to indicate "not found"
    for i in 0..allowed_urls.len() {
        let allowed_url = allowed_urls[i];
        if (allowed_url.len() <= request_url.len()) {
            let (result, match_position) = search(request_url, allowed_url);
            // If a valid result was already found we don't have to store again
            // (A valid result being that the match position is 0)
            if result & (match_position == 0) & !found {
                found = true;
                index = i;
            }
        }
    }
    (found, index)
}
