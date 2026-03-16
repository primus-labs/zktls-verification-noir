use poseidon::poseidon2::Poseidon2;
use sha256::sha256_var;
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};
use string_search::{StringBody, StringBody1024, SubString, SubString1024};

global MAX_URL_LEN: u32 = 1024;
global MAX_CONTENT_LEN: u32 = 1000;

/// Verify attestation using Poseidon2 digest binding (commitment approach).
///
/// Both URL matching and JSON parsing are performed off-chain by the attestation
/// service. The service computes a Poseidon2 digest over all attestation data
/// (including extracted values and URL hashes) and signs it with ECDSA.
///
/// The circuit verifies:
///   1. ECDSA signature over the Poseidon2 digest
///   2. Poseidon2 binding (all circuit inputs match the signed digest)
///   3. Pedersen commitment verification (G*m + H*r == C)
///
/// Security model:
///   - ECDSA proves the digest was produced by the trusted attestation service
///   - Poseidon2 binding proves all inputs (URL hashes, commitments, extracted
///     values) are exactly what the service signed -- no substitution possible
///   - On-chain public function verifies URL hashes are in the allowed set
///
/// DIGEST_LEN must equal 4 + MAX_COMMS * 5 + NUM_VALUES
pub fn verify_attestation_comm_poseidon<let MAX_COMMS: u32, let NUM_VALUES: u32, let DIGEST_LEN: u32>(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    allowed_url_matches_hashes: [Field; 2],
    coms: BoundedVec<EmbeddedCurvePoint, MAX_COMMS>,
    rnds: BoundedVec<Field, MAX_COMMS>,
    msgs_chunks: BoundedVec<Field, MAX_COMMS>,
    extracted_values: [Field; NUM_VALUES],
    H: EmbeddedCurvePoint,
) {
    // 1. Verify ECDSA signature over the Poseidon2 digest
    assert(std::ecdsa_secp256k1::verify_signature(public_key_x, public_key_y, signature, hash));

    // 2. Verify Poseidon2 binding: recompute digest and check it matches signed hash
    let computed_digest = compute_attestation_digest_comm::<MAX_COMMS, NUM_VALUES, DIGEST_LEN>(
        allowed_url_matches_hashes,
        coms,
        rnds,
        msgs_chunks,
        extracted_values,
    );

    // Convert signed hash (big-endian bytes) to Field for comparison
    let mut hash_as_field: Field = 0;
    for i in 0..32 {
        hash_as_field = hash_as_field * 256 + hash[i] as Field;
    }
    assert(computed_digest == hash_as_field, "Attestation data does not match signed digest");

    // 3. Verify commitments: C_i == G * m_i + H * r_i
    let G = EmbeddedCurvePoint::generator();
    for i in 0..MAX_COMMS {
        if i < coms.len() {
            assert(
                multi_scalar_mul(
                    [G, H],
                    [
                        EmbeddedCurveScalar::from_field(msgs_chunks.get(i)),
                        EmbeddedCurveScalar::from_field(rnds.get(i)),
                    ],
                )
                    == coms.get(i),
            );
        }
    }
}

/// Compute the Poseidon2 digest of attestation data (commitment approach).
///
/// Canonical serialization order:
///   [url_hash_0, url_hash_1, coms_len, coms...(x,y,inf), rnds..., msgs_chunks...,
///    num_values, extracted_values...]
///
/// The attestation service MUST use this exact serialization when computing the digest.
///
/// DIGEST_LEN must equal 4 + MAX_COMMS * 5 + NUM_VALUES
pub fn compute_attestation_digest_comm<let MAX_COMMS: u32, let NUM_VALUES: u32, let DIGEST_LEN: u32>(
    allowed_url_matches_hashes: [Field; 2],
    coms: BoundedVec<EmbeddedCurvePoint, MAX_COMMS>,
    rnds: BoundedVec<Field, MAX_COMMS>,
    msgs_chunks: BoundedVec<Field, MAX_COMMS>,
    extracted_values: [Field; NUM_VALUES],
) -> Field {
    let mut input: [Field; DIGEST_LEN] = [0; DIGEST_LEN];
    let mut idx: u32 = 0;

    // Allowed URL hashes (2 fields)
    input[idx] = allowed_url_matches_hashes[0];
    idx += 1;
    input[idx] = allowed_url_matches_hashes[1];
    idx += 1;

    // Commitments length + data
    input[idx] = coms.len() as Field;
    idx += 1;
    for i in 0..MAX_COMMS {
        let com = coms.get_unchecked(i);
        input[idx] = com.x;
        idx += 1;
        input[idx] = com.y;
        idx += 1;
        input[idx] = com.is_infinite as Field;
        idx += 1;
    }

    // Random scalars
    for i in 0..MAX_COMMS {
        input[idx] = rnds.get_unchecked(i);
        idx += 1;
    }

    // Message chunks
    for i in 0..MAX_COMMS {
        input[idx] = msgs_chunks.get_unchecked(i);
        idx += 1;
    }

    // Extracted values count + data
    input[idx] = NUM_VALUES as Field;
    idx += 1;
    for i in 0..NUM_VALUES {
        input[idx] = extracted_values[i];
        idx += 1;
    }

    Poseidon2::hash(input, DIGEST_LEN)
}

// =============================================================================
// Legacy functions (kept for backward compatibility)
// =============================================================================

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
    H: EmbeddedCurvePoint,
) -> [Field; 2] {
    assert(std::ecdsa_secp256k1::verify_signature(public_key_x, public_key_y, signature, hash));

    let mut allowed_url_matches: [Field; 2] = [0; 2];
    for i in 0..2 {
        // Safety: unconstrained hint for URL index, verified by substring_match below
        let (found, url_index) = unsafe { get_allowed_url_index(request_urls[i], allowed_urls) };
        assert(found == true, "No allowed URL matches the request URL");
        let request_url_haystack: StringBody1024 =
            StringBody::new(request_urls[i].storage(), request_urls[i].len());
        let allowed_url = allowed_urls[url_index];
        let needle: SubString1024 = SubString::new(allowed_url.storage(), allowed_url.len());

        let (result, match_position): (bool, u32) = request_url_haystack.substring_match(needle);
        assert(result & (match_position == 0), "URL check failed");
        let mut hash_input: [Field; 1024] = [0; 1024];
        for j in 0..1024 {
            if j < allowed_url.len() {
                hash_input[j] = allowed_url.storage()[j] as Field;
            }
        }
        allowed_url_matches[i] = Poseidon2::hash(hash_input, 1024);
    }

    let G = EmbeddedCurvePoint::generator();
    for i in 0..MAX_COMMS {
        if i < coms.len() {
            assert(
                multi_scalar_mul(
                    [G, H],
                    [
                        EmbeddedCurveScalar::from_field(msgs_chunks.get(i)),
                        EmbeddedCurveScalar::from_field(rnds.get(i)),
                    ],
                )
                    == coms.get(i),
            );
        }
    }

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
    assert(std::ecdsa_secp256k1::verify_signature(public_key_x, public_key_y, signature, hash));

    let mut allowed_url_matches: [Field; 2] = [0; 2];
    for i in 0..2 {
        // Safety: unconstrained hint for URL index, verified by substring_match below
        let (found, url_index) = unsafe { get_allowed_url_index(request_urls[i], allowed_urls) };
        assert(found == true, "No allowed URL matches the request URL");
        let request_url_haystack: StringBody1024 =
            StringBody::new(request_urls[i].storage(), request_urls[i].len());
        let allowed_url = allowed_urls[url_index];
        let needle: SubString1024 = SubString::new(allowed_url.storage(), allowed_url.len());

        let (result, match_position): (bool, u32) = request_url_haystack.substring_match(needle);
        assert(result & (match_position == 0), "URL check failed");
        let mut hash_input: [Field; 1024] = [0; 1024];
        for j in 0..1024 {
            if j < allowed_url.len() {
                hash_input[j] = allowed_url.storage()[j] as Field;
            }
        }
        allowed_url_matches[i] = Poseidon2::hash(hash_input, 1024);
    }

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
    let mut index: u32 = 3050913689;
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
