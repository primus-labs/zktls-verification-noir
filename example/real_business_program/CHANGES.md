# Redesign: Poseidon2 Digest Binding for Aztec v4 Compatibility

## Problem

After upgrading from Aztec v3.0.0-devnet.5 to v4.0.0-devnet.2-patch.1, the
`verify_comm` private function's gate count increased from 711,763 to 3,907,426
-- exceeding the ClientIVC limit of 2^21 (2,097,152) gates and causing proof
generation to fail.

The two largest contributors to the gate count were:

1. **JSON parsing in-circuit (93% of gates):** The `JSON2055` parser operating
   on 2,054-byte messages accounted for ~3.5M of the 3.9M gates. The parser's
   internal data structures generate massive numbers of RAM/ROM memory
   operations in the compiled circuit.

2. **Large function parameters (memory overhead):** The function accepted
   ~7,672 serialized field elements as parameters, including raw URL arrays
   (`[BoundedVec<u8, 1024>; 2]` and `[BoundedVec<u8, 1024>; 3]`) and raw
   message bytes (`BoundedVec<u8, 2054>`). Each field contributes to memory
   gate overhead through args hashing and BoundedVec access patterns.

### Root cause in the Noir compiler

Between Noir 1.0.0-beta.15 (used by Aztec v3) and 1.0.0-beta.18 (used by
Aztec v4), two optimization passes were removed from the ACIR pipeline:

- `bounded-codegen` feature removal (noir-lang/noir#10693): expressions are no
  longer width-bounded during ACIR generation
- ACIR transformation removal (noir-lang/noir#10561): the compilation step no
  longer decomposes expressions to fit the backend's gate width

These changes caused the same circuit logic to produce significantly more gates
under the new compiler, with memory operations being the dominant cost.

## Solution

Redesign the circuit to move URL matching and JSON parsing off-chain to the
attestation service, using a Poseidon2 digest binding to maintain cryptographic
soundness.

### Architecture

**Attestation service (off-chain):**

1. Observes the TLS session, captures request URLs and API response
2. Performs URL prefix matching against allowed URLs
3. Computes Poseidon2 hashes of matched allowed URLs
4. Parses JSON response and extracts business-relevant values
5. Computes Pedersen commitments over response data chunks
6. Serializes all data into a canonical field array and computes
   `digest = Poseidon2(serialized_fields)`
7. Signs `digest_as_bytes` with ECDSA secp256k1

**Circuit (on-chain verification):**

1. Verifies ECDSA signature over the Poseidon2 digest
2. Recomputes `Poseidon2(all_inputs)` and asserts it matches the signed digest
   -- this cryptographically binds every circuit input to the attestation
3. Verifies Pedersen commitments: `G * m_i + H * r_i == C_i`
4. Application-specific assertions on the extracted values
5. Enqueues a public function that checks URL hashes against on-chain storage

### Security model

- **ECDSA signature** proves the digest was produced by the trusted attestation
  service
- **Poseidon2 binding** proves all circuit inputs (URL hashes, commitments,
  extracted values) are exactly what the service signed -- a prover cannot
  substitute any value without invalidating the digest
- **On-chain storage check** proves the URL hashes correspond to approved API
  endpoints
- **Commitment verification** proves the response data chunks are consistent
  with the committed values

This is strictly stronger than the previous design, which verified URL matching
and commitments in-circuit but had no cryptographic binding between the ECDSA-
signed hash and the other circuit inputs.

## Changes

### att_verifier_lib/src/lib.nr

- Added `verify_attestation_comm_poseidon`: new verification function that
  checks ECDSA signature, Poseidon2 digest binding, and Pedersen commitments
- Added `compute_attestation_digest_comm`: canonical serialization and Poseidon2
  hashing of all attestation data (public, so the attestation service can
  replicate the exact same computation)
- Optimized the commitment verification loop from 3 EC operations per iteration
  (`fixed_base_scalar_mul` + `multi_scalar_mul` + `embedded_curve_add`) to a
  single `multi_scalar_mul([G, H], [msg_scalar, rnd_scalar])`, following the
  Noir stdlib recommendation
- Fixed deprecated `dep::poseidon` import path
- Legacy functions retained for backward compatibility

### example/real_business_program/src/main.nr

- Rewrote `verify_comm` to use Poseidon2 digest binding
- Replaced `request_urls` and `allowed_urls` parameters (~5,125 fields) with
  `allowed_url_matches_hashes: [Field; 2]`
- Replaced `msgs: BoundedVec<u8, 2054>` (~2,055 fields) with
  `extracted_values: [Field; 6]`
- Removed in-circuit JSON parsing (`JSON2055`, `JSON2kb`) and URL string
  matching (`string_search`)
- Removed `verify_hash` function (can be reimplemented with the same Poseidon2
  pattern if needed)
- Removed `check_urls_emit_event` (consolidated into `check_values_emit_event`)

## Results

| Metric                  | Before (v4, original) | After (v4, redesign) |
|-------------------------|-----------------------|----------------------|
| Function parameters     | ~7,672 fields         | ~496 fields          |
| ACIR opcodes            | 701,405               | 6,004                |
| **Circuit gate count**  | **3,907,426**         | **152,135**          |
| Fits ClientIVC (2^21)?  | No                    | Yes                  |

Gate breakdown (after):

| Gate type     | Count   | Share  |
|---------------|---------|--------|
| arithmetic    | 57,275  | 37.6%  |
| elliptic      | 26,912  | 17.7%  |
| memory        | 21,922  | 14.4%  |
| poseidon int  | 16,190  | 10.6%  |
| delta range   | 14,942  |  9.8%  |
| nnf           | 11,007  |  7.2%  |
| poseidon ext  |  2,842  |  1.9%  |
| **Total**     |**152,135**|       |

## Required changes to the attestation service

The Primus attestation service must be updated to:

1. Compute Poseidon2 hashes of allowed URLs (instead of or in addition to the
   existing URL handling)
2. Extract JSON values off-chain and encode them as field elements
3. Serialize all attestation data using the canonical format defined in
   `compute_attestation_digest_comm`
4. Compute the Poseidon2 digest of the serialized data
5. Sign the digest (as 32 big-endian bytes) with ECDSA secp256k1

The canonical serialization order is documented in `att_verifier_lib/src/lib.nr`
and must be replicated exactly by the attestation service.

## Notes

- The `json_parser` dependency in `real_business_program/Nargo.toml` is no
  longer used and can be removed
- The `string_search`, `sha256`, and legacy URL matching code in
  `att_verifier_lib` are retained for backward compatibility but are not used by
  the new `verify_comm` function
- `NUM_VALUES` (currently 6) is application-specific and should match the number
  of values the attestation service extracts from the JSON response
- All gate counts measured using `bb gates --scheme chonk` (MegaCircuitBuilder)
  which matches the Aztec ClientIVC proving system
