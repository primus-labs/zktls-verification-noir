use dep::aztec::macros::aztec;
use dep::json_parser::JSON2kb;
#[aztec]
pub contract BusinessProgram {
    use dep::json_parser::JSON512b;
    use aztec::macros::functions::{external, initializer, internal};
    use aztec::macros::storage::storage;
    use aztec::protocol_types::{address::AztecAddress, hash::poseidon2_hash};
    use aztec::state_vars::{public_immutable::PublicImmutable, public_mutable::PublicMutable};
    use std::embedded_curve_ops::EmbeddedCurvePoint;

    global MAX_URL_LEN: u32 = 1024;
    global MAX_CONTENT_LEN: u32 = 1000;
    global MAX_MSGS_LEN: u32 = 100;

    #[storage]
    struct Storage<Context> {
        admin: PublicMutable<AztecAddress, Context>,
        allowed_url_hashes: PublicMutable<[Field; 3], Context>,
        H: PublicImmutable<EmbeddedCurvePoint, Context>,
    }

    #[external("public")]
    fn set_admin(new_admin: AztecAddress) {
        assert(storage.admin.read().eq(context.msg_sender().unwrap()), "caller is not admin");
        storage.admin.write(new_admin);
    }

    #[initializer]
    #[external("public")]
    fn constructor(admin: AztecAddress, allowed_url_hashes: [Field; 3], H: EmbeddedCurvePoint) {
        assert(!admin.is_zero(), "invalid admin");
        storage.admin.write(admin);
        storage.allowed_url_hashes.write(allowed_url_hashes);
        storage.H.initialize(H);
    }

    // TODO - allow update single url with index?
    #[external("public")]
    fn update_allowed_url_hashes(allowed_url_hashes: [Field; 3]) {
        assert(storage.admin.read().eq(context.msg_sender().unwrap()), "caller is not admin");
        storage.allowed_url_hashes.write(allowed_url_hashes);
    }

    #[external("public")]
    fn check_public_values(allowed_url_matches_hashes: [Field; 2], H: EmbeddedCurvePoint) {
        // Check allowed_url_matches_hashes are in storage
        let allowed_url_hashes: [Field; 3] = storage.allowed_url_hashes.read();
        for i in 0..2 {
            let check_hash = allowed_url_matches_hashes[i];
            let mut found = false;
            for j in 0..3 {
                if allowed_url_hashes[j] == check_hash {
                    found = true;
                }
            }
            assert(found);
        }

        // Check H equals the publicly known value
        let stored_H: EmbeddedCurvePoint = storage.H.read();
        assert(H == stored_H);
    }

    // Check H equals the publicly known value
    // do asserts on msgs
    #[external("private")]
    fn verify(
        msgs: BoundedVec<u8, MAX_MSGS_LEN>,
        H: EmbeddedCurvePoint,
        allowed_url_matches_hashes: [Field; 2],
    ) -> bool {
        // Check values
        let (trailing_stop_order, limit_order) = get_values(msgs);

        BusinessProgram::at(context.this_address())
            .check_public_values(allowed_url_matches_hashes, H)
            .enqueue(&mut context);

        true
    }

    #[contract_library_method]
    fn get_values(plaintext: BoundedVec<u8, MAX_MSGS_LEN>) -> (bool, bool) {
        let json = JSON512b::parse_bounded_vec_json(plaintext);

        // for attestation_data_gumpkin.json
        let key0: BoundedVec<u8, 17> = BoundedVec::from_array("trailingStopOrder".as_bytes());
        let trailing_stop_order = json.get_literal(key0).unwrap();

        let key1: BoundedVec<u8, 10> = BoundedVec::from_array("limitOrder".as_bytes());
        let limit_order = json.get_literal(key1).unwrap();

        (trailing_stop_order.to_bool(), limit_order.to_bool())
    }

    #[contract_library_method]
    unconstrained fn sanitize_ascii<let N: u32>(input: BoundedVec<u8, N>) -> BoundedVec<u8, N> {
        let mut clean = BoundedVec::<u8, N>::new();
        for i in 0..N {
            if i < input.len() {
                let b = input.get(i);
                // Keep only printable ASCII, else use '?'
                let valid = (b >= 32) & (b <= 126);
                let valid_f = valid as u8;
                let sanitized = b * valid_f + 63 * (1 - valid_f); // '?' = 63

                clean.push(sanitized);
            }
        }
        clean
    }

    #[contract_library_method]
    fn verify_sanitized_ascii(plaintext: BoundedVec<u8, 4096>, sanitized: BoundedVec<u8, 4096>) {
        assert(plaintext.len() == sanitized.len());
        for i in 0..4096 {
            if i < plaintext.len() {
                // plaintext.get(i) should be either equal to sanitized.get(i) or 63 (we intentionally replaced it)
                let b = plaintext.get(i);
                let s = sanitized.get(i);
                assert((b == s) | (s == 63));
            }
        }
    }

}
