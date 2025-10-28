use dep::aztec::macros::aztec;
use dep::json_parser::JSON2kb;
#[aztec]
pub contract BusinessProgram {
    use dep::json_parser::JSON2kb;
    use aztec::macros::functions::{initializer, private, public};
    use aztec::macros::storage::storage;
    use aztec::protocol_types::{address::AztecAddress, hash::poseidon2_hash};
    use aztec::state_vars::{public_immutable::PublicImmutable, public_mutable::PublicMutable};

    global MAX_URL_LEN: u32 = 1024;
    global MAX_CONTENT_LEN: u32 = 1000;

    #[storage]
    struct Storage<Context> {
        admin: PublicMutable<AztecAddress, Context>,
        allowed_url_hashes: PublicMutable<[Field; 3], Context>,
    }

    #[public]
    fn set_admin(new_admin: AztecAddress) {
        assert(storage.admin.read().eq(context.msg_sender().unwrap()), "caller is not admin");
        storage.admin.write(new_admin);
    }

    #[public]
    #[initializer]
    fn constructor(admin: AztecAddress, allowed_url_hashes: [Field; 3]) {
        assert(!admin.is_zero(), "invalid admin");
        storage.admin.write(admin);
        storage.allowed_url_hashes.write(allowed_url_hashes);
    }

    // TODO - allow update single url with index?
    #[public]
    fn update_allowed_url_hashes(allowed_url_hashes: [Field; 3]) {
        assert(storage.admin.read().eq(context.msg_sender().unwrap()), "caller is not admin");
        storage.allowed_url_hashes.write(allowed_url_hashes);
    }

    #[public]
    fn check_allowed_url(allowed_url_matches_hashes: [Field; 2]) {
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
    }

    // gatecount 222.973 (versus 476.199), but note there are no assertions done on the values
    // Opcode count: 200841, Total gates by opcodes: 405505, Circuit size: 415536
    // json_paths.push("$.data[*].baseCcy"); is a string
    // json_paths.push("$.data[*].instIdCode"); is a number
    #[private]
    fn verify(
        plain_json_response: [BoundedVec<u8, MAX_CONTENT_LEN>; 2],
        allowed_url_matches_hashes: [Field; 2],
    ) -> bool {
        // Each of the plaintexts must be parsed to json
        for i in 0..2 {
            // Parse plaintext to JSON and obtain the custom values we want to check
            let (base_ccy, inst_id_code) = get_values(plain_json_response[i]);

            // TODO what to assert about base_ccy and inst_id_code
        }

        BusinessProgram::at(context.this_address())
            .check_allowed_url(allowed_url_matches_hashes)
            .enqueue(&mut context);

        true
    }

    #[contract_library_method]
    fn get_values(plaintext: BoundedVec<u8, MAX_CONTENT_LEN>) -> (BoundedVec<u8, 5>, u64) {
        // TODO is this needed?
        // // Safety: first sanitize the plaintext to ensure it is valid ASCII, then check this was done correctly
        // let sanitized = unsafe { sanitize_ascii(plaintext) };
        // // Uncommenting this check fails compilation
        // verify_sanitized_ascii(plaintext, sanitized);

        let json = JSON2kb::parse_bounded_vec_json(plaintext);

        let key0: BoundedVec<u8, 4> = BoundedVec::from_array("data".as_bytes());

        let data_array = json.get_array(key0).unwrap();
        let first_item: JSON2kb = data_array.get_object_from_array(0).unwrap();

        let key1: BoundedVec<u8, 7> = BoundedVec::from_array("baseCcy".as_bytes());
        let base_ccy: BoundedVec<u8, 5> = first_item.get_string_from_path([key1]).unwrap();

        let key2: BoundedVec<u8, 10> = BoundedVec::from_array("instIdCode".as_bytes());
        let inst_id_code: u64 = first_item.get_number(key2).unwrap();

        (base_ccy, inst_id_code)
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
