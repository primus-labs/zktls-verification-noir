use dep::aztec::macros::aztec;

#[aztec]
pub contract BusinessProgram {
    use dep::json_parser::JSON1kb;
    use aztec::macros::functions::private;
    global MAX_CONTENT_LEN: u32 = 1000;

    // gatecount 222.973 (versus 476.199), but note there are no assertions done on the values
    // json_paths.push("$.data[*].baseCcy"); is a string
    // json_paths.push("$.data[*].instIdCode"); is a number
    #[private]
    fn verify(plain_json_response: [BoundedVec<u8, MAX_CONTENT_LEN>; 2]) -> bool {
        // Each of the plaintexts must be parsed to json
        for i in 0..2 {
            // Parse plaintext to JSON and obtain the custom values we want to check
            let (base_ccy, inst_id_code) = get_values(plain_json_response[i]);

            // TODO what to assert about base_ccy and inst_id_code
        }

        true
    }

    #[contract_library_method]
    fn get_values(plaintext: BoundedVec<u8, MAX_CONTENT_LEN>) -> (BoundedVec<u8, 5>, u64) {
        // TODO is this needed?
        // // Safety: first sanitize the plaintext to ensure it is valid ASCII, then check this was done correctly
        // let sanitized = unsafe { sanitize_ascii(plaintext) };
        // // Uncommenting this check fails compilation
        // verify_sanitized_ascii(plaintext, sanitized);

        let json = JSON1kb::parse_bounded_vec_json(plaintext);

        let key0: BoundedVec<u8, 4> = BoundedVec::from_array("data".as_bytes());

        let data_array = json.get_array(key0).unwrap();
        let first_item: JSON1kb = data_array.get_object_from_array(0).unwrap();

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
