use dep::aztec::macros::aztec;

#[aztec]
pub contract BusinessProgram {
    use dep::json_parser::JSON8kb;
    use aztec::{
        macros::{functions::{initializer, private, public, utility}, storage::storage},
        oracle::debug_log::debug_log_format,
        protocol_types::{address::AztecAddress, traits::ToField},
        state_vars::Map,
    };

    // TODO review what must be constrained

    #[private]
    fn verify(plaintext: BoundedVec<u8, 4096>) -> bool {
        // parse the data and verify custom condition
        // Safety:
        let (screen_name, followers_count) = unsafe { get_values(plaintext) };

        // Assume the contract has some array of approved screen names, then we can do string_search check
        assert(screen_name == BoundedVec::from_array("primus_labs".as_bytes()));

        assert(followers_count >= 1000);

        true
    }

    #[contract_library_method]
    unconstrained fn get_values(plaintext: BoundedVec<u8, 4096>) -> (BoundedVec<u8, 50>, u64) {
        let sanitized = unsafe { sanitize_ascii(plaintext) };
        let json = unsafe { JSON8kb::parse_bounded_vec_json(sanitized) };

        let key0: BoundedVec<u8, 15> = BoundedVec::from_array("data".as_bytes());
        let key1: BoundedVec<u8, 15> = BoundedVec::from_array("user".as_bytes());
        let key2: BoundedVec<u8, 15> = BoundedVec::from_array("result".as_bytes());

        let keys: [BoundedVec<u8, 15>; 3] = [key0, key1, key2];

        let mut target = json;
        for i in 0..3 {
            let child = target.get_object(keys[i]);
            target = child.unwrap_unchecked();
        }
        let result_json = target;

        let key3: BoundedVec<u8, 15> = BoundedVec::from_array("core".as_bytes());
        let key4: BoundedVec<u8, 15> = BoundedVec::from_array("screen_name".as_bytes());
        // TODO add error handeling for unwrap
        let screen_name: BoundedVec<u8, 50> =
            result_json.get_string_from_path([key3, key4]).unwrap();

        // Retrieve number data.user.result.legacy.followers_count
        let key5: BoundedVec<u8, 15> = BoundedVec::from_array("legacy".as_bytes());
        let key6: BoundedVec<u8, 15> = BoundedVec::from_array("followers_count".as_bytes());

        let legacy_obj = result_json.get_object(key5).unwrap_unchecked();
        let followers_count = legacy_obj.get_number(key6).unwrap_unchecked();

        (screen_name, followers_count)
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

}
