use dep::aztec::macros::aztec;

#[aztec]
pub contract AttVerifier {
    use aztec::{
        macros::{functions::{initializer, private, public, utility}, storage::storage},
        protocol_types::address::AztecAddress,
    };
    use business_program::BusinessProgram;
    use string_search::{StringBody, StringBody1024, SubString, SubString1024};

    global MAX_URL_LEN: u32 = 1024;

    #[private]
    fn verify_attestation(
        public_key_x: [u8; 32],
        public_key_y: [u8; 32],
        hash: [u8; 32],
        signature: [u8; 64],
        request_url: BoundedVec<u8, MAX_URL_LEN>,
        // Compilation fails for BoundedVec<BoundedVec<u8, 1400>, 10>
        // It passes for BoundedVec<BoundedVec<u8, 1400>, 4>
        // In this approach; pack the ciphertexts together and pass the exact lengths of each ciphertext separately
        ciphertexts: [u8; 7000],
        ciphertext_lengths: BoundedVec<u32, 10>,
        address: AztecAddress,
    ) -> bool {
        // TODO allowed URLS can be set in the contract storage?
        let allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 4] = [
            BoundedVec::from_array(
                "https://x.com/i/api/graphql/96tVxbPqMZDoYB5pmzezKA/UserByScreenName".as_bytes(),
            ),
            BoundedVec::from_array("https://github.com".as_bytes()),
            BoundedVec::from_array("https://x.com".as_bytes()),
            BoundedVec::from_array("https://primuslabs.xyz".as_bytes()),
        ];
        // 1. Check signature
        assert(std::ecdsa_secp256k1::verify_signature(public_key_x, public_key_y, signature, hash));

        // 2. Check that the request_url starts with one of the allowed_urls
        // Safety: First, obtain the index of the url in allowed_urls that matches request_url (unconstrained)
        let (found, url_index) = unsafe { get_allowed_url_index(request_url, allowed_urls) };
        assert(found == true, "No allowed URL matches the request URL");
        // Then, prove that it indeed matches
        let request_url_haystack: StringBody1024 =
            StringBody::new(request_url.storage(), request_url.len());
        let allowed_url = allowed_urls[url_index];
        let needle: SubString1024 = SubString::new(allowed_url.storage(), allowed_url.len());

        let (result, match_position): (bool, u32) = request_url_haystack.substring_match(needle);

        // A match result is only valid if the match position is 0 (i.e., the allowed_url is a prefix of request_url)
        assert(result & (match_position == 0), "URL check failed");

        // TODO add missing input arguments
        // TODO decrypt ciphertexts

        let plaintext = BoundedVec::<u8, 1024>::from_array([0u8; 1024]);

        BusinessProgram::at(address).verify(plaintext).call(&mut context);
    }

    #[utility]
    unconstrained fn get_allowed_url_index(
        request_url: BoundedVec<u8, MAX_URL_LEN>,
        allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 4], // TODO this probably shouldn't have a fixed len
    ) -> (bool, u32) {
        let mut found = false;
        let mut index: u32 = 3050913689; // max u32 value to indicate "not found"
        for i in 0..allowed_urls.len() {
            let allowed_url = allowed_urls[i];
            let (result, match_position) = search(request_url, allowed_url);
            // If a valid result was already found we don't have to store again
            // (A valid result being that the match position is 0)
            if result & (match_position == 0) & !found {
                found = true;
                index = i;
            }
        }
        (found, index)
    }

    // Adapted version of library function, which doesn't assert found to be true
    // https://github.com/noir-lang/noir_string_search/blob/v0.3.3/src/utils.nr#L1-L29
    #[utility]
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

    // #[private]
    // fn sig_verfier(
    //     public_key_x: [u8; 32],
    //     public_key_y: [u8; 32],
    //     hash: [u8; 32],
    //     sig: [u8; 64],
    // ) -> bool {
    //     std::ecdsa_secp256k1::verify_signature(public_key_x, public_key_y, sig, hash)
    // }

    // #[private]
    // fn check_allowed_url() -> bool {
    //     true
    // }

    // #[private]
    // fn decrypt_and_check(ct: BoundedVec<u8, 1024>, address: AztecAddress) -> bool {
    //     let plaintext = BoundedVec::<u8, 1024>::from_array([
    //         72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10, 67, 111, 110, 116,
    //         101, 110, 116, 45, 84, 121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105,
    //         111, 110, 47, 106, 115, 111, 110, 13, 10, 84, 114, 97, 110, 115, 102, 101, 114, 45, 69,
    //         110, 99, 111, 100, 105, 110, 103, 58, 32, 99, 104, 117, 110, 107, 101, 100, 13, 10, 13,
    //         10, 57, 54, 13, 10, 91, 10, 32, 32, 32, 32, 123, 10, 32, 32, 32, 32, 32, 32, 34, 97,
    //         115, 115, 101, 116, 34, 58, 32, 34, 66, 84, 67, 34, 44, 10, 32, 32, 32, 32, 32, 32, 34,
    //         102, 114, 101, 101, 34, 58, 32, 34, 49, 49, 46, 56, 48, 48, 51, 50, 57, 53, 50, 34, 44,
    //         10, 32, 32, 32, 32, 32, 32, 34, 108, 111, 99, 107, 101, 100, 34, 58, 32, 34, 48, 46, 53,
    //         34, 44, 10, 32, 32, 32, 32, 32, 32, 34, 102, 114, 101, 101, 122, 101, 34, 58, 32, 34,
    //         57, 46, 51, 34, 44, 10, 32, 32, 32, 32, 32, 32, 34, 119, 105, 116, 104, 100, 114, 97,
    //         119, 105, 110, 103, 34, 58, 32, 34, 48, 46, 48, 51, 34, 44, 10, 32, 32, 32, 32, 32, 32,
    //         34, 105, 112, 111, 97, 98, 108, 101, 34, 58, 13, 10,
    //     ]);
    //     BusinessProgram::at(address).verify(plaintext).call(&mut context);
    // }
}
