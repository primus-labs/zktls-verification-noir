mod aes;
use dep::aztec::macros::aztec;

#[aztec]
pub contract PartialAttVerifier {

    use crate::aes::{aes_decrypt_opt_slot800, BlockInfo};
    use aztec::{
        event::event_interface::emit_event_in_public,
        macros::{events::event, functions::{internal, private, public}},
        protocol_types::address::AztecAddress,
    };
    use business_program::BusinessProgram;
    use string_search::{StringBody, StringBody1024, SubString, SubString1024};

    global MAX_URL_LEN: u32 = 1024;

    //Emitted public log limit: 13 fields
    #[event]
    struct SuccessEvent {
        sender: AztecAddress,
        att_verifier_address: AztecAddress,
        business_logic_address: AztecAddress,
        id: Field,
    }

    #[private]
    fn verify_partial_attestation(
        public_key_x: [u8; 32],
        public_key_y: [u8; 32],
        hash: [u8; 32],
        signature: [u8; 64],
        request_url: BoundedVec<u8, MAX_URL_LEN>,
        ciphertexts: [[u8; 800]; 4], // empty ciphertexts should be padded 0
        number_of_ciphertexts: u32,
        blocks: [BlockInfo; 50], // TODO - current max block length is 50 -> max ciphertext length is 50*16 bytes
        blocks_len: u32,
        nonce: [[u8; 12]; 4],
        aes_key: [u8; 16],
        business_logic_address: AztecAddress,
        id: Field, // id for this attestation
    ) -> bool {
        assert(blocks_len <= 50, "blocks_len exceeds max len of 50");
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
        // Safety: Get the index of the url in allowed_urls that matches request_url (unconstrained) and then check it
        let (found, url_index) = unsafe { get_allowed_url_index(request_url, allowed_urls) };
        assert(found == true, "No allowed URL matches the request URL");
        let request_url_haystack: StringBody1024 =
            StringBody::new(request_url.storage(), request_url.len());
        let allowed_url = allowed_urls[url_index];
        let needle: SubString1024 = SubString::new(allowed_url.storage(), allowed_url.len());

        let (result, match_position): (bool, u32) = request_url_haystack.substring_match(needle);

        // A match result is only valid if the match position is 0 (i.e., the allowed_url is a prefix of request_url)
        assert(result & (match_position == 0), "URL check failed");

        // 3. Obtain plaintext and get the json part out of it
        let (plaintext, plaintext_len) = decrypt_opt(
            ciphertexts,
            number_of_ciphertexts,
            nonce,
            aes_key,
            blocks,
            blocks_len,
        );

        // Safety: extract the json part from the plaintext and then we check it was done correctly
        let json = unsafe { extract_json_opt(plaintext, number_of_ciphertexts, plaintext_len) };
        // verify_extracted_json(plaintext, json, json_blocks);

        // let result = BusinessProgram::at(business_logic_address).verify(json).call(&mut context);
        // if result {
        //     AttVerifier::at(context.this_address())
        //         ._emit_success_event(
        //             context.msg_sender(),
        //             context.this_address(),
        //             business_logic_address,
        //             id,
        //         )
        //         .enqueue(&mut context);
        // }
        // result
        true
    }

    #[public]
    #[internal]
    fn _emit_success_event(
        sender: AztecAddress,
        att_verifier_address: AztecAddress,
        business_logic_address: AztecAddress,
        id: Field,
    ) {
        emit_event_in_public(
            SuccessEvent { sender, att_verifier_address, business_logic_address, id },
            &mut context,
        );
    }

    #[contract_library_method]
    unconstrained fn extract_json_opt(
        plaintext: [u8; 3200],
        number_of_ciphertexts: u32,
        plaintext_len: [u32; 4],
    ) -> BoundedVec<u8, 4096> {
        let mut json_bytes: BoundedVec<u8, 4096> = BoundedVec::new();

        for i in 0..number_of_ciphertexts {
            for j in 0..plaintext_len[i] {
                json_bytes.push(plaintext[i * 800 + j]);
            }
        }

        json_bytes
    }

    #[contract_library_method]
    fn decrypt_opt(
        ciphertexts: [[u8; 800]; 4], // empty ciphertexts should be padded with 0
        number_of_ciphertexts: u32,
        nonce: [[u8; 12]; 4],
        aes_key: [u8; 16],
        blocks: [BlockInfo; 50],
        blocks_len: u32,
    ) -> ([u8; 3200], [u32; 4]) {
        let mut plaintexts: [u8; 3200] = [0u8; 3200];
        // length of each plaintext
        let mut plaintext_len: [u32; 4] = [0u32; 4];
        for i in 0..4 {
            if i < number_of_ciphertexts {
                // decrypt entire 800-byte ciphertext in one go
                let (pt, pt_len) =
                    aes_decrypt_opt_slot800(aes_key, nonce[i], blocks, ciphertexts[i], blocks_len);
                for j in 0..800 {
                    plaintexts[i * 800 + j] = pt[j];
                }
                plaintext_len[i] = pt_len;
            }
        }
        (plaintexts, plaintext_len)
    }

    #[contract_library_method]
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
    #[contract_library_method]
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
}
