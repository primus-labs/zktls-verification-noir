use aztec::macros::aztec;

/**
  * Github repository contributor example. Prove that *username* with *github_id* is 
  * a contributor to a Github repository.
  * 
  * The attestation is expected to have exactly two responseResolves:
  *   responseResolves[0] the contributor login (username)
  *   responseResolves[1] the contributor id (numeric, as a string)
  */
#[aztec]
pub contract GithubVerifier {
    use att_verifier_lib::{verify_attestation_comm, verify_attestation_hashing};
    use aztec::macros::{events::event, functions::{external, initializer}};
    use aztec::macros::storage::storage;
    use aztec::protocol::address::AztecAddress;
    use aztec::state_vars::{PublicImmutable, PublicMutable};
    use std::embedded_curve_ops::EmbeddedCurvePoint;

    // Set these values according to your use-case needs
    // Max length of URL
    global MAX_URL_LEN: u32 = 128;
    // Max length of plaintext message for both types of commitment
    global MAX_PLAINTEXT_LEN: u32 = 50;
    // Number of responseResolves. This determines:
    // - the number of hashes for hash-based
    // - OR the number of groups of commitments for commitment-based
    global NUM_RESPONSE_RESOLVE: u32 = 2;
    // Number of request URLs
    global NUM_REQUEST_URLS: u32 = 2; 
    // Number of allowed URLs
    global NUM_ALLOWED_URLS: u32 = 3;
    // Upper limit of number of commitments in a single group
    global MAX_COMMS: u32 = 2;

    #[event]
    struct SuccessEvent {
        sender: AztecAddress,
        contract_address: AztecAddress,
        id: Field,
    }

    #[storage]
    struct Storage<Context> {
        // Admin address that can update allowed_url_hashes
        admin: PublicMutable<AztecAddress, Context>,
        // Hashes of allowed URLs (storing complete URLs was too large for contract storage)
        allowed_url_hashes: PublicMutable<[Field; NUM_ALLOWED_URLS], Context>,
        // Point H used in commitment verification
        H: PublicImmutable<EmbeddedCurvePoint, Context>,
    }

    // Set admin that is allowed to adjust allowed_url_hashes
    #[external("public")]
    fn set_admin(new_admin: AztecAddress) {
        assert(self.storage.admin.read().eq(self.msg_sender()), "caller is not admin");
        self.storage.admin.write(new_admin);
    }

    // Contract constructor
    #[initializer]
    #[external("public")]
    fn constructor(admin: AztecAddress, allowed_url_hashes: [Field; NUM_ALLOWED_URLS], H: EmbeddedCurvePoint) {
        assert(!admin.is_zero(), "invalid admin");
        self.storage.admin.write(admin);
        self.storage.allowed_url_hashes.write(allowed_url_hashes);
        self.storage.H.initialize(H);
    }

    // Update allowed_url_hashes (only callable by admin)
    #[external("public")]
    fn update_allowed_url_hashes(allowed_url_hashes: [Field; NUM_ALLOWED_URLS]) {
        assert(self.storage.admin.read().eq(self.msg_sender()), "caller is not admin");
        self.storage.allowed_url_hashes.write(allowed_url_hashes);
    }

    // Check:
    // - allowed_url_matches_hashes are in storage
    // - H matches stored H
    // then emit (public) Success event
    #[external("public")]
    fn check_values_emit_event(
        sender: AztecAddress,
        contract_address: AztecAddress,
        id: Field,
        allowed_url_matches_hashes: [Field; NUM_REQUEST_URLS],
        H: EmbeddedCurvePoint,
    ) {
        // Check allowed_url_matches_hashes are in storage
        let allowed_url_hashes: [Field; NUM_ALLOWED_URLS] = self.storage.allowed_url_hashes.read();
        for i in 0..NUM_REQUEST_URLS {
            let check_hash = allowed_url_matches_hashes[i];
            let mut found = false;
            for j in 0..NUM_ALLOWED_URLS {
                if allowed_url_hashes[j] == check_hash {
                    found = true;
                }
            }
            assert(found);
        }

        // Check H equals the publicly known value
        let stored_H: EmbeddedCurvePoint = self.storage.H.read();
        assert(H == stored_H);

        self.emit(SuccessEvent { sender, contract_address, id });
    }

    // Check:
    // - allowed_url_matches_hashes are in storage
    // then emit (public) Success event
    #[external("public")]
    fn check_urls_emit_event(
        sender: AztecAddress,
        contract_address: AztecAddress,
        id: Field,
        allowed_url_matches_hashes: [Field; NUM_REQUEST_URLS],
    ) {
        // Check allowed_url_matches_hashes are in storage
        let allowed_url_hashes: [Field; NUM_ALLOWED_URLS] = self.storage.allowed_url_hashes.read();
        for i in 0..NUM_REQUEST_URLS {
            let check_hash = allowed_url_matches_hashes[i];
            let mut found = false;
            for j in 0..NUM_ALLOWED_URLS {
                if allowed_url_hashes[j] == check_hash {
                    found = true;
                }
            }
            assert(found);
        }

        self.emit(SuccessEvent { sender, contract_address, id });
    }

    // Verify commitment-based attestation and emit event upon success.
    // After verifying the attestation, checks the following:
    //   msgs_1 = committed content of responseResolves[0] equals the Github username
    //   msgs_2 = committed content of responseResolves[1] eqials the Github ID
    #[external("private")]
    fn verify_comm(
        public_key_x: [u8; 32],
        public_key_y: [u8; 32],
        hash: [u8; 32],
        signature: [u8; 64],
        request_urls: [BoundedVec<u8, MAX_URL_LEN>; NUM_REQUEST_URLS],
        allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; NUM_ALLOWED_URLS],
        coms_per_group: [BoundedVec<EmbeddedCurvePoint, MAX_COMMS>; NUM_RESPONSE_RESOLVE],
        rnds_per_group: [BoundedVec<Field, MAX_COMMS>; NUM_RESPONSE_RESOLVE],
        msgs_chunks_per_group: [BoundedVec<Field, MAX_COMMS>; NUM_RESPONSE_RESOLVE],
        msgs_per_group: [BoundedVec<u8, MAX_PLAINTEXT_LEN>; NUM_RESPONSE_RESOLVE],
        H: EmbeddedCurvePoint,
        id: Field,
        github_username: BoundedVec<u8, MAX_PLAINTEXT_LEN>,
        github_id: BoundedVec<u8, MAX_PLAINTEXT_LEN>,
    ) -> bool {
        let allowed_url_matches_hashes: [Field; NUM_REQUEST_URLS] = verify_attestation_comm(
            public_key_x,
            public_key_y,
            hash,
            signature,
            request_urls,
            allowed_urls,
            coms_per_group,
            rnds_per_group,
            msgs_chunks_per_group,
            H,
        );

        // Verify the attested username matches the expected value
        assert(msgs_per_group[0].storage() == github_username.storage());
        // Verify the attested contributor ID matches the expected value
        assert(msgs_per_group[1].storage() == github_id.storage());

        GithubVerifier::at(self.address)
            .check_values_emit_event(
                self.msg_sender(),
                self.address,
                id,
                allowed_url_matches_hashes,
                H,
            )
            .enqueue(self.context);

        true
    }

    // Verify hashing-based attestation and emit event upon success.
    // After verifying the attestation, checks the following:
    //   msgs_1 = committed content of responseResolves[0] equals the Github username
    //   msgs_2 = committed content of responseResolves[1] eqials the Github ID
    #[external("private")]
    fn verify_hash(
        public_key_x: [u8; 32],
        public_key_y: [u8; 32],
        hash: [u8; 32],
        signature: [u8; 64],
        request_urls: [BoundedVec<u8, MAX_URL_LEN>; NUM_REQUEST_URLS],
        allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; NUM_ALLOWED_URLS],
        data_hashes: [[u8; 32]; NUM_RESPONSE_RESOLVE],
        contents: [BoundedVec<u8, MAX_PLAINTEXT_LEN>; NUM_RESPONSE_RESOLVE],
        id: Field,
        github_username: BoundedVec<u8, MAX_PLAINTEXT_LEN>,
        github_id: BoundedVec<u8, MAX_PLAINTEXT_LEN>,
    ) -> bool {
        let allowed_url_matches_hashes: [Field; NUM_REQUEST_URLS] = verify_attestation_hashing(
            public_key_x,
            public_key_y,
            hash,
            signature,
            request_urls,
            allowed_urls,
            data_hashes,
            contents,
        );

        // Verify the attested username matches the expected value
        assert(contents[0].storage() == github_username.storage());
        // Verify the attested contributor ID matches the expected value
        assert(contents[1].storage() == github_id.storage());

        GithubVerifier::at(self.address)
            .check_urls_emit_event(
                self.msg_sender(),
                self.address,
                id,
                allowed_url_matches_hashes,
            )
            .enqueue(self.context);

        true
    }
}
