use aztec::macros::aztec;
#[aztec]
pub contract BusinessProgram {
    use att_verifier_lib::verify_attestation_comm_poseidon;
    use aztec::macros::{events::event, functions::{external, initializer}};
    use aztec::macros::storage::storage;
    use aztec::protocol::address::AztecAddress;
    use aztec::state_vars::{PublicImmutable, PublicMutable};
    use std::embedded_curve_ops::EmbeddedCurvePoint;

    global MAX_COMMS: u32 = 65;

    // Number of application-specific values extracted from the JSON response
    // by the attestation service. For this example: 6 numeric strings from
    // attestation_data_grumpkin.json, .data[0][0..5]
    global NUM_VALUES: u32 = 6;

    // Digest serialization length: 4 + MAX_COMMS * 5 + NUM_VALUES
    // = 4 + 65 * 5 + 6 = 335
    global DIGEST_LEN: u32 = 335;

    #[event]
    struct SuccessEvent {
        sender: AztecAddress,
        contract_address: AztecAddress,
        id: Field,
    }

    #[storage]
    struct Storage<Context> {
        admin: PublicMutable<AztecAddress, Context>,
        allowed_url_hashes: PublicMutable<[Field; 3], Context>,
        H: PublicImmutable<EmbeddedCurvePoint, Context>,
    }

    #[external("public")]
    fn set_admin(new_admin: AztecAddress) {
        assert(self.storage.admin.read().eq(self.msg_sender()), "caller is not admin");
        self.storage.admin.write(new_admin);
    }

    #[initializer]
    #[external("public")]
    fn constructor(admin: AztecAddress, allowed_url_hashes: [Field; 3], H: EmbeddedCurvePoint) {
        assert(!admin.is_zero(), "invalid admin");
        self.storage.admin.write(admin);
        self.storage.allowed_url_hashes.write(allowed_url_hashes);
        self.storage.H.initialize(H);
    }

    #[external("public")]
    fn update_allowed_url_hashes(allowed_url_hashes: [Field; 3]) {
        assert(self.storage.admin.read().eq(self.msg_sender()), "caller is not admin");
        self.storage.allowed_url_hashes.write(allowed_url_hashes);
    }

    #[external("public")]
    fn check_values_emit_event(
        sender: AztecAddress,
        contract_address: AztecAddress,
        id: Field,
        allowed_url_matches_hashes: [Field; 2],
        H: EmbeddedCurvePoint,
    ) {
        // Check allowed_url_matches_hashes are in storage
        let allowed_url_hashes: [Field; 3] = self.storage.allowed_url_hashes.read();
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
        let stored_H: EmbeddedCurvePoint = self.storage.H.read();
        assert(H == stored_H);

        self.emit(SuccessEvent { sender, contract_address, id });
    }

    /// Verify attestation with Poseidon2 digest binding.
    ///
    /// URL matching and JSON parsing are performed off-chain by the attestation
    /// service. The service extracts values from the API response, computes
    /// Poseidon2 URL hashes, and signs a Poseidon2 digest of ALL data.
    ///
    /// The extracted_values array contains the business-relevant values parsed
    /// from the JSON response (e.g., numeric values, encoded strings).
    /// These are application-specific and defined by NUM_VALUES.
    ///
    /// Security:
    ///   - ECDSA signature: attestation came from trusted service
    ///   - Poseidon2 binding: all inputs match the signed attestation
    ///   - On-chain check: URL hashes are in the approved set
    ///   - Commitment check: response data integrity
    #[external("private")]
    fn verify_comm(
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
        id: Field,
    ) -> bool {
        verify_attestation_comm_poseidon::<MAX_COMMS, NUM_VALUES, DIGEST_LEN>(
            public_key_x,
            public_key_y,
            hash,
            signature,
            allowed_url_matches_hashes,
            coms,
            rnds,
            msgs_chunks,
            extracted_values,
            H,
        );

        // Application-specific assertions on the extracted values.
        // These values were parsed from the JSON response by the attestation
        // service and are bound to the ECDSA signature via the Poseidon2 digest.
        //
        // Example: for attestation_data_grumpkin.json, extracted_values contains
        // 6 numeric values from .data[0][0..5]. Add business logic checks here:
        // assert(extracted_values[0] > some_threshold, "value below threshold");

        BusinessProgram::at(self.address)
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
}
