use dep::aztec::macros::aztec;

/**
  * An Aztec smart contract template for usage of Primus Noir.
  * This smart contract can verify 2 types of attestations from Primus:
  * 1) Commitment-based attestations, via the `verify_comm` function.
  * 2) Hashing-based attestations, via the `verify_hash` function.
  *
  * In both cases, upon successful verification of the attestation, an event is emitted.
  *
  * Note that the point H in storage is only needed for commitment-based attestations. 
  * 
  * TODO: Add the custom checks on the attested data in the verification function(s).
  * For this, you might want to use the json_parser library. 
  */
#[aztec]
pub contract BusinessProgram {
    use att_verifier_lib::{verify_attestation_comm, verify_attestation_hashing};
    use aztec::macros::{events::event, functions::{external, initializer}};
    use aztec::macros::storage::storage;
    use aztec::protocol_types::address::AztecAddress;
    use aztec::state_vars::{public_immutable::PublicImmutable, public_mutable::PublicMutable};
    use std::embedded_curve_ops::EmbeddedCurvePoint;

    global MAX_URL_LEN: u32 = 1024;
    global MAX_MSGS_LEN: u32 = 2054;
    global MAX_CONTENT_LEN: u32 = 1000;
    global MAX_COMMS: u32 = 65;

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
        allowed_url_hashes: PublicMutable<[Field; 3], Context>,
        // Point H used in commitment verification
        H: PublicImmutable<EmbeddedCurvePoint, Context>,
    }

    // Set admin that is allowed to adjust allowed_url_hashes
    #[external("public")]
    fn set_admin(new_admin: AztecAddress) {
        assert(self.storage.admin.read().eq(self.msg_sender().unwrap()), "caller is not admin");
        self.storage.admin.write(new_admin);
    }

    // Contract constructor
    #[initializer]
    #[external("public")]
    fn constructor(admin: AztecAddress, allowed_url_hashes: [Field; 3], H: EmbeddedCurvePoint) {
        assert(!admin.is_zero(), "invalid admin");
        self.storage.admin.write(admin);
        self.storage.allowed_url_hashes.write(allowed_url_hashes);
        self.storage.H.initialize(H);
    }

    // Update allowed_url_hashes (only callable by admin)
    #[external("public")]
    fn update_allowed_url_hashes(allowed_url_hashes: [Field; 3]) {
        assert(self.storage.admin.read().eq(self.msg_sender().unwrap()), "caller is not admin");
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

    // Check:
    // - allowed_url_matches_hashes are in storage
    // then emit (public) Success event
    #[external("public")]
    fn check_urls_emit_event(
        sender: AztecAddress,
        contract_address: AztecAddress,
        id: Field,
        allowed_url_matches_hashes: [Field; 2],
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

        self.emit(SuccessEvent { sender, contract_address, id });
    }

    // Verify commitment-based attestation and emit event upon success
    // TODO: insert here your own checks on msgs
    #[external("private")]
    fn verify_comm(
        public_key_x: [u8; 32],
        public_key_y: [u8; 32],
        hash: [u8; 32],
        signature: [u8; 64],
        request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
        allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
        coms: BoundedVec<EmbeddedCurvePoint, MAX_COMMS>,
        rnds: BoundedVec<Field, MAX_COMMS>,
        msgs_chunks: BoundedVec<Field, MAX_COMMS>,
        msgs: BoundedVec<u8, MAX_MSGS_LEN>,
        H: EmbeddedCurvePoint, // G is fixed, H is fixed per business case
        id: Field,
    ) -> bool {
        let allowed_url_matches_hashes: [Field; 2] = verify_attestation_comm(
            public_key_x,
            public_key_y,
            hash,
            signature,
            request_urls,
            allowed_urls,
            coms,
            rnds,
            msgs_chunks,
            H,
        );

        // TODO insert checks on msgs

        BusinessProgram::at(self.address)
            .check_values_emit_event(
                self.msg_sender().unwrap(),
                self.address,
                id,
                allowed_url_matches_hashes,
                H,
            )
            .enqueue(self.context);

        true
    }

    // Verify hashing-based attestation and emit event upon success
    // TODO: insert here your own checks on plain_json_response_contents
    #[external("private")]
    fn verify_hash(
        public_key_x: [u8; 32],
        public_key_y: [u8; 32],
        hash: [u8; 32],
        signature: [u8; 64],
        request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
        allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
        data_hashes: [[u8; 32]; 2],
        plain_json_response_contents: [BoundedVec<u8, MAX_CONTENT_LEN>; 2],
        id: Field, // id for this attestation
    ) -> bool {
        let allowed_url_matches_hashes: [Field; 2] = verify_attestation_hashing(
            public_key_x,
            public_key_y,
            hash,
            signature,
            request_urls,
            allowed_urls,
            data_hashes,
            plain_json_response_contents,
        );

        // TODO insert checks on plain_json_response_contents

        BusinessProgram::at(self.address)
            .check_urls_emit_event(
                self.msg_sender().unwrap(),
                self.address,
                id,
                allowed_url_matches_hashes,
            )
            .enqueue(self.context);

        true
    }
}
