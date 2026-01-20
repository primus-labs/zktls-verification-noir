use dep::aztec::macros::aztec;
#[aztec]
pub contract BusinessProgramSmallComm {
    use dep::json_parser::JSON512b;
    use att_verifier_lib::verify_attestation_comm;
    use aztec::macros::{events::event, functions::{external, initializer}};
    use aztec::macros::storage::storage;
    use aztec::protocol_types::address::AztecAddress;
    use aztec::state_vars::{public_immutable::PublicImmutable, public_mutable::PublicMutable};
    use std::embedded_curve_ops::EmbeddedCurvePoint;

    global MAX_URL_LEN: u32 = 1024;
    global MAX_MSGS_LEN: u32 = 50;
    global MAX_COMMS: u32 = 1;

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
        assert(self.storage.admin.read().eq(self.msg_sender().unwrap()), "caller is not admin");
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

    // TODO - allow update single url with index?
    #[external("public")]
    fn update_allowed_url_hashes(allowed_url_hashes: [Field; 3]) {
        assert(self.storage.admin.read().eq(self.msg_sender().unwrap()), "caller is not admin");
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

    // Check H equals the publicly known value
    // do asserts on msgs
    // Opcode count: 57636, Total gates by opcodes: 316323, Circuit size: 321513
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
        // Check value
        // TODO what assert to do here?
        let val = get_value(msgs);

        BusinessProgramSmallComm::at(self.address)
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

    #[contract_library_method]
    fn get_value(plaintext: BoundedVec<u8, MAX_MSGS_LEN>) -> BoundedVec<u8, 20> {
        let json = JSON512b::parse_bounded_vec_json(plaintext);

        // for attestation_data_grumpkin.json
        // obtain .data[0], this is an array of 6 decimal numbers, which we'll read out as string
        let key0: BoundedVec<u8, 4> = BoundedVec::from_array("data".as_bytes());

        let data0 = json.get_array(key0).unwrap().get_object_from_array(0).unwrap();
        let key1: BoundedVec<u8, 7> = BoundedVec::from_array("baseCcy".as_bytes());
        let val: BoundedVec<u8, 20> = data0.get_string_from_path([key1]).unwrap();

        val
    }

}
