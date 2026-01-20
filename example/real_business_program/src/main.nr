use dep::aztec::macros::aztec;
#[aztec]
pub contract BusinessProgram {
    use dep::json_parser::{JSON2055, JSON2kb};
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

    // Check H equals the publicly known value
    // do asserts on msgs
    // Opcode count: 208423, Total gates by opcodes: 696795, Circuit size: 711763
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
        // Check values
        // TODO what assert to do here?
        let _numbers_as_strings = get_values(msgs);

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

    // Opcode count: 253113, Total gates by opcodes: 778309, Circuit size: 794646
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

        for i in 0..2 {
            // Parse plaintext to JSON and obtain the custom values we want to check
            let (base_ccy, inst_id_code) = get_values2(plain_json_response_contents[i]);

            // TODO what to assert about base_ccy and inst_id_code
        }

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

    #[contract_library_method]
    fn get_values(plaintext: BoundedVec<u8, MAX_MSGS_LEN>) -> [BoundedVec<u8, 20>; 6] {
        let json = JSON2055::parse_bounded_vec_json(plaintext);

        // for attestation_data_grumpkin.json
        // obtain .data[0], this is an array of 6 decimal numbers, which we'll read out as string
        let key0: BoundedVec<u8, 4> = BoundedVec::from_array("data".as_bytes());
        let data0 = json.get_array(key0).unwrap().get_array_from_array(0).unwrap();

        [
            data0.get_string_from_array(0).unwrap(),
            data0.get_string_from_array(1).unwrap(),
            data0.get_string_from_array(2).unwrap(),
            data0.get_string_from_array(3).unwrap(),
            data0.get_string_from_array(4).unwrap(),
            data0.get_string_from_array(5).unwrap(),
        ]
    }

    #[contract_library_method]
    fn get_values2(plaintext: BoundedVec<u8, MAX_CONTENT_LEN>) -> (u64, BoundedVec<u8, 10>) {
        let json = JSON2kb::parse_bounded_vec_json(plaintext);
        // for eth_hash.json
        let key0: BoundedVec<u8, 15> = BoundedVec::from_array("makerCommission".as_bytes());
        let maker_commission = json.get_number(key0).unwrap();

        let key1: BoundedVec<u8, 15> = BoundedVec::from_array("commissionRates".as_bytes());
        let commission_rate_obj: JSON2kb = json.get_object(key1).unwrap();

        let key2: BoundedVec<u8, 5> = BoundedVec::from_array("maker".as_bytes());
        let maker_rate_str: BoundedVec<u8, 10> =
            commission_rate_obj.get_string_from_path([key2]).unwrap();
        (maker_commission, maker_rate_str)
    }

}
