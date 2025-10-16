use dep::aztec::macros::aztec;

#[aztec]
pub contract AttVerifier {
    use aztec::{
        macros::{functions::{initializer, private, public, utility}, storage::storage},
        protocol_types::{address::AztecAddress},
    };
    use business_program::BusinessProgram;

    #[private]
    fn sig_verfier(
        public_key_x: [u8; 32],
        public_key_y: [u8; 32], 
        hash: [u8;32], 
        sig:[u8;64]) -> bool{
        std::ecdsa_secp256k1::verify_signature(public_key_x, public_key_y, sig, hash)
    }

    #[private]
    fn check_allowed_url() -> bool {
        true
    }

    #[private]
    fn decrypt_and_check(ct: BoundedVec<u8, 1024>, address: AztecAddress) -> bool{
        let plaintext = BoundedVec::<u8, 1024>::from_array([
            72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10, 67, 111, 110, 116,
            101, 110, 116, 45, 84, 121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105,
            111, 110, 47, 106, 115, 111, 110, 13, 10, 84, 114, 97, 110, 115, 102, 101, 114, 45, 69,
            110, 99, 111, 100, 105, 110, 103, 58, 32, 99, 104, 117, 110, 107, 101, 100, 13, 10, 13,
            10, 57, 54, 13, 10, 91, 10, 32, 32, 32, 32, 123, 10, 32, 32, 32, 32, 32, 32, 34, 97,
            115, 115, 101, 116, 34, 58, 32, 34, 66, 84, 67, 34, 44, 10, 32, 32, 32, 32, 32, 32, 34,
            102, 114, 101, 101, 34, 58, 32, 34, 49, 49, 46, 56, 48, 48, 51, 50, 57, 53, 50, 34, 44,
            10, 32, 32, 32, 32, 32, 32, 34, 108, 111, 99, 107, 101, 100, 34, 58, 32, 34, 48, 46, 53,
            34, 44, 10, 32, 32, 32, 32, 32, 32, 34, 102, 114, 101, 101, 122, 101, 34, 58, 32, 34,
            57, 46, 51, 34, 44, 10, 32, 32, 32, 32, 32, 32, 34, 119, 105, 116, 104, 100, 114, 97,
            119, 105, 110, 103, 34, 58, 32, 34, 48, 46, 48, 51, 34, 44, 10, 32, 32, 32, 32, 32, 32,
            34, 105, 112, 111, 97, 98, 108, 101, 34, 58, 13, 10,
        ]);
        BusinessProgram::at(address).verify(plaintext).call(&mut context);
    }
}





