use dep::aztec::macros::aztec;

#[aztec]
pub contract BusinessProgram {
    use aztec::macros::{functions::{initializer, private, public, utility}, storage::storage};

    #[private]
    fn verify(plaintext: BoundedVec<u8, 4096>) -> bool {
        // parse the data and verify custom condition
        true
    }

}
