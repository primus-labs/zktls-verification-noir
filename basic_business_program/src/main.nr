use dep::aztec::macros::aztec;

#[aztec]
pub contract BusinessProgram {
    use aztec::{
        macros::{functions::{initializer, private, public, utility}, storage::storage},
    };

    #[private]
    fn verify(data: BoundedVec<u8, 1024>) -> bool{
        // parse the data and verify custom condition
        true
    }

}
