use dep::aztec::macros::aztec;

#[aztec]
pub contract BusinessProgram {
    use aztec::{
        macros::{functions::{initializer, private, public, utility}, storage::storage},
        oracle::debug_log::debug_log_format,
        protocol_types::{address::AztecAddress, traits::ToField},
        state_vars::Map,
    };

    #[private]
    fn verify(data: BoundedVec<u8, 1024>) -> bool{
        // parse the data and verify custom condition
        assert(1 == 1);
        true
    }

}
