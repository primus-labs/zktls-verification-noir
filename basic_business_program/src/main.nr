use dep::aztec::macros::aztec;

#[aztec]
pub contract BusinessProgram {
    use aztec::macros::functions::{external, internal};
    use std::embedded_curve_ops::EmbeddedCurvePoint;

    global MAX_MSGS_LEN: u32 = 200;

    #[external("private")]
    fn verify(
        msgs: BoundedVec<u8, MAX_MSGS_LEN>,
        H: EmbeddedCurvePoint,
        allowed_url_matches_hashes: [Field; 2],
    ) -> bool {
        // parse the data and verify custom condition
        true
    }
}
