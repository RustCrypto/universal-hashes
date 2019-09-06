//! **GHASH**: universal hash over GF(2^128) used by AES-GCM.

use crate::{
    field::{backend::U64x2, Block},
    Polyval,
};
use universal_hash::generic_array::{typenum::U16, GenericArray};
use universal_hash::{Output, UniversalHash};

/// **GHASH**: universal hash over GF(2^128) used by AES-GCM.
///
/// GHASH is a universal hash function whose polynomial is the "reverse" of
/// the one used by POLYVAL, and is used for message authentication in
/// the AES-GCM authenticated encryption cipher.
///
/// From RFC 8452 Appendix A:
/// <https://tools.ietf.org/html/rfc8452#appendix-A>
///
/// > GHASH and POLYVAL both operate in GF(2^128), although with different
/// > irreducible polynomials: POLYVAL works modulo x^128 + x^127 + x^126 +
/// > x^121 + 1 and GHASH works modulo x^128 + x^7 + x^2 + x + 1.  Note
/// > that these irreducible polynomials are the "reverse" of each other.
#[allow(non_snake_case)]
#[derive(Clone)]
#[repr(align(16))]
pub struct GHash(Polyval);

impl UniversalHash for GHash {
    type KeySize = U16;
    type OutputSize = U16;

    /// Initialize GHASH with the given `H` field element
    fn new(h: &GenericArray<u8, U16>) -> Self {
        let mut h: Block = h.clone().into();
        h.reverse();

        let h_polyval: Block = U64x2::from(h).mulx().into();
        GHash(Polyval::new(&h_polyval.into()))
    }

    /// Input a field element `X` to be authenticated
    fn update_block(&mut self, x: &GenericArray<u8, U16>) {
        let mut x: Block = x.clone().into();
        x.reverse();
        self.0.update_block(&x.into());
    }

    /// Reset internal state
    fn reset(&mut self) {
        self.0.reset();
    }

    /// Get POLYVAL result (i.e. computed `S` field element)
    fn result(self) -> Output<U16> {
        let mut output: Block = self.0.result().into_bytes().into();
        output.reverse();
        Output::new(output.into())
    }
}
