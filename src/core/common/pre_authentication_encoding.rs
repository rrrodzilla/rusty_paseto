use std::ops::Deref;

pub struct PreAuthenticationEncoding(Vec<u8>);

/// Performs Pre-Authentication Encoding (or PAE) as described in the
/// Paseto Specification v2.
///
impl PreAuthenticationEncoding {
    /// * `pieces` - The Pieces to concatenate, and encode together.
    ///   Refactored from original code found at
    ///   <https://github.com/instructure/paseto/blob/trunk/src/pae.rs>
    pub fn parse<'a>(pieces: &'a [&'a [u8]]) -> Self {
        let the_vec = Self::le64(pieces.len() as u64);

        Self(pieces.iter().fold(the_vec, |mut acc, piece| {
            acc.extend(Self::le64(piece.len() as u64));
            acc.extend(piece.iter());
            acc
        }))
    }
    /// Encodes a u64-bit unsigned integer into a little-endian binary string.
    ///
    /// Per the PASETO spec, the high bit of the encoded value is cleared
    /// (`n &= 0x7FFF_FFFF_FFFF_FFFF`). In Rust this masking is structurally
    /// redundant — Vec / slice lengths are bounded by `isize::MAX` (< 2^63) so
    /// bit 63 is always zero — but we apply it for byte-exact compatibility
    /// with the reference implementation and to remain correct in the
    /// hypothetical case the function is called with a constructed value.
    ///
    /// * `to_encode` - The u64 to encode.
    ///   Copied and gently refactored from <https://github.com/instructure/paseto/blob/trunk/src/pae.rs>
    pub(crate) fn le64(mut to_encode: u64) -> Vec<u8> {
        to_encode &= 0x7FFF_FFFF_FFFF_FFFF;
        let mut the_vec = Vec::with_capacity(8);

        for _idx in 0..8 {
            the_vec.push((to_encode & 255) as u8);
            to_encode >>= 8;
        }

        the_vec
    }
}

impl Deref for PreAuthenticationEncoding {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Vec<u8>> for PreAuthenticationEncoding {
    fn as_ref(&self) -> &Vec<u8> {
        &self.0
    }
}
