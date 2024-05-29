#[cfg(feature = "chacha20poly1305")]
use chacha20poly1305::XNonce;

#[cfg(feature = "chacha20poly1305")]
struct EncryptionNonce(XNonce);

#[cfg(feature = "chacha20poly1305")]
impl AsRef<XNonce> for EncryptionNonce {
    fn as_ref(&self) -> &XNonce {
        &self.0
    }
}
