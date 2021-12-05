/// a simple marker trait to identify claims
pub trait PasetoClaim: erased_serde::Serialize {
  fn get_key(&self) -> &str;
}
