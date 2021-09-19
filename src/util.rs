use ring::rand::{SecureRandom, SystemRandom};

pub(crate) fn get_random_256_bit_buf() -> [u8; 32] {
  let rng = SystemRandom::new();
  let mut buf = [0u8; 32];
  rng.fill(&mut buf).unwrap();
  buf
}

pub(crate) fn get_random_192_bit_buf() -> [u8; 24] {
  let rng = SystemRandom::new();
  let mut buf = [0u8; 24];
  rng.fill(&mut buf).unwrap();
  buf
}
