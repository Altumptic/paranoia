//! Entropy and cryptographic hashes.

use sha1::Digest as _;

use crate::model::Hashes;

/// Shannon entropy in bits per byte (0.0 ..= 8.0).
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Entropy of `buckets` equally sized chunks (fewer for small files).
pub fn entropy_map(data: &[u8], buckets: usize) -> Vec<f32> {
    if data.is_empty() {
        return Vec::new();
    }
    let chunk = data.len().div_ceil(buckets).max(64);
    data.chunks(chunk).map(|c| entropy(c) as f32).collect()
}

pub fn hashes(data: &[u8]) -> Hashes {
    Hashes {
        md5: hex::encode(md5::Md5::digest(data)),
        sha1: hex::encode(sha1::Sha1::digest(data)),
        sha256: hex::encode(sha2::Sha256::digest(data)),
        imphash: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[0u8; 128]), 0.0);
        let all: Vec<u8> = (0..=255).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn known_hash() {
        let h = hashes(b"abc");
        assert_eq!(h.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(h.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
