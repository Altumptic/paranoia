//! Function memory: fingerprints that identify a function across builds,
//! versions and samples, a matcher for two binaries (binary diffing), and what a
//! local knowledge base stores so names and comments carry over to new files.
//!
//! Accuracy is measured with `paranoia diff --check-names` and `paranoia memory recall --check-names`.

mod diff;
mod knowledge;
mod print;

pub use diff::{diff, DiffOptions, DiffReport, FunctionMatch, MatchKind, Unmatched};
pub use knowledge::{best_known, resolve, Applied, KnownFunction, LearnFrom, Recall, RECALL_MIN_SCORE};
pub use print::{band_keys, similarity, sketch_similarity, Fingerprint, FunctionPrint, BANDS, MIN_INSTRUCTIONS, SKETCH};
