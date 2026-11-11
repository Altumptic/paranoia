//! What a knowledge base remembers about a function, and how it's put back.
//!
//! Storage lives outside the core (`paranoia-db`); this module only decides what
//! to take from an analysed binary and how to apply a remembered function to a
//! new one.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use super::print::{similarity, Fingerprint, FunctionPrint, MIN_INSTRUCTIONS};
use crate::Binary;

/// One function as a knowledge base stores it. Holds no addresses, so it applies
/// to any binary that contains the same or similar code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownFunction {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Pseudocode variables renamed by the user: generated name → name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub var_names: BTreeMap<String, String>,
    /// Pseudocode variable types set by the user.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub var_types: BTreeMap<String, String>,
    /// Comments inside the function, by offset from its start. Only applied where
    /// the code is identical, since offsets move when code changes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub comments: Vec<(u32, String)>,
    /// Names of the named functions it calls, used as context when recalling.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<String>,
    pub print: Fingerprint,
    /// File the function was learned from: its name and SHA-256.
    pub source: String,
    pub source_sha256: String,
}

/// Which names a knowledge base learns from a binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearnFrom {
    /// Only what the user named.
    User,
    /// Also names from symbols, exports and debug info, for building a base from
    /// builds that have them.
    UserAndSymbols,
}

/// A remembered function proposed for an address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recall {
    pub address: u64,
    /// Current name at the address.
    pub current: String,
    pub score: f32,
    /// The code is identical, so comments by offset apply too.
    pub exact: bool,
    pub known: KnownFunction,
}

/// What [`Binary::apply_known`] changed.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Applied {
    pub renamed: bool,
    pub comments: usize,
    pub variables: usize,
}

/// How close a differently named runner-up may score before the answer counts as ambiguous.
const AMBIGUITY_MARGIN: f32 = 0.05;

/// The best candidate for `print` and its score, if any reaches `min_score`.
///
/// Returns `None` when a candidate with another name scores almost as well:
/// identical helpers under different names are common (wrappers, generated
/// equality functions), and guessing between them would put wrong names on code.
pub fn best_known<'k>(
    print: &Fingerprint,
    candidates: impl IntoIterator<Item = &'k KnownFunction>,
    min_score: f32,
) -> Option<(&'k KnownFunction, f32)> {
    let mut scored: Vec<(&KnownFunction, f32)> =
        candidates.into_iter().map(|k| (k, similarity(print, &k.print))).filter(|(_, s)| *s >= min_score).collect();
    scored.sort_by(|x, y| y.1.total_cmp(&x.1).then_with(|| x.0.name.cmp(&y.0.name)));
    let (best, score) = *scored.first()?;
    // Identical code only competes with other identical code.
    let margin = if score >= 1.0 { f32::EPSILON } else { AMBIGUITY_MARGIN };
    let rival = scored.iter().skip(1).any(|(k, s)| k.name != best.name && score - s < margin);
    (!rival).then_some((best, score))
}

/// Lowest similarity at which a remembered function is offered by default.
pub const RECALL_MIN_SCORE: f32 = 0.7;

/// Lowest code similarity for a function recognised through its neighbours.
const CONTEXT_MIN_SCORE: f32 = 0.45;
/// Score added per agreeing neighbour (up to three).
const CONTEXT_BONUS: f32 = 0.1;
const CONTEXT_ROUNDS: usize = 4;

/// Picks remembered functions for the functions of one binary.
///
/// `candidates[i]` holds what the index found for `prints[i]` (same or similar
/// code). The first round accepts confident, unambiguous matches on code alone.
/// Later rounds use the call graph: a function whose recognised callers are known
/// to call a name, or whose recognised callees are what a candidate is known to
/// call, gets that candidate on a lower code score. `by_name` finds remembered
/// functions by name, for callees whose code changed too much for the index.
///
/// A name is given to at most one function; when two functions would get the same
/// name, only the better one keeps it.
pub fn resolve(
    prints: &[FunctionPrint],
    mut candidates: Vec<Vec<KnownFunction>>,
    min_score: f32,
    by_name: &mut dyn FnMut(&str) -> Vec<KnownFunction>,
) -> Vec<Recall> {
    let idx: HashMap<u64, usize> = prints.iter().enumerate().map(|(i, p)| (p.address, i)).collect();
    let mut callers: Vec<Vec<usize>> = vec![Vec::new(); prints.len()];
    for (i, p) in prints.iter().enumerate() {
        for c in &p.callees {
            if let Some(&j) = idx.get(c) {
                callers[j].push(i);
            }
        }
    }
    let mut chosen: Vec<Option<(KnownFunction, f32)>> = vec![None; prints.len()];
    for (i, p) in prints.iter().enumerate() {
        if let Some((k, s)) = best_known(&p.print, &candidates[i], min_score) {
            chosen[i] = Some((k.clone(), s));
        }
    }

    let mut named: HashMap<String, Vec<KnownFunction>> = HashMap::new();
    for _ in 0..CONTEXT_ROUNDS {
        let mut changed = false;
        for i in 0..prints.len() {
            if chosen[i].is_some() || prints[i].print.instructions < MIN_INSTRUCTIONS {
                continue;
            }
            // Names the recognised callers are known to call.
            let mut expected: Vec<String> = Vec::new();
            for &c in &callers[i] {
                if let Some((k, _)) = &chosen[c] {
                    expected.extend(k.calls.iter().cloned());
                }
            }
            let callee_names: Vec<String> = prints[i]
                .callees
                .iter()
                .filter_map(|c| idx.get(c))
                .filter_map(|&j| chosen[j].as_ref().map(|(k, _)| k.name.clone()))
                .collect();
            if expected.is_empty() && callee_names.is_empty() {
                continue;
            }
            expected.sort();
            expected.dedup();
            for n in &expected {
                if !named.contains_key(n) {
                    let found = by_name(n);
                    named.insert(n.clone(), found);
                }
                for k in &named[n] {
                    if !candidates[i].iter().any(|c| c.name == k.name && c.print.exact == k.print.exact) {
                        candidates[i].push(k.clone());
                    }
                }
            }
            let mut scored: Vec<(f32, f32, usize)> = Vec::new();
            for (ci, k) in candidates[i].iter().enumerate() {
                let sim = similarity(&prints[i].print, &k.print);
                if sim < CONTEXT_MIN_SCORE {
                    continue;
                }
                let from_callers = expected.binary_search(&k.name).is_ok() as usize;
                let from_callees = callee_names.iter().filter(|n| k.calls.binary_search(n).is_ok()).count();
                let agree = (from_callers + from_callees).min(3);
                if agree == 0 {
                    continue;
                }
                scored.push((sim + CONTEXT_BONUS * agree as f32, sim, ci));
            }
            scored.sort_by(|x, y| y.0.total_cmp(&x.0));
            let Some(&(top, sim, ci)) = scored.first() else { continue };
            let name = &candidates[i][ci].name;
            if scored.iter().skip(1).any(|(s, _, cj)| candidates[i][*cj].name != *name && top - s < AMBIGUITY_MARGIN) {
                continue;
            }
            chosen[i] = Some((candidates[i][ci].clone(), sim));
            changed = true;
        }
        if !changed {
            break;
        }
    }

    // One function per name: the best score keeps it, a tie for the best drops it.
    let mut best_for: HashMap<&str, (usize, f32, bool)> = HashMap::new();
    for (i, c) in chosen.iter().enumerate() {
        if let Some((k, s)) = c {
            match best_for.get_mut(k.name.as_str()) {
                None => {
                    best_for.insert(k.name.as_str(), (i, *s, false));
                }
                Some(e) if *s > e.1 => *e = (i, *s, false),
                Some(e) if *s == e.1 => e.2 = true,
                Some(_) => {}
            }
        }
    }
    let mut out = Vec::new();
    for (i, c) in chosen.iter().enumerate() {
        let Some((k, s)) = c else { continue };
        let (winner, _, tied) = best_for[k.name.as_str()];
        if winner != i || tied || k.name == prints[i].name {
            continue;
        }
        let p = &prints[i].print;
        out.push(Recall {
            address: prints[i].address,
            current: prints[i].name.clone(),
            score: *s,
            exact: k.print.exact == p.exact && k.print.size == p.size,
            known: k.clone(),
        });
    }
    out
}

impl Binary {
    /// The functions worth remembering from this binary, with the user's names,
    /// comments and variable names and types.
    pub fn knowledge(&self, from: LearnFrom) -> Vec<KnownFunction> {
        let Some(a) = &self.analysis else { return Vec::new() };
        let ann = &self.annotations;
        let mut out = Vec::new();
        for f in a.functions.iter().filter(|f| f.thunk_slot.is_none()) {
            let user = ann.names.get(&f.address);
            let name = match (user, from) {
                (Some(n), _) => n.clone(),
                (None, LearnFrom::UserAndSymbols) => match self.static_names.get(&f.address) {
                    Some(n) => n.clone(),
                    None => continue,
                },
                (None, LearnFrom::User) => continue,
            };
            let fp = self.fingerprint_of(f, &a.by_start);
            if fp.print.instructions < MIN_INSTRUCTIONS {
                continue;
            }
            let mut calls: Vec<String> = fp
                .callees
                .iter()
                .filter_map(|c| match from {
                    LearnFrom::User => ann.names.get(c),
                    LearnFrom::UserAndSymbols => self.real_name(*c),
                })
                .cloned()
                .collect();
            calls.sort();
            calls.dedup();
            let comments = ann
                .comments
                .range(f.address + 1..f.end)
                .filter(|(va, _)| a.function_containing(**va).is_some_and(|g| g.address == f.address))
                .filter_map(|(va, c)| u32::try_from(va - f.address).ok().map(|off| (off, c.clone())))
                .collect();
            out.push(KnownFunction {
                name,
                comment: ann.comments.get(&f.address).cloned(),
                var_names: ann.var_names.get(&f.address).cloned().unwrap_or_default(),
                var_types: ann.var_types.get(&f.address).cloned().unwrap_or_default(),
                comments,
                calls,
                print: fp.print,
                source: self.info.file_name.clone(),
                source_sha256: self.info.hashes.sha256.clone(),
            });
        }
        out
    }

    /// Applies a remembered function to the function at `va`: its name, its comment
    /// and its variable names and types. Comments inside the function are applied
    /// only when `exact` is set. Existing user names and comments are kept.
    /// Call [`Binary::checkpoint`] first to make this undoable.
    pub fn apply_known(&mut self, va: u64, k: &KnownFunction, exact: bool) -> Applied {
        let mut done = Applied::default();
        if !self.annotations.names.contains_key(&va) && is_symbol_name(&k.name) {
            self.rename(va, &k.name);
            done.renamed = true;
        }
        if let Some(c) = &k.comment {
            if !self.annotations.comments.contains_key(&va) {
                self.set_comment(va, c);
                done.comments += 1;
            }
        }
        if exact {
            for (off, c) in &k.comments {
                let at = va + *off as u64;
                if !self.annotations.comments.contains_key(&at) {
                    self.set_comment(at, c);
                    done.comments += 1;
                }
            }
        }
        for (var, name) in &k.var_names {
            if self.annotations.var_names.get(&va).is_some_and(|m| m.contains_key(var)) {
                continue;
            }
            if self.set_var_name(va, var, name).is_ok() {
                done.variables += 1;
            }
        }
        for (var, ty) in &k.var_types {
            if self.annotations.var_types.get(&va).is_some_and(|m| m.contains_key(var)) {
                continue;
            }
            self.set_var_type(va, var, ty);
            done.variables += 1;
        }
        done
    }
}

/// Names from symbols can contain `::`, `.`, `$`, `@` and the like; they're fine as
/// labels as long as they hold no whitespace or control characters and aren't huge.
fn is_symbol_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 512 && !n.chars().any(|c| c.is_whitespace() || c.is_control())
}
