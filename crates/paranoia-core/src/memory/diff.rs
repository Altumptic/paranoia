//! Matching the functions of two binaries.
//!
//! The passes run from the most to the least certain, and a function matched by
//! one pass is never reconsidered by a later one:
//!
//! 1. names, when both sides have real names and the caller allows it;
//! 2. identical masked bytes, when the fingerprint is unique on both sides;
//! 3. identical instruction shape, unique on both sides;
//! 4. identical set of anchors (imports, strings, constants), unique on both sides;
//! 5. the call graph: callees and callers of matched pairs are matched among themselves;
//! 6. fuzzy: candidates from LSH buckets over the MinHash sketches, best pairs first;
//! 7. the call graph again, from the pairs pass 6 found;
//! 8. copies: when both binaries still have the same number of unmatched,
//!    identical copies of some code, they are paired in address order (the
//!    linker keeps the order of the objects), then the call graph once more.
//!
//! Uniqueness matters more than score in the early passes: two identical copies
//! of a small helper can't be told apart by their code, so they're left for the
//! call graph to decide.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use super::print::{band_keys, hash_bytes, similarity, FunctionPrint, MIN_INSTRUCTIONS};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    Name,
    Exact,
    Shape,
    Anchors,
    CallGraph,
    Fuzzy,
    /// Identical copies paired by their order in the file.
    Order,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionMatch {
    pub a: u64,
    pub b: u64,
    pub a_name: String,
    pub b_name: String,
    /// The names are real (user, symbols, exports), not `sub_…`.
    pub a_named: bool,
    pub b_named: bool,
    /// 1 for identical code, lower the more it changed.
    pub score: f32,
    pub kind: MatchKind,
    /// The masked machine code differs.
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Unmatched {
    pub address: u64,
    pub name: String,
    pub instructions: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    /// Matched functions, by address in the first binary.
    pub matches: Vec<FunctionMatch>,
    /// Functions only in the first binary (removed).
    pub only_a: Vec<Unmatched>,
    /// Functions only in the second binary (added).
    pub only_b: Vec<Unmatched>,
    /// How much code the two binaries share, weighted by instruction count (0–1).
    pub similarity: f32,
}

#[derive(Debug, Clone, Copy)]
pub struct DiffOptions {
    /// Match functions with the same real name first. Off when the names can't be
    /// trusted, or when measuring the matcher against names.
    pub use_names: bool,
    /// Lowest score accepted by the fuzzy pass.
    pub min_score: f32,
}

impl Default for DiffOptions {
    fn default() -> Self {
        DiffOptions { use_names: true, min_score: 0.55 }
    }
}

/// Lowest combined score (code and neighbours) for pairs suggested by the call graph.
const GRAPH_MIN_SCORE: f32 = 0.45;
/// Weight of the neighbours in that combined score.
const CONTEXT_WEIGHT: f32 = 0.35;
/// Buckets bigger than this are skipped by the fuzzy pass: they hold generic code.
const MAX_BUCKET: usize = 64;

struct State<'p> {
    a: &'p [FunctionPrint],
    b: &'p [FunctionPrint],
    a_of: Vec<Option<usize>>,
    b_of: Vec<Option<usize>>,
    out: Vec<(usize, usize, f32, MatchKind)>,
    /// Callers and callees of each function, sorted.
    nbr_a: Vec<Vec<usize>>,
    nbr_b: Vec<Vec<usize>>,
}

fn index_by(side: &[FunctionPrint], taken: &[Option<usize>], key: &dyn Fn(&FunctionPrint) -> Option<u64>) -> HashMap<u64, Vec<usize>> {
    let mut m: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, p) in side.iter().enumerate() {
        if taken[i].is_none() {
            if let Some(k) = key(p) {
                m.entry(k).or_default().push(i);
            }
        }
    }
    m
}

impl State<'_> {
    fn add(&mut self, i: usize, j: usize, score: f32, kind: MatchKind) -> bool {
        if self.a_of[i].is_some() || self.b_of[j].is_some() {
            return false;
        }
        self.a_of[i] = Some(j);
        self.b_of[j] = Some(i);
        self.out.push((i, j, score, kind));
        true
    }

    /// Matches functions whose key is unique among the unmatched ones on both sides.
    fn unique_pass(&mut self, kind: MatchKind, min_score: f32, key: &dyn Fn(&FunctionPrint) -> Option<u64>) {
        let ia = index_by(self.a, &self.a_of, key);
        let ib = index_by(self.b, &self.b_of, key);
        let mut pairs: Vec<(usize, usize)> =
            ia.iter().filter(|(_, v)| v.len() == 1).filter_map(|(k, v)| ib.get(k).filter(|w| w.len() == 1).map(|w| (v[0], w[0]))).collect();
        pairs.sort_unstable();
        for (i, j) in pairs {
            let s = similarity(&self.a[i].print, &self.b[j].print);
            if s >= min_score {
                self.add(i, j, s, kind);
            }
        }
    }

    /// How well the neighbourhoods of `i` and `j` agree: of their callers and callees
    /// that are matched already, the share matched to each other (0–1), and how many.
    fn context(&self, i: usize, j: usize) -> (f32, usize) {
        let matched_a = self.nbr_a[i].iter().filter(|&&n| self.a_of[n].is_some()).count();
        let matched_b = self.nbr_b[j].iter().filter(|&&n| self.b_of[n].is_some()).count();
        let agree = self.nbr_a[i].iter().filter_map(|&n| self.a_of[n]).filter(|m| self.nbr_b[j].binary_search(m).is_ok()).count();
        let total = matched_a.max(matched_b);
        if total == 0 {
            (0.0, 0)
        } else {
            (agree as f32 / total as f32, agree)
        }
    }

    /// Code similarity blended with neighbourhood agreement. A single agreeing
    /// neighbour (usually the pair that led here) counts for little.
    fn graph_score(&self, i: usize, j: usize) -> f32 {
        let sim = similarity(&self.a[i].print, &self.b[j].print);
        let (ctx, agree) = self.context(i, j);
        let ctx = if agree >= 2 { ctx } else { ctx * 0.5 };
        (1.0 - CONTEXT_WEIGHT) * sim + CONTEXT_WEIGHT * ctx
    }

    /// Best partner for each unmatched function in `xs` among `ys`, kept when the choice is mutual.
    fn match_sets(&mut self, xs: &[usize], ys: &[usize], min_score: f32, kind: MatchKind) -> Vec<(usize, usize)> {
        let xs: Vec<usize> = xs.iter().copied().filter(|&i| self.a_of[i].is_none()).collect();
        let ys: Vec<usize> = ys.iter().copied().filter(|&j| self.b_of[j].is_none()).collect();
        if xs.is_empty() || ys.is_empty() || xs.len() * ys.len() > 4096 {
            return Vec::new();
        }
        let scores: Vec<Vec<f32>> = xs.iter().map(|&i| ys.iter().map(|&j| self.graph_score(i, j)).collect()).collect();
        let best_y = |xi: usize| (0..ys.len()).max_by(|&p, &q| scores[xi][p].total_cmp(&scores[xi][q]));
        let best_x = |yi: usize| (0..xs.len()).max_by(|&p, &q| scores[p][yi].total_cmp(&scores[q][yi]));
        let mut added = Vec::new();
        for xi in 0..xs.len() {
            let Some(yi) = best_y(xi) else { continue };
            // A lone pair on both sides is accepted on a lower score: nothing else could fit.
            let lone = xs.len() == 1 && ys.len() == 1;
            let min = if lone { min_score * 0.75 } else { min_score };
            let (i, j) = (xs[xi], ys[yi]);
            if best_x(yi) == Some(xi) && scores[xi][yi] >= min && self.add(i, j, similarity(&self.a[i].print, &self.b[j].print), kind) {
                added.push((i, j));
            }
        }
        added
    }

    /// Spreads matches along call edges until nothing changes.
    fn propagate(&mut self, callers_a: &[Vec<usize>], callers_b: &[Vec<usize>], idx_a: &HashMap<u64, usize>, idx_b: &HashMap<u64, usize>) {
        let mut work: VecDeque<(usize, usize)> = self.out.iter().map(|&(i, j, _, _)| (i, j)).collect();
        let mut seen: HashSet<(usize, usize)> = HashSet::new();
        while let Some((i, j)) = work.pop_front() {
            if !seen.insert((i, j)) {
                continue;
            }
            let callees_a: Vec<usize> = self.a[i].callees.iter().filter_map(|c| idx_a.get(c).copied()).collect();
            let callees_b: Vec<usize> = self.b[j].callees.iter().filter_map(|c| idx_b.get(c).copied()).collect();
            for p in self.match_sets(&callees_a, &callees_b, GRAPH_MIN_SCORE, MatchKind::CallGraph) {
                work.push_back(p);
            }
            for p in self.match_sets(&callers_a[i], &callers_b[j], GRAPH_MIN_SCORE, MatchKind::CallGraph) {
                work.push_back(p);
            }
        }
    }

    /// Candidates from shared LSH buckets, matched best score first.
    /// Pairs identical copies left over on both sides, in address order, when both
    /// sides have the same number of them.
    fn copies(&mut self) {
        let key = |p: &FunctionPrint| Some(p.print.exact ^ p.print.size as u64);
        let ia = index_by(self.a, &self.a_of, &key);
        let ib = index_by(self.b, &self.b_of, &key);
        let mut groups: Vec<(Vec<usize>, Vec<usize>)> =
            ia.into_iter().filter_map(|(k, xs)| ib.get(&k).filter(|ys| ys.len() == xs.len()).map(|ys| (xs, ys.clone()))).collect();
        groups.sort();
        for (mut xs, mut ys) in groups {
            xs.sort_by_key(|&i| self.a[i].address);
            ys.sort_by_key(|&j| self.b[j].address);
            for (i, j) in xs.into_iter().zip(ys) {
                self.add(i, j, 1.0, MatchKind::Order);
            }
        }
    }

    fn fuzzy(&mut self, min_score: f32) {
        let eligible = |p: &FunctionPrint| p.print.instructions >= MIN_INSTRUCTIONS;
        let mut buckets: HashMap<u64, (Vec<usize>, Vec<usize>)> = HashMap::new();
        for (i, p) in self.a.iter().enumerate() {
            if self.a_of[i].is_none() && eligible(p) {
                for k in band_keys(&p.print.minhash) {
                    buckets.entry(k).or_default().0.push(i);
                }
            }
        }
        for (j, p) in self.b.iter().enumerate() {
            if self.b_of[j].is_none() && eligible(p) {
                for k in band_keys(&p.print.minhash) {
                    if let Some(e) = buckets.get_mut(&k) {
                        e.1.push(j);
                    }
                }
            }
        }
        let mut pairs: HashSet<(usize, usize)> = HashSet::new();
        for (xs, ys) in buckets.values() {
            if ys.is_empty() || xs.len() > MAX_BUCKET || ys.len() > MAX_BUCKET {
                continue;
            }
            for &i in xs {
                for &j in ys {
                    pairs.insert((i, j));
                }
            }
        }
        // Ranked by code similarity, with agreeing neighbours breaking ties between
        // look-alike functions (identical small helpers are common).
        let mut scored: Vec<(f32, f32, usize, usize)> = pairs
            .into_iter()
            .map(|(i, j)| (similarity(&self.a[i].print, &self.b[j].print), i, j))
            .filter(|(s, _, _)| *s >= min_score)
            .map(|(s, i, j)| (s + 0.15 * self.context(i, j).0, s, i, j))
            .collect();
        scored.sort_by(|x, y| y.0.total_cmp(&x.0).then(x.2.cmp(&y.2)).then(x.3.cmp(&y.3)));
        for (_, s, i, j) in scored {
            self.add(i, j, s, MatchKind::Fuzzy);
        }
    }
}

fn callers(side: &[FunctionPrint], idx: &HashMap<u64, usize>) -> Vec<Vec<usize>> {
    let mut v = vec![Vec::new(); side.len()];
    for (i, p) in side.iter().enumerate() {
        for c in &p.callees {
            if let Some(&j) = idx.get(c) {
                if !v[j].contains(&i) {
                    v[j].push(i);
                }
            }
        }
    }
    v
}

fn anchor_key(p: &FunctionPrint) -> Option<u64> {
    if p.print.anchors.len() < 2 {
        return None;
    }
    let bytes: Vec<u8> = p.print.anchors.iter().flat_map(|a| a.to_le_bytes()).collect();
    Some(hash_bytes(3, &bytes))
}

/// Matches the functions of two binaries (see the module docs for the passes).
pub fn diff(a: &[FunctionPrint], b: &[FunctionPrint], opts: DiffOptions) -> DiffReport {
    let idx_a: HashMap<u64, usize> = a.iter().enumerate().map(|(i, p)| (p.address, i)).collect();
    let idx_b: HashMap<u64, usize> = b.iter().enumerate().map(|(i, p)| (p.address, i)).collect();
    let (callers_a, callers_b) = (callers(a, &idx_a), callers(b, &idx_b));
    let neighbours = |side: &[FunctionPrint], idx: &HashMap<u64, usize>, callers: &[Vec<usize>]| -> Vec<Vec<usize>> {
        side.iter()
            .enumerate()
            .map(|(i, p)| {
                let mut v: Vec<usize> = p.callees.iter().filter_map(|c| idx.get(c).copied()).chain(callers[i].iter().copied()).collect();
                v.sort_unstable();
                v.dedup();
                v
            })
            .collect()
    };
    let (nbr_a, nbr_b) = (neighbours(a, &idx_a, &callers_a), neighbours(b, &idx_b, &callers_b));
    let mut st = State { a, b, a_of: vec![None; a.len()], b_of: vec![None; b.len()], out: Vec::new(), nbr_a, nbr_b };

    if opts.use_names {
        st.unique_pass(MatchKind::Name, 0.0, &|p| p.named.then(|| hash_bytes(4, p.name.as_bytes())));
    }
    let big = |p: &FunctionPrint| p.print.instructions >= MIN_INSTRUCTIONS;
    st.unique_pass(MatchKind::Exact, 0.0, &|p| big(p).then_some(p.print.exact ^ p.print.size as u64));
    st.unique_pass(MatchKind::Shape, 0.0, &|p| big(p).then_some(p.print.shape));
    st.unique_pass(MatchKind::Anchors, 0.5, &anchor_key);
    st.propagate(&callers_a, &callers_b, &idx_a, &idx_b);
    st.fuzzy(opts.min_score);
    st.propagate(&callers_a, &callers_b, &idx_a, &idx_b);
    st.copies();
    st.propagate(&callers_a, &callers_b, &idx_a, &idx_b);

    let mut matches: Vec<FunctionMatch> = st
        .out
        .iter()
        .map(|&(i, j, score, kind)| FunctionMatch {
            a: a[i].address,
            b: b[j].address,
            a_name: a[i].name.clone(),
            b_name: b[j].name.clone(),
            a_named: a[i].named,
            b_named: b[j].named,
            score,
            kind,
            changed: a[i].print.exact != b[j].print.exact || a[i].print.size != b[j].print.size,
        })
        .collect();
    matches.sort_by_key(|m| m.a);
    let unmatched = |side: &[FunctionPrint], taken: &[Option<usize>]| -> Vec<Unmatched> {
        side.iter()
            .zip(taken)
            .filter(|(_, t)| t.is_none())
            .map(|(p, _)| Unmatched { address: p.address, name: p.name.clone(), instructions: p.print.instructions })
            .collect()
    };
    let total: f64 = a.iter().chain(b).map(|p| p.print.instructions as f64).sum();
    let shared: f64 = st.out.iter().map(|&(i, j, s, _)| s as f64 * (a[i].print.instructions + b[j].print.instructions) as f64).sum();
    DiffReport {
        matches,
        only_a: unmatched(a, &st.a_of),
        only_b: unmatched(b, &st.b_of),
        similarity: if total > 0.0 { (shared / total) as f32 } else { 0.0 },
    }
}
