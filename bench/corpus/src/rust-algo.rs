// Benchmark corpus sample: a deterministic Rust program that exercises std
// collections, iterators, trait objects, error handling and formatting.
use std::collections::{BTreeMap, HashMap};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Item {
    name: String,
    score: u64,
    tags: Vec<String>,
}

trait Scorer {
    fn score(&self, item: &Item) -> u64;
    fn label(&self) -> &'static str;
}

struct Baseline;
struct Weighted {
    weights: HashMap<String, u64>,
}

impl Scorer for Baseline {
    fn score(&self, item: &Item) -> u64 {
        item.score + item.name.len() as u64
    }
    fn label(&self) -> &'static str {
        "baseline"
    }
}

impl Scorer for Weighted {
    fn score(&self, item: &Item) -> u64 {
        let base = item.score + item.name.len() as u64;
        item.tags.iter().filter_map(|t| self.weights.get(t)).fold(base, |acc, w| acc + w)
    }
    fn label(&self) -> &'static str {
        "weighted"
    }
}

#[derive(Debug)]
enum ParseError {
    Empty,
    BadNumber(String),
    MissingField(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => write!(f, "empty line"),
            ParseError::BadNumber(s) => write!(f, "bad number: {s}"),
            ParseError::MissingField(s) => write!(f, "missing field: {s}"),
        }
    }
}

fn parse_line(line: &str) -> Result<Item, ParseError> {
    let line = line.trim();
    if line.is_empty() {
        return Err(ParseError::Empty);
    }
    let mut parts = line.split('|');
    let name = parts.next().ok_or(ParseError::MissingField("name"))?.to_string();
    let raw = parts.next().ok_or(ParseError::MissingField("score"))?;
    let score: u64 = raw.parse().map_err(|_| ParseError::BadNumber(raw.to_string()))?;
    let tags = parts.next().map(|t| t.split(',').map(str::to_string).collect()).unwrap_or_default();
    Ok(Item { name, score, tags })
}

fn dedupe(items: Vec<Item>) -> Vec<Item> {
    let mut seen = HashMap::new();
    for item in items {
        seen.entry(item.name.clone()).or_insert(item);
    }
    let mut out: Vec<Item> = seen.into_values().collect();
    out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.name.cmp(&b.name)));
    out
}

fn histogram(items: &[Item]) -> BTreeMap<char, usize> {
    let mut hist = BTreeMap::new();
    for item in items {
        for ch in item.name.chars() {
            *hist.entry(ch).or_insert(0) += 1;
        }
    }
    hist
}

fn run() -> Result<String, Box<dyn std::error::Error>> {
    let raw = "alpha|10|x,y\nbeta|7|y\ngamma|10|z\nbeta|9|y,w\nalpha|3|w\n";
    let items: Vec<Item> = raw.lines().filter_map(|l| parse_line(l).ok()).collect();
    let mut weighted = Weighted { weights: HashMap::new() };
    weighted.weights.insert("w".into(), 5);
    weighted.weights.insert("y".into(), 1);
    let scorer: &dyn Scorer = if items.len() % 2 == 0 { &Baseline } else { &weighted };
    let scored: Vec<Item> = dedupe(items)
        .into_iter()
        .map(|mut it| {
            it.score = scorer.score(&it);
            it
        })
        .collect();
    let hist = histogram(&scored);
    let top = scored.iter().take(3).map(|i| format!("{}:{}", i.name, i.score)).collect::<Vec<_>>().join(", ");
    Ok(format!("{} [{}] top {} hist {}", scorer.label(), scored.len(), top, hist.len()))
}

fn main() {
    match run() {
        Ok(line) => println!("{line}"),
        Err(e) => eprintln!("error: {e}"),
    }
}
