// Benchmark corpus sample: the smallest useful Rust+std program.
fn greet(name: &str) -> String {
    format!("hello, {name}")
}

fn main() {
    let names = ["world", "bench"];
    for n in names {
        println!("{}", greet(n));
    }
    let sum: u64 = (1..=100u64).filter(|v| v % 3 == 0).sum();
    println!("sum={sum}");
}
