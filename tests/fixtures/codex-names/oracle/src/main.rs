// Reads corpus.json (an array of { id, doc, ... }) on stdin and prints one JSON object per document:
//   { "id": ..., "codexName": <string or null> }
// `codexName` is the `name` that Codex's own frontmatter parser (skills/src/parser.rs, parse_skill_frontmatter_metadata,
// rust-v0.166.0) returns, or null when the parser rejects the document or returns no name.
// Usage: cargo run --release < ../corpus.json > recorded.jsonl
use std::io::Read;

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).expect("stdin");
    let corpus: serde_json::Value = serde_json::from_str(&input).expect("corpus.json");
    for entry in corpus.as_array().expect("array") {
        let id = entry["id"].as_str().expect("id");
        let doc = entry["doc"].as_str().expect("doc");
        let name = match codex_skills::parse_skill_frontmatter_metadata(doc) {
            Ok(meta) => meta.name.map(serde_json::Value::from).unwrap_or(serde_json::Value::Null),
            Err(_) => serde_json::Value::Null,
        };
        println!("{}", serde_json::json!({ "id": id, "codexName": name }));
    }
}
