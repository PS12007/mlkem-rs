//! Official NIST ACVP test vectors for FIPS 203 (ML-KEM).
//!
//! Source: https://github.com/usnistgov/ACVP-Server, directory
//! gen-val/json-files/ML-KEM-{keyGen,encapDecap}-FIPS203/, file
//! internalProjection.json (inputs and expected outputs together), at
//! commit 975de31eb83d87039ec88934fdc47d8c312b892d. Copies and SHA-256
//! hashes are in vectors/acvp/. See vectors/README.md.
//!
//! Every test case in both files is run, and the counts are checked so a
//! case cannot be skipped silently.

mod common;

use common::{by_name, hex_decode, hex32};
use serde_json::Value;

fn load(file: &str) -> Value {
    let path = format!("{}/../../vectors/acvp/{file}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).expect("valid JSON")
}

fn s<'a>(t: &'a Value, key: &str) -> &'a str {
    t[key].as_str().unwrap_or_else(|| panic!("missing {key}"))
}

/// ML-KEM.KeyGen_internal(d, z) must give exactly ek and dk.
#[test]
fn acvp_keygen() {
    let v = load("keyGen-internalProjection.json");
    assert_eq!(v["revision"], "FIPS203");
    let mut n = 0;
    for g in v["testGroups"].as_array().unwrap() {
        let kem = by_name(s(g, "parameterSet"));
        for t in g["tests"].as_array().unwrap() {
            let (ek, dk) = kem.keygen_internal(&hex32(s(t, "d")), &hex32(s(t, "z")));
            let id = &t["tcId"];
            assert_eq!(ek, hex_decode(s(t, "ek")), "tcId {id}: ek");
            assert_eq!(dk, hex_decode(s(t, "dk")), "tcId {id}: dk");
            n += 1;
        }
    }
    assert_eq!(n, 75, "3 parameter sets x 25 cases");
}

#[test]
fn acvp_encap_decap() {
    let v = load("encapDecap-internalProjection.json");
    assert_eq!(v["revision"], "FIPS203");
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for g in v["testGroups"].as_array().unwrap() {
        let kem = by_name(s(g, "parameterSet"));
        let function = s(g, "function");
        for t in g["tests"].as_array().unwrap() {
            let id = &t["tcId"];
            match function {
                // ML-KEM.Encaps_internal(ek, m) must give exactly c and K.
                "encapsulation" => {
                    let (c, k) = kem
                        .encaps_internal(&hex_decode(s(t, "ek")), &hex32(s(t, "m")))
                        .unwrap_or_else(|| panic!("tcId {id}: valid ek rejected"));
                    assert_eq!(c, hex_decode(s(t, "c")), "tcId {id}: c");
                    assert_eq!(k, hex32(s(t, "k")), "tcId {id}: k");
                }
                // ML-KEM.Decaps(dk, c) must give K, which for a modified
                // ciphertext is the implicit-rejection key J(z || c).
                "decapsulation" => {
                    let k = kem
                        .decaps(&hex_decode(s(t, "dk")), &hex_decode(s(t, "c")))
                        .unwrap_or_else(|| panic!("tcId {id}: valid dk/c rejected"));
                    assert_eq!(k, hex32(s(t, "k")), "tcId {id} ({})", s(t, "reason"));
                }
                // §7.2 / §7.3 input checks: accept or reject as expected.
                "encapsulationKeyCheck" => {
                    let want = t["testPassed"].as_bool().unwrap();
                    let got = kem.ek_check(&hex_decode(s(t, "ek")));
                    assert_eq!(got, want, "tcId {id} ({})", s(t, "reason"));
                }
                "decapsulationKeyCheck" => {
                    let want = t["testPassed"].as_bool().unwrap();
                    let got = kem.dk_check(&hex_decode(s(t, "dk")));
                    assert_eq!(got, want, "tcId {id} ({})", s(t, "reason"));
                }
                other => panic!("unknown function {other}"),
            }
            *counts.entry(function.to_string()).or_default() += 1;
        }
    }
    let expected: std::collections::BTreeMap<String, usize> = [
        ("encapsulation", 75),
        ("decapsulation", 30),
        ("encapsulationKeyCheck", 30),
        ("decapsulationKeyCheck", 30),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    assert_eq!(counts, expected);
}
