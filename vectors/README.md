# Test vectors

## `acvp/`: NIST ACVP vectors for FIPS 203

Copied unmodified from NIST's ACVP-Server repository, pinned to commit
`975de31eb83d87039ec88934fdc47d8c312b892d`:

| Local file | Upstream path |
|---|---|
| `keyGen-internalProjection.json` | `gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json` |
| `encapDecap-internalProjection.json` | `gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json` |

Download URLs:

```
https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json
https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json
```

An `internalProjection.json` contains each test's inputs *and* expected
outputs (the same content as `prompt.json` + `expectedResults.json`).
The encapDecap file is marked `"isSample": true` by NIST: it is a sample
vector set, which is what is published publicly.

Contents (240 cases), all run by `crates/mlkem/tests/acvp.rs`:

| Group | Cases | What is checked |
|---|---:|---|
| keyGen | 75 | KeyGen_internal(d, z) = (ek, dk) |
| encapsulation | 75 | Encaps_internal(ek, m) = (c, K) |
| decapsulation | 30 | Decaps(dk, c) = K; 15 use a modified c (implicit rejection) |
| encapsulationKeyCheck | 30 | §7.2 modulus check; 15 keys have values ≥ q |
| decapsulationKeyCheck | 30 | §7.3 hash check; 15 keys have a modified H(ek) |

Verify the files are unchanged:

```powershell
Get-FileHash vectors\acvp\*.json -Algorithm SHA256
```

and compare with `acvp/SHA256SUMS`.
