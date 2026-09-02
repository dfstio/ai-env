# Test fixtures

Generated 2026-08-30 on macOS 26.5.2 (arm64) with **age 1.3.2** and
**age-plugin-se 0.2.1** (Homebrew bottles). The SE identities that produced
these were throwaway (`--access-control=none`) and are device-bound to the
generating Mac; the fixtures only exercise the public header/tag path.

| file | command |
|---|---|
| `test-tag.age` | `echo "hello ai-env gate three" \| age -r $REC -o test-tag.age` |
| `dual.age` | `echo "dual recipient fixture" \| age -r $REC -r $XREC -o dual.age` |
| `foreign.age` | `echo "foreign fixture" \| age -r $REC2 -o foreign.age` |

```
REC  = age1tag1qwww38sn08g0m3x3ue8wh33wa4vs2wcx0427jya9fjrhxa94fxjk7yz4e4r   (age-plugin-se keygen --access-control=none --recipient-type=tag)
REC2 = age1tag1qv5pjtsk9c4p8gw6uhcsz8k2zsm2tvhxl4jq0sa2mu0gy7d4j8lhgwd2tuv   (second key, same command)
XREC = age15csf02ez9ze9xnk3djhm497jwjysdg96tcqwpsn4m5clex767vrs5da5j0        (age-keygen)
```

Frozen known answer (gate G3): `test-tag.age`'s stanza is
`-> p256tag UqDsiQ BA0W0yGw…` and `UqDsiQ` = `52a0ec89` =
`HKDF-Extract-SHA256(salt="age-encryption.org/p256tag", ikm=enc‖SHA256(recip)[..4])[..4]`
with the **RFC argument order** (`Hkdf::extract(Some(salt), ikm)` in Rust).
The reversed (Go-style) order yields `6128bc5f` — if you see that, the
argument order regressed.
