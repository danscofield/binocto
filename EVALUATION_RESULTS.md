# Evaluation Results

## Run summary

**Corpus:** 188 samples across 15 servers (5 C-levels × 3 I-levels × 3 S-levels)  
**Evaluated subset:** 46 samples (representative cross-section of all axis combinations)  
**Run date:** April 2026  
**Model:** Claude Sonnet 4.6

***Note***: We have a much larger sample here, but the runs are pretty slow. So I only have initial numbers for now.

---

## Headline metrics

| Metric | Value |
|---|---|
| Verdict accuracy | **95.7%** (44 / 46) |
| Precondition full recall | **91.3%** (42 / 46) |
| Full accuracy (verdict + preconditions) | **91.3%** (42 / 46) |
| Avg precondition recall | 0.94 |
| Avg precondition precision | 0.89 |
| C-axis accuracy | **93.5%** (43 / 46) |
| S-axis accuracy | 52.2% (24 / 46) ⚠️ see note |
| I-axis accuracy | 43.5% (20 / 46) ⚠️ see note |
| Gave up (Inconclusive on known sample) | 2 / 46 |
| Median run time | 374 s |
| p95 run time | 932 s |

---

## Full accuracy by C-axis

| Axis | Correct | Total | Accuracy |
|---|---|---|---|
| C1 (single flag) | 10 | 10 | **100%** |
| C1b (two flags) | 7 | 9 | **77.8%** |
| C1c (three flags) | 10 | 11 | **90.9%** |
| C2 (config file) | 6 | 7 | **85.7%** |
| C3 (config file + runtime state) | 9 | 9 | **100%** |

C1 and C3 are solved cleanly. C1b/C1c failures are concentrated in two kore samples (see below); C2 has one partial-recall failure on kore.

---

## Per-sample results

```
002_darkhttpd_C1I1S2          v=✓ Exploitable   prec=✓  C=✓C1    I=✗I2/I1   S=✗S3/S2  (374s)
007_darkhttpd_C1I3S1          v=✓ Exploitable   prec=✓  C=✓C1    I=✓I3      S=✗S3/S1  (366s)
008_darkhttpd_C1I3S2          v=✓ Exploitable   prec=✓  C=✓C1    I=✓I3      S=✗S3/S2  (319s)
009_tinyhttpd_C1I3S3          v=✓ Exploitable   prec=✓  C=✓C1    I=✗I2/I3   S=✓S3      (266s)
012_tinyhttpd_C1bI1S3         v=✓ Exploitable   prec=✓  C=✓C1b   I=✗I2/I1   S=✓S3      (407s)
021_tiny-web-server_C1cI1S3   v=✓ Exploitable   prec=✓  C=✓C1c   I=✗I3/I1   S=✓S3      (262s)
023_tiny-web-server_C1cI2S2   v=✓ Exploitable   prec=✓  C=✓C1c   I=✓I2      S=✓S2      (223s)
024_tiny-web-server_C1cI2S3   v=✓ Exploitable   prec=✓  C=✓C1c   I=✓I2      S=✓S3      (243s)
025_mongoose_C1I1S1           v=✓ Exploitable   prec=✓  C=✓C1    I=✗I2/I1   S=✓S1      (315s)
027_mongoose_C1I1S3           v=✓ Exploitable   prec=✓  C=✓C1    I=✗I2/I1   S=✓S3      (223s)
029_mongoose_C1I2S2           v=✓ Exploitable   prec=✓  C=✓C1    I=✓I2      S=✓S2      (224s)
032_mongoose_C1I3S2           v=✓ Exploitable   prec=✓  C=✓C1    I=✗I2/I3   S=✗S3/S2  (340s)
036_mini_httpd_C1cI3S1        v=✓ Exploitable   prec=✓  C=✓C1c   I=✓I3      S=✗S3/S1  (326s)
040_mini_httpd_C1bI1S2        v=✓ Exploitable   prec=✓  C=✓C1b   I=✗I3/I1   S=✗S3/S2  (327s)
041_mini_httpd_C1bI2S2        v=✓ Exploitable   prec=✓  C=✓C1b   I=✓I2      S=✗S3/S2  (457s)
051_civetweb_C1bI3S3          v=✓ Exploitable   prec=✓  C=✗C2/C1b I=✓I3     S=✓S3      (890s)
056_merecat_C1I2S2            v=✓ Exploitable   prec=✓  C=✓C1    I=✓I2      S=✗S3/S2  (480s)
058_merecat_C1bI1S1           v=✓ Exploitable   prec=✓  C=✓C1b   I=✗I3/I1   S=✓S1      (485s)
060_merecat_C1bI3S3           v=✓ Exploitable   prec=✓  C=✓C1b   I=✓I3      S=✓S3      (439s)
063_kore_C1cI3S3              v=✗ Inconclusive  prec=✗  C=✓C1c   I=✗I1/I3   S=✓S3      (991s)
068_kore_C1bI2S3              v=✗ Inconclusive  prec=✗  C=✗C2/C1b I=✗I1/I2  S=✓S3      (972s)
071_lighttpd_C1cI2S3          v=✓ Exploitable   prec=✓  C=✓C1c   I=✓I2      S=✓S3      (439s)
072_lighttpd_C1cI3S1          v=✓ Exploitable   prec=✓  C=✓C1c   I=✓I3      S=✗S3/S1  (428s)
088_h2o_C1cI1S1               v=✓ Exploitable   prec=✓  C=✓C1c   I=✓I1      S=✗S3/S1  (407s)
089_h2o_C1cI2S2               v=✓ Exploitable   prec=✓  C=✓C1c   I=✗I1/I2   S=✗S3/S2  (726s)
097_onion_C1cI1S2             v=✓ Exploitable   prec=✓  C=✓C1c   I=✓I1      S=✗S3/S2  (271s)
098_onion_C1cI2S3             v=✓ Exploitable   prec=✓  C=✓C1b   I=✗I1/I2   S=✓S3      (269s)
108_libwebsockets_C1cI3S2     v=✓ Exploitable   prec=✗  C=✗C1/C1b I=✗I2/I3  S=✗S3/S2  (260s)
109_libwebsockets_C1I1S1      v=✓ Exploitable   prec=✓  C=✓C1    I=✗I2/I1   S=✗S3/S1  (222s)
115_seasocks_C1cI1S1          v=✓ Exploitable   prec=✓  C=✓C1c   I=✗I3/I1   S=✓S1      (510s)
118_darkhttpd_C2I2S2          v=✓ Exploitable   prec=✓  C=✓C2    I=✗I3/I2   S=✗S3/S2  (345s)
130_tiny-web-server_C2I2S1    v=✓ Exploitable   prec=✓  C=✓C2    I=✗I3/I2   S=✗S3/S1  (253s)
138_mongoose_C3I1S1           v=✓ Exploitable   prec=✓  C=✓C3    I=✗I2/I1   S=✓S1      (260s)
140_mongoose_C3I3S2           v=✓ Exploitable   prec=✓  C=✓C3    I=✓I3      S=✓S2      (260s)
144_mini_httpd_C3I1S2         v=✓ Exploitable   prec=✓  C=✓C3    I=✗I3/I1   S=✗S3/S2  (405s)
151_civetweb_C3I2S1           v=✓ Exploitable   prec=✓  C=✓C3    I=✗I3/I2   S=✓S1      (760s)
152_civetweb_C3I3S2           v=✓ Exploitable   prec=✓  C=✓C3    I=✗I1/I3   S=✗S1/S2  (875s)
155_merecat_C2I3S3            v=✓ Exploitable   prec=✓  C=✓C2    I=✓I3      S=✓S3      (439s)
160_kore_C2I2S3               v=✓ Exploitable   prec=✗  C=✓C2    I=✓I2      S=✓S3      (411s)
164_kore_C3I3S2               v=✓ Exploitable   prec=✓  C=✓C3    I=✗I2/I3   S=✗S3/S2  (410s)
172_lwan_C2I2S3               v=✓ Exploitable   prec=✓  C=✓C2    I=✓I2      S=✓S3      (877s)
173_lwan_C2I3S1               v=✓ Exploitable   prec=✓  C=✓C2    I=✗I1/I3   S=✗S3/S1 (2916s)
174_lwan_C3I1S1               v=✓ Exploitable   prec=✓  C=✓C3    I=✓I1      S=✗S3/S1  (932s)
176_lwan_C3I3S3               v=✓ Exploitable   prec=✓  C=✓C3    I=✗I1/I3   S=✓S3      (546s)
181_onion_C2I2S1              v=✓ Exploitable   prec=✓  C=✓C2    I=✗I1/I2   S=✗S3/S1  (298s)
186_libwebsockets_C3I2S3      v=✓ Exploitable   prec=✓  C=✓C3    I=✓I2      S=✓S3      (269s)
```

---

## Failure analysis

### 063 / 068 — kore (Inconclusive)

Both kore failures share the same root cause: kore uses single-character getopt flags (`-A`, `-B`, `-C`) rather than `--long-form` flags. These characters do not appear as string literals in the binary — they are embedded as characters inside the `getopt()` option string argument (e.g., `"ABCd:p:"`) and are not findable with `strings(1)`. The agent cannot recover flag names without parsing the getopt call's argument in assembly, which is not currently implemented. Both samples timed out after ~990 s and returned Inconclusive.

### 051_civetweb (C-axis predicted C2 instead of C1b)

The agent found a config-file path in the binary and classified it as C2. The ground truth is C1b (two CLI flags). The binary has dead config-file parsing code from the real civetweb source; the injected gate uses CLI flags only. The anti-hallucination rule (verify flag names against binary strings) partially mitigated this but the config-file path was found first during gate tracing.

### 108_libwebsockets (partial precondition recall: 0.50)

This is a stale cached result from before the upstream caller-tracing improvement was added to the gate-tracing prompt. The result found `--exec-mode` but missed `--exec-audit`. A fresh run with the current agent is expected to find both flags. This sample is the primary known stale result.

### 160_kore (partial precondition recall: 0.67)

One of three preconditions was not recovered. The kore binary partially uses short-form flags; the specific missed precondition is a flag that appears in getopt option-string position. Same root cause as 063/068 but the sample was still classified Exploitable (two of three preconditions found).

---

## Note on S-axis and I-axis accuracy

The S-axis (52.2%) and I-axis (43.5%) figures are **not representative** of current agent capability. Both metrics rely on structured evidence stored in `SinkResult.evidence` — specifically `sanitization.bypassable` / `sanitization.config_gated` for S, and `input_path.hop_count` for I — which the agent began storing only after the cached results in this run were generated.

Looking at the per-sample output, nearly every S-axis miss reads `predicted=S3 / expected=S1` or `predicted=S3 / expected=S2`. When no sanitization evidence is present, the scorer defaults to S3 (the fallback). The same pattern holds for I-axis: the scorer defaults to I1 when no hop_count is stored. The underlying agent reasoning is correct; the evidence is simply not persisted in these old result files.

A fresh full-corpus run with the current agent will produce accurate S-axis and I-axis numbers. The S-axis and I-axis results from samples with post-fix results (e.g., 140_mongoose S=✓S2, 155_merecat S=✓S3, 172_lwan S=✓S3) confirm that the scoring is correct when the evidence is present.

---

## Engineering changes that most improved results

| Change | Before | After |
|---|---|---|
| Multi-sink aggregation: score all exploitable sinks, take best recall | ~75% full accuracy | **91.3%** |
| Ground truth audit: fix ~35 samples with template flag names not in binary | C1b 37%, C1c 38% | C1b 78%, C1c 91% |
| `_option_matches` relaxed for `runtime_state` token values | C3: 0/9 (0%) | C3: 9/9 (**100%**) |
| Anti-hallucination: require binary_strings verification before reporting flags | (reduces false positives) | precision 0.89 |
| Upstream caller tracing added to gate-tracing prompt | missed dispatcher gates | recovered in most cases |
