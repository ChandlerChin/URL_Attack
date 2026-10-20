# Code-to-paper correspondence

| Component | Module | Role |
|---|---|---|
| Input enumeration | construct_pairs.py, dictionaries.py | 26 patterns, 77,208 parameterized entries |
| Paired messages | build_emails.py | Reference/attack MIME serialization |
| Algorithm 1 | algorithm_flow.algorithm1 | Construct, iterate targets/pairs, delivery boundary, link observations, MR1, record |
| Algorithm 2 | algorithm_flow.algorithm2 | Construct, iterate targets/pairs, delivery boundary, warning or image branch, MR2/MR3, record |
| Assessment | execution.py, mr_assessment.py | Validate supplied observations and apply relations |
| Images | compare_regions.py | Fixed-region MD5 comparison |
| Summary | aggregate_results.py | Aggregate supplied local result records |
| External parameters | configuration.py | Read private environment parameters; no values distributed |
| Verification | verify_artifact.py | Offline catalog, MIME, sample and integrity checks |

TargetOperations is intentionally unimplemented: both algorithms stop at delivery when called with a target. No delivery, browser or Windows automation implementation is included. The code is available for inspection of the core method; this release cannot independently execute the historical measurement.
