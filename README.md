# Email-link measurement core artifact

The public release contains the core logic of Algorithms 1 and 2, the 26 construction patterns (77,208 entries), MR assessment, image-region comparison and local result aggregation.

## Email samples

Each attack technique is accompanied by 10 attack samples and 10 paired reference samples. In consideration of the relevant vendors' vulnerability disclosure policies and restrictions on the scope of publicly released attack materials, this artifact provides representative samples rather than publishing every test email. The paper specifies the mutation rules, parameter ranges and construction counts in full. Together with the message structures and payload carriers illustrated by the public samples, these rules enable generation of the complete EML test-input space defined in this paper.

The release contains 140 EML files in total. They are redacted display samples. From and To are both `redacted@example.com`. Date is omitted. MIME base64 preserves the inserted characters; message lines use CRLF. The files contain message data, not SMTP session commands.

```sh
python code/build_emails.py --samples --out eml_samples
python code/verify_artifact.py
```

Python 3.9+ and Pillow are required. The verifier checks catalog consistency, sample formatting and file integrity offline. `prepare_eml.py` updates mailbox headers and the Date header while preserving the decoded message body.

## Core code

`algorithm_flow.py` presents the core flow of Algorithms 1 and 2: input construction, target/pair iteration, observation, MR assessment and result recording. `configuration.py` provides the external-parameter reader. `mr_assessment.py` and `compare_regions.py` implement relation assessment and image-region comparison; `aggregate_results.py` summarizes supplied result records.

`construction_parameters.md` describes input ranges. `code_paper_mapping.md` maps the core to the paper. `eml_samples/INDEX.md` lists the sample pairs. `SHA256SUMS` inventories the public files.
