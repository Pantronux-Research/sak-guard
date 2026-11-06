# Security Policy

## Reporting a vulnerability

Report privately through GitHub's
**[private vulnerability reporting](https://github.com/Pantronux-Research/sak-guard/security/advisories/new)**
rather than opening a public issue. This keeps the report and any reproduction out of
public view until a fix is available.

Please include: affected version or commit, the input that triggers the behaviour, what
you expected, and what happened. A minimal reproducing file is worth more than a long
description.

**There is no dedicated security mailbox yet.** Once a lab address exists it will be
listed here; until then the private advisory form above is the only channel, and it is
monitored.

## Scope

**In scope** — defects that make `sak-guard` unsafe or misleading as a security tool:

- a **false negative** on a pattern the README claims to detect (the tool says clean
  when the code is vulnerable);
- a **crash, hang, or unbounded resource use** caused by auditing hostile input;
- the engine **executing or importing** the code it audits, or otherwise escaping static
  analysis (it must never run the target);
- a packaging defect that installs something other than the reviewed source.

**Out of scope** — misses that are *disclosed* limitations. The README documents the
detection envelope: `sak-guard` is static analysis and cannot see runtime state,
economic conditions, or on-chain state. A vulnerability in one of those classes is not a
bug in this tool, and reporting it as one wastes your time and ours.

## What we commit to

`sak-guard` is a security tool, so its own failure modes matter as much as its
detections:

1. **We publish false negatives and false positives**, not just detection rates. A tool
   that overstates coverage is itself a risk, and a green check must not be readable as
   a guarantee.
2. **We will not weaken a detector to make numbers look better.** Any detection removed
   is documented in the changelog with its reason.
3. **This tool must never execute the code it audits.** Anything that changes that is
   treated as a critical vulnerability regardless of its other effects.

## Supported versions

Pre-1.0: only the latest release and `main` receive fixes.

| Version | Supported |
|---|---|
| 0.1.x-alpha | yes |
| < 0.1 | no |
