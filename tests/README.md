# ASN.1 Test Suite

This suite exercises every public value object and the BER/DER codec engine.

## Coverage groups

- `[errors]`, `[metadata]`, and `[limits]`: structured errors, identifiers, and resource policies.
- `[der][encoder]`: canonical primitive values, lengths, identifiers, SET OF ordering, raw TLV validation, and limits.
- `[ber][decoder]`: BER permissiveness, indefinite lengths, EOC, high tags, transactionality, truncation, borrowed views, raw TLVs, and limits.
- `[der][decoder]`: canonical BOOLEAN, INTEGER, length, indefinite-length, and SET OF rejection paths.
- `[big-int]`, `[bit-string]`, `[octet-string]`, `[utf8-string]`, `[ia5-string]`, `[printable-string]`, `[any]`, `[time]`, and `[oid]`: semantic value objects.
- `[sequence-of]`, `[set-of]`, `[optional]`, and `[default]`: reusable ASN.1 containers and field semantics.

## Standards-derived vectors

The suite includes:

- INTEGER boundary encodings and identifier/length rules from ITU-T X.690.
- The OBJECT IDENTIFIER `1.0.8571.2.1`, encoded as `06 05 28 C2 7B 02 01`.
- The `sha256WithRSAEncryption` OBJECT IDENTIFIER `1.2.840.113549.1.1.11` used by PKIX.
- Canonical UTCTime and GeneralizedTime forms used by RFC 5280.

References:

- ITU-T X.690 (2021): https://www.itu.int/rec/T-REC-X.690
- RFC 5280: https://www.rfc-editor.org/rfc/rfc5280

