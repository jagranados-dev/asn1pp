# Security policy

ASN.1 decoders process potentially hostile binary input. Security reports should include the affected version, a minimal reproducer, expected behavior, actual behavior, and sanitizer output when available.

Do not publish an uncoordinated proof of concept for memory corruption, resource exhaustion, or parser state corruption before a fix is available.

The project treats the following as security-sensitive:

- integer overflow and out-of-bounds access;
- excessive allocation, recursion, or item counts;
- incorrect acceptance of malformed BER or non-canonical DER;
- transactional decoder failures that consume input;
- lifetime errors involving borrowed `std::span` values.
