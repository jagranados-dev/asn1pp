# Public API

This page complements the Doxygen comments in the public headers.

## Object model

Every reusable ASN.1 value derives from `asn1pp::ASN1_Object` and implements
`encode_into()` and `decode_from()`. `DER_Encoder` always emits canonical DER.
`BER_Decoder` accepts BER, while `DER_Decoder` enables strict DER validation.

## BER strings

`BER_Decoder::decode_string_bytes()` accepts primitive and recursively
constructed BER string values with definite or indefinite length. It joins the
fragments while applying the configured element-size and nesting limits.
`BER_Decoder::decode_bit_string()` also enforces the BER rule that only the
final component can contain unused bits. `Octet_String`, `Bit_String`, and the
new PKIX character string classes use these operations automatically.

## Open types

`ASN1_Any` preserves one BER TLV exactly and records whether that encoding is
canonical DER. `Open_Type_Registry` associates object identifiers with concrete
`ASN1_Object` factories. Protocol layers can therefore preserve unknown values
and decode known algorithm parameters, attributes, extensions, and CMS content
without coupling the codec to a particular RFC.

## PKIX and CMS building blocks

`Algorithm_Identifier`, `Attribute`, `Extension`, and `Content_Info` implement
the common ASN.1 structures used by PKIX and CMS. `Directory_String` supports
UTF8String, PrintableString, TeletexString, UniversalString, and BMPString.
`Enumerated<T>` preserves known and unknown numeric values. `Binary_Time`
implements the non-negative INTEGER representation from RFC 6019.

## Constraints

`Sized_Octet_String<Minimum, Maximum>` enforces an ASN.1 SIZE constraint during
assignment and decoding. Schema classes remain responsible for their semantic
constraints, such as permitted enumeration values and relationships between
fields.

## Signed objects

Use `BER_Decoder::get_next_raw_tlv()` before semantic decoding when a protocol
requires the original signed octets. Do not re-encode a received object before
signature verification. X.509 `TBSCertificate`, CMS signed attributes, OCSP
`ResponseData`, and PKCS #10 `CertificationRequestInfo` must be verified using
the protocol-defined encoded octets.
