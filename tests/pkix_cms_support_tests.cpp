/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <cstdint>
#include <vector>

#include <asn1pp/asn1pp.hpp>
#include <catch2/catch_test_macros.hpp>

namespace
{

    enum class Status : int64_t
    {
        successful = 0,
        malformed_request = 1
    };

} // namespace

TEST_CASE ("BER constructed OCTET STRING fragments are concatenated", "[ber][octet-string][cms]")
{
    const std::vector < uint8_t > encoded {
        0x24, 0x80,
        0x04, 0x02, 'a', 'b',
        0x24, 0x03, 0x04, 0x01, 'c',
        0x00, 0x00
    };
    asn1pp::BER_Decoder decoder (encoded);
    asn1pp::Octet_String value;
    decoder.decode (value);
    REQUIRE (value.value () == std::vector < uint8_t > {'a', 'b', 'c'});
}

TEST_CASE ("DER rejects constructed OCTET STRING", "[der][octet-string][cms]")
{
    const std::vector < uint8_t > encoded {0x24, 0x03, 0x04, 0x01, 0x00};
    asn1pp::DER_Decoder decoder (encoded);
    asn1pp::Octet_String value;
    REQUIRE_THROWS_AS (decoder.decode (value), asn1pp::ASN1_DecodingError);
}

TEST_CASE ("BER constructed BIT STRING preserves final unused bits", "[ber][bit-string]")
{
    const std::vector < uint8_t > encoded {
        0x23, 0x80,
        0x03, 0x02, 0x00, 0xAA,
        0x03, 0x02, 0x04, 0xB0,
        0x00, 0x00
    };
    asn1pp::BER_Decoder decoder (encoded);
    asn1pp::Bit_String value;
    decoder.decode (value);
    REQUIRE (value.bytes () == std::vector < uint8_t > {0xAA, 0xB0});
    REQUIRE (value.unused_bits () == 4);
}

TEST_CASE ("ENUMERATED provides a type-safe DER round trip", "[der][enumerated][ocsp]")
{
    const asn1pp::Enumerated < Status > original (Status::malformed_request);
    const std::vector < uint8_t > encoded = original.DER_encode ();
    asn1pp::DER_Decoder decoder (encoded);
    asn1pp::Enumerated < Status > decoded;
    decoder.decode (decoded);
    REQUIRE (decoded.value () == Status::malformed_request);
}

TEST_CASE ("ASN1 ANY preserves non-canonical BER", "[ber][any][cms]")
{
    const std::vector < uint8_t > encoded {0x01, 0x01, 0x01};
    const asn1pp::ASN1_Any value (encoded);
    REQUIRE (value.encoded_tlv () == encoded);
    REQUIRE_FALSE (value.is_der_canonical ());
    REQUIRE_THROWS_AS (value.DER_encode (), asn1pp::ASN1_EncodingError);
}

TEST_CASE ("RFC 8954 nonce constraint accepts one through thirty-two octets", "[constraint][ocsp]")
{
    using Nonce = asn1pp::Sized_Octet_String < 1, 32 >;
    const std::vector < uint8_t > minimum (1, 0xA5);
    const std::vector < uint8_t > maximum (32, 0xA5);
    const std::vector < uint8_t > too_large (33, 0xA5);
    REQUIRE_NOTHROW (Nonce (minimum));
    REQUIRE_NOTHROW (Nonce (maximum));
    REQUIRE_THROWS_AS (Nonce (too_large), asn1pp::ASN1_InvalidArgument);
}
