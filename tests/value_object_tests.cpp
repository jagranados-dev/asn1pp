/*********************************************************************************
 * MIT License
 *
 * Copyright (c) 2026 Jose Alberto Granados
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *********************************************************************************/

#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include <asn1pp/asn1pp.hpp>
#include <catch2/catch_test_macros.hpp>

#include "test_helpers.hpp"

using asn1pp::test::bytes;
using asn1pp::test::encode;

TEST_CASE ( "Big_Int encodes official INTEGER boundary forms", "[big-int][integer][x690]" )
{
    REQUIRE ( encode ( asn1pp::Big_Int ( "0" ) ) == bytes ( { 0x02, 0x01, 0x00 } ) );
    REQUIRE ( encode ( asn1pp::Big_Int ( "127" ) ) == bytes ( { 0x02, 0x01, 0x7F } ) );
    REQUIRE ( encode ( asn1pp::Big_Int ( "128" ) ) == bytes ( { 0x02, 0x02, 0x00, 0x80 } ) );
    REQUIRE ( encode ( asn1pp::Big_Int ( "-128" ) ) == bytes ( { 0x02, 0x01, 0x80 } ) );
    REQUIRE ( encode ( asn1pp::Big_Int ( "-129" ) ) == bytes ( { 0x02, 0x02, 0xFF, 0x7F } ) );
}

TEST_CASE ( "Big_Int supports arbitrary decimal round trips", "[big-int]" )
{
    const std::vector < std::string > values {
        "0",
        "1",
        "-1",
        "1234567890123456789012345678901234567890",
        "-1234567890123456789012345678901234567890"
    };

    for ( const std::string& value : values )
    {
        const asn1pp::Big_Int integer ( value );
        REQUIRE ( integer.to_decimal () == value );

        const std::vector < uint8_t > encoded = encode ( integer );
        asn1pp::DER_Decoder decoder ( encoded );
        asn1pp::Big_Int decoded;
        decoder.decode ( decoded );
        REQUIRE ( decoded.bytes () == integer.bytes () );
    }
}

TEST_CASE ( "Big_Int canonicalizes redundant sign extension", "[big-int]" )
{
    asn1pp::Big_Int positive;
    positive.set_bytes ( bytes ( { 0x00, 0x00, 0x7F } ) );
    REQUIRE ( positive.bytes () == bytes ( { 0x7F } ) );

    asn1pp::Big_Int negative;
    negative.set_bytes ( bytes ( { 0xFF, 0xFF, 0x80 } ) );
    REQUIRE ( negative.bytes () == bytes ( { 0x80 } ) );

    REQUIRE_THROWS_AS ( positive.set_bytes ( std::span < const uint8_t > () ), asn1pp::ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( positive.set_decimal ( "" ), asn1pp::ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( positive.set_decimal ( "12x" ), asn1pp::ASN1_InvalidArgument );
}

TEST_CASE ( "Bit_String encodes and decodes unused bits", "[bit-string][x690]" )
{
    const asn1pp::Bit_String value ( bytes ( { 0xA0 } ), 4 );
    REQUIRE ( value.bit_count () == 4 );
    REQUIRE ( value.unused_bits () == 4 );
    REQUIRE ( encode ( value ) == bytes ( { 0x03, 0x02, 0x04, 0xA0 } ) );

    const std::vector < uint8_t > encoded { 0x03, 0x02, 0x04, 0xA0 };
    asn1pp::DER_Decoder decoder ( encoded );
    asn1pp::Bit_String decoded;
    decoder.decode ( decoded );
    REQUIRE ( decoded.bytes () == value.bytes () );
    REQUIRE ( decoded.unused_bits () == value.unused_bits () );
}

TEST_CASE ( "Bit_String rejects invalid unused-bit state", "[bit-string]" )
{
    REQUIRE_THROWS_AS ( asn1pp::Bit_String ( bytes ( { 0x00 } ), 8 ), asn1pp::ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( asn1pp::Bit_String ( bytes ( {} ), 1 ), asn1pp::ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( asn1pp::Bit_String ( bytes ( { 0x01 } ), 1 ), asn1pp::ASN1_InvalidArgument );

    const std::vector < uint8_t > missing_unused_count { 0x03, 0x00 };
    asn1pp::DER_Decoder decoder ( missing_unused_count );
    asn1pp::Bit_String value;
    REQUIRE_THROWS_AS ( decoder.decode ( value ), asn1pp::ASN1_DecodingError );
}

TEST_CASE ( "Octet_String preserves arbitrary octets", "[octet-string]" )
{
    const asn1pp::Octet_String value ( bytes ( { 0x00, 0x7F, 0x80, 0xFF } ) );
    REQUIRE ( encode ( value ) == bytes ( { 0x04, 0x04, 0x00, 0x7F, 0x80, 0xFF } ) );

    const std::vector < uint8_t > encoded = encode ( value );
    asn1pp::DER_Decoder decoder ( encoded );
    asn1pp::Octet_String decoded;
    decoder.decode ( decoded );
    REQUIRE ( decoded.value () == value.value () );
}

TEST_CASE ( "UTF8_String accepts valid Unicode scalar values", "[utf8-string]" )
{
    const std::string text = "ASCII \xE2\x82\xAC \xF0\x9F\x98\x80";
    const asn1pp::UTF8_String value ( text );
    REQUIRE ( value.value () == text );

    const std::vector < uint8_t > encoded = encode ( value );
    asn1pp::DER_Decoder decoder ( encoded );
    asn1pp::UTF8_String decoded;
    decoder.decode ( decoded );
    REQUIRE ( decoded.value () == text );
}

TEST_CASE ( "UTF8_String rejects malformed Unicode encodings", "[utf8-string]" )
{
    REQUIRE_THROWS_AS ( asn1pp::UTF8_String ( "\x80" ), asn1pp::ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( asn1pp::UTF8_String ( "\xC0\x80" ), asn1pp::ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( asn1pp::UTF8_String ( "\xE2\x82" ), asn1pp::ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( asn1pp::UTF8_String ( "\xED\xA0\x80" ), asn1pp::ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( asn1pp::UTF8_String ( "\xF4\x90\x80\x80" ), asn1pp::ASN1_InvalidArgument );
}

TEST_CASE ( "IA5_String accepts ASCII and rejects non-ASCII octets", "[ia5-string]" )
{
    const asn1pp::IA5_String valid ( "test@example.com" );
    REQUIRE ( encode ( valid ) == bytes ( {
        0x16, 0x10, 't', 'e', 's', 't', '@', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'
    } ) );
    REQUIRE_THROWS_AS ( asn1pp::IA5_String ( "\xC3\xB1" ), asn1pp::ASN1_InvalidArgument );
}

TEST_CASE ( "Printable_String enforces its restricted alphabet", "[printable-string]" )
{
    const asn1pp::Printable_String valid ( "AZaz09 '()+,-./:=?" );
    REQUIRE ( valid.value () == "AZaz09 '()+,-./:=?" );
    REQUIRE_THROWS_AS ( asn1pp::Printable_String ( "invalid@value" ), asn1pp::ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( asn1pp::Printable_String ( "invalid_value" ), asn1pp::ASN1_InvalidArgument );
}

TEST_CASE ( "ASN1_Any preserves one complete DER TLV", "[any]" )
{
    const std::vector < uint8_t > encoded { 0x05, 0x00 };
    const asn1pp::ASN1_Any value ( encoded );
    REQUIRE ( value.encoded_tlv () == encoded );
    REQUIRE ( encode ( value ) == encoded );

    asn1pp::DER_Decoder decoder ( encoded );
    asn1pp::ASN1_Any decoded;
    decoder.decode ( decoded );
    REQUIRE ( decoded.encoded_tlv () == encoded );
}

TEST_CASE ( "ASN1_Any rejects empty and multiple values", "[any]" )
{
    REQUIRE_THROWS_AS ( asn1pp::ASN1_Any ( std::span < const uint8_t > () ), asn1pp::ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( asn1pp::ASN1_Any ( bytes ( { 0x05, 0x00, 0x05, 0x00 } ) ), asn1pp::ASN1_InvalidArgument );
}

TEST_CASE ( "ASN1_Any preserves BER and reports DER canonicality", "[any][ber][der]" )
{
    const std::vector < uint8_t > encoded = bytes ( { 0x01, 0x01, 0x01 } );
    const asn1pp::ASN1_Any value ( encoded );
    REQUIRE ( value.encoded_tlv () == encoded );
    REQUIRE_FALSE ( value.is_der_canonical () );
    REQUIRE_THROWS_AS ( value.DER_encode (), asn1pp::ASN1_EncodingError );

    asn1pp::BER_Decoder ber ( encoded );
    asn1pp::ASN1_Any decoded;
    ber.decode ( decoded );
    REQUIRE ( decoded == value );

    asn1pp::DER_Decoder der ( encoded );
    REQUIRE_THROWS_AS ( der.decode ( decoded ), asn1pp::ASN1_DecodingError );
    REQUIRE ( der.remaining () == encoded.size () );
}

TEST_CASE ( "ASN1_Time encodes RFC 5280 canonical time forms", "[time][rfc5280]" )
{
    const asn1pp::ASN1_Time utc ( asn1pp::ASN1_TimeType::UTC, "910506234540Z" );
    const asn1pp::ASN1_Time generalized ( asn1pp::ASN1_TimeType::GENERALIZED, "20500101000000Z" );

    REQUIRE ( encode ( utc ) == bytes ( {
        0x17, 0x0D, '9', '1', '0', '5', '0', '6', '2', '3', '4', '5', '4', '0', 'Z'
    } ) );
    REQUIRE ( encode ( generalized ) == bytes ( {
        0x18, 0x0F, '2', '0', '5', '0', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'
    } ) );
}

TEST_CASE ( "ASN1_Time validates calendar dates and time ranges", "[time]" )
{
    REQUIRE_NOTHROW ( asn1pp::ASN1_Time ( asn1pp::ASN1_TimeType::GENERALIZED, "20240229010203Z" ) );
    REQUIRE_THROWS_AS ( asn1pp::ASN1_Time ( asn1pp::ASN1_TimeType::GENERALIZED, "20230229010203Z" ), asn1pp::ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( asn1pp::ASN1_Time ( asn1pp::ASN1_TimeType::UTC, "500230000000Z" ), asn1pp::ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( asn1pp::ASN1_Time ( asn1pp::ASN1_TimeType::UTC, "500101240000Z" ), asn1pp::ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( asn1pp::ASN1_Time ( asn1pp::ASN1_TimeType::UTC, "500101000060Z" ), asn1pp::ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( asn1pp::ASN1_Time ( asn1pp::ASN1_TimeType::UTC, "500101000000+0100" ), asn1pp::ASN1_InvalidArgument );
}

TEST_CASE ( "ASN1_Time selects the encoded universal time type", "[time]" )
{
    const std::vector < uint8_t > utc_encoded {
        0x17, 0x0D, '9', '1', '0', '5', '0', '6', '2', '3', '4', '5', '4', '0', 'Z'
    };
    const std::vector < uint8_t > generalized_encoded {
        0x18, 0x0F, '2', '0', '5', '0', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'
    };

    asn1pp::ASN1_Time utc;
    asn1pp::DER_Decoder utc_decoder ( utc_encoded );
    utc_decoder.decode ( utc );
    REQUIRE ( utc.type () == asn1pp::ASN1_TimeType::UTC );

    asn1pp::ASN1_Time generalized;
    asn1pp::DER_Decoder generalized_decoder ( generalized_encoded );
    generalized_decoder.decode ( generalized );
    REQUIRE ( generalized.type () == asn1pp::ASN1_TimeType::GENERALIZED );
}

TEST_CASE ( "OID encodes the X.690 1.0.8571.2.1 example", "[oid][x690]" )
{
    const asn1pp::OID oid ( "1.0.8571.2.1" );
    REQUIRE ( encode ( oid ) == bytes ( { 0x06, 0x05, 0x28, 0xC2, 0x7B, 0x02, 0x01 } ) );
    REQUIRE ( oid.to_string () == "1.0.8571.2.1" );
}

TEST_CASE ( "OID encodes common RFC 5280 algorithm identifiers", "[oid][rfc5280]" )
{
    const asn1pp::OID sha256_with_rsa ( "1.2.840.113549.1.1.11" );
    REQUIRE ( encode ( sha256_with_rsa ) == bytes ( {
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B
    } ) );
}

TEST_CASE ( "OID validates roots, syntax, minimal base-128 form, and overflow", "[oid]" )
{
    REQUIRE_THROWS_AS ( asn1pp::OID ( "" ), asn1pp::ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( asn1pp::OID ( "3.1" ), asn1pp::ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( asn1pp::OID ( "1.40" ), asn1pp::ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( asn1pp::OID ( "1..2" ), asn1pp::ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( asn1pp::OID ( "1.a.2" ), asn1pp::ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( asn1pp::OID ( "2.18446744073709551616" ), asn1pp::ASN1_InvalidArgument );

    const std::vector < uint8_t > non_minimal { 0x06, 0x02, 0x80, 0x2A };
    asn1pp::DER_Decoder decoder ( non_minimal );
    asn1pp::OID oid;
    REQUIRE_THROWS_AS ( decoder.decode ( oid ), asn1pp::ASN1_DecodingError );
}
