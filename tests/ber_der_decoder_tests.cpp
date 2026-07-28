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
#include <span>
#include <string>
#include <vector>

#include <asn1pp/asn1pp.hpp>
#include <catch2/catch_test_macros.hpp>

#include "test_helpers.hpp"

using asn1pp::test::bytes;

TEST_CASE ( "BER decoder accepts non-canonical true while DER decoder rejects it", "[ber][der][decoder][boolean]" )
{
    const std::vector < uint8_t > encoded { 0x01, 0x01, 0x01 };
    bool value = false;

    asn1pp::BER_Decoder ber ( encoded );
    REQUIRE_NOTHROW ( ber.decode ( value ) );
    REQUIRE ( value );

    asn1pp::DER_Decoder der ( encoded );
    REQUIRE_THROWS_AS ( der.decode ( value ), asn1pp::ASN1_DecodingError );
    REQUIRE ( der.remaining () == encoded.size () );
}

TEST_CASE ( "DER decoder rejects non-minimal INTEGER sign extension", "[der][decoder][integer]" )
{
    const std::vector < uint8_t > positive { 0x02, 0x02, 0x00, 0x7F };
    const std::vector < uint8_t > negative { 0x02, 0x02, 0xFF, 0x80 };
    int64_t value = 0;

    asn1pp::DER_Decoder positive_decoder ( positive );
    REQUIRE_THROWS_AS ( positive_decoder.decode ( value ), asn1pp::ASN1_DecodingError );

    asn1pp::DER_Decoder negative_decoder ( negative );
    REQUIRE_THROWS_AS ( negative_decoder.decode ( value ), asn1pp::ASN1_DecodingError );
}

TEST_CASE ( "BER decoder accepts redundant INTEGER sign extension", "[ber][decoder][integer]" )
{
    const std::vector < uint8_t > positive { 0x02, 0x02, 0x00, 0x7F };
    const std::vector < uint8_t > negative { 0x02, 0x02, 0xFF, 0x80 };
    int64_t value = 0;

    asn1pp::BER_Decoder positive_decoder ( positive );
    positive_decoder.decode ( value );
    REQUIRE ( value == 127 );

    asn1pp::BER_Decoder negative_decoder ( negative );
    negative_decoder.decode ( value );
    REQUIRE ( value == -128 );
}

TEST_CASE ( "Unsigned INTEGER decoder handles UINT64_MAX and rejects negative values", "[ber][decoder][integer]" )
{
    const std::vector < uint8_t > maximum {
        0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };
    const std::vector < uint8_t > negative { 0x02, 0x01, 0xFF };
    uint64_t value = 0;

    asn1pp::DER_Decoder maximum_decoder ( maximum );
    maximum_decoder.decode ( value );
    REQUIRE ( value == std::numeric_limits < uint64_t >::max () );

    asn1pp::BER_Decoder negative_decoder ( negative );
    REQUIRE_THROWS_AS ( negative_decoder.decode ( value ), asn1pp::ASN1_DecodingError );
}

TEST_CASE ( "DER decoder rejects non-minimal length encodings", "[der][decoder][length]" )
{
    const std::vector < uint8_t > short_value_in_long_form { 0x04, 0x81, 0x01, 0x00 };
    const std::vector < uint8_t > leading_zero { 0x04, 0x82, 0x00, 0x80 };

    asn1pp::DER_Decoder first ( short_value_in_long_form );
    REQUIRE_THROWS_AS ( first.get_next_object (), asn1pp::ASN1_DecodingError );

    asn1pp::DER_Decoder second ( leading_zero );
    REQUIRE_THROWS_AS ( second.get_next_object (), asn1pp::ASN1_DecodingError );
}

TEST_CASE ( "BER decoder handles constructed indefinite-length SEQUENCE", "[ber][decoder][indefinite]" )
{
    const std::vector < uint8_t > encoded { 0x30, 0x80, 0x02, 0x01, 0x2A, 0x00, 0x00 };
    uint64_t value = 0;

    asn1pp::BER_Decoder decoder ( encoded );
    decoder.decode_sequence ( [&] ( asn1pp::BER_Decoder& sequence )
    {
        sequence.decode ( value );
    } );

    REQUIRE ( value == 42 );
    REQUIRE_FALSE ( decoder.more_items () );
}

TEST_CASE ( "DER decoder rejects indefinite length and BER rejects primitive indefinite length", "[ber][der][decoder][indefinite]" )
{
    const std::vector < uint8_t > constructed { 0x30, 0x80, 0x00, 0x00 };
    const std::vector < uint8_t > primitive { 0x04, 0x80, 0x00, 0x00 };

    asn1pp::DER_Decoder der ( constructed );
    REQUIRE_THROWS_AS ( der.get_next_object (), asn1pp::ASN1_DecodingError );

    asn1pp::BER_Decoder ber ( primitive );
    REQUIRE_THROWS_AS ( ber.get_next_object (), asn1pp::ASN1_DecodingError );
}

TEST_CASE ( "Standalone and malformed EOC values are rejected", "[ber][decoder][eoc]" )
{
    const std::vector < uint8_t > standalone { 0x00, 0x00 };
    const std::vector < uint8_t > malformed { 0x00, 0x01, 0x00 };

    asn1pp::BER_Decoder first ( standalone );
    REQUIRE_THROWS_AS ( first.get_next_object (), asn1pp::ASN1_DecodingError );

    asn1pp::BER_Decoder second ( malformed );
    REQUIRE_THROWS_AS ( second.get_next_object (), asn1pp::ASN1_DecodingError );
}

TEST_CASE ( "Decoder parses high-tag-number form and rejects non-minimal forms", "[ber][decoder][tag]" )
{
    const std::vector < uint8_t > valid { 0x9F, 0x81, 0x49, 0x01, 0x2A };
    const std::vector < uint8_t > leading_zero_group { 0x9F, 0x80, 0x1F, 0x00 };
    const std::vector < uint8_t > short_tag_in_long_form { 0x9F, 0x1E, 0x00 };

    asn1pp::BER_Decoder decoder ( valid );
    const auto header = decoder.peek_next_header ();
    REQUIRE ( header.has_value () );
    REQUIRE ( header->tag.tag_class == asn1pp::ASN1_TagClass::CONTEXT_SPECIFIC );
    REQUIRE ( header->tag.number == 201 );
    REQUIRE_FALSE ( header->tag.constructed );

    asn1pp::BER_Decoder first_invalid ( leading_zero_group );
    REQUIRE_THROWS_AS ( first_invalid.get_next_object (), asn1pp::ASN1_DecodingError );

    asn1pp::BER_Decoder second_invalid ( short_tag_in_long_form );
    REQUIRE_THROWS_AS ( second_invalid.get_next_object (), asn1pp::ASN1_DecodingError );
}

TEST_CASE ( "Decoder operations are transactional on failure", "[ber][decoder][transaction]" )
{
    const std::vector < uint8_t > invalid_boolean { 0x01, 0x02, 0x00, 0x00 };
    bool value = false;
    asn1pp::BER_Decoder decoder ( invalid_boolean );

    REQUIRE_THROWS_AS ( decoder.decode ( value ), asn1pp::ASN1_DecodingError );
    REQUIRE ( decoder.remaining () == invalid_boolean.size () );
}

TEST_CASE ( "Constructed decoder rejects unconsumed child values transactionally", "[ber][decoder][sequence]" )
{
    const std::vector < uint8_t > encoded { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
    uint64_t first = 0;
    asn1pp::DER_Decoder decoder ( encoded );

    REQUIRE_THROWS_AS (
        decoder.decode_sequence ( [&] ( asn1pp::BER_Decoder& sequence )
        {
            sequence.decode ( first );
        } ),
        asn1pp::ASN1_DecodingError
    );
    REQUIRE ( decoder.remaining () == encoded.size () );
}

TEST_CASE ( "decode_view borrows primitive content and advances the decoder", "[ber][decoder][view]" )
{
    const std::vector < uint8_t > encoded { 0x04, 0x03, 0x01, 0x02, 0x03 };
    asn1pp::DER_Decoder decoder ( encoded );
    std::span < const uint8_t > view;

    decoder.decode_view ( view );

    REQUIRE ( std::vector < uint8_t > ( view.begin (), view.end () ) == bytes ( { 0x01, 0x02, 0x03 } ) );
    REQUIRE_FALSE ( decoder.more_items () );
}

TEST_CASE ( "Raw TLV extraction returns exactly one encoded object", "[ber][decoder][raw]" )
{
    const std::vector < uint8_t > encoded { 0x05, 0x00, 0x02, 0x01, 0x01 };
    asn1pp::BER_Decoder decoder ( encoded );

    REQUIRE ( decoder.get_next_raw_tlv () == bytes ( { 0x05, 0x00 } ) );
    REQUIRE ( decoder.get_next_raw_tlv () == bytes ( { 0x02, 0x01, 0x01 } ) );
    REQUIRE_FALSE ( decoder.more_items () );
}

TEST_CASE ( "DER SET OF ordering validator accepts sorted and rejects unsorted encodings", "[der][decoder][set-of]" )
{
    const std::vector < uint8_t > sorted { 0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
    const std::vector < uint8_t > unsorted { 0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01 };

    asn1pp::DER_Decoder first ( sorted );
    REQUIRE_NOTHROW ( first.decode_set ( [] ( asn1pp::BER_Decoder& set )
    {
        set.validate_set_of_order ();
        while ( set.more_items () )
        {
            uint64_t value = 0;
            set.decode ( value );
        }
    } ) );

    asn1pp::DER_Decoder second ( unsorted );
    REQUIRE_THROWS_AS ( second.decode_set ( [] ( asn1pp::BER_Decoder& set )
    {
        set.validate_set_of_order ();
    } ), asn1pp::ASN1_DecodingError );
}

TEST_CASE ( "Decoder rejects every truncated prefix of a valid TLV", "[ber][decoder][truncation]" )
{
    const std::vector < uint8_t > valid { 0x04, 0x82, 0x01, 0x00 };
    std::vector < uint8_t > complete = valid;
    complete.insert ( complete.end (), 256, 0xA5 );

    for ( size_t length = 0; length < complete.size (); ++length )
    {
        const std::span < const uint8_t > prefix ( complete.data (), length );
        asn1pp::BER_Decoder decoder ( prefix );
        std::vector < uint8_t > value;
        REQUIRE_THROWS_AS ( decoder.decode ( value ), asn1pp::ASN1_DecodingError );
    }
}

TEST_CASE ( "Decoder enforces input, element, item, and tag limits", "[ber][decoder][limits]" )
{
    asn1pp::BER_DecoderLimits input_limits;
    input_limits.max_input_size = 2;
    const std::vector < uint8_t > three_octets { 0x02, 0x01, 0x00 };
    REQUIRE_THROWS_AS ( asn1pp::BER_Decoder ( three_octets, input_limits ), asn1pp::ASN1_DecodingError );

    asn1pp::BER_DecoderLimits item_limits;
    item_limits.max_items = 0;
    asn1pp::BER_Decoder item_decoder ( three_octets, item_limits );
    uint64_t value = 0;
    REQUIRE_THROWS_AS ( item_decoder.decode ( value ), asn1pp::ASN1_DecodingError );

    asn1pp::BER_DecoderLimits tag_limits;
    tag_limits.max_tag_octets = 1;
    const std::vector < uint8_t > long_tag { 0x9F, 0x81, 0x49, 0x00 };
    asn1pp::BER_Decoder tag_decoder ( long_tag, tag_limits );
    REQUIRE_THROWS_AS ( tag_decoder.get_next_object (), asn1pp::ASN1_DecodingError );
}

TEST_CASE ( "Decoder reports tag mismatches without consuming input", "[ber][decoder][tag][transaction]" )
{
    const std::vector < uint8_t > encoded { 0x04, 0x01, 0x2A };
    uint64_t value = 0;
    asn1pp::BER_Decoder decoder ( encoded );

    REQUIRE_THROWS_AS ( decoder.decode ( value ), asn1pp::ASN1_DecodingError );
    REQUIRE ( decoder.remaining () == encoded.size () );
}

TEST_CASE ( "NULL decoder rejects non-empty contents", "[ber][decoder][null]" )
{
    const std::vector < uint8_t > encoded { 0x05, 0x01, 0x00 };
    asn1pp::BER_Decoder decoder ( encoded );

    REQUIRE_THROWS_AS ( decoder.decode_null (), asn1pp::ASN1_DecodingError );
    REQUIRE ( decoder.remaining () == encoded.size () );
}

TEST_CASE ( "Malformed OPTIONAL headers are errors rather than absent fields", "[ber][decoder][optional]" )
{
    const std::vector < uint8_t > truncated { 0x0C };
    asn1pp::BER_Decoder decoder ( truncated );
    std::optional < asn1pp::UTF8_String > value;

    REQUIRE_THROWS_AS (
        decoder.decode_optional ( value, asn1pp::ASN1_Type::UTF8_STRING ),
        asn1pp::ASN1_DecodingError
    );
}

TEST_CASE ( "Decoder enforces element, length, integer, and depth limits", "[ber][decoder][limits]" )
{
    asn1pp::BER_DecoderLimits element_limits;
    element_limits.max_element_size = 1;
    const std::vector < uint8_t > octets { 0x04, 0x02, 0x00, 0x00 };
    asn1pp::BER_Decoder element_decoder ( octets, element_limits );
    REQUIRE_THROWS_AS ( element_decoder.get_next_object (), asn1pp::ASN1_DecodingError );

    asn1pp::BER_DecoderLimits length_limits;
    length_limits.max_length_octets = 1;
    const std::vector < uint8_t > long_length { 0x04, 0x82, 0x01, 0x00 };
    asn1pp::BER_Decoder length_decoder ( long_length, length_limits );
    REQUIRE_THROWS_AS ( length_decoder.get_next_object (), asn1pp::ASN1_DecodingError );

    asn1pp::BER_DecoderLimits integer_limits;
    integer_limits.max_integer_octets = 1;
    const std::vector < uint8_t > integer { 0x02, 0x02, 0x00, 0x80 };
    asn1pp::BER_Decoder integer_decoder ( integer, integer_limits );
    uint64_t value = 0;
    REQUIRE_THROWS_AS ( integer_decoder.decode ( value ), asn1pp::ASN1_DecodingError );

    asn1pp::BER_DecoderLimits depth_limits;
    depth_limits.max_depth = 1;
    const std::vector < uint8_t > nested_indefinite {
        0x30, 0x80, 0x30, 0x80, 0x00, 0x00, 0x00, 0x00
    };
    asn1pp::BER_Decoder depth_decoder ( nested_indefinite, depth_limits );
    REQUIRE_THROWS_AS ( depth_decoder.get_next_object (), asn1pp::ASN1_DecodingError );
}
