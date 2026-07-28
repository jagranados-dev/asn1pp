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

TEST_CASE ( "DER encoder emits canonical BOOLEAN values", "[der][encoder][boolean][x690]" )
{
    asn1pp::DER_Encoder encoder;
    encoder.encode ( false ).encode ( true );

    REQUIRE ( encoder.get_contents () == bytes ( { 0x01, 0x01, 0x00, 0x01, 0x01, 0xFF } ) );
}

TEST_CASE ( "DER encoder emits minimal signed INTEGER values", "[der][encoder][integer][x690]" )
{
    const std::vector < std::pair < int64_t, std::vector < uint8_t > > > vectors {
        { 0, bytes ( { 0x02, 0x01, 0x00 } ) },
        { 127, bytes ( { 0x02, 0x01, 0x7F } ) },
        { 128, bytes ( { 0x02, 0x02, 0x00, 0x80 } ) },
        { -1, bytes ( { 0x02, 0x01, 0xFF } ) },
        { -128, bytes ( { 0x02, 0x01, 0x80 } ) },
        { -129, bytes ( { 0x02, 0x02, 0xFF, 0x7F } ) },
        { std::numeric_limits < int64_t >::min (),
          bytes ( { 0x02, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } ) },
        { std::numeric_limits < int64_t >::max (),
          bytes ( { 0x02, 0x08, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } ) }
    };

    for ( const auto& [ value, expected ] : vectors )
    {
        asn1pp::DER_Encoder encoder;
        encoder.encode ( value );
        REQUIRE ( encoder.get_contents () == expected );
    }
}

TEST_CASE ( "DER encoder emits canonical unsigned INTEGER boundaries", "[der][encoder][integer]" )
{
    asn1pp::DER_Encoder encoder;
    encoder.encode ( std::numeric_limits < uint64_t >::max () );

    REQUIRE ( encoder.get_contents () == bytes ( {
        0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    } ) );
}

TEST_CASE ( "DER encoder uses canonical short and long length forms", "[der][encoder][length][x690]" )
{
    const std::vector < size_t > lengths { 0, 1, 127, 128, 255, 256 };
    const std::vector < std::vector < uint8_t > > prefixes {
        bytes ( { 0x04, 0x00 } ),
        bytes ( { 0x04, 0x01 } ),
        bytes ( { 0x04, 0x7F } ),
        bytes ( { 0x04, 0x81, 0x80 } ),
        bytes ( { 0x04, 0x81, 0xFF } ),
        bytes ( { 0x04, 0x82, 0x01, 0x00 } )
    };

    for ( size_t i = 0; i < lengths.size (); ++i )
    {
        asn1pp::DER_Encoder encoder;
        encoder.encode ( std::vector < uint8_t > ( lengths [ i ], 0xA5 ) );
        const std::vector < uint8_t > encoded = encoder.get_contents ();

        REQUIRE ( encoded.size () >= prefixes [ i ].size () );
        REQUIRE ( std::equal ( prefixes [ i ].begin (), prefixes [ i ].end (), encoded.begin () ) );
    }
}

TEST_CASE ( "DER encoder supports high-tag-number identifiers", "[der][encoder][tag]" )
{
    asn1pp::DER_Encoder encoder;
    const std::vector < uint8_t > value { 0x2A };
    encoder.add_object ( { asn1pp::ASN1_TagClass::CONTEXT_SPECIFIC, false, 201 }, value );

    REQUIRE ( encoder.get_contents () == bytes ( { 0x9F, 0x81, 0x49, 0x01, 0x2A } ) );
}

TEST_CASE ( "DER SET OF sorts complete element encodings lexicographically", "[der][encoder][set-of]" )
{
    asn1pp::DER_Encoder encoder;
    encoder.encode_set_of ( [] ( asn1pp::DER_Encoder& set )
    {
        set.encode ( uint64_t ( 2 ) );
        set.encode ( uint64_t ( 1 ) );
    } );

    REQUIRE ( encoder.get_contents () == bytes ( {
        0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02
    } ) );
}

TEST_CASE ( "DER encoder validates pre-encoded TLV input", "[der][encoder][raw]" )
{
    asn1pp::DER_Encoder encoder;
    const std::vector < uint8_t > valid { 0x05, 0x00 };
    const std::vector < uint8_t > two_values { 0x05, 0x00, 0x05, 0x00 };
    const std::vector < uint8_t > non_canonical_length { 0x04, 0x81, 0x01, 0x00 };

    REQUIRE_NOTHROW ( encoder.append_encoded_tlv ( valid ) );
    REQUIRE_THROWS_AS ( encoder.append_encoded_tlv ( two_values ), asn1pp::ASN1_EncodingError );
    REQUIRE_THROWS_AS ( encoder.append_encoded_tlv ( non_canonical_length ), asn1pp::ASN1_DecodingError );
}

TEST_CASE ( "DER encoder enforces output limits", "[der][encoder][limits]" )
{
    asn1pp::DER_EncoderLimits limits;
    limits.max_output_size = 3;
    asn1pp::DER_Encoder encoder ( limits );

    REQUIRE_THROWS_AS ( encoder.encode ( std::vector < uint8_t > { 0x01, 0x02 } ), asn1pp::ASN1_EncodingError );
}

TEST_CASE ( "DER encoder enforces constructed nesting depth", "[der][encoder][limits]" )
{
    asn1pp::DER_EncoderLimits limits;
    limits.max_depth = 1;
    asn1pp::DER_Encoder encoder ( limits );

    REQUIRE_THROWS_AS (
        encoder.encode_sequence ( [] ( asn1pp::DER_Encoder& outer )
        {
            outer.encode_sequence ( [] ( asn1pp::DER_Encoder& inner )
            {
                inner.encode_null ();
            } );
        } ),
        asn1pp::ASN1_EncodingError
    );
}
