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
#include <vector>

#include <asn1pp/asn1pp.hpp>
#include <catch2/catch_test_macros.hpp>

#include "test_helpers.hpp"

using asn1pp::test::bytes;
using asn1pp::test::encode;

TEST_CASE ( "Sequence_Of preserves element order", "[sequence-of]" )
{
    asn1pp::Sequence_Of < asn1pp::IA5_String > sequence;
    sequence.values.emplace_back ( "first" );
    sequence.values.emplace_back ( "second" );

    const std::vector < uint8_t > encoded = encode ( sequence );
    asn1pp::DER_Decoder decoder ( encoded );
    asn1pp::Sequence_Of < asn1pp::IA5_String > decoded;
    decoder.decode ( decoded );

    REQUIRE ( decoded.values.size () == 2 );
    REQUIRE ( decoded.values [ 0 ].value () == "first" );
    REQUIRE ( decoded.values [ 1 ].value () == "second" );
}

TEST_CASE ( "Set_Of emits canonical DER order and decoder exposes encoded order", "[set-of]" )
{
    asn1pp::Set_Of < asn1pp::Printable_String > set;
    set.values.emplace_back ( "Signing" );
    set.values.emplace_back ( "Administrator" );
    set.values.emplace_back ( "Encryption" );

    const std::vector < uint8_t > encoded = encode ( set );
    asn1pp::DER_Decoder decoder ( encoded );
    asn1pp::Set_Of < asn1pp::Printable_String > decoded;
    decoder.decode ( decoded );

    REQUIRE ( decoded.values.size () == 3 );
    REQUIRE ( decoded.values [ 0 ].value () == "Signing" );
    REQUIRE ( decoded.values [ 1 ].value () == "Encryption" );
    REQUIRE ( decoded.values [ 2 ].value () == "Administrator" );
}

TEST_CASE ( "OPTIONAL encoder and decoder preserve presence and absence", "[optional]" )
{
    const std::optional < asn1pp::UTF8_String > present ( asn1pp::UTF8_String ( "comment" ) );
    const std::optional < asn1pp::UTF8_String > absent;

    asn1pp::DER_Encoder encoder;
    encoder.encode_sequence ( [&] ( asn1pp::DER_Encoder& sequence )
    {
        sequence.encode_optional ( present );
        sequence.encode_optional ( absent );
    } );

    std::optional < asn1pp::UTF8_String > decoded_present;
    std::optional < asn1pp::UTF8_String > decoded_absent;
    asn1pp::DER_Decoder decoder ( encoder.contents () );
    decoder.decode_sequence ( [&] ( asn1pp::BER_Decoder& sequence )
    {
        sequence.decode_optional ( decoded_present, asn1pp::ASN1_Type::UTF8_STRING );
        sequence.decode_optional ( decoded_absent, asn1pp::ASN1_Type::UTF8_STRING );
    } );

    REQUIRE ( decoded_present.has_value () );
    REQUIRE ( decoded_present->value () == "comment" );
    REQUIRE_FALSE ( decoded_absent.has_value () );
}

TEST_CASE ( "DEFAULT encoder omits default and decoder restores it", "[default]" )
{
    asn1pp::DER_Encoder encoder;
    encoder.encode_sequence ( [] ( asn1pp::DER_Encoder& sequence )
    {
        sequence.encode_default ( false, false );
        sequence.encode_default ( true, false );
    } );

    REQUIRE ( encoder.get_contents () == bytes ( { 0x30, 0x03, 0x01, 0x01, 0xFF } ) );

    bool defaulted = true;
    bool encoded = false;
    asn1pp::DER_Decoder decoder ( encoder.contents () );
    decoder.decode_sequence ( [&] ( asn1pp::BER_Decoder& sequence )
    {
        sequence.decode_default ( defaulted, false, asn1pp::ASN1_Type::INTEGER );
        sequence.decode_default ( encoded, false, asn1pp::ASN1_Type::BOOLEAN );
    } );

    REQUIRE_FALSE ( defaulted );
    REQUIRE ( encoded );
}

TEST_CASE ( "ASN1_Object convenience encoders return the same canonical DER", "[object][der]" )
{
    const asn1pp::OID oid ( "1.2.840.113549.1.1.11" );

    REQUIRE ( oid.DER_encode () == oid.BER_encode () );
    REQUIRE ( oid.DER_encode () == encode ( oid ) );
}
