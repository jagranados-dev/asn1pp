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

#include <optional>
#include <sstream>
#include <vector>

#include <asn1pp/asn1pp.hpp>
#include <catch2/catch_test_macros.hpp>

#include "test_helpers.hpp"

namespace
{

    using Tagged_OID = asn1pp::Implicit_Tagged <
        asn1pp::OID,
        asn1pp::ASN1_Tag { asn1pp::ASN1_TagClass::CONTEXT_SPECIFIC, false, 0 },
        asn1pp::ASN1_Tag { asn1pp::ASN1_TagClass::UNIVERSAL, false, 6 }
    >;

    using Tagged_OID_Sequence = asn1pp::Implicit_Tagged <
        asn1pp::Sequence_Of < asn1pp::OID >,
        asn1pp::ASN1_Tag { asn1pp::ASN1_TagClass::CONTEXT_SPECIFIC, true, 2 },
        asn1pp::ASN1_Tag { asn1pp::ASN1_TagClass::UNIVERSAL, true, 16 }
    >;

    using Explicit_Octets = asn1pp::Explicit_Tagged <
        asn1pp::Octet_String,
        asn1pp::ASN1_Tag { asn1pp::ASN1_TagClass::CONTEXT_SPECIFIC, true, 1 }
    >;

    using High_Tag_Explicit_OID = asn1pp::Explicit_Tagged <
        asn1pp::OID,
        asn1pp::ASN1_Tag { asn1pp::ASN1_TagClass::APPLICATION, true, 201 }
    >;

    using Subject = asn1pp::Choice_Of <
        asn1pp::Choice_Alternative <
            Tagged_OID,
            asn1pp::ASN1_Tag { asn1pp::ASN1_TagClass::CONTEXT_SPECIFIC, false, 0 },
            "identifier"
        >,
        asn1pp::Choice_Alternative <
            Explicit_Octets,
            asn1pp::ASN1_Tag { asn1pp::ASN1_TagClass::CONTEXT_SPECIFIC, true, 1 },
            "payload"
        >
    >;

} // namespace

TEST_CASE ( "Implicit tagging replaces primitive identifiers", "[tagging][implicit][primitive]" )
{
    const Tagged_OID original ( asn1pp::OID ( "1.2.3" ) );
    const std::vector < uint8_t > encoded = original.DER_encode ();

    REQUIRE ( encoded == asn1pp::test::bytes ( { 0x80, 0x02, 0x2A, 0x03 } ) );

    asn1pp::DER_Decoder decoder ( encoded );
    Tagged_OID decoded;
    decoder.decode ( decoded );

    REQUIRE ( decoded == original );
    REQUIRE_FALSE ( decoder.more_items () );
}

TEST_CASE ( "Implicit tagging replaces constructed identifiers", "[tagging][implicit][constructed]" )
{
    asn1pp::Sequence_Of < asn1pp::OID > sequence;
    sequence.values.emplace_back ( "1.2.3" );
    sequence.values.emplace_back ( "1.2.840.113549.1.1.11" );
    const Tagged_OID_Sequence original ( sequence );
    const std::vector < uint8_t > encoded = original.DER_encode ();

    REQUIRE ( encoded.front () == 0xA2 );

    asn1pp::DER_Decoder decoder ( encoded );
    Tagged_OID_Sequence decoded;
    decoder.decode ( decoded );

    REQUIRE ( decoded == original );
}

TEST_CASE ( "Explicit tagging adds a constructed wrapper", "[tagging][explicit]" )
{
    const Explicit_Octets original (
        asn1pp::Octet_String ( asn1pp::test::bytes ( { 0xDE, 0xAD } ) )
    );
    const std::vector < uint8_t > encoded = original.DER_encode ();

    REQUIRE ( encoded == asn1pp::test::bytes ( { 0xA1, 0x04, 0x04, 0x02, 0xDE, 0xAD } ) );

    asn1pp::DER_Decoder decoder ( encoded );
    Explicit_Octets decoded;
    decoder.decode ( decoded );

    REQUIRE ( decoded == original );
}

TEST_CASE ( "Tagged wrappers support high tag numbers and non-context classes", "[tagging][high-tag]" )
{
    const High_Tag_Explicit_OID original ( asn1pp::OID ( "1.2.3" ) );
    const std::vector < uint8_t > encoded = original.DER_encode ();

    REQUIRE ( encoded == asn1pp::test::bytes ( { 0x7F, 0x81, 0x49, 0x04, 0x06, 0x02, 0x2A, 0x03 } ) );

    asn1pp::DER_Decoder decoder ( encoded );
    High_Tag_Explicit_OID decoded;
    decoder.decode ( decoded );
    REQUIRE ( decoded == original );
}

TEST_CASE ( "Tagging failures are transactional", "[tagging][transaction]" )
{
    const std::vector < uint8_t > wrong_tag { 0x81, 0x02, 0x2A, 0x03 };
    asn1pp::DER_Decoder decoder ( wrong_tag );
    Tagged_OID value;

    REQUIRE_THROWS_AS ( decoder.decode ( value ), asn1pp::ASN1_DecodingError );
    REQUIRE ( decoder.remaining () == wrong_tag.size () );
}

TEST_CASE ( "CHOICE selects alternatives by effective identifier", "[choice]" )
{
    Subject original;
    original.emplace < Tagged_OID > ( asn1pp::OID ( "1.2.3" ) );

    REQUIRE ( original.has_value () );
    REQUIRE ( original.index () == 0 );
    REQUIRE ( original.holds_alternative < Tagged_OID > () );

    const std::vector < uint8_t > encoded = original.DER_encode ();
    asn1pp::DER_Decoder decoder ( encoded );
    Subject decoded;
    decoder.decode ( decoded );

    REQUIRE ( decoded == original );
    REQUIRE ( decoded.get < Tagged_OID > ().value ().to_string () == "1.2.3" );
}

TEST_CASE ( "CHOICE alternatives encode without an additional wrapper", "[choice][der]" )
{
    const Tagged_OID tagged_oid ( asn1pp::OID ( "1.2.3" ) );
    Subject choice ( tagged_oid );

    REQUIRE ( choice.DER_encode () == tagged_oid.DER_encode () );

    choice.emplace < Explicit_Octets > (
        asn1pp::Octet_String ( asn1pp::test::bytes ( { 0x01, 0x02 } ) )
    );
    REQUIRE ( choice.DER_encode () == choice.get < Explicit_Octets > ().DER_encode () );
}

TEST_CASE ( "Empty and unknown CHOICE values are rejected", "[choice][errors]" )
{
    Subject empty;
    REQUIRE_THROWS_AS ( (void) empty.DER_encode (), asn1pp::ASN1_EncodingError );

    const std::vector < uint8_t > unknown { 0x82, 0x00 };
    asn1pp::DER_Decoder decoder ( unknown );
    Subject decoded;

    REQUIRE_THROWS_AS ( decoder.decode ( decoded ), asn1pp::ASN1_DecodingError );
    REQUIRE ( decoder.remaining () == unknown.size () );
}

TEST_CASE ( "CHOICE integrates with SEQUENCE and OPTIONAL", "[choice][sequence][optional]" )
{
    const std::optional < Subject > present (
        Subject ( Tagged_OID ( asn1pp::OID ( "1.2.3" ) ) )
    );
    const std::optional < Subject > absent;

    asn1pp::DER_Encoder encoder;
    encoder.encode_sequence ( [&] ( asn1pp::DER_Encoder& sequence )
    {
        sequence.encode_optional ( present );
        sequence.encode_optional ( absent );
    } );

    const std::vector < uint8_t > encoded = encoder.get_contents ();
    asn1pp::DER_Decoder decoder ( encoded );
    Subject decoded;
    decoder.decode_sequence ( [&] ( asn1pp::BER_Decoder& sequence )
    {
        sequence.decode ( decoded );
    } );

    REQUIRE ( decoded == *present );
}

TEST_CASE ( "CHOICE stream output includes the stable alternative name", "[choice][stream]" )
{
    Subject choice ( Tagged_OID ( asn1pp::OID ( "1.2.3" ) ) );
    std::ostringstream stream;
    stream << choice;

    REQUIRE ( stream.str () == "choice[identifier]=1.2.3" );
}
