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

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/asn1_types.hpp>
#include <asn1pp/der_encoder.hpp>
#include <asn1pp/ia5_string.hpp>
#include <asn1pp/printable_string.hpp>
#include <asn1pp/raw_value.hpp>
#include <asn1pp/sequence_of.hpp>
#include <asn1pp/set_of.hpp>

using namespace asn1pp;

//-----------------------------------------------------------------------------
// 1. PRIMITIVE TYPES ENCODING
//-----------------------------------------------------------------------------

TEST_CASE ( "Encode Boolean values canonical DER representations", "[enc-bool]" )
{
    DER_Encoder encoder;
    encoder.encode ( true )
           .encode ( false );

    const std::vector < uint8_t > expected = {
        0x01, 0x01, 0xFF, // BOOLEAN True (DER strictly requires 0xFF)
        0x01, 0x01, 0x00  // BOOLEAN False (0x00)
    };

    REQUIRE ( encoder.get_contents () == expected );
}

TEST_CASE ( "Encode unsigned integer with and without sign bit padding", "[enc-uint]" )
{
    DER_Encoder encoder;
    // 127 (0x7F) -> MSB is 0, no padding needed
    encoder.encode ( static_cast < uint64_t > ( 127 ) );
    // 128 (0x80) -> MSB is 1, requires 0x00 prepend byte to keep it evaluated as positive
    encoder.encode ( static_cast < uint64_t > ( 128 ) );

    const std::vector < uint8_t > expected = {
        0x02, 0x01, 0x7F,       // INTEGER 127
        0x02, 0x02, 0x00, 0x80  // INTEGER 128 with sign padding
    };

    REQUIRE ( encoder.get_contents () == expected );
}

TEST_CASE ( "Encode signed integer using two's complement encoding", "[enc-int-signed]" )
{
    DER_Encoder encoder;
    encoder.encode ( static_cast < int64_t > ( -1 ) )
           .encode ( static_cast < int64_t > ( -128 ) );

    const std::vector < uint8_t > expected = {
        0x02, 0x01, 0xFF, // INTEGER -1
        0x02, 0x01, 0x80  // INTEGER -128
    };

    REQUIRE ( encoder.get_contents () == expected );
}

TEST_CASE ( "Encode Octet String and Null objects", "[enc-octet-null]" )
{
    const std::vector < uint8_t > raw_data = { 0xDE, 0xAD, 0xBE, 0xEF };

    DER_Encoder encoder;
    encoder.encode ( std::span < const uint8_t > ( raw_data ) )
           .encode_null ();

    const std::vector < uint8_t > expected = {
        0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, // OCTET STRING
        0x05, 0x00                          // NULL (always zero length)
    };

    REQUIRE ( encoder.get_contents () == expected );
}

//-----------------------------------------------------------------------------
// 2. CANONICAL RESTRICTED STRINGS ENCODING
//-----------------------------------------------------------------------------

TEST_CASE ( "Encode IA5String and PrintableString domain objects", "[enc-strings]" )
{
    IA5_String ia5 ( "test@domain.com" );
    Printable_String printable ( "User 123 +-" );

    DER_Encoder encoder;
    encoder.encode ( ia5 )
           .encode ( printable );

    const std::vector < uint8_t > expected = {
        0x16, 0x0F, 't', 'e', 's', 't', '@', 'd', 'o', 'm', 'a', 'i', 'n', '.', 'c', 'o', 'm',
        0x13, 0x0B, 'U', 's', 'e', 'r', ' ', '1', '2', '3', ' ', '+', '-'
    };

    REQUIRE ( encoder.get_contents () == expected );
}

TEST_CASE ( "PrintableString rejects characters outside restricted ASN.1 charset", "[enc-strings-validation]" )
{
    REQUIRE_THROWS_AS ( Printable_String ( "Invalid char @" ), ASN1_InvalidArgument );
    REQUIRE_THROWS_AS ( Printable_String ( "Invalid char _" ), ASN1_InvalidArgument );
}

//-----------------------------------------------------------------------------
// 3. OVERLOAD RESOLUTION BUG FIX VERIFICATION
//-----------------------------------------------------------------------------

TEST_CASE ( "Encode string literal via const char* without pointer decay to Boolean", "[enc-bug-fix]" )
{
    DER_Encoder encoder;
    encoder.encode ( "ASN1", ASN1_Type::UTF8_STRING, ASN1_Class::UNIVERSAL );

    const std::vector < uint8_t > expected = {
        0x0C, 0x04, 'A', 'S', 'N', '1' // Tag 0x0C corresponds to UTF8String
    };

    REQUIRE ( encoder.get_contents () == expected );
}

//-----------------------------------------------------------------------------
// 4. CONSTRUCTED TYPES AND OPEN TYPES (RAW VALUES)
//-----------------------------------------------------------------------------

TEST_CASE ( "Encode nested SEQUENCE and SET structural containers", "[enc-cons]" )
{
    DER_Encoder encoder;
    encoder.start_sequence ()
               .encode ( true )
               .start_set ()
                   .encode ( static_cast < uint64_t > ( 42 ) )
               .end_cons ()
           .end_cons ();

    const std::vector < uint8_t > expected = {
        0x30, 0x08,           // SEQUENCE (length 8)
        0x01, 0x01, 0xFF,     //   BOOLEAN True
        0x31, 0x03,           //   SET (length 3)
        0x02, 0x01, 0x2A      //     INTEGER 42
    };

    REQUIRE ( encoder.get_contents () == expected );
}

TEST_CASE ( "Encode Raw_Value cleanly injects open TLV structures without wrapping", "[enc-raw-value]" )
{
    const std::vector < uint8_t > pre_encoded_oid = { 0x06, 0x03, 0x55, 0x04, 0x03 }; // OID 2.5.4.3 (commonName)
    Raw_Value open_type ( pre_encoded_oid );

    DER_Encoder encoder;
    encoder.start_sequence ()
               .encode ( static_cast < uint64_t > ( 1 ) )
               .encode ( open_type )
           .end_cons ();

    const std::vector < uint8_t > expected = {
        0x30, 0x08,                 // SEQUENCE (length 8)
        0x02, 0x01, 0x01,           //   INTEGER 1
        0x06, 0x03, 0x55, 0x04, 0x03//   Injected open TLV byte stream
    };

    REQUIRE ( encoder.get_contents () == expected );
}

//-----------------------------------------------------------------------------
// 5. COLLECTIONS (SEQUENCE OF AND SET OF WITH DER CANONICAL SORTING)
//-----------------------------------------------------------------------------

TEST_CASE ( "Encode Sequence_Of maintains exact insertion order", "[enc-seq-of]" )
{
    Sequence_Of < uint64_t > seq_of = { 30ULL, 10ULL, 20ULL };

    DER_Encoder encoder;
    encoder.encode ( seq_of );

    const std::vector < uint8_t > expected = {
        0x30, 0x09,         // SEQUENCE OF (length 9)
        0x02, 0x01, 0x1E,   //   INTEGER 30
        0x02, 0x01, 0x0A,   //   INTEGER 10
        0x02, 0x01, 0x14    //   INTEGER 20
    };

    REQUIRE ( encoder.get_contents () == expected );
}

TEST_CASE ( "Encode Set_Of strictly enforces ITU-T X.690 DER canonical lexicographical sorting", "[enc-set-of]" )
{
    // Elements inserted out of binary order: 300 (0x01, 0x2C), 5 (0x05), 20 (0x14)
    Set_Of < uint64_t > set_of;
    set_of.push_back ( 300ULL ); // Binary DER: 02 02 01 2C
    set_of.push_back ( 5ULL );   // Binary DER: 02 01 05
    set_of.push_back ( 20ULL );  // Binary DER: 02 01 14

    DER_Encoder encoder;
    encoder.encode ( set_of );

    // Expected order inside SET (0x31) after X.690 lexicographical sort:
    // 1. 02 01 05      (5)   -> First byte 0x02, length 0x01, val 0x05
    // 2. 02 01 14      (20)  -> First byte 0x02, length 0x01, val 0x14
    // 3. 02 02 01 2C   (300) -> First byte 0x02, length 0x02 (greater than 0x01)
    const std::vector < uint8_t > expected = {
        0x31, 0x0A,
        0x02, 0x01, 0x05,
        0x02, 0x01, 0x14,
        0x02, 0x02, 0x01, 0x2C
    };

    REQUIRE ( encoder.get_contents () == expected );
}

//-----------------------------------------------------------------------------
// 6. CONTEXT-SPECIFIC TAGGING
//-----------------------------------------------------------------------------

TEST_CASE ( "Encode IMPLICIT and EXPLICIT tagged elements", "[enc-tagging]" )
{
    DER_Encoder encoder;
    encoder.start_sequence ()
               // [0] IMPLICIT INTEGER 10
               .encode ( static_cast < uint64_t > ( 10 ), static_cast < ASN1_Type > ( 0 ), ASN1_Class::CONTEXT_SPECIFIC )
               // [1] EXPLICIT BOOLEAN False
               .start_explicit ( 1 )
                   .encode ( false )
               .end_explicit ()
           .end_cons ();

    const std::vector < uint8_t > expected = {
        0x30, 0x08,           // SEQUENCE
        0x80, 0x01, 0x0A,     //   [0] IMPLICIT (80 hex = Context-specific 0 primitive)
        0xA1, 0x03,           //   [1] EXPLICIT (A1 hex = Context-specific 1 constructed)
        0x01, 0x01, 0x00      //     BOOLEAN False
    };

    REQUIRE ( encoder.get_contents () == expected );
}

//-----------------------------------------------------------------------------
// 7. DEFAULT AND OPTIONAL HANDLING
//-----------------------------------------------------------------------------

TEST_CASE ( "Encode DEFAULT values only when differing from expected canonical value", "[enc-default]" )
{
    DER_Encoder encoder;
    encoder.start_sequence ()
               .encode_default ( true, true )                             // Matches default -> Omitted
               .encode_default ( static_cast < uint64_t > ( 5 ), 10ULL )  // Differs -> Encoded
               .encode_default ( "SKIP", "SKIP" )                         // Matches -> Omitted
           .end_cons ();

    const std::vector < uint8_t > expected = {
        0x30, 0x03,         // SEQUENCE (only contains the integer)
        0x02, 0x01, 0x05    //   INTEGER 5
    };

    REQUIRE ( encoder.get_contents () == expected );
}

TEST_CASE ( "Encode std::optional cleanly ignores nullopt values", "[enc-optional]" )
{
    std::optional < uint64_t > present_val = 99;
    std::optional < uint64_t > absent_val = std::nullopt;

    DER_Encoder encoder;
    encoder.start_sequence ()
               .encode_optional ( present_val )
               .encode_optional ( absent_val )
           .end_cons ();

    const std::vector < uint8_t > expected = {
        0x30, 0x03,         // SEQUENCE
        0x02, 0x01, 0x63    //   INTEGER 99 (0x63)
    };

    REQUIRE ( encoder.get_contents () == expected );
}

TEST_CASE ( "DER_Encoder serializes optional implicit constructed collections with exact X.690 byte output", "[enc-opt-implicit]" )
{
    SECTION ( "When the optional collection has values, emits correct CONSTRUCTED context-specific tag and sorted DER bytes" )
    {
        // Simulate: [0] IMPLICIT SET OF INTEGER OPTIONAL
        std::optional < Set_Of < uint64_t > > opt_set;
        opt_set.emplace ();
        opt_set->push_back ( 5 );
        opt_set->push_back ( 10 );

        DER_Encoder encoder;
        encoder.encode_optional_implicit ( 0, opt_set );

        const std::vector < uint8_t > result = encoder.get_contents ();

        // Expected X.690 calculation:
        // Tag byte for [0] IMPLICIT CONSTRUCTED:
        //   Class: CONTEXT_SPECIFIC (0x80) | Form: CONSTRUCTED (0x20) | Tag Number: 0 = 0xA0
        // Length of inner SET contents:
        //   INTEGER 5  -> 02 01 05 (3 bytes)
        //   INTEGER 10 -> 02 01 0A (3 bytes)
        //   Total internal length = 6 (0x06)
        // Final canonical DER stream: A0 06 02 01 05 02 01 0A
        const std::vector < uint8_t > expected_bytes = {
            0xA0, 0x06,
            0x02, 0x01, 0x05,
            0x02, 0x01, 0x0A
        };

        REQUIRE ( result == expected_bytes );
    }

    SECTION ( "When the optional collection is std::nullopt, emits zero bytes without corrupting stream" )
    {
        std::optional < Set_Of < uint64_t > > opt_set = std::nullopt;

        DER_Encoder encoder;
        encoder.encode_optional_implicit ( 0, opt_set );

        REQUIRE ( encoder.get_contents ().empty () );
    }

    SECTION ( "When chaining multiple optional implicit collections, preserves exact sequence order and omissions" )
    {
        // [0] IMPLICIT present, [1] IMPLICIT absent, [2] IMPLICIT present
        std::optional < Set_Of < uint64_t > > set_0;
        set_0.emplace ();
        set_0->push_back ( 1 ); // 02 01 01 (3 bytes)

        std::optional < Set_Of < uint64_t > > set_1 = std::nullopt;

        std::optional < Set_Of < uint64_t > > set_2;
        set_2.emplace ();
        set_2->push_back ( 2 ); // 02 01 02 (3 bytes)

        DER_Encoder encoder;
        encoder.start_sequence ()
                   .encode_optional_implicit ( 0, set_0 ) // Should emit tag 0xA0
                   .encode_optional_implicit ( 1, set_1 ) // Should be skipped completely
                   .encode_optional_implicit ( 2, set_2 ) // Should emit tag 0xA2
               .end_cons ();

        const std::vector < uint8_t > result = encoder.get_contents ();

        // Expected SEQUENCE (0x30) of length 10 (0x0A):
        //   [0] IMPLICIT -> A0 03 02 01 01
        //   [2] IMPLICIT -> A2 03 02 01 02
        const std::vector < uint8_t > expected_bytes = {
            0x30, 0x0A,
            0xA0, 0x03, 0x02, 0x01, 0x01,
            0xA2, 0x03, 0x02, 0x01, 0x02
        };

        REQUIRE ( result == expected_bytes );
    }
}

//-----------------------------------------------------------------------------
// 8. ENCODER ERROR HANDLING
//-----------------------------------------------------------------------------

TEST_CASE ( "Encoder throws ASN1_EncodingError on unclosed structural scope", "[enc-errors]" )
{
    DER_Encoder encoder;
    encoder.start_sequence ()
               .encode ( true );
    // Intentionally omitting .end_cons()

    REQUIRE_THROWS_AS ( encoder.get_contents (), ASN1_EncodingError );
}

TEST_CASE ( "Encoder throws ASN1_EncodingError when ending unopened scope", "[enc-errors-scope]" )
{
    DER_Encoder encoder;
    REQUIRE_THROWS_AS ( encoder.end_cons (), ASN1_EncodingError );
}