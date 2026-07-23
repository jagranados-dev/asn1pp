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
#include <string>
#include <vector>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/asn1_types.hpp>
#include <asn1pp/ber_decoder.hpp>

using namespace asn1pp;

//-----------------------------------------------------------------------------
// 1. PRIMITIVE TYPES DECODING
//-----------------------------------------------------------------------------

TEST_CASE ( "Boolean (True) decode success", "[dec-bool-true]" )
{
    bool decoded_value = false;
    const std::vector < uint8_t > test_vector = { 0x01, 0x01, 0xFF };

    BER_Decoder decoder ( test_vector );
    decoder.decode ( decoded_value );

    REQUIRE ( decoded_value == true );
    REQUIRE ( !decoder.more_items () );
}

TEST_CASE ( "Boolean (False) decode success", "[dec-bool-false]" )
{
    bool decoded_value = true;
    const std::vector < uint8_t > test_vector = { 0x01, 0x01, 0x00 };

    BER_Decoder decoder ( test_vector );
    decoder.decode ( decoded_value );

    REQUIRE ( decoded_value == false );
    REQUIRE ( !decoder.more_items () );
}

TEST_CASE ( "Decode signed and unsigned integers successfully", "[dec-int]" )
{
    // Unsigned 128 (with 0x00 leading sign padding byte) and Signed -1
    const std::vector < uint8_t > test_vector = { 
        0x02, 0x02, 0x00, 0x80, 
        0x02, 0x01, 0xFF 
    };

    uint64_t unsigned_val = 0;
    int64_t signed_val = 0;

    BER_Decoder decoder ( test_vector );
    decoder.decode ( unsigned_val )
           .decode ( signed_val );

    REQUIRE ( unsigned_val == 128ULL );
    REQUIRE ( signed_val == -1LL );
    REQUIRE ( !decoder.more_items () );
}

TEST_CASE ( "Decode Octet String, UTF8String, and Null objects", "[dec-string-null]" )
{
    const std::vector < uint8_t > test_vector = {
        0x04, 0x03, 0x01, 0x02, 0x03,   // OCTET STRING
        0x0C, 0x04, 'T', 'e', 's', 't', // UTF8String
        0x05, 0x00                      // NULL
    };

    std::vector < uint8_t > octet_val;
    std::string str_val;

    BER_Decoder decoder ( test_vector );
    decoder.decode ( octet_val )
           .decode ( str_val, ASN1_Type::UTF8_STRING )
           .decode_null ();

    REQUIRE ( octet_val == std::vector < uint8_t > ( { 0x01, 0x02, 0x03 } ) );
    REQUIRE ( str_val == "Test" );
    REQUIRE ( !decoder.more_items () );
}

//-----------------------------------------------------------------------------
// 2. CONSTRUCTED TYPES (SEQUENCE AND SET)
//-----------------------------------------------------------------------------

TEST_CASE ( "Decode nested SEQUENCE and SET structures with scope boundary checks", "[dec-cons]" )
{
    const std::vector < uint8_t > test_vector = {
        0x30, 0x08,           // SEQUENCE (7 bytes)
        0x02, 0x01, 0x01,     //   INTEGER 1
        0x31, 0x03,           //   SET (2 bytes)
        0x01, 0x01, 0xFF      //     BOOLEAN True
    };

    uint64_t int_val = 0;
    bool bool_val = false;

    BER_Decoder decoder ( test_vector );
    decoder.start_sequence ()
               .decode ( int_val )
               .start_set ()
                   .decode ( bool_val )
               .end_cons ()
           .end_cons ();

    REQUIRE ( int_val == 1ULL );
    REQUIRE ( bool_val == true );
    REQUIRE ( !decoder.more_items () );
}

//-----------------------------------------------------------------------------
// 3. CONTEXT-SPECIFIC TAGGING AND HEADER INSPECTION
//-----------------------------------------------------------------------------

TEST_CASE ( "Decode IMPLICIT tags and inspect headers using peek_next_header", "[dec-tagging]" )
{
    const std::vector < uint8_t > test_vector = {
        0x80, 0x01, 0x2A // [0] IMPLICIT INTEGER 42
    };

    BER_Decoder decoder ( test_vector );

    // Verify non-destructive lookahead
    auto hdr = decoder.peek_next_header ();
    REQUIRE ( hdr.has_value () );
    REQUIRE ( hdr->type_tag == static_cast < ASN1_Type > ( 0 ) );
    REQUIRE ( ( hdr->class_tag & 0xC0u ) == static_cast < uint8_t > ( ASN1_Class::CONTEXT_SPECIFIC ) );

    uint64_t val = 0;
    decoder.decode ( val, static_cast < ASN1_Type > ( 0 ), ASN1_Class::CONTEXT_SPECIFIC );

    REQUIRE ( val == 42ULL );
    REQUIRE ( !decoder.more_items () );
}

TEST_CASE ( "Decode EXPLICIT context-specific containers", "[dec-explicit]" )
{
    const std::vector < uint8_t > test_vector = {
        0xA3, 0x03,         // [3] EXPLICIT constructed
        0x01, 0x01, 0xFF    //   BOOLEAN True
    };

    bool val = false;
    BER_Decoder decoder ( test_vector );
    decoder.start_explicit ( 3 )
               .decode ( val )
           .end_explicit ();

    REQUIRE ( val == true );
}

//-----------------------------------------------------------------------------
// 4. DEFAULT AND OPTIONAL HANDLING
//-----------------------------------------------------------------------------

TEST_CASE ( "Decode DEFAULT values apply fallback when stream tag is absent", "[dec-default]" )
{
    // Sequence only contains a string; the leading boolean is omitted
    const std::vector < uint8_t > test_vector = {
        0x30, 0x05,
        0x0C, 0x03, 'A', 'S', 'N'
    };

    bool active = false;
    std::string name;

    BER_Decoder decoder ( test_vector );
    decoder.start_sequence ()
               // Missing in stream -> must fall back to provided default value (true)
               .decode_default ( active, true, ASN1_Type::BOOLEAN, ASN1_Class::UNIVERSAL )
               // Present in stream -> must decode actual string
               .decode_default ( name, "DEFAULT", ASN1_Type::UTF8_STRING, ASN1_Class::UNIVERSAL )
           .end_cons ();

    REQUIRE ( active == true );
    REQUIRE ( name == "ASN" );
}

TEST_CASE ( "Decode OPTIONAL values handle both present and missing elements via std::optional", "[dec-optional]" )
{
    const std::vector < uint8_t > test_vector = {
        0x30, 0x03,
        0x02, 0x01, 0x07 // Contains only an INTEGER
    };

    std::optional < uint64_t > opt_int = std::nullopt;
    std::optional < bool > opt_bool = true; // Pre-populated to check reset()

    BER_Decoder decoder ( test_vector );
    decoder.start_sequence ()
               .decode_optional ( opt_int, ASN1_Type::INTEGER, ASN1_Class::UNIVERSAL )
               .decode_optional ( opt_bool, ASN1_Type::BOOLEAN, ASN1_Class::UNIVERSAL )
           .end_cons ();

    REQUIRE ( opt_int.has_value () );
    REQUIRE ( *opt_int == 7ULL );
    REQUIRE ( !opt_bool.has_value () ); // Must be reset to nullopt because tag was absent
}

//-----------------------------------------------------------------------------
// 5. DECODER ERROR HANDLING AND BOUNDARY CHECKS
//-----------------------------------------------------------------------------

TEST_CASE ( "Decoder throws ASN1_DecodingError when reading past buffer end", "[dec-errors-eof]" )
{
    const std::vector < uint8_t > empty_vector = {};
    BER_Decoder decoder ( empty_vector );
    bool val = false;

    REQUIRE_THROWS_AS ( decoder.decode ( val ), ASN1_DecodingError );
}

TEST_CASE ( "Decoder throws ASN1_DecodingError on tag mismatch", "[dec-errors-tag]" )
{
    const std::vector < uint8_t > test_vector = { 0x02, 0x01, 0x01 }; // Contains INTEGER
    BER_Decoder decoder ( test_vector );
    bool val = false;

    // Expecting BOOLEAN, but stream has INTEGER
    REQUIRE_THROWS_AS ( decoder.decode ( val, ASN1_Type::BOOLEAN ), ASN1_DecodingError );
}

TEST_CASE ( "Decoder throws ASN1_DecodingError when BOOLEAN length is not exactly 1", "[dec-errors-bool-len]" )
{
    const std::vector < uint8_t > test_vector = { 0x01, 0x02, 0xFF, 0xFF }; // Invalid length 2
    BER_Decoder decoder ( test_vector );
    bool val = false;

    REQUIRE_THROWS_AS ( decoder.decode ( val ), ASN1_DecodingError );
}

TEST_CASE ( "Decoder throws ASN1_DecodingError on unconsumed bytes when closing structural scope", "[dec-errors-scope]" )
{
    const std::vector < uint8_t > test_vector = {
        0x30, 0x06,
        0x02, 0x01, 0x01,
        0x02, 0x01, 0x02 // Two integers inside sequence
    };

    uint64_t val1 = 0;
    BER_Decoder decoder ( test_vector );
    decoder.start_sequence ()
               .decode ( val1 );
    
    // Intentionally attempting to close scope before decoding the second integer
    REQUIRE_THROWS_AS ( decoder.end_cons (), ASN1_DecodingError );
}