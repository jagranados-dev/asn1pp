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
#include <asn1pp/ia5_string.hpp>
#include <asn1pp/oid.hpp>
#include <asn1pp/printable_string.hpp>
#include <asn1pp/raw_value.hpp>
#include <asn1pp/sequence_of.hpp>
#include <asn1pp/set_of.hpp>

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
// 2. CANONICAL RESTRICTED STRINGS DECODING
//-----------------------------------------------------------------------------

TEST_CASE ( "Decode IA5String and PrintableString domain objects", "[dec-strings]" )
{
    const std::vector < uint8_t > test_vector = {
        0x16, 0x04, 'u', 's', 'e', 'r', // IA5String
        0x13, 0x04, 'N', 'a', 'm', 'e'  // PrintableString
    };

    IA5_String ia5_val;
    Printable_String printable_val;

    BER_Decoder decoder ( test_vector );
    decoder.decode ( ia5_val )
           .decode ( printable_val );

    REQUIRE ( ia5_val.get_string () == "user" );
    REQUIRE ( printable_val.get_string () == "Name" );
    REQUIRE ( !decoder.more_items () );
}

TEST_CASE ( "PrintableString throws ASN1_InvalidArgument when decoding invalid byte payloads", "[dec-strings-validation]" )
{
    // Tag 0x13 with payload '@' which is strictly forbidden in PrintableString
    const std::vector < uint8_t > test_vector = { 0x13, 0x01, '@' };

    BER_Decoder decoder ( test_vector );
    Printable_String val;

    REQUIRE_THROWS_AS ( decoder.decode ( val ), ASN1_InvalidArgument );
}

//-----------------------------------------------------------------------------
// 3. CONSTRUCTED TYPES AND OPEN TYPES (RAW VALUES)
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

TEST_CASE ( "Decode Raw_Value extracts complete open TLV structures accurately", "[dec-raw-value]" )
{
    const std::vector < uint8_t > test_vector = {
        0x30, 0x07,                     // SEQUENCE (length 7)
        0x02, 0x01, 0x01,               //   INTEGER 1
        0x06, 0x02, 0x2A, 0x03          //   OID 1.2.3 (captured as raw open type)
    };

    uint64_t int_val = 0;
    Raw_Value open_val;

    BER_Decoder decoder ( test_vector );
    decoder.start_sequence ()
               .decode ( int_val )
               .decode ( open_val )
           .end_cons ();

    const std::vector < uint8_t > expected_raw = { 0x06, 0x02, 0x2A, 0x03 };

    REQUIRE ( int_val == 1ULL );
    REQUIRE ( open_val.get_bytes () == expected_raw );
    REQUIRE ( !decoder.more_items () );
}

//-----------------------------------------------------------------------------
// 4. COLLECTIONS (SEQUENCE OF AND SET OF DECODING)
//-----------------------------------------------------------------------------

TEST_CASE ( "Decode Sequence_Of and Set_Of collections cleanly populate containers", "[dec-collections]" )
{
    const std::vector < uint8_t > test_vector = {
        0x30, 0x06,                     // SEQUENCE OF (length 6)
        0x02, 0x01, 0x0A,               //   INTEGER 10
        0x02, 0x01, 0x14,               //   INTEGER 20
        0x31, 0x06,                     // SET OF (length 6)
        0x02, 0x01, 0x05,               //   INTEGER 5
        0x02, 0x01, 0x64                //   INTEGER 100
    };

    Sequence_Of < uint64_t > seq_of;
    Set_Of < uint64_t > set_of;

    BER_Decoder decoder ( test_vector );
    decoder.decode ( seq_of )
           .decode ( set_of );

    REQUIRE ( seq_of.size () == 2 );
    REQUIRE ( seq_of [ 0 ] == 10ULL );
    REQUIRE ( seq_of [ 1 ] == 20ULL );

    REQUIRE ( set_of.size () == 2 );
    // Set_Of iterator inspection
    auto it = set_of.begin ();
    REQUIRE ( *( it++ ) == 5ULL );
    REQUIRE ( *it == 100ULL );
    REQUIRE ( !decoder.more_items () );
}

//-----------------------------------------------------------------------------
// 5. CONTEXT-SPECIFIC TAGGING AND HEADER INSPECTION
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
// 6. DEFAULT AND OPTIONAL HANDLING
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
// 7. DECODER ERROR HANDLING AND BOUNDARY CHECKS
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

//-----------------------------------------------------------------------------
// 8. ONE-ARGUMENT OPTIONAL AND OPEN TYPE (RAW_VALUE) DECODING
//-----------------------------------------------------------------------------

TEST_CASE ( "Decode 1-argument optional cleanly captures trailing Open Types (Raw_Value)", "[dec-opt-open-type]" )
{
    SECTION ( "When the optional Open Type is present at the end of a SEQUENCE" )
    {
        // Build a SEQUENCE with an INTEGER (1) and an open TLV (OID 2.5.4.3)
        DER_Encoder encoder;
        encoder.start_sequence ()
                   .encode ( static_cast < uint64_t > ( 1 ) )
                   .encode ( OID ( "2.5.4.3" ) )
               .end_cons ();

        const std::vector < uint8_t > der_buffer = encoder.get_contents (); // Explicit lvalue lifetime!
        uint64_t int_val = 0;
        std::optional < Raw_Value > opt_raw = std::nullopt;

        BER_Decoder decoder ( der_buffer );
        decoder.start_sequence ()
                   .decode ( int_val )
                   // Uses the new 1-arg overload: consumes remaining TLV without tag assertions
                   .decode_optional ( opt_raw )
               .end_cons ();

        REQUIRE ( int_val == 1ULL );
        REQUIRE ( opt_raw.has_value () );
        REQUIRE ( opt_raw->get_bytes () == std::vector < uint8_t > ( { 0x06, 0x03, 0x55, 0x04, 0x03 } ) );
        REQUIRE ( !decoder.more_items () );
    }

    SECTION ( "When the optional Open Type is omitted from the SEQUENCE" )
    {
        // Build a SEQUENCE containing ONLY the INTEGER (1)
        DER_Encoder encoder;
        encoder.start_sequence ()
                   .encode ( static_cast < uint64_t > ( 1 ) )
               .end_cons ();

        const std::vector < uint8_t > der_buffer = encoder.get_contents (); // Explicit lvalue lifetime!
        uint64_t int_val = 0;
        // Pre-populate with a bogus value to prove it gets reset to nullopt
        std::optional < Raw_Value > opt_raw = Raw_Value ( std::vector < uint8_t > ( { 0x05, 0x00 } ) );

        BER_Decoder decoder ( der_buffer );
        decoder.start_sequence ()
                   .decode ( int_val )
                   // Scope is empty, must safely reset to nullopt
                   .decode_optional ( opt_raw )
               .end_cons ();

        REQUIRE ( int_val == 1ULL );
        REQUIRE ( !opt_raw.has_value () );
        REQUIRE ( !decoder.more_items () );
    }
}

TEST_CASE ( "Decode 1-argument optional establishes symmetry with Encoder for standard objects", "[dec-opt-symmetry]" )
{
    std::optional < OID > opt_oid_present = OID ( "1.2.840.113549.1.1.1" );
    std::optional < OID > opt_oid_absent = std::nullopt;

    DER_Encoder encoder;
    encoder.start_sequence ()
               .encode_optional ( opt_oid_present )
               .encode_optional ( opt_oid_absent )
           .end_cons ();

    const std::vector < uint8_t > der_buffer = encoder.get_contents (); // Explicit lvalue lifetime!
    std::optional < OID > dec_oid_1;
    std::optional < OID > dec_oid_2 = OID ( "2.5.4.3" ); // Should be reset

    BER_Decoder decoder ( der_buffer );
    decoder.start_sequence ()
               .decode_optional ( dec_oid_1 )
               .decode_optional ( dec_oid_2 )
           .end_cons ();

    REQUIRE ( dec_oid_1.has_value () );
    REQUIRE ( *dec_oid_1 == *opt_oid_present );
    REQUIRE ( !dec_oid_2.has_value () );
    REQUIRE ( !decoder.more_items () );
}