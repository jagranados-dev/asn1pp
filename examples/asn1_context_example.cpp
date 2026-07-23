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

#include <cassert>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/big_int.hpp>
#include <asn1pp/der_encoder.hpp>
#include <asn1pp/oid.hpp>

using namespace asn1pp;

int
main ()
{
    std::cout << "--- Testing Comprehensive ASN.1 Engine (Explicit, Implicit, Optional, Default) ---\n";

    uint64_t version = 1ULL; // As it matches 1ULL (DEFAULT), it must be omitted in DER encoding
    uint64_t serial_number = 123456789ULL;
    OID algorithm_oid ( "1.2.840.113549.1.1.1" );
    std::optional < std::string > issuer_name = "CN=Root CA, C=ES";
    std::optional < Big_Int > opt_unique_id = std::nullopt;

    DER_Encoder encoder;
    encoder.start_sequence ();

    // [0] EXPLICIT DEFAULT: We only open context [0] if the value differs from the default
    if ( version != 1ULL )
    {
        encoder.start_explicit ( 0 )
               .encode ( version )
               .end_explicit ();
    }

    // [1] IMPLICIT INTEGER and mandatory OID (Chained linear flow)
    encoder.encode ( serial_number, static_cast < ASN1_Type > ( 1 ), ASN1_Class::CONTEXT_SPECIFIC )
           .encode ( algorithm_oid );

    // [2] EXPLICIT OPTIONAL: We only open context [2] if the optional value is present
    if ( issuer_name.has_value () )
    {
        encoder.start_explicit ( 2 )
               .encode ( *issuer_name, ASN1_Type::UTF8_STRING, ASN1_Class::UNIVERSAL )
               .end_explicit ();
    }

    // [3] IMPLICIT OPTIONAL and closure of the main sequence structure
    encoder.encode_optional ( opt_unique_id )
           .end_cons ();

    std::vector < uint8_t > der_stream = encoder.get_contents ();
    std::cout << "Successfully encoded structure. Total size: " << der_stream.size () << " bytes.\n";

    uint64_t dec_version = 0;
    uint64_t dec_serial  = 0;
    OID dec_oid;
    std::optional < std::string > dec_issuer = std::nullopt;
    std::optional < Big_Int > dec_unique_id = std::nullopt;

    BER_Decoder decoder ( der_stream );
    decoder.start_sequence ();

    // [0] EXPLICIT DEFAULT: Check whether tag [0] is present in the underlying buffer
    auto hdr_0 = decoder.peek_next_header ();
    if ( hdr_0 && hdr_0->type_tag == static_cast < ASN1_Type > ( 0 ) &&
       ( hdr_0->class_tag & 0xC0u ) == static_cast < uint8_t > ( ASN1_Class::CONTEXT_SPECIFIC ) )
    {
        decoder.start_explicit ( 0 )
               .decode ( dec_version )
               .end_explicit ();
    }
    else
    {
        dec_version = 1ULL; // Apply default fallback value as it was omitted in the stream
    }

    // [1] IMPLICIT INTEGER and mandatory OID
    decoder.decode ( dec_serial, static_cast < ASN1_Type > ( 1 ), ASN1_Class::CONTEXT_SPECIFIC )
           .decode ( dec_oid );

    // [2] EXPLICIT OPTIONAL: Check whether tag [2] is present in the underlying buffer
    auto hdr_2 = decoder.peek_next_header ();
    if ( hdr_2 && hdr_2->type_tag == static_cast < ASN1_Type > ( 2 ) &&
       ( hdr_2->class_tag & 0xC0u ) == static_cast < uint8_t > ( ASN1_Class::CONTEXT_SPECIFIC ) )
    {
        std::string temp_issuer;
        decoder.start_explicit ( 2 )
               .decode ( temp_issuer, ASN1_Type::UTF8_STRING )
               .end_explicit ();
        dec_issuer = std::move ( temp_issuer );
    }

    // [3] IMPLICIT OPTIONAL (The decode_optional method internally manages missing values)
    decoder.decode_optional ( dec_unique_id, static_cast < ASN1_Type > ( 3 ), ASN1_Class::CONTEXT_SPECIFIC )
           .end_cons ();

    std::cout << "Decoded Version   : " << dec_version << " (fallback applied as version was omitted)\n";
    std::cout << "Decoded Serial    : " << dec_serial  << "\n";
    std::cout << "Decoded Algorithm : " << dec_oid     << "\n";
    std::cout << "Decoded Issuer    : " << ( dec_issuer ? *dec_issuer : "<nullopt>" ) << "\n";
    std::cout << "Decoded Unique ID : " << ( dec_unique_id.has_value () ? "Present" : "Absent (nullopt)" ) << "\n";

    assert ( dec_version == 1ULL );
    assert ( dec_serial == 123456789ULL );
    assert ( dec_oid == algorithm_oid );
    assert ( dec_issuer.has_value () && *dec_issuer == "CN=Root CA, C=ES" );
    assert ( !dec_unique_id.has_value () );
    assert ( !decoder.more_items () );

    std::cout << "\nSUCCESS: Explicit, Implicit, Optional, and Default features working in harmony!\n";

    return EXIT_SUCCESS;
}