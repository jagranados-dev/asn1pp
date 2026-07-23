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

#include <asn1pp/asn1_time.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/big_int.hpp>
#include <asn1pp/der_encoder.hpp>
#include <asn1pp/oid.hpp>

using namespace asn1pp;

/**
 * @brief We model an advanced CMS / PKIX Cryptographic Structure (RFC 5652 / RFC 5958):
 *
 * AdvancedCmsKeyPackage ::= SEQUENCE {
 *     version             [0] EXPLICIT INTEGER DEFAULT 1,
 *     serialNumber        [1] IMPLICIT INTEGER,
 *     algorithm           OBJECT IDENTIFIER,
 *     attributes          [2] IMPLICIT SEQUENCE {
 *                             contentType    OBJECT IDENTIFIER,
 *                             timestamp      UTCTime
 *                         } OPTIONAL,
 *     signerInfo          [3] EXPLICIT SEQUENCE {
 *                             issuer         UTF8String,
 *                             serial         INTEGER
 *                         },
 *     privateKey          [4] IMPLICIT BIT STRING OPTIONAL
 * }
 */
int
main ()
{
    std::cout << "--- Testing Comprehensive Cryptographic Engine (CMS / KeyPackage Schema) ---\n";

    // Data initialization
    uint64_t version               = 1ULL; // Matches DEFAULT 1 -> omitted in DER stream
    uint64_t serial_number         = 987654321ULL;
    OID algorithm_oid              ( "1.2.840.113549.1.1.11" ); // sha256WithRSAEncryption
    
    // Optional collection under [2] IMPLICIT SEQUENCE
    struct AttributeCollection
    {
        OID content_type;
        ASN1_Time timestamp;
    };
    std::optional < AttributeCollection > opt_attributes = AttributeCollection {
        OID ( "1.2.840.113549.1.9.16.1.4" ), // id-ct-KP-keyPackage
        ASN1_Time ( "260723125011Z", ASN1_Type::UTC_TIME )
    };

    // Mandatory nested structure under [3] EXPLICIT SEQUENCE
    std::string signer_issuer      = "CN=NSA High Assurance CA, O=U.S. Government, C=US";
    uint64_t signer_serial         = 42ULL;

    // Optional primitive under [4] IMPLICIT
    std::optional < Big_Int > opt_private_key = Big_Int ( "00FFEEDDCCBBAA998877665544332211" );

    // -------------------------------------------------------------------------
    // 1. ENCODING: Zero boilerplate, 100% fluent method chaining
    // -------------------------------------------------------------------------
    DER_Encoder encoder;
    encoder.start_sequence ()
           .encode_explicit_default ( version, 0, 1ULL )               // [0] EXPLICIT DEFAULT 1
           .encode_implicit ( serial_number, 1 )                       // [1] IMPLICIT INTEGER
           .encode ( algorithm_oid );                                  // Mandatory OID

    // Multi-element collection under [2] IMPLICIT SEQUENCE OPTIONAL
    if ( opt_attributes.has_value () )
    {
        encoder.start_implicit_cons ( 2 )                              // Replaces universal 0x30 with [2]
               .encode ( opt_attributes->content_type )
               .encode ( opt_attributes->timestamp )
               .end_implicit_cons ();                                  // Closes [2]
    }

    // Multi-element collection under [3] EXPLICIT SEQUENCE
    encoder.start_explicit ( 3 )                                       // Outer container [3]
           .start_sequence ()                                          // Inner universal SEQUENCE
           .encode ( signer_issuer, ASN1_Type::UTF8_STRING )
           .encode ( signer_serial )
           .end_cons ()                                                // Closes SEQUENCE
           .end_explicit ()                                            // Closes [3]
           .encode_implicit_optional ( opt_private_key, 4 )            // [4] IMPLICIT OPTIONAL Big_Int
           .end_cons ();                                               // Closes AdvancedCmsKeyPackage

    std::vector < uint8_t > der_stream = encoder.get_contents ();
    std::cout << "Successfully encoded AdvancedCmsKeyPackage. Total size: " << der_stream.size () << " bytes.\n";

    // -------------------------------------------------------------------------
    // 2. DECODING: Perfectly mirroring the schema without breaking linear flow
    // -------------------------------------------------------------------------
    uint64_t dec_version = 0;
    uint64_t dec_serial  = 0;
    OID dec_oid;
    std::optional < AttributeCollection > dec_attributes = std::nullopt;
    std::string dec_issuer;
    uint64_t dec_signer_serial = 0;
    std::optional < Big_Int > dec_private_key = std::nullopt;

    BER_Decoder decoder ( der_stream );
    decoder.start_sequence ()
           .decode_explicit_default ( dec_version, 0, 1ULL )           // [0] EXPLICIT DEFAULT 1
           .decode_implicit ( dec_serial, 1, ASN1_Type::INTEGER )      // [1] IMPLICIT INTEGER
           .decode ( dec_oid );                                        // Mandatory OID

    // Multi-element collection under [2] IMPLICIT SEQUENCE OPTIONAL
    if ( decoder.has_implicit_cons ( 2 ) )
    {
        AttributeCollection temp_attr;
        decoder.start_implicit_cons ( 2 )
               .decode ( temp_attr.content_type )
               .decode ( temp_attr.timestamp )
               .end_implicit_cons ();
        dec_attributes = std::move ( temp_attr );
    }

    // Multi-element collection under [3] EXPLICIT SEQUENCE
    decoder.start_explicit ( 3 )
           .start_sequence ()
           .decode ( dec_issuer, ASN1_Type::UTF8_STRING )
           .decode ( dec_signer_serial )
           .end_cons ()
           .end_explicit ()
           .decode_implicit_optional ( dec_private_key, 4, ASN1_Type::INTEGER ) // [4] IMPLICIT OPTIONAL
           .end_cons ();

    // -------------------------------------------------------------------------
    // 3. VERIFICATION
    // -------------------------------------------------------------------------
    std::cout << "Decoded Version       : " << dec_version << " (default applied cleanly)\n";
    std::cout << "Decoded Serial Number : " << dec_serial  << "\n";
    std::cout << "Decoded Algorithm     : " << dec_oid     << "\n";
    std::cout << "Decoded Attributes    : " << ( dec_attributes ? "Present (Content-Type & UTCTime verified)" : "Absent" ) << "\n";
    std::cout << "Decoded Signer Issuer : " << dec_issuer  << "\n";
    std::cout << "Decoded Signer Serial : " << dec_signer_serial << "\n";
    std::cout << "Decoded Private Key   : " << ( dec_private_key ? "Present (Big_Int matching)" : "Absent" ) << "\n";

    assert ( dec_version == 1ULL );
    assert ( dec_serial == 987654321ULL );
    assert ( dec_oid == algorithm_oid );
    assert ( dec_attributes.has_value () );
    assert ( dec_attributes->content_type == opt_attributes->content_type );
    assert ( dec_attributes->timestamp == opt_attributes->timestamp );
    assert ( dec_issuer == signer_issuer );
    assert ( dec_signer_serial == signer_serial );
    assert ( dec_private_key.has_value () && *dec_private_key == *opt_private_key );
    assert ( !decoder.more_items () );

    std::cout << "\nSUCCESS: Complex Cryptographic Schema (RFC 5652 / RFC 5958 style) compiled and executed flawlessly!\n";

    return EXIT_SUCCESS;
}