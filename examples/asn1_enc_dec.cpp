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

#include <iostream>
#include <iomanip>
#include <cassert>

#include <asn1pp/der_encoder.hpp>
#include <asn1pp/ber_decoder.hpp>

using namespace asn1pp;

/**
 * @brief Helper function to hex dump of encoded DER stream.
 */
std::string
hex_encode ( std::span < const uint8_t > data )
{
    std::stringstream ss;
    for ( uint8_t byte : data )
    {
        ss << std::hex << std::setw ( 2 ) << std::setfill ( '0' ) << static_cast < int > ( byte ) << " ";
    }

    return ss.str ();
}

int
main ( int, char** )
{
    try
    {
        std::cout << "--- 1. Starting ASN.1 DER Encoding ---\n";

        // Encode a complex nested ASN.1 structure:
        // SEQUENCE {
        //   version INTEGER (1),
        //   active BOOLEAN (true),
        //   username UTF8String ("ASN1_User"),
        //   payload SEQUENCE {
        //     id INTEGER (9988776655),
        //     data OCTET STRING (0xDE, 0xAD, 0xBE, 0xEF)
        //   }
        // }
        std::vector < uint8_t > raw_payload = { 0xDE, 0xAD, 0xBE, 0xEF };

        DER_Encoder encoder;
        encoder.start_sequence ()
            .encode ( static_cast < uint64_t > ( 1 ) )
            .encode ( true )
            .encode ( "ASN1_User", ASN1_Type::UTF8_STRING )
            .start_sequence ()
            .encode ( static_cast < uint64_t > ( 9988776655ULL ) )
            .encode ( raw_payload, ASN1_Type::OCTET_STRING )
            .end_cons ()
            .end_cons ();

        auto encoded_data = encoder.get_contents ();

        std::cout << "Successfully encoded " << encoded_data.size () << " bytes.\n";
        std::cout << "Hex Dump: " << hex_encode ( encoded_data ) << "\n\n";

        std::cout << "--- 2. Starting ASN.1 BER Decoding ---\n";

        uint64_t version = 0;
        bool active = false;
        std::string username;
        uint64_t id = 0;
        std::vector < uint8_t > decoded_payload;

        BER_Decoder decoder ( encoded_data );
        decoder.start_sequence ()
            .decode ( version )
            .decode ( active )
            .decode ( username, ASN1_Type::UTF8_STRING )
            .start_sequence ()
            .decode ( id )
            .decode ( decoded_payload, ASN1_Type::OCTET_STRING )
            .end_cons ()
            .end_cons ();

        std::cout << "Decoded Values:\n";
        std::cout << " - Version : " << version << "\n";
        std::cout << " - Active  : " << ( active ? "true" : "false" ) << "\n";
        std::cout << " - Username: " << username << "\n";
        std::cout << " - Nested ID: " << id << "\n";
        std::cout << " - Payload : " << hex_encode ( decoded_payload ) << "\n";

        // Verify asserts
        assert ( version == 1 );
        assert ( active == true );
        assert ( username == "ASN1_User" );
        assert ( id == 9988776655ULL );
        assert ( decoded_payload == raw_payload );
        assert ( !decoder.more_items () );

        std::cout << "\nSUCCESS: All ASN.1 structures encoded and decoded perfectly!\n";
    }
    catch ( const std::exception& ex )
    {
        std::cerr << "FATAL ERROR: " << ex.what () << "\n";

        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}