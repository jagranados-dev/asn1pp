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
#include <iomanip>
#include <iostream>
#include <span>
#include <string>
#include <vector>

#include <asn1pp/asn1pp.hpp>

namespace
{

    /**
     * @brief Prints an encoded ASN.1 stream using hexadecimal notation.
     * @param data Encoded byte sequence to print.
     */
    void
    print_hex ( std::span < const uint8_t > data )
    {
        for ( uint8_t byte : data )
        {
            std::cout << std::hex
                      << std::uppercase
                      << std::setw ( 2 )
                      << std::setfill ( '0' )
                      << static_cast < unsigned int > ( byte )
                      << ' ';
        }

        std::cout << std::dec << '\n';
    }

} // namespace

int
main ()
{
    try
    {
        const bool original_boolean = true;
        const uint64_t original_unsigned = 65537;
        const int64_t original_signed = -129;

        const std::vector < uint8_t > original_octets {
            0xDE,
            0xAD,
            0xBE,
            0xEF
        };

        const std::string original_text = "Hello ASN.1";

        asn1pp::DER_Encoder encoder;

        encoder.encode ( original_boolean )
               .encode ( original_unsigned )
               .encode ( original_signed )
               .encode ( original_octets )
               .encode ( original_text )
               .encode_null ();

        std::vector < uint8_t > encoded = encoder.take_contents ();

        std::cout << "Encoded DER stream:\n";
        print_hex ( encoded );

        asn1pp::DER_Decoder decoder ( encoded );

        bool decoded_boolean = false;
        uint64_t decoded_unsigned = 0;
        int64_t decoded_signed = 0;
        std::vector < uint8_t > decoded_octets;
        std::string decoded_text;

        decoder.decode ( decoded_boolean )
               .decode ( decoded_unsigned )
               .decode ( decoded_signed )
               .decode ( decoded_octets )
               .decode ( decoded_text )
               .decode_null ();

        if ( decoder.more_items () )
        {
            throw std::runtime_error (
                "Unexpected ASN.1 values remain after decoding"
            );
        }

        std::cout << "\nDecoded values:\n";
        std::cout << "BOOLEAN: "
                  << std::boolalpha
                  << decoded_boolean
                  << '\n';

        std::cout << "Unsigned INTEGER: "
                  << decoded_unsigned
                  << '\n';

        std::cout << "Signed INTEGER: "
                  << decoded_signed
                  << '\n';

        std::cout << "OCTET STRING: ";
        print_hex ( decoded_octets );

        std::cout << "UTF8String: "
                  << decoded_text
                  << '\n';

        std::cout << "NULL: decoded successfully\n";

        if ( decoded_boolean != original_boolean ||
             decoded_unsigned != original_unsigned ||
             decoded_signed != original_signed ||
             decoded_octets != original_octets ||
             decoded_text != original_text )
        {
            throw std::runtime_error (
                "The decoded values do not match the original values"
            );
        }

        std::cout << "\nPrimitive round-trip completed successfully.\n";
    }
    catch ( const asn1pp::ASN1_Error& error )
    {
        std::cerr << "ASN.1 error at offset "
                  << error.offset ()
                  << ": "
                  << error.what ()
                  << '\n';

        return 1;
    }
    catch ( const std::exception& error )
    {
        std::cerr << "Error: "
                  << error.what ()
                  << '\n';

        return 1;
    }

    return 0;
}