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

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include <asn1pp/asn1pp.hpp>

namespace
{

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

    class Certificate_Metadata : public asn1pp::ASN1_Object
    {
    public:
        asn1pp::OID algorithm;
        asn1pp::ASN1_Time not_before;
        asn1pp::ASN1_Time not_after;
        asn1pp::Big_Int serial_number;
        asn1pp::UTF8_String issuer;
        asn1pp::Sequence_Of < asn1pp::IA5_String > subject_alt_names;
        asn1pp::Set_Of < asn1pp::Printable_String > roles;
        bool critical = false;
        std::optional < asn1pp::UTF8_String > comment;

        void
        encode_into ( asn1pp::DER_Encoder& to ) const override
        {
            to.encode_sequence (
                [&] ( asn1pp::DER_Encoder& sequence )
                {
                    sequence.encode ( algorithm );
                    sequence.encode ( not_before );
                    sequence.encode ( not_after );
                    sequence.encode ( serial_number );
                    sequence.encode ( issuer );
                    sequence.encode ( subject_alt_names );
                    sequence.encode ( roles );
                    sequence.encode_default ( critical, false );
                    sequence.encode_optional ( comment );
                }
            );
        }

        void
        decode_from ( asn1pp::BER_Decoder& from ) override
        {
            from.decode_sequence (
                [&] ( asn1pp::BER_Decoder& sequence )
                {
                    sequence.decode ( algorithm );
                    sequence.decode ( not_before );
                    sequence.decode ( not_after );
                    sequence.decode ( serial_number );
                    sequence.decode ( issuer );
                    sequence.decode ( subject_alt_names );
                    sequence.decode ( roles );
                    sequence.decode_default ( critical, false, asn1pp::ASN1_Type::BOOLEAN );
                    sequence.decode_optional ( comment, asn1pp::ASN1_Type::UTF8_STRING );
                }
            );
        }
    };

    bool
    equal_ia5_sequence ( const asn1pp::Sequence_Of < asn1pp::IA5_String >& lhs,
                         const asn1pp::Sequence_Of < asn1pp::IA5_String >& rhs )
    {
        if ( lhs.values.size () != rhs.values.size () )
        {
            return false;
        }

        for ( size_t i = 0; i < lhs.values.size (); ++i )
        {
            if ( lhs.values [ i ].value () != rhs.values [ i ].value () )
            {
                return false;
            }
        }

        return true;
    }

    bool
    equal_printable_set ( const asn1pp::Set_Of < asn1pp::Printable_String >& lhs,
                          const asn1pp::Set_Of < asn1pp::Printable_String >& rhs )
    {
        if ( lhs.values.size () != rhs.values.size () )
        {
            return false;
        }

        std::vector < std::string > lhs_values;
        std::vector < std::string > rhs_values;

        for ( const asn1pp::Printable_String& value : lhs.values )
        {
            lhs_values.push_back ( value.value () );
        }

        for ( const asn1pp::Printable_String& value : rhs.values )
        {
            rhs_values.push_back ( value.value () );
        }

        std::sort ( lhs_values.begin (), lhs_values.end () );
        std::sort ( rhs_values.begin (), rhs_values.end () );

        return lhs_values == rhs_values;
    }

    bool
    equal_optional_utf8 ( const std::optional < asn1pp::UTF8_String >& lhs,
                          const std::optional < asn1pp::UTF8_String >& rhs )
    {
        if ( lhs.has_value () != rhs.has_value () )
        {
            return false;
        }

        return !lhs.has_value () || lhs->value () == rhs->value ();
    }

    bool
    equal_metadata ( const Certificate_Metadata& lhs,
                     const Certificate_Metadata& rhs )
    {
        return lhs.algorithm.arcs () == rhs.algorithm.arcs () &&
               lhs.not_before.type () == rhs.not_before.type () &&
               lhs.not_before.value () == rhs.not_before.value () &&
               lhs.not_after.type () == rhs.not_after.type () &&
               lhs.not_after.value () == rhs.not_after.value () &&
               lhs.serial_number.bytes () == rhs.serial_number.bytes () &&
               lhs.issuer.value () == rhs.issuer.value () &&
               equal_ia5_sequence ( lhs.subject_alt_names, rhs.subject_alt_names ) &&
               equal_printable_set ( lhs.roles, rhs.roles ) &&
               lhs.critical == rhs.critical &&
               equal_optional_utf8 ( lhs.comment, rhs.comment );
    }

    Certificate_Metadata
    create_metadata ()
    {
        Certificate_Metadata metadata;
        metadata.algorithm.assign ( "1.2.840.113549.1.1.11" );
        metadata.not_before.assign ( asn1pp::ASN1_TimeType::UTC, "260728060000Z" );
        metadata.not_after.assign ( asn1pp::ASN1_TimeType::GENERALIZED, "20500728060000Z" );
        metadata.serial_number.set_decimal ( "123456789012345678901234567890" );
        metadata.issuer.assign ( "ASN.1 Example Authority" );
        metadata.subject_alt_names.values.emplace_back ( "example.com" );
        metadata.subject_alt_names.values.emplace_back ( "www.example.com" );
        metadata.roles.values.emplace_back ( "Signing" );
        metadata.roles.values.emplace_back ( "Administrator" );
        metadata.roles.values.emplace_back ( "Encryption" );
        metadata.critical = true;
        metadata.comment = asn1pp::UTF8_String ( "Advanced ASN.1 DER example" );
        return metadata;
    }

} // namespace

int
main ()
{
    try
    {
        const Certificate_Metadata original = create_metadata ();
        asn1pp::DER_Encoder encoder;
        encoder.encode ( original );
        std::vector < uint8_t > encoded = encoder.take_contents ();

        std::cout << "Encoded DER:\n";
        print_hex ( encoded );

        asn1pp::DER_Decoder decoder ( encoded );
        Certificate_Metadata decoded;
        decoder.decode ( decoded );

        if ( decoder.more_items () )
        {
            throw std::runtime_error ( "Unexpected ASN.1 values remain after decoding" );
        }

        if ( !equal_metadata ( original, decoded ) )
        {
            throw std::runtime_error ( "The decoded object does not match the original object" );
        }

        std::cout << "Advanced round-trip completed successfully.\n";
    }
    catch ( const asn1pp::ASN1_Error& error )
    {
        std::cerr << error.what () << '\n';
        return 1;
    }

    return 0;
}
