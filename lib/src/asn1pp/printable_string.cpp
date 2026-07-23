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

#include <asn1pp/printable_string.hpp>

#include <utility>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    void
    Printable_String::validate ( std::string_view str )
    {
        for ( char c : str )
        {
            bool valid = ( c >= 'a' && c <= 'z' ) ||
                         ( c >= 'A' && c <= 'Z' ) ||
                         ( c >= '0' && c <= '9' ) ||
                         c == ' ' || c == '\'' || c == '(' || c == ')' ||
                         c == '+' || c == ','  || c == '-' || c == '.' ||
                         c == '/' || c == ':'  || c == '=' || c == '?';

            if ( !valid )
            {
                throw ASN1_InvalidArgument ( "Character invalid for ASN.1 PrintableString restricted charset" );
            }
        }
    }

    Printable_String::Printable_String ( std::string_view str )
        : _value ( str )
    {
        validate ( _value );
    }

    void
    Printable_String::encode_into ( DER_Encoder& to ) const
    {
        to.encode ( _value, ASN1_Type::PRINTABLE_STRING, ASN1_Class::UNIVERSAL );
    }

    void
    Printable_String::decode_from ( BER_Decoder& from )
    {
        std::string temp;
        from.decode ( temp, ASN1_Type::PRINTABLE_STRING, ASN1_Class::UNIVERSAL );
        validate ( temp );
        _value = std::move ( temp );
    }

    const std::string&
    Printable_String::get_string () const noexcept
    {
        return _value;
    }

    bool
    Printable_String::empty () const noexcept
    {
        return _value.empty ();
    }

    void
    Printable_String::clear () noexcept
    {
        _value.clear ();
    }

    bool
    Printable_String::operator== ( const Printable_String& other ) const noexcept
    {
        return _value == other._value;
    }

    bool
    Printable_String::operator!= ( const Printable_String& other ) const noexcept
    {
        return !( *this == other );
    }

} // asn1pp