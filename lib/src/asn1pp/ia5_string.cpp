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

#include <asn1pp/ia5_string.hpp>

#include <utility>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    void
    IA5_String::validate ( std::string_view str )
    {
        for ( char c : str )
        {
            if ( static_cast < unsigned char > ( c ) > 0x7Fu )
            {
                throw ASN1_InvalidArgument ( "IA5String must contain only ASCII characters (0x00-0x7F)" );
            }
        }
    }

    IA5_String::IA5_String ( std::string_view str )
        : _value ( str )
    {
        validate ( _value );
    }

    void
    IA5_String::encode_into ( DER_Encoder& to ) const
    {
        to.encode ( _value, ASN1_Type::IA5_STRING, ASN1_Class::UNIVERSAL );
    }

    void
    IA5_String::decode_from ( BER_Decoder& from )
    {
        std::string temp;
        from.decode ( temp, ASN1_Type::IA5_STRING, ASN1_Class::UNIVERSAL );
        validate ( temp );
        _value = std::move ( temp );
    }

    const std::string&
    IA5_String::get_string () const noexcept
    {
        return _value;
    }

    bool
    IA5_String::empty () const noexcept
    {
        return _value.empty ();
    }

    void
    IA5_String::clear () noexcept
    {
        _value.clear ();
    }

    bool
    IA5_String::operator== ( const IA5_String& other ) const noexcept
    {
        return _value == other._value;
    }

    bool
    IA5_String::operator!= ( const IA5_String& other ) const noexcept
    {
        return !( *this == other );
    }

} // asn1pp