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

#include <asn1pp/bit_string.hpp>

#include <iomanip>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <utility>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp 
{
    namespace
    {
        
        void
        validate_unused_bits ( uint8_t unused_bits, size_t data_size )
        {
            if ( unused_bits > 7 )
            {
                throw ASN1_InvalidArgument ( "Unused bits must be between 0 and 7" );
            }

            if ( data_size == 0 && unused_bits != 0 )
            {
                throw ASN1_InvalidArgument ( "Empty BIT STRING cannot have unused bits" );
            }
        }

    } // namespace

    //-----------------------------------------------------------------------------

    Bit_String::Bit_String ( std::vector < uint8_t > bits, uint8_t unused_bits )
        : _bits ( std::move ( bits ) ), _unused_bits ( unused_bits ) 
    {
        validate_unused_bits ( _unused_bits, _bits.size () );
    }

    Bit_String::Bit_String ( std::span < const uint8_t > bits, uint8_t unused_bits )
        : _bits ( bits.begin (), bits.end () ), _unused_bits ( unused_bits )
    {
        validate_unused_bits ( _unused_bits, _bits.size () );
    }

    Bit_String::Bit_String ( std::initializer_list < uint8_t > bits, uint8_t unused_bits )
        : _bits ( bits ), _unused_bits ( unused_bits )
    {
        validate_unused_bits ( _unused_bits, _bits.size () );
    }

    void
    Bit_String::encode_into ( DER_Encoder& to ) const
    {
        if ( _unused_bits > 7 )
        {
            throw ASN1_EncodingError ( "Unused bits count exceeds maximum allowed value of 7" );
        }

        if ( _bits.empty () && _unused_bits != 0 )
        {
            throw ASN1_EncodingError ( "Cannot encode non-zero unused bits for an empty BIT STRING" );
        }

        std::vector < uint8_t > contents;
        contents.reserve ( _bits.size () + 1 );
        
        // DER rule: the first octet indicates the number of unused bits in the final octet
        contents.push_back ( _unused_bits );
        contents.insert ( contents.end (), _bits.begin (), _bits.end () );

        to.add_object ( ASN1_Type::BIT_STRING, ASN1_Class::UNIVERSAL, contents );
    }

    void
    Bit_String::decode_from ( BER_Decoder& from )
    {
        std::vector < uint8_t > raw_bytes;
        from.decode ( raw_bytes, ASN1_Type::BIT_STRING, ASN1_Class::UNIVERSAL );

        if ( raw_bytes.empty () )
        {
            throw ASN1_DecodingError ( "Empty BIT STRING data stream" );
        }

        const uint8_t unused = raw_bytes [ 0 ];
        if ( unused > 7 )
        {
            throw ASN1_DecodingError ( "Invalid unused bits count in BIT STRING header" );
        }

        if ( raw_bytes.size () == 1 && unused != 0 )
        {
            throw ASN1_DecodingError ( "Zero-length BIT STRING cannot specify unused bits" );
        }

        _unused_bits = unused;
        _bits.assign ( raw_bytes.begin () + 1, raw_bytes.end () );
    }

    const std::vector < uint8_t >&
    Bit_String::get_bits () const noexcept
    {
        return _bits;
    }

    uint8_t
    Bit_String::get_unused_bits () const noexcept
    {
        return _unused_bits;
    }

    bool
    Bit_String::empty () const noexcept
    {
        return _bits.empty ();
    }

    void
    Bit_String::clear () noexcept
    {
        _bits.clear ();
        _unused_bits = 0;
    }

    std::string
    Bit_String::to_string () const
    {
        std::ostringstream oss;
        oss << std::hex << std::uppercase << std::setfill ( '0' );

        for ( uint8_t b : _bits )
        {
            oss << std::setw ( 2 ) << static_cast < int > ( b );
        }

        return oss.str ();
    }

    bool
    Bit_String::operator== ( const Bit_String& other ) const noexcept
    {
        return ( _unused_bits == other._unused_bits ) && ( _bits == other._bits );
    }

    bool
    Bit_String::operator!= ( const Bit_String& other ) const noexcept
    {
        return !( *this == other );
    }

    bool
    Bit_String::operator< ( const Bit_String& other ) const noexcept
    {
        if ( _bits != other._bits )
        {
            return _bits < other._bits;
        }

        return _unused_bits < other._unused_bits;
    }

    std::ostream&
    operator<< ( std::ostream& os, const Bit_String& bit_string )
    {
        os << bit_string.to_string ();
        if ( bit_string.get_unused_bits () > 0 )
        {
            os << " (unused bits: " << static_cast < int > ( bit_string.get_unused_bits () ) << ")";
        }
        return os;
    }

} // asn1pp