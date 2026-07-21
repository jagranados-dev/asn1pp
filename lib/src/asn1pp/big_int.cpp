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

#include <asn1pp/big_int.hpp>

#include <algorithm>
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
        
        uint8_t
        hex_char_to_nibble ( char c )
        {
            if ( c >= '0' && c <= '9' ) return static_cast < uint8_t > ( c - '0' );
            if ( c >= 'a' && c <= 'f' ) return static_cast < uint8_t > ( c - 'a' + 10 );
            if ( c >= 'A' && c <= 'F' ) return static_cast < uint8_t > ( c - 'A' + 10 );
            throw ASN1_InvalidArgument ( "Invalid hexadecimal character in Big_Int string representation" );
        }

        std::vector < uint8_t >
        parse_hex_string ( std::string_view str )
        {
            size_t start = 0;
            if ( str.size () >= 2 && str [ 0 ] == '0' && ( str [ 1 ] == 'x' || str [ 1 ] == 'X' ) )
            {
                start = 2;
            }

            if ( start == str.size () )
            {
                return { 0x00 };
            }

            if ( ( str.size () - start ) % 2 != 0 )
            {
                throw ASN1_InvalidArgument ( "Hexadecimal string must contain an even number of digits" );
            }

            std::vector < uint8_t > out;
            out.reserve ( ( str.size () - start ) / 2 );

            for ( size_t idx = start; idx < str.size (); idx += 2 )
            {
                uint8_t high = hex_char_to_nibble ( str [ idx ] );
                uint8_t low = hex_char_to_nibble ( str [ idx + 1 ] );
                out.push_back ( static_cast < uint8_t > ( ( high << 4 ) | low ) );
            }

            return out;
        }

    } // namespace

    //-----------------------------------------------------------------------------

    Big_Int::Big_Int ()
        : _bytes ( { 0x00 } )
    {}

    Big_Int::Big_Int ( uint64_t val )
    {
        if ( val == 0 )
        {
            _bytes = { 0x00 };
        }
        else
        {
            while ( val > 0 )
            {
                _bytes.push_back ( static_cast < uint8_t > ( val & 0xFFu ) );
                val >>= 8;
            }
            std::reverse ( _bytes.begin (), _bytes.end () );
        }
    }

    Big_Int::Big_Int ( std::string_view hex_str )
        : _bytes ( parse_hex_string ( hex_str ) )
    {
        normalize ();
    }

    Big_Int::Big_Int ( std::vector < uint8_t > bytes )
        : _bytes ( std::move ( bytes ) )
    {
        normalize ();
    }

    Big_Int::Big_Int ( std::span < const uint8_t > bytes )
        : _bytes ( bytes.begin (), bytes.end () )
    {
        normalize ();
    }

    Big_Int::Big_Int ( std::initializer_list < uint8_t > bytes )
        : _bytes ( bytes )
    {
        normalize ();
    }

    void
    Big_Int::normalize ()
    {
        size_t first_non_zero = 0;
        while ( first_non_zero + 1 < _bytes.size () && _bytes [ first_non_zero ] == 0x00 )
        {
            first_non_zero++;
        }

        if ( first_non_zero > 0 )
        {
            _bytes.erase ( _bytes.begin (), _bytes.begin () + static_cast < ptrdiff_t > ( first_non_zero ) );
        }

        if ( _bytes.empty () )
        {
            _bytes.push_back ( 0x00 );
        }
    }

    void
    Big_Int::encode_into ( DER_Encoder& to ) const
    {
        std::vector < uint8_t > der_bytes;
        der_bytes.reserve ( _bytes.size () + 1 );

        // DER two's-complement rule: prepend 0x00 if MSB is set so it is evaluated as a positive integer
        if ( !_bytes.empty () && ( _bytes [ 0 ] & 0x80u ) != 0 )
        {
            der_bytes.push_back ( 0x00 );
        }

        der_bytes.insert ( der_bytes.end (), _bytes.begin (), _bytes.end () );

        to.add_object ( ASN1_Type::INTEGER, ASN1_Class::UNIVERSAL, der_bytes );
    }

    void
    Big_Int::decode_from ( BER_Decoder& from )
    {
        std::vector < uint8_t > raw_bytes;
        from.decode ( raw_bytes, ASN1_Type::INTEGER, ASN1_Class::UNIVERSAL );

        if ( raw_bytes.empty () )
        {
            throw ASN1_DecodingError ( "Empty INTEGER data stream" );
        }

        // Validate DER shortest-form rule: leading 0x00 is ONLY permitted if the next byte has MSB set (>= 0x80)
        if ( raw_bytes.size () > 1 && raw_bytes [ 0 ] == 0x00 )
        {
            if ( ( raw_bytes [ 1 ] & 0x80u ) == 0 )
            {
                throw ASN1_DecodingError ( "Non-canonical DER integer: superfluous leading zero byte detected" );
            }
            // Cleanly strip the DER sign padding byte
            raw_bytes.erase ( raw_bytes.begin () );
        }

        _bytes = std::move ( raw_bytes );
        normalize ();
    }

    const std::vector < uint8_t >&
    Big_Int::get_bytes () const noexcept
    {
        return _bytes;
    }

    bool
    Big_Int::is_zero () const noexcept
    {
        return _bytes.size () == 1 && _bytes [ 0 ] == 0x00;
    }

    void
    Big_Int::clear () noexcept
    {
        _bytes = { 0x00 };
    }

    uint64_t
    Big_Int::to_uint64 () const
    {
        if ( _bytes.size () > sizeof ( uint64_t ) )
        {
            throw ASN1_InvalidArgument ( "Big_Int value exceeds uint64_t bounds" );
        }

        uint64_t val = 0;
        for ( uint8_t b : _bytes )
        {
            val = ( val << 8 ) | static_cast < uint64_t > ( b );
        }
        return val;
    }

    std::string
    Big_Int::to_string () const
    {
        std::ostringstream oss;
        oss << std::hex << std::uppercase << std::setfill ( '0' );

        for ( uint8_t b : _bytes )
        {
            oss << std::setw ( 2 ) << static_cast < int > ( b );
        }

        return oss.str ();
    }

    bool
    Big_Int::operator== ( const Big_Int& other ) const noexcept
    {
        return _bytes == other._bytes;
    }

    bool
    Big_Int::operator!= ( const Big_Int& other ) const noexcept
    {
        return !( *this == other );
    }

    bool
    Big_Int::operator< ( const Big_Int& other ) const noexcept
    {
        if ( _bytes.size () != other._bytes.size () )
        {
            return _bytes.size () < other._bytes.size ();
        }
        return _bytes < other._bytes;
    }

    bool
    Big_Int::operator<= ( const Big_Int& other ) const noexcept
    {
        return !( other < *this );
    }

    bool
    Big_Int::operator> ( const Big_Int& other ) const noexcept
    {
        return other < *this;
    }

    bool
    Big_Int::operator>= ( const Big_Int& other ) const noexcept
    {
        return !( *this < other );
    }

    std::ostream&
    operator<< ( std::ostream& os, const Big_Int& big_int )
    {
        return os << "0x" << big_int.to_string ();
    }

} // asn1pp