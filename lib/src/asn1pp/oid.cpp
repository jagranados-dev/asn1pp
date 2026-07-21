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

#include <asn1pp/oid.hpp>

#include <ostream>
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
        parse_oid_string ( std::string_view str, std::vector < uint32_t >& out )
        {
            out.clear ();
            if ( str.empty () ) return;

            size_t start = 0;
            while ( start < str.size () )
            {
                size_t end = str.find ( '.', start );
                if ( end == std::string_view::npos )
                {
                    end = str.size();
                }

                if ( start == end )
                {
                    throw ASN1_InvalidArgument ( "Empty OID arc in string representation" );
                }

                uint64_t val = 0;
                for ( size_t idx = start; idx < end; idx++ )
                {
                    if ( str [ idx ] < '0' || str [ idx ] > '9' )
                    {
                        throw ASN1_InvalidArgument ( "Invalid character in OID string" );
                    }

                    val = val * 10u + static_cast < uint64_t > ( str [ idx ] - '0' );

                    if ( val > UINT32_MAX )
                    {
                        throw ASN1_InvalidArgument ( "OID arc value exceeds uint32_t bounds" );
                    }
                }

                out.push_back ( static_cast < uint32_t > ( val ) );

                start = end + 1;
            }
        }

        void
        encode_base128 ( std::vector < uint8_t >& out, uint32_t val )
        {
            if ( val == 0 )
            {
                out.push_back ( 0x00 );
                return;
            }

            std::vector < uint8_t > stack;
            while ( val > 0 )
            {
                stack.push_back ( static_cast < uint8_t > ( val & 0x7Fu ) );
                val >>= 7;
            }

            for ( size_t i = stack.size (); i > 0; i-- )
            {
                uint8_t b = stack [ i - 1 ];

                if ( i > 1 )
                {
                    b = static_cast < uint8_t > ( b | 0x80u );
                }

                out.push_back ( b );
            }
        }

    } // namespace

    //-----------------------------------------------------------------------------

    OID::OID ( std::string_view str )
    {
        parse_oid_string ( str, _components );
    }

    OID::OID ( std::vector < uint32_t > components )
        : _components ( std::move ( components ) ) 
    {}

    OID::OID ( std::initializer_list < uint32_t > components )
        : _components ( components )
    {}

    void
    OID::encode_into ( DER_Encoder& to ) const
    {
        if ( _components.size () < 2)
        {
            throw ASN1_EncodingError ( "OID must have at least two components to be encoded" );
        }

        if ( _components [ 0 ] > 2 || ( _components [ 0 ] < 2 && _components [ 1 ] > 39 ) )
        {
            throw ASN1_EncodingError ( "Invalid initial OID arcs for encoding" );
        }

        std::vector < uint8_t > contents;
        const uint64_t first_val = static_cast < uint64_t > ( _components [ 0 ] ) * 40u + _components [ 1 ];
        if ( first_val > UINT32_MAX )
        {
            throw ASN1_EncodingError ( "Combined initial OID arc exceeds uint32_t bounds" );
        }

        encode_base128 ( contents, static_cast < uint32_t > ( first_val ) );

        for ( size_t idx = 2; idx < _components.size(); idx++ )
        {
            encode_base128 ( contents, _components [ idx ] );
        }

        to.add_object ( ASN1_Type::OBJECT_ID, ASN1_Class::UNIVERSAL, contents );
    }

    void
    OID::decode_from ( BER_Decoder& from )
    {
        std::vector < uint8_t > raw_bytes;
        from.decode ( raw_bytes, ASN1_Type::OBJECT_ID, ASN1_Class::UNIVERSAL );

        if ( raw_bytes.empty () )
        {
            throw ASN1_DecodingError ( "Empty OID" );
        }

        if ( ( raw_bytes.back () & 0x80u ) != 0 )
        {
            throw ASN1_DecodingError ( "Truncated OID base-128 sequence" );
        }

        bool first = true;
        uint64_t current = 0;
        std::vector < uint32_t > components;

        for ( uint8_t b : raw_bytes )
        {
            if ( current > ( UINT64_MAX >> 7 ) )
            {
                throw ASN1_DecodingError ( "OID arc overflow during base-128 decoding" );
            }

            current = ( current << 7 ) | static_cast < uint64_t >( b & 0x7Fu );

            if ( ( b & 0x80u ) == 0 )
            {
                if ( current > UINT32_MAX )
                {
                    throw ASN1_DecodingError ( "OID arc exceeds uint32_t limit" );
                }

                if ( first )
                {
                    if ( current < 40 )
                    {
                        components.push_back ( 0 );
                        components.push_back ( static_cast < uint32_t > ( current ) );
                    } 
                    else if ( current < 80 )
                    {
                        components.push_back ( 1 );
                        components.push_back ( static_cast < uint32_t > ( current - 40u ) );
                    }
                    else
                    {
                        components.push_back ( 2 );
                        components.push_back ( static_cast < uint32_t > ( current - 80u ) );
                    }

                    first = false;
                }
                else
                {
                    components.push_back ( static_cast < uint32_t > ( current ) );
                }

                current = 0;
            }
        }

        _components = std::move ( components );
    }

    const std::vector < uint32_t >&
    OID::get_components() const noexcept
    {
        return _components;
    }

    bool
    OID::empty () const noexcept
    {
        return _components.empty ();
    }

    void
    OID::clear () noexcept
    {
        return _components.clear ();
    }

    std::string
    OID::to_string () const
    {
        std::string oid_str;

        for ( auto component : _components )
        {
            oid_str += std::to_string ( component ) + ".";
        }

        // Remove last dot
        if ( !oid_str.empty () ) oid_str.pop_back ();

        return oid_str;
    }

    OID&
    OID::operator+= ( uint32_t new_component )
    {
        _components.push_back ( new_component );
        return *this;
    }

    OID
    OID::operator+ ( uint32_t new_component ) const
    {
        OID copy ( *this );
        copy += new_component;
        return copy;
    }

    bool
    OID::operator== ( const OID& other ) const noexcept
    {
        return _components == other._components;
    }

    bool
    OID::operator!= ( const OID& other ) const noexcept
    {
        return !(*this == other);
    }

    bool
    OID::operator< ( const OID& other ) const noexcept
    {
        return _components < other._components;
    }

    std::ostream&
    operator<< ( std::ostream& os, const OID& oid )
    {
        return os << oid.to_string ();
    }

} // asn1pp