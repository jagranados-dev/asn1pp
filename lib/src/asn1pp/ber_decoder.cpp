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

#include <asn1pp/ber_decoder.hpp>

#include <asn1pp/asn1_errors.hpp>

namespace asn1pp
{

    BER_Decoder::BER_Decoder ( std::span < const uint8_t > data )
        : _offset ( 0 ), _data ( data )
    {
        _limits.push_back ( data.size () );
    }

    BER_Decoder::BER_Decoder ( const std::vector < uint8_t >& data )
        : BER_Decoder ( std::span < const uint8_t > ( data ) )
    {}

    bool
    BER_Decoder::more_items () const
    {
        if ( _limits.empty () )
        {
            return false;
        }

        return _offset < _limits.back ();
    }

    BER_ObjectHeader
    BER_Decoder::get_next_header () const
    {
        if ( !more_items () )
        {
            throw ASN1_DecodingError ( "Attempted to read past the end of the ASN.1 buffer" );
        }

        size_t pos = _offset;
        const uint8_t tag_byte = _data [ pos++ ];

        // Parse tag and class
        const auto type_tag = static_cast < ASN1_Type > ( tag_byte & 0x1F );
        const uint8_t class_tag = tag_byte & 0xE0;

        if ( static_cast < uint8_t > ( type_tag ) == 0x1F )
        {
            throw ASN1_DecodingError ( "High-tag number form (>30) is not supported in this standalone view" );
        }

        if ( pos >= _limits.back () )
        {
            throw ASN1_DecodingError ( "Buffer truncated while reading length byte" );
        }

        // Parse BER/DER length
        size_t length = 0;
        const uint8_t len_byte = _data [ pos++ ];

        if ( ( len_byte & 0x80 ) == 0 )
        {
            length = len_byte;
        }
        else
        {
            const size_t num_bytes = len_byte & 0x7F;
            if ( num_bytes == 0 || num_bytes > sizeof ( size_t ) )
            {
                throw ASN1_DecodingError ( "Invalid or unsupported length encoding size" );
            }

            if ( pos + num_bytes > _limits.back () )
            {
                throw ASN1_DecodingError ( "Buffer overflow while reading length bytes" );
            }

            for ( size_t i = 0; i < num_bytes; ++i )
            {
                length = ( length << 8 ) | _data [ pos++ ];
            }
        }

        if ( ( pos + length ) > _limits.back () )
        {
            throw ASN1_DecodingError ( "ASN.1 object value extends beyond enclosing scope limit" );
        }
        
        const size_t header_size = pos - _offset;
        return BER_ObjectHeader ( type_tag, class_tag, length, header_size );
    }

    BER_ObjectHeader
    BER_Decoder::get_next_object ()
    {
        BER_ObjectHeader hdr = get_next_header ();
        _offset += hdr.header_size + hdr.length;

        return hdr;
    }

    std::optional < BER_ObjectHeader >
    BER_Decoder::peek_next_header () const
    {
        if ( !more_items () )
        {
            return std::nullopt;
        }

        try
        {
            return get_next_header ();
        }
        catch ( ... )
        {
            return std::nullopt;
        }
    }

    std::vector < uint8_t >
    BER_Decoder::get_next_value ( ASN1_Type expected_type, ASN1_Class expected_class )
    {
        BER_ObjectHeader hdr = get_next_header ();
        const uint8_t exp_class_val = static_cast < uint8_t > ( expected_class );

        if ( hdr.type_tag != expected_type || ( hdr.class_tag & 0xC0 ) != ( exp_class_val & 0xC0 ) )
        {
            throw ASN1_DecodingError ( "Tag mismatch: expected different type or class tag" );
        }

        _offset += hdr.header_size;
        std::vector < uint8_t > val ( _data.begin () + _offset, _data.begin () + _offset + hdr.length );
        _offset += hdr.length;

        return val;
    }

    BER_Decoder&
    BER_Decoder::decode ( bool& out )
    {
        std::vector < uint8_t > val = get_next_value ( ASN1_Type::BOOLEAN, ASN1_Class::UNIVERSAL );

        if ( val.size () != 1 )
        {
            throw ASN1_DecodingError ( "Invalid length for ASN.1 BOOLEAN" );
        }

        out = ( val [ 0 ] != 0 );

        return *this;
    }

    BER_Decoder&
    BER_Decoder::decode ( uint64_t& out )
    {
        std::vector < uint8_t > val = get_next_value ( ASN1_Type::INTEGER, ASN1_Class::UNIVERSAL );

        if ( val.empty () || val.size () > 9 )
        {
            throw ASN1_DecodingError ( "INTEGER size out of uint64_t supported bounds" );
        }

        out = 0;
        for ( uint8_t b : val )
        {
            out = ( out << 8 ) | b;
        }

        return *this;
    }

    BER_Decoder&
    BER_Decoder::decode ( int64_t& out )
    {
        std::vector < uint8_t > val = get_next_value ( ASN1_Type::INTEGER, ASN1_Class::UNIVERSAL );

        if ( val.empty () || val.size () > 8)
        {
            throw ASN1_DecodingError ( "INTEGER size out of int64_t supported bounds" );
        }

        // Check if sign bit is set for two's complement negative number
        bool is_negative = ( val [ 0 ] & 0x80 ) != 0;
        uint64_t temp = is_negative ? static_cast < uint64_t > ( -1 ) : 0;

        for ( uint8_t b : val )
        {
            temp = ( temp << 8 ) | b;
        }

        out = static_cast < int64_t > ( temp );

        return *this;
    }

    BER_Decoder&
    BER_Decoder::decode ( std::vector < uint8_t >& out, ASN1_Type type_tag, ASN1_Class class_tag )
    {
        out = get_next_value ( type_tag, class_tag );

        return *this;
    }

    BER_Decoder&
    BER_Decoder::decode ( std::string& out, ASN1_Type type_tag, ASN1_Class class_tag )
    {
        std::vector < uint8_t > val = get_next_value ( type_tag, class_tag );
        out.assign ( val.begin (), val.end () );

        return *this;
    }

    BER_Decoder&
    BER_Decoder::decode_null ()
    {
        std::vector < uint8_t > val = get_next_value ( ASN1_Type::NULL_TAG, ASN1_Class::UNIVERSAL );

        if ( !val.empty () )
        {
            throw ASN1_DecodingError ( "ASN.1 NULL must have zero length" );
        }

        return *this;
    }

    void
    BER_Decoder::start_cons ( ASN1_Type expected_type )
    {
        BER_ObjectHeader hdr = get_next_header ();
        if ( hdr.type_tag != expected_type || ( hdr.class_tag & static_cast < uint8_t > ( ASN1_Class::CONSTRUCTED ) ) == 0 )
        {
            throw ASN1_DecodingError ( "Expected CONSTRUCTED structure tag" );
        }

        _offset += hdr.header_size;
        _limits.push_back ( _offset + hdr.length );
    }

    BER_Decoder&
    BER_Decoder::start_sequence ()
    {
        start_cons ( ASN1_Type::SEQUENCE );
        return *this;
    }

    BER_Decoder&
    BER_Decoder::start_set ()
    {
        start_cons ( ASN1_Type::SET );
        return *this;
    }

    BER_Decoder&
    BER_Decoder::end_cons ()
    {
        if ( _limits.size () <= 1 )
        {
            throw ASN1_DecodingError ( "end_cons() called with no open sequence/set" );
        }

        const size_t scope_limit = _limits.back ();

        if ( _offset != scope_limit )
        {
            throw ASN1_DecodingError ( "Unconsumed bytes remaining in closed SEQUENCE/SET scope" );
        }

        _limits.pop_back ();

        return *this;
    }

} // namespace asn1pp