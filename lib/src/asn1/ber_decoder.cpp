#include <asn1/ber_decoder.hpp>

#include <stdexcept>

namespace asn1
{
    BER_Decoder::BER_Decoder ( std::span < const uint8_t > data )
        : _data ( data ), _offset ( 0 )
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

    BER_Object_Header
    BER_Decoder::get_next_header ()
    {
        if ( !more_items () )
        {
            throw ASN1_Decoding_Error ( "Attempted to read past the end of the ASN.1 buffer" );
        }

        size_t pos = _offset;
        const uint8_t tag_byte = _data [ pos++ ];

        // Parse tag and class
        const auto type_tag = static_cast < ASN1_Type > ( tag_byte & 0x1F );
        const uint8_t class_tag = tag_byte & 0xE0;

        if ( static_cast < uint8_t > ( type_tag ) == 0x1F )
        {
            throw ASN1_Decoding_Error ( "High-tag number form (>30) is not supported in this standalone view" );
        }

        if ( pos >= _limits.back () )
        {
            throw ASN1_Decoding_Error ( "Buffer truncated while reading length byte" );
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
                throw ASN1_Decoding_Error ( "Invalid or unsupported length encoding size" );
            }

            if ( pos + num_bytes > _limits.back () )
            {
                throw ASN1_Decoding_Error ( "Buffer overflow while reading length bytes" );
            }

            for ( size_t i = 0; i < num_bytes; ++i )
            {
                length = ( length << 8 ) | _data [ pos++ ];
            }
        }

        if ( ( pos + length ) > _limits.back () )
        {
            throw ASN1_Decoding_Error ( "ASN.1 object value extends beyond enclosing scope limit" );
        }
        
        const size_t header_size = pos - _offset;
        return BER_Object_Header ( type_tag, class_tag, length, header_size );
    }

    BER_Object_Header
    BER_Decoder::get_next_object ()
    {
        BER_Object_Header hdr = get_next_header ();
        _offset += hdr.header_size + hdr.length;

        return hdr;
    }

    std::vector < uint8_t >
    BER_Decoder::get_next_value ( ASN1_Type expected_type, ASN1_Class expected_class )
    {
        BER_Object_Header hdr = get_next_header();
        const uint8_t exp_class_val = static_cast < uint8_t > ( expected_class );

        if ( hdr.type_tag != expected_type || ( hdr.class_tag & 0xC0 ) != ( exp_class_val & 0xC0 ) )
        {
            throw ASN1_Decoding_Error ( "Tag mismatch: expected different type or class tag" );
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
            throw ASN1_Decoding_Error ( "Invalid length for ASN.1 BOOLEAN" );
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
            throw ASN1_Decoding_Error ( "INTEGER size out of uint64_t supported bounds" );
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
            throw ASN1_Decoding_Error ( "INTEGER size out of int64_t supported bounds" );
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
    BER_Decoder::decode_null()
    {
        std::vector < uint8_t > val = get_next_value ( ASN1_Type::NULL_TAG, ASN1_Class::UNIVERSAL );

        if ( !val.empty () )
        {
            throw ASN1_Decoding_Error ( "ASN.1 NULL must have zero length" );
        }

        return *this;
    }

    void
    BER_Decoder::start_cons ( ASN1_Type expected_type )
    {
        BER_Object_Header hdr = get_next_header ();
        if ( hdr.type_tag != expected_type || ( hdr.class_tag & static_cast < uint8_t > ( ASN1_Class::CONSTRUCTED ) ) == 0 )
        {
            throw ASN1_Decoding_Error ( "Expected CONSTRUCTED structure tag" );
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
            throw ASN1_Decoding_Error ( "end_cons() called with no open sequence/set" );
        }

        const size_t scope_limit = _limits.back ();

        if ( _offset != scope_limit )
        {
            throw ASN1_Decoding_Error ( "Unconsumed bytes remaining in closed SEQUENCE/SET scope" );
        }

        _limits.pop_back ();

        return *this;
    }
} // namespace asn1