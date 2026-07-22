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

#include <asn1pp/der_encoder.hpp>

#include <algorithm>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/asn1_object.hpp>

namespace asn1pp
{

    std::vector < uint8_t >&
    DER_Encoder::current_stream()
    {
        if ( _subsequences.empty () )
        {
            return _contents;
        }

        return _subsequences.back().contents;
    }

    const std::vector < uint8_t >&
    DER_Encoder::current_stream () const
    {
        if ( _subsequences.empty () )
        {
            return _contents;
        }

        return _subsequences.back ().contents;
    }

    std::vector < uint8_t >
    DER_Encoder::get_contents () const
    {
        if ( !_subsequences.empty() )
        {
            throw ASN1_EncodingError ( "Unclosed SEQUENCE/SET at get_contents()" );
        }

        return _contents;
    }

    void
    DER_Encoder::encode_length ( std::vector < uint8_t >& out, size_t length )
    {
        if ( length < 128 )
        {
            out.push_back ( static_cast < uint8_t > ( length ) );
        }
        else
        {
            std::vector < uint8_t > len_bytes;
            while ( length > 0 )
            {
                len_bytes.push_back ( static_cast < uint8_t > ( length & 0xFF ) );
                length >>= 8;
            }

            out.push_back ( static_cast < uint8_t > ( 0x80 | len_bytes.size () ) );

            for ( auto it = len_bytes.rbegin (); it != len_bytes.rend (); ++it )
            {
                out.push_back ( *it );
            }
        }
    }

    void
    DER_Encoder::encode_tag ( std::vector < uint8_t >& out, ASN1_Type type_tag, uint8_t class_tag )
    {
        // Standard low-tag number encoding (tags <= 30)
        const uint8_t tag_byte = class_tag | static_cast < uint8_t > ( type_tag );
        out.push_back ( tag_byte );
    }

    DER_Encoder&
    DER_Encoder::add_object ( ASN1_Type type_tag, ASN1_Class class_tag, std::span < const uint8_t > rep )
    {
        return add_object ( type_tag, static_cast < uint8_t > ( class_tag ), rep );
    }

    DER_Encoder&
    DER_Encoder::add_object ( ASN1_Type type_tag, uint8_t class_tag, std::span < const uint8_t > rep )
    {
        std::vector < uint8_t >& stream = current_stream ();

        encode_tag ( stream, type_tag, class_tag );
        encode_length ( stream, rep.size () );
        stream.insert ( stream.end (), rep.begin (), rep.end () );
        
        return *this;
    }

    DER_Encoder&
    DER_Encoder::raw_bytes ( std::span < const uint8_t > val )
    {
        std::vector < uint8_t >& stream = current_stream ();
        stream.insert ( stream.end (), val.begin (), val.end () );

        return *this;
    }

    DER_Encoder&
    DER_Encoder::encode ( bool val, ASN1_Type type_tag, ASN1_Class class_tag )
    {
        const uint8_t byte_val = val ? 0xFF : 0x00;
        return add_object ( type_tag, class_tag, std::span ( &byte_val, 1 ) );
    }

    DER_Encoder&
    DER_Encoder::encode ( uint64_t val, ASN1_Type type_tag, ASN1_Class class_tag )
    {
        std::vector < uint8_t > contents;

        if ( !val )
        {
            contents.push_back ( 0x00 );
        }
        else
        {
            while ( val > 0 )
            {
                contents.push_back ( static_cast < uint8_t > ( val & 0xFF ) );
                val >>= 8;
            }

            // DER integers are signed; if the MSB is set, prepend a 0x00 padding byte
            if ( contents.back () & 0x80 )
            {
                contents.push_back ( 0x00 );
            }

            std::reverse ( contents.begin (), contents.end () );
        }

        return add_object ( type_tag, class_tag, contents );
    }

    DER_Encoder&
    DER_Encoder::encode ( int64_t val, ASN1_Type type_tag, ASN1_Class class_tag )
    {
        if ( val >= 0 )
        {
            return encode ( static_cast < uint64_t > ( val ), type_tag, class_tag );
        }

        // Handle negative integers via two's complement DER rules
        std::vector < uint8_t > contents;
        int64_t temp = val;

        do
        {
            contents.push_back ( static_cast < uint8_t > ( temp & 0xFF ) );
            temp >>= 8;
        } while ( temp != -1 && temp != 0 );

        // Ensure proper sign bit representation
        if ( ( contents.back () & 0x80 ) == 0 )
        {
            contents.push_back ( 0xFF );
        }

        std::reverse ( contents.begin (), contents.end () );

        return add_object ( type_tag, class_tag, contents );
    }

    DER_Encoder&
    DER_Encoder::encode ( std::span < const uint8_t > bytes, ASN1_Type type_tag, ASN1_Class class_tag )
    {
        return add_object ( type_tag, static_cast < uint8_t > ( class_tag ), bytes );
    }

    DER_Encoder&
    DER_Encoder::encode ( std::string_view str, ASN1_Type type_tag, ASN1_Class class_tag )
    {
        std::span < const uint8_t > bytes ( reinterpret_cast < const uint8_t* > ( str.data () ), str.size () );
        return add_object ( type_tag, static_cast < uint8_t > ( class_tag ), bytes );
    }

    DER_Encoder&
    DER_Encoder::encode ( const ASN1_Object& obj )
    {
        obj.encode_into ( *this );
        return *this;
    }

    DER_Encoder&
    DER_Encoder::encode_default ( bool val, bool default_val )
    {
        if ( val != default_val )
        {
            encode ( val );
        }

        return *this;
    }

    DER_Encoder&
    DER_Encoder::encode_default ( uint64_t val, uint64_t default_val )
    {
        if ( val != default_val )
        {
            encode ( val );
        }

        return *this;
    }

    DER_Encoder&
    DER_Encoder::encode_default ( int64_t val, int64_t default_val )
    {
        if ( val != default_val )
        {
            encode ( val );
        }

        return *this;
    }

    DER_Encoder&
    DER_Encoder::encode_default ( std::string_view str, std::string_view default_val, ASN1_Type type_tag, ASN1_Class class_tag )
    {
        if ( str != default_val )
        {
            encode ( str, type_tag, class_tag );
        }

        return *this;
    }

    DER_Encoder&
    DER_Encoder::encode_default ( std::span < const uint8_t > bytes, std::span < const uint8_t > default_val, ASN1_Type type_tag, ASN1_Class class_tag )
    {
        if ( !std::equal ( bytes.begin (), bytes.end (), default_val.begin (), default_val.end () ) )
        {
            encode ( bytes, type_tag, class_tag );
        }

        return *this;
    }

    DER_Encoder&
    DER_Encoder::encode_null ()
    {
        return add_object ( ASN1_Type::NULL_TAG, ASN1_Class::UNIVERSAL, {} );
    }

    void
    DER_Encoder::start_cons ( ASN1_Type tag, uint8_t class_tag )
    {
        _subsequences.push_back ({ tag, static_cast < uint8_t > ( class_tag | ASN1_Class::CONSTRUCTED ), {} });
    }

    DER_Encoder&
    DER_Encoder::start_sequence ()
    {
        start_cons ( ASN1_Type::SEQUENCE, static_cast < uint8_t > ( ASN1_Class::UNIVERSAL ) );
        return *this;
    }

    DER_Encoder&
    DER_Encoder::start_set ()
    {
        start_cons ( ASN1_Type::SET, static_cast < uint8_t > ( ASN1_Class::UNIVERSAL ) );
        return *this;
    }

    DER_Encoder&
    DER_Encoder::end_cons ()
    {
        if ( _subsequences.empty () )
        {
            throw ASN1_EncodingError ( "end_cons() called without matching start_sequence/set" );
        }

        Subsequence sub = std::move ( _subsequences.back () );
        _subsequences.pop_back();

        return add_object ( sub.tag, sub.class_tag, sub.contents );
    }

} // asn1pp