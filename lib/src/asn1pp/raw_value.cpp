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

#include <asn1pp/raw_value.hpp>

#include <utility>

#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    Raw_Value::Raw_Value ( std::vector < uint8_t > tlv_bytes )
        : _tlv_bytes ( std::move ( tlv_bytes ) )
    {}

    Raw_Value::Raw_Value ( std::span < const uint8_t > tlv_bytes )
        : _tlv_bytes ( tlv_bytes.begin (), tlv_bytes.end () )
    {}

    void
    Raw_Value::encode_into ( DER_Encoder& to ) const
    {
        if ( !_tlv_bytes.empty () )
        {
            to.raw_bytes ( _tlv_bytes );
        }
    }

    void
    Raw_Value::decode_from ( BER_Decoder& from )
    {
        _tlv_bytes = from.get_next_raw_tlv ();
    }

    const std::vector < uint8_t >&
    Raw_Value::get_bytes () const noexcept
    {
        return _tlv_bytes;
    }

    bool
    Raw_Value::empty () const noexcept
    {
        return _tlv_bytes.empty ();
    }

    void
    Raw_Value::clear () noexcept
    {
        _tlv_bytes.clear ();
    }

    bool
    Raw_Value::operator== ( const Raw_Value& other ) const noexcept
    {
        return _tlv_bytes == other._tlv_bytes;
    }

    bool
    Raw_Value::operator!= ( const Raw_Value& other ) const noexcept
    {
        return !( *this == other );
    }

} // asn1pp