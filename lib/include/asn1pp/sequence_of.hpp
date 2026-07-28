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

#ifndef __ASN1PP_SEQUENCE_OF_HPP_
#define __ASN1PP_SEQUENCE_OF_HPP_

#include <ostream>
#include <utility>
#include <vector>

#include <asn1pp/asn1_object.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    template < typename T >
    class Sequence_Of : public ASN1_Object
    {
    public:
        std::vector < T > values;
        void
        encode_into (DER_Encoder& to) const override
        {
            to.encode_sequence (
                [&] (DER_Encoder& child)
                {
                    for (const T& value : values)
                    {
                        child.encode (value);
                    }
                });
        }

        void
        decode_from (BER_Decoder& from) override
        {
            std::vector < T > result;
            from.decode_sequence (
                [&] (BER_Decoder& child)
                {
                    while (child.more_items ())
                    {
                        T value;
                        child.decode (value);
                        result.push_back (std::move (value));
                    }
                });
            values = std::move (result);
        }
        bool operator== (const Sequence_Of& other) const
        {
            return values == other.values;
        }

        friend std::ostream& operator<< (std::ostream& stream, const Sequence_Of& value)
        {
            stream << '[';
            for (size_t index = 0; index < value.values.size (); ++index)
            {
                if (index != 0) stream << ", ";
                stream << value.values[index];
            }
            stream << ']';
            return stream;
        }
    };

} // asn1pp

#endif // __ASN1PP_SEQUENCE_OF_HPP_
