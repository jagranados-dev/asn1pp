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

#ifndef __ASN1PP_BIT_STRING_HPP_
#define __ASN1PP_BIT_STRING_HPP_

#include <iosfwd>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <asn1pp/asn1_object.hpp>

namespace asn1pp
{

    /** @brief ASN.1 BIT STRING with explicit unused-bit tracking. */
    class Bit_String : public ASN1_Object
    {
    public:
        Bit_String ();
        Bit_String (std::span < const uint8_t > bytes, uint8_t unused_bits = 0);
        [[nodiscard]] const std::vector < uint8_t >& bytes () const noexcept;
        [[nodiscard]] uint8_t unused_bits () const noexcept;
        [[nodiscard]] size_t bit_count () const noexcept;
        void assign (std::span < const uint8_t > bytes, uint8_t unused_bits = 0);
        void encode_into (DER_Encoder& to) const override;
        void decode_from (BER_Decoder& from) override;
        bool operator== (const Bit_String& other) const noexcept;
        friend std::ostream& operator<< (std::ostream& stream, const Bit_String& value);

    private:
        void validate () const;
        std::vector < uint8_t > _bytes;
        uint8_t _unused_bits;
    };

} // asn1pp

#endif // __ASN1PP_BIT_STRING_HPP_
