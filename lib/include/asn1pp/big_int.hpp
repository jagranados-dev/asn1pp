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

#ifndef __ASN1PP_BIG_INT_HPP_
#define __ASN1PP_BIG_INT_HPP_

#include <iosfwd>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <asn1pp/asn1_object.hpp>

namespace asn1pp
{

    /** @brief Arbitrary-precision signed ASN.1 INTEGER value. */
    class Big_Int : public ASN1_Object
    {
    public:
        Big_Int ();
        explicit Big_Int (int64_t value);
        explicit Big_Int (std::string_view decimal);
        [[nodiscard]] const std::vector < uint8_t >& bytes () const noexcept;
        [[nodiscard]] std::string to_decimal () const;
        [[nodiscard]] bool negative () const noexcept;
        void set_bytes (std::span < const uint8_t > value);
        void set_decimal (std::string_view value);
        void encode_into (DER_Encoder& to) const override;
        void decode_from (BER_Decoder& from) override;
        bool operator== (const Big_Int& other) const noexcept;
        friend std::ostream& operator<< (std::ostream& stream, const Big_Int& value);

    private:
        static std::vector < uint8_t > canonicalize (std::span < const uint8_t > value);
        std::vector < uint8_t > _bytes;
    };

} // asn1pp

#endif // __ASN1PP_BIG_INT_HPP_
