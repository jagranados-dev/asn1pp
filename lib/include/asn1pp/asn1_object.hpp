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

#ifndef __ASN1PP_ASN1_OBJECT_HPP_
#define __ASN1PP_ASN1_OBJECT_HPP_

#include <cstdint>
#include <vector>

namespace asn1pp
{

    class DER_Encoder;
    class BER_Decoder;

    /** @brief Polymorphic base class for reusable ASN.1 values. */
    class ASN1_Object
    {
    public:
        /** @brief Destroys an ASN.1 value polymorphically. */
        virtual ~ASN1_Object () = default;
        /** @brief Appends this value to a DER encoder. */
        virtual void encode_into (DER_Encoder& to) const = 0;
        /** @brief Decodes this value transactionally from a BER decoder. */
        virtual void decode_from (BER_Decoder& from) = 0;
        /** @brief Returns the canonical DER encoding of this value. */
        [[nodiscard]] std::vector < uint8_t > DER_encode () const;
        /** @brief Returns the canonical BER-compatible DER encoding of this value. */
        [[nodiscard]] std::vector < uint8_t > BER_encode () const;
    };

} // asn1pp

#endif // __ASN1PP_ASN1_OBJECT_HPP_
