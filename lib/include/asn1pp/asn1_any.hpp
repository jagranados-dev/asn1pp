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

#ifndef __ASN1PP_ASN1_ANY_HPP_
#define __ASN1PP_ASN1_ANY_HPP_

#include <cstdint>
#include <iosfwd>
#include <span>
#include <vector>

#include <asn1pp/asn1_object.hpp>

namespace asn1pp
{

    /**
     * @brief Preserves exactly one ASN.1 TLV using its original BER encoding.
     *
     * The value records whether its preserved encoding is canonical DER. BER
     * values can be decoded and inspected, but only canonical DER values can be
     * appended to DER_Encoder.
     */
    class ASN1_Any : public ASN1_Object
    {
    public:
        /** @brief Creates an empty open value. */
        ASN1_Any () = default;

        /** @brief Creates an open value from exactly one BER TLV. */
        explicit ASN1_Any (std::span < const uint8_t > encoded);

        /** @brief Returns the preserved BER TLV. */
        [[nodiscard]] const std::vector < uint8_t >& encoded_tlv () const noexcept;

        /** @brief Returns true when the preserved TLV is canonical DER. */
        [[nodiscard]] bool is_der_canonical () const noexcept;

        /** @brief Replaces the value with exactly one BER TLV. */
        void assign (std::span < const uint8_t > encoded);

        /**
         * @brief Appends the preserved TLV to a DER encoder.
         * @throws ASN1_EncodingError if the value is empty or is not canonical DER.
         */
        void encode_into (DER_Encoder& to) const override;

        /**
         * @brief Decodes and preserves the next value from a BER or DER decoder.
         *
         * A DER_Decoder rejects non-canonical input before the value is stored.
         */
        void decode_from (BER_Decoder& from) override;

        /** @brief Compares the preserved encodings byte for byte. */
        bool operator== (const ASN1_Any& other) const noexcept;

        /** @brief Writes the preserved TLV using hexadecimal notation. */
        friend std::ostream& operator<< (std::ostream& stream, const ASN1_Any& value);

    private:
        static bool validate_der (std::span < const uint8_t > encoded);

        std::vector < uint8_t > _encoded;
        bool _der_canonical = false;
    };

} // asn1pp

#endif // __ASN1PP_ASN1_ANY_HPP_
