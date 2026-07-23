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

#ifndef __ASN1PP_RAW_VALUE_HPP_
#define __ASN1PP_RAW_VALUE_HPP_

#include <cstdint>
#include <span>
#include <vector>

#include <asn1pp/asn1_object.hpp>

namespace asn1pp
{

    /**
     * @brief Represents an ASN.1 Open Type (ANY or ANY DEFINED BY / Raw TLV).
     * 
     * Encapsulates an uninterpreted, complete binary TLV (Tag, Length, Value) byte slice.
     * Essential for handling dynamic schemas such as AlgorithmIdentifier parameters or CMS content info.
     */
    class Raw_Value final : public ASN1_Object
    {
    public:
        Raw_Value () = default;

        /**
         * @brief Constructs a Raw_Value from a raw TLV byte vector.
         * @param tlv_bytes The complete encoded TLV bytes.
         */
        explicit Raw_Value ( std::vector < uint8_t > tlv_bytes );

        /**
         * @brief Constructs a Raw_Value from a read-only memory span.
         * @param tlv_bytes Read-only view of the complete encoded TLV bytes.
         */
        explicit Raw_Value ( std::span < const uint8_t > tlv_bytes );

        ~Raw_Value () override = default;

        // Copy and move semantics
        Raw_Value ( const Raw_Value& ) = default;
        Raw_Value& operator= ( const Raw_Value& ) = default;
        Raw_Value ( Raw_Value&& ) noexcept = default;
        Raw_Value& operator= ( Raw_Value&& ) noexcept = default;

        /**
         * @brief Injects the raw TLV bytes directly into the target DER encoder stream.
         */
        void encode_into ( DER_Encoder& to ) const override;

        /**
         * @brief Extracts the next complete TLV object from the BER decoder without parsing its internals.
         */
        void decode_from ( BER_Decoder& from ) override;

        /**
         * @brief Returns the read-only vector of underlying TLV bytes.
         */
        [[nodiscard]] const std::vector < uint8_t >& get_bytes () const noexcept;

        /**
         * @brief Checks whether this open type contains no data bytes.
         */
        [[nodiscard]] bool empty () const noexcept;

        /**
         * @brief Clears the stored TLV byte buffer.
         */
        void clear () noexcept;

        // Relational operators
        [[nodiscard]] bool operator== ( const Raw_Value& other ) const noexcept;
        [[nodiscard]] bool operator!= ( const Raw_Value& other ) const noexcept;
    private:
        std::vector < uint8_t > _tlv_bytes;
    };

} // asn1pp

#endif // __ASN1PP_RAW_VALUE_HPP_