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

#include <cstdint>
#include <initializer_list>
#include <iosfwd>
#include <span>
#include <string>
#include <string_view>

#include <asn1pp/asn1_object.hpp>

namespace asn1pp 
{

    /**
     * @brief Represents an ASN.1 INTEGER of arbitrary precision (BigInteger).
     * 
     * Encapsulates a positive arbitrary-length integer stored as big-endian bytes.
     * Automatically handles DER two's-complement rules (injecting/stripping leading
     * 0x00 sign padding bytes when the most significant bit is set).
     */
    class Big_Int final : public ASN1_Object
    {
    public:
        /**
         * @brief Constructs an initialized Big_Int representing the value zero (0x00).
         */
        Big_Int ();

        /**
         * @brief Constructs a Big_Int from a standard 64-bit unsigned integer.
         * @param val The numerical value.
         */
        explicit Big_Int ( uint64_t val );

        /**
         * @brief Constructs a Big_Int from a hexadecimal string representation.
         * @param hex_str Formatted hex string (e.g., "00FF01" or "0xDEADBEEF").
         */
        explicit Big_Int ( std::string_view hex_str );

        /**
         * @brief Constructs a Big_Int from a raw byte vector in big-endian order.
         * @param bytes The raw big-endian byte buffer.
         */
        explicit Big_Int ( std::vector < uint8_t > bytes );

        /**
         * @brief Constructs a Big_Int from a memory span of bytes in big-endian order.
         * @param bytes Read-only view of the byte buffer.
         */
        explicit Big_Int ( std::span < const uint8_t > bytes );

        /**
         * @brief Constructs a Big_Int from an initializer list of bytes.
         * @param bytes Initializer list of big-endian raw bytes.
         */
        Big_Int ( std::initializer_list < uint8_t > bytes );

        ~Big_Int() override = default;

        // Copy and move semantics
        Big_Int ( const Big_Int& ) = default;
        Big_Int& operator= ( const Big_Int& ) = default;
        Big_Int ( Big_Int&& ) noexcept = default;
        Big_Int& operator= ( Big_Int&& ) noexcept = default;

        /**
         * @brief Serializes this arbitrary-precision integer into a DER encoder stream.
         * @param to The target DER encoder.
         */
        void encode_into ( DER_Encoder& to ) const override;

        /**
         * @brief Deserializes an arbitrary-precision integer from a BER decoder stream.
         * @param from The source BER decoder.
         */
        void decode_from ( BER_Decoder& from ) override;

        /**
         * @brief Returns the read-only vector of normalized big-endian bytes (without DER sign padding).
         */
        [[nodiscard]] const std::vector < uint8_t >& get_bytes () const noexcept;

        /**
         * @brief Checks whether the integer evaluates to zero.
         */
        [[nodiscard]] bool is_zero () const noexcept;

        /**
         * @brief Resets the integer value to zero (0x00).
         */
        void clear () noexcept;

        /**
         * @brief Converts the big integer to a standard uint64_t if within bounds.
         * @return The 64-bit integer representation.
         * @throws ASN1_InvalidArgument if the stored value exceeds uint64_t limits.
         */
        [[nodiscard]] uint64_t to_uint64 () const;

        /**
         * @brief Formats the integer as an uppercase hexadecimal string.
         * @return Uppercase hexadecimal representation (without "0x" prefix).
         */
        [[nodiscard]] std::string to_string () const;

        // Relational operators for numerical comparison
        [[nodiscard]] bool operator== ( const Big_Int& other ) const noexcept;
        [[nodiscard]] bool operator!= ( const Big_Int& other ) const noexcept;
        [[nodiscard]] bool operator< ( const Big_Int& other ) const noexcept;
        [[nodiscard]] bool operator<= ( const Big_Int& other ) const noexcept;
        [[nodiscard]] bool operator> ( const Big_Int& other ) const noexcept;
        [[nodiscard]] bool operator>= ( const Big_Int& other ) const noexcept;
    private:
        void normalize ();

        std::vector < uint8_t > _bytes;
    };

    /**
     * @brief Stream insertion operator for printing Big_Int hexadecimal values.
     */
    std::ostream& operator<< ( std::ostream& os, const Big_Int& big_int );

} // asn1pp

#endif // __ASN1PP_BIG_INT_HPP_