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

#include <initializer_list>
#include <span>
#include <string>

#include <asn1pp/asn1_object.hpp>

namespace asn1pp 
{

    /**
     * @brief Represents an ASN.1 BIT STRING.
     * 
     * Encapsulates an arbitrary sequence of bits stored as bytes, along with
     * the count of unused padding bits (0 to 7) in the final byte according to
     * ITU-T X.690 DER/BER encoding rules.
     */
    class Bit_String final : public ASN1_Object {
    public:
        /**
         * @brief Constructs an empty BIT STRING.
         */
        Bit_String () = default;

        /**
         * @brief Constructs a BIT STRING from a vector of bytes and unused bit count.
         * @param bits The raw byte buffer representing the bit sequence.
         * @param unused_bits Number of padding bits in the last byte (0 to 7).
         */
        explicit Bit_String ( std::vector < uint8_t > bits, uint8_t unused_bits = 0 );

        /**
         * @brief Constructs a BIT STRING from a memory span of bytes and unused bit count.
         * @param bits Read-only view of the byte buffer.
         * @param unused_bits Number of padding bits in the last byte (0 to 7).
         */
        explicit Bit_String ( std::span < const uint8_t > bits, uint8_t unused_bits = 0 );

        /**
         * @brief Constructs a BIT STRING from an initializer list of bytes.
         * @param bits Initializer list of raw bytes.
         * @param unused_bits Number of padding bits in the last byte (0 to 7).
         */
        Bit_String ( std::initializer_list < uint8_t > bits, uint8_t unused_bits = 0 );

        ~Bit_String() override = default;

        // Copy and move semantics
        Bit_String ( const Bit_String& ) = default;
        Bit_String& operator= ( const Bit_String& ) = default;
        Bit_String ( Bit_String&& ) noexcept = default;
        Bit_String& operator= ( Bit_String&& ) noexcept = default;

        /**
         * @brief Serializes this BIT STRING into a DER encoder stream.
         * @param to The target DER encoder.
         */
        void encode_into ( DER_Encoder& to ) const override;

        /**
         * @brief Deserializes a BIT STRING from a BER decoder stream.
         * @param from The source BER decoder.
         */
        void decode_from ( BER_Decoder& from ) override;

        /**
         * @brief Returns the read-only vector of underlying bytes.
         */
        [[nodiscard]] const std::vector < uint8_t >& get_bits () const noexcept;

        /**
         * @brief Returns the number of unused padding bits in the last byte (0 to 7).
         */
        [[nodiscard]] uint8_t get_unused_bits () const noexcept;

        /**
         * @brief Checks whether the BIT STRING contains no data bytes.
         */
        [[nodiscard]] bool empty () const noexcept;

        /**
         * @brief Clears all bytes and resets unused bits to zero.
         */
        void clear () noexcept;

        /**
         * @brief Formats the underlying byte buffer as a hexadecimal string.
         * @return Uppercase hexadecimal string representation.
         */
        [[nodiscard]] std::string to_string () const;

        // Relational operators for ordering and equality checks
        [[nodiscard]] bool operator== ( const Bit_String& other ) const noexcept;
        [[nodiscard]] bool operator!= ( const Bit_String& other ) const noexcept;
        [[nodiscard]] bool operator< ( const Bit_String& other ) const noexcept;
    private:
        std::vector < uint8_t > _bits;
        uint8_t _unused_bits = 0;
    };

    /**
     * @brief Stream insertion operator for printing Bit_String hex representations.
     */
    std::ostream& operator<< ( std::ostream& os, const Bit_String& bit_string );

} // asn1pp

#endif // __ASN1PP_BIT_STRING_HPP_