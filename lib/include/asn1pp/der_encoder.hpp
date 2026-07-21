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

#ifndef __ASN1PP_DER_ENCODER_HPP_
#define __ASN1PP_DER_ENCODER_HPP_

#include <string_view>
#include <span>

#include <asn1pp/asn1_types.hpp>

namespace asn1pp
{
    /**
     * @brief DER Encoder implementing a fluent builder pattern with stack-based sequence handling.
     */
    class DER_Encoder
    {
    public:
        DER_Encoder () = default;
        ~DER_Encoder () = default;

        // Move and copy semantics
        DER_Encoder ( const DER_Encoder& ) = default;
        DER_Encoder& operator= ( const DER_Encoder& ) = default;
        DER_Encoder ( DER_Encoder&& ) noexcept = default;
        DER_Encoder& operator= ( DER_Encoder&& ) noexcept = default;

        /**
         * @brief Returns the encoded DER binary stream.
         */
        [[nodiscard]] std::vector < uint8_t > get_contents () const;

        /**
         * @brief Encodes a boolean value.
         */
        DER_Encoder& encode ( bool val );

        /**
         * @brief Encodes an unsigned integer (up to 64-bit).
         */
        DER_Encoder& encode ( uint64_t val );

        /**
         * @brief Encodes a signed integer (up to 64-bit).
         */
        DER_Encoder& encode ( int64_t val );

        /**
         * @brief Encodes an OCTET STRING or raw byte vector with a specific tag.
         */
        DER_Encoder& encode ( std::span < const uint8_t > bytes,
                              ASN1_Type type_tag   = ASN1_Type::OCTET_STRING,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Encodes a string (e.g., UTF8String, PrintableString).
         */
        DER_Encoder& encode ( std::string_view str,
                              ASN1_Type type_tag   = ASN1_Type::UTF8_STRING,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Serializes an abstract ASN.1 domain object by invoking its virtual encode_into method.
         * @param obj The domain object to serialize (e.g., OID, BitString, Certificate).
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        template <typename T>
        DER_Encoder& encode ( const T& obj )
        {
            obj.encode_into ( *this );
            return *this;
        }

        /**
         * @brief Encodes an ASN.1 NULL object.
         */
        DER_Encoder& encode_null ();

        /**
         * @brief Starts a constructed SEQUENCE structure.
         */
        DER_Encoder& start_sequence ();

        /**
         * @brief Starts a constructed SET structure.
         */
        DER_Encoder& start_set ();

        /**
         * @brief Ends the current constructed structure (SEQUENCE or SET) and writes it to the parent stream.
         */
        DER_Encoder& end_cons ();

        /**
         * @brief Injects raw bytes directly into the current stream without TLV wrapping.
         */
        DER_Encoder& raw_bytes ( std::span < const uint8_t > val );

        /**
         * @brief Adds a fully formatted TLV object to the stream.
         */
        DER_Encoder& add_object ( ASN1_Type type_tag,
                                  ASN1_Class class_tag,
                                  std::span < const uint8_t > rep );
        DER_Encoder&  add_object ( ASN1_Type type_tag, 
                                   uint8_t class_tag, 
                                   std::span < const uint8_t > rep );
    private:
        struct Subsequence
        {
            ASN1_Type tag;
            uint8_t class_tag;
            std::vector<uint8_t> contents;
        };

        void start_cons ( ASN1_Type tag, uint8_t class_tag );
        std::vector < uint8_t >& current_stream ();
        const std::vector < uint8_t >& current_stream () const;

        static void encode_length ( std::vector < uint8_t >& out, size_t length );
        static void encode_tag ( std::vector < uint8_t >& out, ASN1_Type type_tag, uint8_t class_tag );
    private:
        std::vector < uint8_t > _contents;
        std::vector < Subsequence > _subsequences;
    };

} // asn1pp

#endif // __ASN1PP_DER_ENCODER_HPP_