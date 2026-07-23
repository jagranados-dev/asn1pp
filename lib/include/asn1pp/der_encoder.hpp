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

#include <optional>
#include <string_view>
#include <span>

#include <asn1pp/asn1_types.hpp>

namespace asn1pp
{

    class ASN1_Object;

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
        DER_Encoder& encode ( bool val,
                              ASN1_Type type_tag   = ASN1_Type::BOOLEAN,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Encodes an unsigned integer (up to 64-bit).
         */
        DER_Encoder& encode ( uint64_t val,
                              ASN1_Type type_tag   = ASN1_Type::INTEGER,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Encodes a signed integer (up to 64-bit).
         */
        DER_Encoder& encode ( int64_t val,
                              ASN1_Type type_tag   = ASN1_Type::INTEGER,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

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
         * @brief Overload for const char* to prevent implicit pointer-to-bool decay.
         */
        DER_Encoder& encode ( const char* str,
                              ASN1_Type type_tag   = ASN1_Type::UTF8_STRING,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Deleted pointer overload to strictly forbid any arbitrary pointer from decaying into bool.
         */
        template < typename T >
        DER_Encoder& encode ( const T* ptr,
                              ASN1_Type type_tag   = ASN1_Type::BOOLEAN,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL ) = delete;

        /**
         * @brief Serializes an abstract ASN.1 domain object by invoking its virtual encode_into method.
         * @param obj The domain object to serialize (e.g., OID, BitString, Certificate).
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        DER_Encoder& encode ( const ASN1_Object& obj );

        /**
         * @brief Encodes a boolean value ONLY if it differs from default_val (ASN.1 DEFAULT).
         */
        DER_Encoder& encode_default ( bool val, bool default_val );

        /**
         * @brief Encodes an unsigned integer ONLY if it differs from default_val (ASN.1 DEFAULT).
         */
        DER_Encoder& encode_default ( uint64_t val, uint64_t default_val );

        /**
         * @brief Encodes a signed integer ONLY if it differs from default_val (ASN.1 DEFAULT).
         */
        DER_Encoder& encode_default ( int64_t val, int64_t default_val );

        /**
         * @brief Encodes a string ONLY if it differs from default_val (ASN.1 DEFAULT).
         */
        DER_Encoder& encode_default ( std::string_view str,
                                      std::string_view default_val,
                                      ASN1_Type type_tag   = ASN1_Type::UTF8_STRING,
                                      ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Overload for const char* to prevent implicit pointer-to-bool decay.
         */
        DER_Encoder& encode_default ( const char* str,
                                      const char* default_val,
                                      ASN1_Type type_tag   = ASN1_Type::UTF8_STRING,
                                      ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Encodes a byte span ONLY if it differs from default_val (ASN.1 DEFAULT).
         */
        DER_Encoder& encode_default ( std::span < const uint8_t > bytes,
                                      std::span < const uint8_t > default_val,
                                      ASN1_Type type_tag   = ASN1_Type::OCTET_STRING,
                                      ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Encodes a domain object ONLY if it differs from default_val (ASN.1 DEFAULT).
         */
        template < typename T >
        requires std::is_base_of_v < ASN1_Object, T >
        DER_Encoder& encode_default ( const T& obj, const T& default_val )
        {
            if ( obj != default_val )
            {
                encode ( obj );
            }

            return *this;
        }

        /**
         * @brief Encodes the value contained in a std::optional<T> ONLY if present (ASN.1 OPTIONAL).
         */
        template < typename T >
        DER_Encoder& encode_optional ( const std::optional < T >& obj )
        {
            if ( obj.has_value () )
            {
                encode ( *obj );
            }

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
         * @brief Starts an EXPLICIT tagged context-specific block (e.g., [0] EXPLICIT).
         */
        DER_Encoder& start_explicit ( uint8_t tag_number );

        /**
         * @brief Ends an EXPLICIT tagged context-specific block.
         */
        DER_Encoder& end_explicit ();

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
        DER_Encoder& add_object ( ASN1_Type type_tag,
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