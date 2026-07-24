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
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/asn1_object.hpp>
#include <asn1pp/asn1_types.hpp>

namespace asn1pp
{

    class ASN1_Object;

    /**
     * @brief DER Encoder implementing a fluent builder pattern with stack-based sequence handling.
     * 
     * Constructs canonical DER (Distinguished Encoding Rules) streams by utilizing
     * an internal stack of subsequences, ensuring proper TLV length computation upon scope closure.
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
         * @return A vector of bytes containing the finalized DER serialization.
         * @throws ASN1_EncodingError if structural scopes (SEQUENCE/SET) remain open.
         */
        [[nodiscard]] std::vector < uint8_t > get_contents () const;

        /**
         * @brief Encodes a boolean value according to DER canonical rules (0xFF for true, 0x00 for false).
         * @param val The boolean value to serialize.
         * @param type_tag ASN.1 type tag (defaults to BOOLEAN).
         * @param class_tag ASN.1 tag class (defaults to UNIVERSAL).
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        DER_Encoder& encode ( bool val,
                              ASN1_Type type_tag   = ASN1_Type::BOOLEAN,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Encodes an unsigned integer (up to 64-bit), automatically injecting leading 0x00 sign padding if required.
         * @param val The unsigned integer value to serialize.
         * @param type_tag ASN.1 type tag (defaults to INTEGER).
         * @param class_tag ASN.1 tag class (defaults to UNIVERSAL).
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        DER_Encoder& encode ( uint64_t val,
                              ASN1_Type type_tag   = ASN1_Type::INTEGER,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Encodes a signed integer (up to 64-bit) using two's complement DER rules.
         * @param val The signed integer value to serialize.
         * @param type_tag ASN.1 type tag (defaults to INTEGER).
         * @param class_tag ASN.1 tag class (defaults to UNIVERSAL).
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        DER_Encoder& encode ( int64_t val,
                              ASN1_Type type_tag   = ASN1_Type::INTEGER,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Encodes an OCTET STRING or raw byte buffer with a specified tag and class.
         * @param bytes Read-only view of the byte payload.
         * @param type_tag ASN.1 type tag (defaults to OCTET_STRING).
         * @param class_tag ASN.1 tag class (defaults to UNIVERSAL).
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        DER_Encoder& encode ( std::span < const uint8_t > bytes,
                              ASN1_Type type_tag   = ASN1_Type::OCTET_STRING,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Encodes a text string (e.g., UTF8String, PrintableString, IA5String).
         * @param str View of the character string payload.
         * @param type_tag ASN.1 type tag (defaults to UTF8_STRING).
         * @param class_tag ASN.1 tag class (defaults to UNIVERSAL).
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        DER_Encoder& encode ( std::string_view str,
                              ASN1_Type type_tag   = ASN1_Type::UTF8_STRING,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Overload for const char* to prevent implicit pointer-to-bool decay during resolution.
         * @param str Null-terminated character string payload.
         * @param type_tag ASN.1 type tag (defaults to UTF8_STRING).
         * @param class_tag ASN.1 tag class (defaults to UNIVERSAL).
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        DER_Encoder& encode ( const char* str,
                              ASN1_Type type_tag   = ASN1_Type::UTF8_STRING,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Deleted pointer overload to strictly forbid any arbitrary pointer from decaying into bool.
         */
        template < typename T >
        requires ( !std::is_same_v < std::decay_t < T >, char > && !std::is_same_v < std::decay_t < T >, const char > )
        DER_Encoder& encode ( const T* ptr,
                              ASN1_Type type_tag   = ASN1_Type::BOOLEAN,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL ) = delete;

        /**
         * @brief Serializes an abstract ASN.1 domain object by invoking its virtual encode_into method.
         * @param obj The domain object instance to serialize (e.g., OID, Big_Int, ASN1_Time).
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        DER_Encoder& encode ( const ASN1_Object& obj );

        /**
         * @brief Encodes a value using IMPLICIT context-specific tagging (e.g., [1] IMPLICIT INTEGER).
         * 
         * When serializing an ASN1_Object derived domain type, it serializes to a temporary buffer
         * and rewrites the outer TLV tag to the specified context-specific tag number while preserving the class structure.
         * @tparam T The target value type.
         * @param val The value or domain object to serialize.
         * @param tag_number The context-specific tag number (e.g., 1 for [1]).
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        template < typename T >
        DER_Encoder& encode_implicit ( const T& val, uint8_t tag_number )
        {
            if constexpr ( std::is_base_of_v < ASN1_Object, T > )
            {
                DER_Encoder temp;
                val.encode_into ( temp );
                const std::vector < uint8_t >& bytes = temp.get_contents ();
                if ( bytes.empty () )
                {
                    return *this;
                }
                size_t pos = 1;
                size_t length = 0;
                if ( ( bytes [ pos ] & 0x80 ) == 0 )
                {
                    length = bytes [ pos++ ];
                }
                else
                {
                    size_t num_bytes = bytes [ pos++ ] & 0x7F;
                    for ( size_t i = 0; i < num_bytes; ++i )
                    {
                        length = ( length << 8 ) | bytes [ pos++ ];
                    }
                }
                uint8_t orig_tag_byte = bytes [ 0 ];
                uint8_t new_class = static_cast < uint8_t > ( ASN1_Class::CONTEXT_SPECIFIC ) | ( orig_tag_byte & static_cast < uint8_t > ( ASN1_Class::CONSTRUCTED ) );
                std::span < const uint8_t > val_span ( bytes.data () + pos, length );
                return add_object ( static_cast < ASN1_Type > ( tag_number ), new_class, val_span );
            }
            else
            {
                return encode ( val, static_cast < ASN1_Type > ( tag_number ), ASN1_Class::CONTEXT_SPECIFIC );
            }
        }

        /**
         * @brief Encodes an optional value using IMPLICIT context-specific tagging ONLY if present.
         * @tparam T The target value type.
         * @param val The optional value to check and serialize.
         * @param tag_number The context-specific tag number (e.g., 3 for [3]).
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        template < typename T >
        DER_Encoder& encode_implicit_optional ( const std::optional < T >& val, uint8_t tag_number )
        {
            if ( val.has_value () )
            {
                encode_implicit ( *val, tag_number );
            }
            return *this;
        }

        /**
         * @brief Encodes a value using EXPLICIT context-specific tagging ONLY if it differs from default_val.
         * @tparam T The target variable type.
         * @tparam U The default fallback literal value type.
         * @param val The value to check and serialize.
         * @param tag_number The context-specific tag number (e.g., 0 for [0]).
         * @param default_val The fallback default value specified in the schema.
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        template < typename T, typename U >
        DER_Encoder& encode_explicit_default ( const T& val, uint8_t tag_number, const U& default_val )
        {
            if ( val != default_val )
            {
                start_explicit ( tag_number );
                encode ( val );
                end_explicit ();
            }
            return *this;
        }

        /**
         * @brief Encodes an optional value using EXPLICIT context-specific tagging ONLY if present.
         * @tparam T The target value type.
         * @param val The optional value to check and serialize.
         * @param tag_number The context-specific tag number (e.g., 2 for [2]).
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        template < typename T >
        DER_Encoder& encode_explicit_optional ( const std::optional < T >& val, uint8_t tag_number )
        {
            if ( val.has_value () )
            {
                start_explicit ( tag_number );
                encode ( *val );
                end_explicit ();
            }
            return *this;
        }

        /**
         * @brief Encodes a primitive value ONLY if it differs from default_val (ASN.1 DEFAULT).
         * @tparam T The target variable type.
         * @tparam U The default fallback literal value type.
         * @param val The value to check and serialize.
         * @param default_val The fallback value specified in the schema.
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        template < typename T, typename U >
        requires ( !std::is_convertible_v < T, std::string_view > && !std::is_base_of_v < ASN1_Object, T > )
        DER_Encoder& encode_default ( const T& val, const U& default_val )
        {
            if ( val != static_cast < T > ( default_val ) )
            {
                encode ( val );
            }
            return *this;
        }

        /**
         * @brief Encodes a string view ONLY if it differs from default_val (ASN.1 DEFAULT).
         * @param str The string view to check and serialize.
         * @param default_val The fallback string specified in the schema.
         * @param type_tag ASN.1 type tag (defaults to UTF8_STRING).
         * @param class_tag ASN.1 tag class (defaults to UNIVERSAL).
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        DER_Encoder& encode_default ( std::string_view str, std::string_view default_val,
                                      ASN1_Type type_tag   = ASN1_Type::UTF8_STRING,
                                      ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Encodes a null-terminated string ONLY if it differs from default_val (ASN.1 DEFAULT).
         * @param str The null-terminated string to check and serialize.
         * @param default_val The fallback string specified in the schema.
         * @param type_tag ASN.1 type tag (defaults to UTF8_STRING).
         * @param class_tag ASN.1 tag class (defaults to UNIVERSAL).
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        DER_Encoder& encode_default ( const char* str, const char* default_val,
                                      ASN1_Type type_tag   = ASN1_Type::UTF8_STRING,
                                      ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Encodes an abstract domain object ONLY if it differs from default_val (ASN.1 DEFAULT).
         * @tparam T The domain object type deriving from ASN1_Object.
         * @param obj The domain object to check and serialize.
         * @param default_val The fallback domain object specified in the schema.
         * @return Reference to this DER_Encoder to allow fluent method chaining.
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
         * @tparam T The target optional data type.
         * @param obj The optional container to inspect and serialize.
         * @return Reference to this DER_Encoder to allow fluent method chaining.
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
         * @brief Encodes an optional value or container using CONSTRUCTED IMPLICIT context-specific tagging.
         * 
         * Properly replaces the underlying universal tag (e.g., SET OF 0x31) with the context tag (e.g., 0xA0)
         * without introducing explicit wrapper sequences.
         * @tparam T The target container or object type.
         * @param tag_number The context-specific tag number (e.g., 0 for [0]).
         * @param obj The optional container to inspect and serialize.
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        template < typename T >
        DER_Encoder& encode_optional_implicit ( uint8_t tag_number, const std::optional < T >& obj )
        {
            if ( obj.has_value () )
            {
                encode_implicit ( *obj, tag_number );
            }
            return *this;
        }

        /**
         * @brief Encodes an ASN.1 NULL object (tag 0x05, zero length).
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        DER_Encoder& encode_null ();

        /**
         * @brief Starts a constructed SEQUENCE scope, pushing a new subsequence onto the stack.
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        DER_Encoder& start_sequence ();

        /**
         * @brief Starts a constructed SET scope, pushing a new subsequence onto the stack.
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        DER_Encoder& start_set ();

        /**
         * @brief Closes the current constructed scope (SEQUENCE/SET/EXPLICIT/IMPLICIT) and writes to parent stream.
         * 
         * Automatically computes the canonical DER length of the accumulated payload.
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         * @throws ASN1_EncodingError if called when the subsequence stack is empty.
         */
        DER_Encoder& end_cons ();

        /**
         * @brief Starts an EXPLICIT tagged context-specific block (e.g., [0] EXPLICIT).
         * @param tag_number The context-specific tag number.
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        DER_Encoder& start_explicit ( uint8_t tag_number );

        /**
         * @brief Ends an EXPLICIT tagged context-specific block (alias of end_cons for semantic clarity).
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        DER_Encoder& end_explicit ();

        /**
         * @brief Starts a CONSTRUCTED IMPLICIT block (e.g., [2] IMPLICIT SEQUENCE) for multi-element collections.
         * @param tag_number The context-specific tag number.
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        DER_Encoder& start_implicit_cons ( uint8_t tag_number );

        /**
         * @brief Ends a CONSTRUCTED IMPLICIT block (alias of end_cons for semantic clarity).
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        DER_Encoder& end_implicit_cons ();

        /**
         * @brief Injects raw bytes directly into the current stream without TLV wrapping.
         * @param val Read-only view of the raw bytes to inject.
         * @return Reference to this DER_Encoder to allow fluent method chaining.
         */
        DER_Encoder& raw_bytes ( std::span < const uint8_t > val );

        /**
         * @brief Adds a fully formatted TLV object to the stream.
         * @param type_tag ASN.1 type tag.
         * @param class_tag ASN.1 tag class.
         * @param rep Payload bytes of the value representation.
         * @return Reference to this DER_Encoder to allow fluent method chaining.
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
            std::vector < uint8_t > contents;
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