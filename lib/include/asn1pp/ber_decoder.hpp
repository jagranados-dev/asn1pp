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

#ifndef __ASN1PP_BER_DECODER_HPP_
#define __ASN1PP_BER_DECODER_HPP_

#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/asn1_object.hpp>
#include <asn1pp/asn1_types.hpp>

namespace asn1pp
{

    class ASN1_Object;

    /**
     * @brief BER/DER object header definition.
     * 
     * Encapsulates the metadata extracted from the TLV (Tag-Length-Value) prefix
     * of an ASN.1 object within a byte stream.
     */
    struct BER_ObjectHeader
    {
        ASN1_Type type_tag;
        uint8_t class_tag;
        size_t length;
        size_t header_size;
    };

    /**
     * @brief BER/DER Decoder providing sequential TLV parsing, bounds checking, and high-ergonomics tagging.
     * 
     * Manages an internal offset and scope limit stack to safely traverse ASN.1 structures
     * while preventing buffer overflows and enforcing strict structural boundaries.
     */
    class BER_Decoder
    {
    public:
        /**
         * @brief Constructs a decoder over a read-only memory span.
         * @param data Read-only view of the binary ASN.1 BER/DER stream.
         */
        explicit BER_Decoder ( std::span < const uint8_t > data );

        /**
         * @brief Constructs a decoder over a read-only byte vector.
         * @param data Reference to the vector containing the binary ASN.1 BER/DER stream.
         */
        explicit BER_Decoder ( const std::vector < uint8_t >& data );

        /**
         * @brief Deleted rvalue constructor to strictly prevent Use-After-Free and dangling span bugs.
         * 
         * Storing a std::span view over a temporary rvalue vector (e.g., BER_Decoder(encoder.get_contents()))
         * causes the underlying buffer to be deallocated immediately after the constructor statement completes.
         */
        explicit BER_Decoder ( const std::vector < uint8_t >&& data ) = delete;

        ~BER_Decoder () = default;

        /**
         * @brief Checks if there are more items to decode within the current structural scope.
         * @return true if the current stream offset is below the active scope limit; false otherwise.
         */
        [[nodiscard]] bool more_items () const;

        /**
         * @brief Decodes a boolean value from the current stream position.
         * @param out Reference to the boolean variable where the decoded value will be stored.
         * @param type_tag Expected ASN.1 type tag (defaults to BOOLEAN).
         * @param class_tag Expected ASN.1 tag class (defaults to UNIVERSAL).
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         * @throws ASN1_DecodingError if the tag does not match or the length is invalid.
         */
        BER_Decoder& decode ( bool& out,
                              ASN1_Type type_tag   = ASN1_Type::BOOLEAN,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Decodes an unsigned integer (up to 64-bit) from the current stream position.
         * @param out Reference to the uint64_t variable where the decoded value will be stored.
         * @param type_tag Expected ASN.1 type tag (defaults to INTEGER).
         * @param class_tag Expected ASN.1 tag class (defaults to UNIVERSAL).
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         * @throws ASN1_DecodingError if the integer size exceeds 64-bit bounds.
         */
        BER_Decoder& decode ( uint64_t& out,
                              ASN1_Type type_tag   = ASN1_Type::INTEGER,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Decodes a signed integer (up to 64-bit) using two's complement decoding.
         * @param out Reference to the int64_t variable where the decoded value will be stored.
         * @param type_tag Expected ASN.1 type tag (defaults to INTEGER).
         * @param class_tag Expected ASN.1 tag class (defaults to UNIVERSAL).
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         * @throws ASN1_DecodingError if the integer size exceeds 64-bit bounds.
         */
        BER_Decoder& decode ( int64_t& out,
                              ASN1_Type type_tag   = ASN1_Type::INTEGER,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Decodes a raw byte vector (e.g., OCTET STRING or BIT STRING payload).
         * @param out Reference to the byte vector where the raw contents will be copied.
         * @param type_tag Expected ASN.1 type tag (defaults to OCTET_STRING).
         * @param class_tag Expected ASN.1 tag class (defaults to UNIVERSAL).
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         */
        BER_Decoder& decode ( std::vector < uint8_t >& out,
                              ASN1_Type type_tag   = ASN1_Type::OCTET_STRING,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Decodes a text string (e.g., UTF8String, PrintableString, IA5String).
         * @param out Reference to the string variable where the decoded characters will be assigned.
         * @param type_tag Expected ASN.1 type tag (defaults to UTF8_STRING).
         * @param class_tag Expected ASN.1 tag class (defaults to UNIVERSAL).
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         */
        BER_Decoder& decode ( std::string& out,
                              ASN1_Type type_tag   = ASN1_Type::UTF8_STRING,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Deserializes an abstract ASN.1 domain object by invoking its virtual decode_from method.
         * @param obj The domain object instance to populate from the current BER stream.
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         */
        BER_Decoder& decode ( ASN1_Object& obj );

        /**
         * @brief Decodes a value using IMPLICIT context-specific tagging (e.g., [1] IMPLICIT INTEGER).
         * 
         * For domain objects deriving from ASN1_Object, it dynamically reconstructs a temporary
         * universal TLV stream in memory to satisfy internal decoding invariants.
         * @tparam T The target data type to decode.
         * @param out Reference to the variable to populate.
         * @param tag_number The expected context-specific tag number (e.g., 1 for [1]).
         * @param expected_type The underlying universal ASN.1 type tag for validation.
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         */
        template < typename T >
        BER_Decoder& decode_implicit ( T& out, uint8_t tag_number, ASN1_Type expected_type = ASN1_Type::INTEGER )
        {
            if constexpr ( std::is_base_of_v < ASN1_Object, T > )
            {
                BER_ObjectHeader hdr = get_next_header ();
                if ( hdr.type_tag != static_cast < ASN1_Type > ( tag_number ) || 
                   ( hdr.class_tag & 0xC0u ) != static_cast < uint8_t > ( ASN1_Class::CONTEXT_SPECIFIC ) )
                {
                    throw ASN1_DecodingError ( "Tag mismatch in decode_implicit for ASN1_Object" );
                }
                _offset += hdr.header_size;
                std::vector < uint8_t > val_bytes ( _data.begin () + _offset, _data.begin () + _offset + hdr.length );
                _offset += hdr.length;

                std::vector < uint8_t > temp_stream;
                uint8_t orig_class = static_cast < uint8_t > ( ASN1_Class::UNIVERSAL ) | ( hdr.class_tag & static_cast < uint8_t > ( ASN1_Class::CONSTRUCTED ) );
                temp_stream.push_back ( orig_class | static_cast < uint8_t > ( expected_type ) );
                if ( val_bytes.size () < 128 )
                {
                    temp_stream.push_back ( static_cast < uint8_t > ( val_bytes.size () ) );
                }
                else
                {
                    std::vector < uint8_t > len_bytes;
                    size_t len = val_bytes.size ();
                    while ( len > 0 )
                    {
                        len_bytes.push_back ( static_cast < uint8_t > ( len & 0xFF ) );
                        len >>= 8;
                    }
                    temp_stream.push_back ( static_cast < uint8_t > ( 0x80 | len_bytes.size () ) );
                    for ( auto it = len_bytes.rbegin (); it != len_bytes.rend (); ++it )
                    {
                        temp_stream.push_back ( *it );
                    }
                }
                temp_stream.insert ( temp_stream.end (), val_bytes.begin (), val_bytes.end () );

                BER_Decoder temp_dec ( temp_stream );
                out.decode_from ( temp_dec );
            }
            else
            {
                decode ( out, static_cast < ASN1_Type > ( tag_number ), ASN1_Class::CONTEXT_SPECIFIC );
            }
            return *this;
        }

        /**
         * @brief Decodes into a std::optional<T> using IMPLICIT context-specific tagging.
         * 
         * If the expected context-specific tag is absent from the stream, the optional variable is reset to nullopt.
         * @tparam T The target data type to decode.
         * @param out Reference to the optional variable to populate or reset.
         * @param tag_number The expected context-specific tag number (e.g., 3 for [3]).
         * @param expected_type The underlying universal ASN.1 type tag for validation.
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         */
        template < typename T >
        BER_Decoder& decode_implicit_optional ( std::optional < T >& out, uint8_t tag_number, ASN1_Type expected_type = ASN1_Type::INTEGER )
        {
            auto hdr = peek_next_header ();
            if ( hdr && hdr->type_tag == static_cast < ASN1_Type > ( tag_number ) &&
               ( hdr->class_tag & 0xC0u ) == static_cast < uint8_t > ( ASN1_Class::CONTEXT_SPECIFIC ) )
            {
                T val;
                decode_implicit ( val, tag_number, expected_type );
                out = std::move ( val );
            }
            else
            {
                out.reset ();
            }
            return *this;
        }

/**
         * @brief Decodes an optional CONSTRUCTED IMPLICIT context-specific container (e.g., [0] IMPLICIT SET OF).
         * 
         * Inspects the stream without advancing; if the expected context tag is present, it dynamically
         * restores the expected universal tag (e.g., SET or BIT_STRING) and decodes the container.
         * @tparam T The target container or object type (e.g., Set_Of<Attribute>, Bit_String).
         * @param tag_number The expected context-specific tag number (e.g., 0 for [0]).
         * @param out Reference to the optional variable to populate or reset.
         * @param expected_type The underlying universal tag to restore (defaults to SET for Attribute collections).
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         */
        template < typename T >
        BER_Decoder& decode_optional_implicit ( uint8_t tag_number,
                                                std::optional < T >& out,
                                                ASN1_Type expected_type = ASN1_Type::SET )
        {
            auto hdr = peek_next_header ();
            if ( hdr && hdr->type_tag == static_cast < ASN1_Type > ( tag_number ) &&
               ( hdr->class_tag & 0xC0u ) == static_cast < uint8_t > ( ASN1_Class::CONTEXT_SPECIFIC ) )
            {
                T val;
                decode_implicit ( val, tag_number, expected_type );
                out = std::move ( val );
            }
            else
            {
                out.reset ();
            }
            return *this;
        }

        /**
         * @brief Decodes an EXPLICIT context-specific tagged value, falling back to default_val if the tag is absent.
         * @tparam T The target variable type.
         * @tparam U The default fallback literal value type.
         * @param out Reference to the variable to populate.
         * @param tag_number The expected context-specific tag number (e.g., 0 for [0]).
         * @param default_val The fallback value to apply if the explicit container is omitted in the stream.
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         */
        template < typename T, typename U >
        BER_Decoder& decode_explicit_default ( T& out, uint8_t tag_number, const U& default_val )
        {
            if ( has_explicit ( tag_number ) )
            {
                start_explicit ( tag_number );
                decode ( out );
                end_explicit ();
            }
            else
            {
                out = static_cast < T > ( default_val );
            }
            return *this;
        }

        /**
         * @brief Decodes into a std::optional<T> using EXPLICIT context-specific tagging.
         * 
         * Automatically handles opening and closing the explicit constructed container wrapper.
         * @tparam T The target data type to decode.
         * @param out Reference to the optional variable to populate or reset.
         * @param tag_number The expected context-specific tag number (e.g., 2 for [2]).
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         */
        template < typename T >
        BER_Decoder& decode_explicit_optional ( std::optional < T >& out, uint8_t tag_number )
        {
            if ( has_explicit ( tag_number ) )
            {
                T val;
                start_explicit ( tag_number );
                decode ( val );
                end_explicit ();
                out = std::move ( val );
            }
            else
            {
                out.reset ();
            }
            return *this;
        }

        /**
         * @brief Decodes a value, falling back to default_val if the expected tag is missing (ASN.1 DEFAULT).
         * @tparam T The target variable type.
         * @tparam U The default fallback literal value type.
         * @param out Reference to the variable to populate.
         * @param default_val The fallback value to apply if the tag is omitted from the stream.
         * @param expected_type Expected ASN.1 type tag.
         * @param expected_class Expected ASN.1 tag class (defaults to UNIVERSAL).
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         */
        template < typename T, typename U >
        BER_Decoder& decode_default ( T& out,
                                      const U& default_val,
                                      ASN1_Type expected_type,
                                      ASN1_Class expected_class = ASN1_Class::UNIVERSAL )
        {
            auto hdr = peek_next_header ();
            if ( hdr && hdr->type_tag == expected_type &&
               ( hdr->class_tag & 0xC0u ) == ( static_cast < uint8_t > ( expected_class ) & 0xC0u ) )
            {
                decode ( out );
            }
            else
            {
                out = static_cast < T > ( default_val );
            }
            return *this;
        }

        /**
         * @brief Decodes into a std::optional<T>, leaving it empty if the expected tag is absent (ASN.1 OPTIONAL).
         * @tparam T The target data type to decode.
         * @param out Reference to the optional variable to populate or reset.
         * @param expected_type Expected ASN.1 type tag.
         * @param expected_class Expected ASN.1 tag class (defaults to UNIVERSAL).
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         */
        template < typename T >
        BER_Decoder& decode_optional ( std::optional < T >& out,
                                       ASN1_Type expected_type,
                                       ASN1_Class expected_class = ASN1_Class::UNIVERSAL )
        {
            auto hdr = peek_next_header ();

            if ( hdr && hdr->type_tag == expected_type &&
               ( hdr->class_tag & 0xC0u ) == ( static_cast < uint8_t > ( expected_class ) & 0xC0u ) )
            {
                T val;

                if constexpr ( std::is_base_of_v < ASN1_Object, T > )
                {
                    decode ( val );
                }
                else
                {
                    decode ( val, expected_type, expected_class );
                }

                out = std::move ( val );
            }
            else
            {
                out.reset ();
            }

            return *this;
        }

        /**
         * @brief Decodes an optional value based on scope item availability without strict tag matching.
         * 
         * Ideal for Open Types (such as Raw_Value / ANY DEFINED BY) or trailing optional domain objects
         * where any present TLV within the remaining structural scope should be consumed.
         * Establishes perfect ergonomic symmetry with DER_Encoder::encode_optional(val).
         * @tparam T The target data type to decode.
         * @param out Reference to the optional variable to populate or reset to nullopt.
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         */
        template < typename T >
        BER_Decoder& decode_optional ( std::optional < T >& out )
        {
            if ( more_items () )
            {
                T val;
                decode ( val );
                out = std::move ( val );
            }
            else
            {
                out.reset ();
            }

            return *this;
        }

        /**
         * @brief Decodes and verifies an ASN.1 NULL object, enforcing zero length.
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         * @throws ASN1_DecodingError if the tag is not NULL or length is non-zero.
         */
        BER_Decoder& decode_null ();

        /**
         * @brief Opens a constructed SEQUENCE scope and pushes its end boundary to the limit stack.
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         * @throws ASN1_DecodingError if the next tag is not a CONSTRUCTED SEQUENCE.
         */
        BER_Decoder& start_sequence ();

        /**
         * @brief Opens a constructed SET scope and pushes its end boundary to the limit stack.
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         * @throws ASN1_DecodingError if the next tag is not a CONSTRUCTED SET.
         */
        BER_Decoder& start_set ();

        /**
         * @brief Closes the current constructed structural scope (SEQUENCE/SET/EXPLICIT/IMPLICIT).
         * 
         * Enforces that all bytes within the opened scope have been completely consumed.
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         * @throws ASN1_DecodingError if unconsumed bytes remain or no scope is open.
         */
        BER_Decoder& end_cons ();

        /**
         * @brief Opens an EXPLICIT tagged context-specific scope (e.g., [0] EXPLICIT).
         * @param tag_number The expected context-specific tag number.
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         * @throws ASN1_DecodingError if the tag or constructed bit does not match.
         */
        BER_Decoder& start_explicit ( uint8_t tag_number );

        /**
         * @brief Closes an EXPLICIT tagged context-specific scope (alias of end_cons for semantic clarity).
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         */
        BER_Decoder& end_explicit ();

        /**
         * @brief Opens a CONSTRUCTED IMPLICIT scope (e.g., [2] IMPLICIT SEQUENCE) for multi-element collections.
         * @param tag_number The expected context-specific tag number.
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         * @throws ASN1_DecodingError if the tag does not match or the CONSTRUCTED bit is missing.
         */
        BER_Decoder& start_implicit_cons ( uint8_t tag_number );

        /**
         * @brief Closes a CONSTRUCTED IMPLICIT scope (alias of end_cons for semantic clarity).
         * @return Reference to this BER_Decoder to allow fluent method chaining.
         */
        BER_Decoder& end_implicit_cons ();

        /**
         * @brief Checks if an EXPLICIT context-specific tag is present at the current stream offset.
         * @param tag_number The context-specific tag number to look for.
         * @return true if the next header matches the tag and is CONSTRUCTED; false otherwise.
         */
        [[nodiscard]] bool has_explicit ( uint8_t tag_number ) const;

        /**
         * @brief Checks if a CONSTRUCTED IMPLICIT tag is present at the current stream offset.
         * @param tag_number The context-specific tag number to look for.
         * @return true if the next header matches the tag and is CONSTRUCTED; false otherwise.
         */
        [[nodiscard]] bool has_implicit_cons ( uint8_t tag_number ) const;

        /**
         * @brief Reads and advances past the next TLV object without enforcing type checks.
         * @return The parsed BER_ObjectHeader metadata structure.
         */
        BER_ObjectHeader get_next_object ();

        /**
         * @brief Inspects the next ASN.1 object header without advancing the stream offset.
         * @return An optional containing the header if available; std::nullopt if at end of buffer.
         */
        [[nodiscard]] std::optional < BER_ObjectHeader > peek_next_header () const;

        /**
         * @brief Extracts the entire raw TLV (Tag, Length, and Value bytes) of the next object and advances offset.
         * @return A byte vector containing the exact unparsed TLV binary slice.
         */
        std::vector < uint8_t > get_next_raw_tlv ();
    private:
        BER_ObjectHeader get_next_header () const;
        std::vector < uint8_t > get_next_value ( ASN1_Type expected_type, ASN1_Class expected_class );
        void start_cons ( ASN1_Type expected_type );
    private:
        size_t _offset;
        std::vector < size_t > _limits;
        std::span < const uint8_t > _data;
    };

} // asn1pp

#endif // __ASN1PP_BER_DECODER_HPP_