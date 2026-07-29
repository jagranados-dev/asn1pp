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

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/asn1_limits.hpp>
#include <asn1pp/asn1_types.hpp>

namespace asn1pp
{
    
    class ASN1_Object;

    /** @brief Parsed BER identifier and length metadata. */
    struct BER_ObjectHeader
    {
        ASN1_Tag tag;
        size_t length;
        size_t header_size;
        size_t encoded_size;
        bool indefinite_length;
    };

    /** @brief Parsed BER metadata and borrowed content octets. */
    struct BER_ValueView
    {
        BER_ObjectHeader header;
        std::span < const uint8_t > value;
    };

    /** @brief Transactional BER decoder with configurable resource limits. */
    class BER_Decoder
    {
    public:
        explicit BER_Decoder (std::span < const uint8_t > data, BER_DecoderLimits limits = {});
        explicit BER_Decoder (const std::vector < uint8_t >& data, BER_DecoderLimits limits = {});
        explicit BER_Decoder (const std::vector < uint8_t >&& data) = delete;
        virtual ~BER_Decoder () = default;
        [[nodiscard]] bool more_items () const;
        [[nodiscard]] size_t remaining () const;
        [[nodiscard]] size_t offset () const noexcept;
        [[nodiscard]] std::optional < BER_ObjectHeader > peek_next_header () const;
        BER_ObjectHeader get_next_object ();
        BER_ObjectHeader validate_next_der_object ();
        std::vector < uint8_t > get_next_raw_tlv ();
        BER_Decoder& decode (bool& out, ASN1_Type type = ASN1_Type::BOOLEAN, ASN1_Class cls = ASN1_Class::UNIVERSAL);
        BER_Decoder&
        decode (uint64_t& out, ASN1_Type type = ASN1_Type::INTEGER, ASN1_Class cls = ASN1_Class::UNIVERSAL);
        BER_Decoder& decode (int64_t& out, ASN1_Type type = ASN1_Type::INTEGER, ASN1_Class cls = ASN1_Class::UNIVERSAL);
        BER_Decoder& decode (std::vector < uint8_t >& out,
                             ASN1_Type type = ASN1_Type::OCTET_STRING,
                             ASN1_Class cls = ASN1_Class::UNIVERSAL);
        BER_Decoder&
        decode (std::string& out, ASN1_Type type = ASN1_Type::UTF8_STRING, ASN1_Class cls = ASN1_Class::UNIVERSAL);
        BER_Decoder& decode (ASN1_Object& out);
        /**
         * @brief Decodes a primitive or constructed BER string into octets.
         * @param out Concatenated logical contents.
         * @param type Universal string type expected at the outer identifier.
         * @param cls Identifier class used by an implicitly tagged outer value.
         * @return This decoder.
         */
        BER_Decoder& decode_string_bytes (
            std::vector < uint8_t >& out,
            ASN1_Type type = ASN1_Type::OCTET_STRING,
            ASN1_Class cls = ASN1_Class::UNIVERSAL);
        /**
         * @brief Decodes a primitive or constructed BER BIT STRING.
         * @param out Concatenated data octets without the unused-bit count.
         * @param unused_bits Number of unused bits in the final data octet.
         * @param type Universal type expected at the outer identifier.
         * @param cls Identifier class used by an implicitly tagged outer value.
         * @return This decoder.
         */
        BER_Decoder& decode_bit_string (
            std::vector < uint8_t >& out,
            uint8_t& unused_bits,
            ASN1_Type type = ASN1_Type::BIT_STRING,
            ASN1_Class cls = ASN1_Class::UNIVERSAL);
        /** @brief Decodes a value whose natural identifier was replaced implicitly. */
        BER_Decoder& decode_implicit (ASN1_Object& out, ASN1_Tag expected, ASN1_Tag natural);
        BER_Decoder& decode_view (std::span < const uint8_t >& out,
                                  ASN1_Type type = ASN1_Type::OCTET_STRING,
                                  ASN1_Class cls = ASN1_Class::UNIVERSAL);
        BER_Decoder& decode_null ();

        template < typename T >
        BER_Decoder&
        decode_optional (std::optional < T >& out, ASN1_Type type, ASN1_Class cls = ASN1_Class::UNIVERSAL)
        {
            auto header = peek_next_header ();
            if (header && header->tag.tag_class == tag_class (cls) &&
                header->tag.number == static_cast < uint64_t > (type))
            {
                T value;
                if constexpr (std::is_base_of_v < ASN1_Object, T >)
                {
                    decode (value);
                }
                else
                {
                    decode (value, type, cls);
                }
                out = std::move (value);
            }
            else
            {
                out.reset ();
            }
            return *this;
        }

        template < typename T, typename U >
        BER_Decoder&
        decode_default (T& out, const U& default_value, ASN1_Type type, ASN1_Class cls = ASN1_Class::UNIVERSAL)
        {
            auto header = peek_next_header ();
            if (header && header->tag.tag_class == tag_class (cls) &&
                header->tag.number == static_cast < uint64_t > (type))
            {
                if constexpr (std::is_base_of_v < ASN1_Object, T >)
                {
                    decode (out);
                }
                else
                {
                    decode (out, type, cls);
                }
            }
            else
            {
                out = static_cast < T > (default_value);
            }
            return *this;
        }

        template < typename Callback >
        BER_Decoder&
        decode_sequence (Callback&& callback)
        {
            return decode_constructed ({ASN1_TagClass::UNIVERSAL, true, 16}, std::forward < Callback > (callback));
        }

        template < typename Callback >
        BER_Decoder&
        decode_set (Callback&& callback)
        {
            return decode_constructed ({ASN1_TagClass::UNIVERSAL, true, 17}, std::forward < Callback > (callback));
        }

        template < typename Callback >
        BER_Decoder&
        decode_constructed (ASN1_Tag expected, Callback&& callback)
        {
            State checkpoint = save_state ();
            try
            {
                BER_ValueView view = peek_value (expected, false);
                BER_Decoder child (
                    view.value,
                    _limits,
                    _strict_der,
                    _base_offset + _offset + view.header.header_size);
                std::forward < Callback > (callback) (child);
                if (child.more_items ())
                {
                    throw ASN1_DecodingError (
                        ASN1_ErrorCode::UNCONSUMED_DATA, _offset, "Constructed value contains unconsumed data");
                }
                commit (view);
                return *this;
            }
            catch (...)
            {
                restore_state (checkpoint);
                throw;
            }
        }

        BER_Decoder& validate_set_of_order ();

        [[nodiscard]] bool is_strict_der () const noexcept;

    protected:
        BER_Decoder (std::span < const uint8_t > data, BER_DecoderLimits limits, bool strict_der);
        BER_Decoder (std::span < const uint8_t > data,
                     BER_DecoderLimits limits,
                     bool strict_der,
                     size_t base_offset);
        [[nodiscard]] bool strict_der () const noexcept;

    private:
        struct State
        {
            size_t offset;
            size_t items;
        };

        BER_ObjectHeader parse_header (size_t offset, size_t limit, size_t depth, bool allow_eoc) const;
        size_t find_eoc (size_t content, size_t limit, size_t depth) const;
        BER_ValueView peek_value (ASN1_Tag expected, bool primitive) const;
        BER_ObjectHeader validate_der_object_at (size_t offset, size_t limit, size_t depth) const;
        void validate_der_primitive (const BER_ObjectHeader& header, size_t content_offset) const;
        void commit (const BER_ValueView& view);
        void count_item ();
        [[nodiscard]] State save_state () const noexcept;
        void restore_state (State state) noexcept;
        static ASN1_TagClass tag_class (ASN1_Class cls) noexcept;

    private:
        size_t _base_offset;
        size_t _offset;
        std::span < const uint8_t > _data;
        BER_DecoderLimits _limits;
        size_t _items;
        bool _strict_der;
    };

} // asn1pp

#endif // __ASN1PP_BER_DECODER_HPP_
