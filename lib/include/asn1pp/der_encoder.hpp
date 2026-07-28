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

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/asn1_limits.hpp>
#include <asn1pp/asn1_types.hpp>

namespace asn1pp
{

    class ASN1_Object;

    struct BER_ObjectHeader;

    class DER_Encoder
    {
    public:
        explicit DER_Encoder (DER_EncoderLimits limits = {});
        [[nodiscard]] std::vector < uint8_t > get_contents () const;
        [[nodiscard]] std::span < const uint8_t > contents () const;
        [[nodiscard]] std::vector < uint8_t > take_contents ();
        DER_Encoder& encode (bool value, ASN1_Type type = ASN1_Type::BOOLEAN, ASN1_Class cls = ASN1_Class::UNIVERSAL);
        DER_Encoder&
        encode (uint64_t value, ASN1_Type type = ASN1_Type::INTEGER, ASN1_Class cls = ASN1_Class::UNIVERSAL);
        DER_Encoder&
        encode (int64_t value, ASN1_Type type = ASN1_Type::INTEGER, ASN1_Class cls = ASN1_Class::UNIVERSAL);
        DER_Encoder& encode (std::span < const uint8_t > value,
                             ASN1_Type type = ASN1_Type::OCTET_STRING,
                             ASN1_Class cls = ASN1_Class::UNIVERSAL);
        DER_Encoder& encode (std::string_view value,
                             ASN1_Type type = ASN1_Type::UTF8_STRING,
                             ASN1_Class cls = ASN1_Class::UNIVERSAL);
        DER_Encoder&
        encode (const char* value, ASN1_Type type = ASN1_Type::UTF8_STRING, ASN1_Class cls = ASN1_Class::UNIVERSAL);
        DER_Encoder& encode (const ASN1_Object& value);
        /** @brief Encodes an object after replacing its natural identifier. */
        DER_Encoder& encode_implicit (const ASN1_Object& value, ASN1_Tag replacement, ASN1_Tag natural);
        /** @brief Encodes one CHOICE alternative and verifies its effective identifier. */
        DER_Encoder& encode_choice_alternative (const ASN1_Object& value, ASN1_Tag expected);
        DER_Encoder& encode_null ();
        DER_Encoder& add_object (ASN1_Tag tag, std::span < const uint8_t > value);
        DER_Encoder& append_encoded_tlv (std::span < const uint8_t > der);

        template < typename T >
        DER_Encoder&
        encode_optional (const std::optional < T >& value)
        {
            if (value)
            {
                encode (*value);
            }
            return *this;
        }

        template < typename T, typename U >
        DER_Encoder&
        encode_default (const T& value, const U& default_value)
        {
            if (value != static_cast < T > (default_value))
            {
                encode (value);
            }
            return *this;
        }

        template < typename Callback >
        DER_Encoder&
        encode_sequence (Callback&& callback)
        {
            return encode_constructed (
                {ASN1_TagClass::UNIVERSAL, true, 16}, false, std::forward < Callback > (callback));
        }

        template < typename Callback >
        DER_Encoder&
        encode_set (Callback&& callback)
        {
            return encode_constructed (
                {ASN1_TagClass::UNIVERSAL, true, 17}, false, std::forward < Callback > (callback));
        }

        template < typename Callback >
        DER_Encoder&
        encode_set_of (Callback&& callback)
        {
            return encode_constructed ({ASN1_TagClass::UNIVERSAL, true, 17}, true, std::forward < Callback > (callback));
        }

        template < typename Callback >
        DER_Encoder&
        encode_constructed (ASN1_Tag tag, bool sort_elements, Callback&& callback)
        {
            if (_depth >= _limits.max_depth)
            {
                throw ASN1_EncodingError (ASN1_ErrorCode::LIMIT_EXCEEDED,
                                          "ASN.1 nesting depth exceeds the configured limit");
            }
            DER_Encoder child (_limits, _depth + 1);
            child._collect_elements = sort_elements;
            std::forward < Callback > (callback) (child);
            return add_object (tag, child.finalize_child ());
        }

    private:
        DER_Encoder (DER_EncoderLimits limits, size_t depth);
        void append_encoded (std::vector < uint8_t > encoded);
        std::vector < uint8_t > finalize_child ();
        void ensure_size (size_t additional) const;
        static void encode_tag (std::vector < uint8_t >& out, ASN1_Tag tag);
        static void encode_length (std::vector < uint8_t >& out, size_t length);
        static BER_ObjectHeader validate_one_der_tlv (std::span < const uint8_t > bytes);

    private:
        std::vector < uint8_t > _contents;
        DER_EncoderLimits _limits;
        size_t _depth;
        bool _collect_elements;
        std::vector < std::vector < uint8_t > > _elements;
    };

} // asn1pp

#endif // __ASN1PP_DER_ENCODER_HPP_
