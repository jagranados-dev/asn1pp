/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <asn1pp/der_encoder.hpp>

#include <algorithm>
#include <limits>

#include <asn1pp/asn1_object.hpp>
#include <asn1pp/der_decoder.hpp>

#include "codec_utils.hpp"

namespace asn1pp
{

    using detail::append_base128;
    DER_Encoder::DER_Encoder (DER_EncoderLimits limits) : DER_Encoder (limits, 0)
    {}

    DER_Encoder::DER_Encoder (DER_EncoderLimits limits, size_t depth)
        : _limits (limits), _depth (depth), _collect_elements (false)
    {}

    std::vector < uint8_t >
    DER_Encoder::get_contents () const
    {
        return _contents;
    }

    std::span < const uint8_t >
    DER_Encoder::contents () const
    {
        return _contents;
    }

    std::vector < uint8_t >
    DER_Encoder::take_contents ()
    {
        return std::move (_contents);
    }

    void
    DER_Encoder::ensure_size (size_t additional) const
    {
        if (additional > _limits.max_output_size || _contents.size () > _limits.max_output_size - additional)
        {
            throw ASN1_EncodingError (ASN1_ErrorCode::LIMIT_EXCEEDED, "Output exceeds the configured limit");
        }
    }

    void
    DER_Encoder::encode_tag (std::vector < uint8_t >& out, ASN1_Tag tag)
    {
        uint8_t first = static_cast < uint8_t > (tag.tag_class) | (tag.constructed ? 0x20u : 0);
        if (tag.number < 31)
        {
            out.push_back (first | static_cast < uint8_t > (tag.number));
            return;
        }
        out.push_back (first | 0x1Fu);
        append_base128 (out, tag.number);
    }

    void
    DER_Encoder::encode_length (std::vector < uint8_t >& out, size_t length)
    {
        if (length < 128)
        {
            out.push_back (static_cast < uint8_t > (length));
            return;
        }
        uint8_t b[sizeof (size_t)];
        size_t n = 0;
        while (length)
        {
            b[n++] = length & 0xFFu;
            length >>= 8;
        }
        out.push_back (0x80u | static_cast < uint8_t > (n));
        while (n)
        {
            out.push_back (b[--n]);
        }
    }

    void
    DER_Encoder::append_encoded (std::vector < uint8_t > encoded)
    {
        if (_collect_elements)
        {
            _elements.push_back (std::move (encoded));
            return;
        }
        ensure_size (encoded.size ());
        _contents.insert (_contents.end (), encoded.begin (), encoded.end ());
    }

    DER_Encoder&
    DER_Encoder::add_object (ASN1_Tag tag, std::span < const uint8_t > value)
    {
        std::vector < uint8_t > encoded;
        encoded.reserve (value.size () + 16);
        encode_tag (encoded, tag);
        encode_length (encoded, value.size ());
        encoded.insert (encoded.end (), value.begin (), value.end ());
        append_encoded (std::move (encoded));
        return *this;
    }

    DER_Encoder&
    DER_Encoder::encode (bool v, ASN1_Type t, ASN1_Class c)
    {
        uint8_t b = v ? 0xFFu : 0;
        return add_object (
            {static_cast < ASN1_TagClass > (static_cast < uint8_t > (c) & 0xC0u), false, static_cast < uint64_t > (t)},
            std::span < const uint8_t > (&b, 1));
    }

    DER_Encoder&
    DER_Encoder::encode (uint64_t v, ASN1_Type t, ASN1_Class c)
    {
        uint8_t rev[9];
        size_t n = 0;
        do
        {
            rev[n++] = v & 0xFFu;
            v >>= 8;
        } while (v);
        if (rev[n - 1] & 0x80u)
        {
            rev[n++] = 0;
        }
        std::vector < uint8_t > b;
        while (n)
        {
            b.push_back (rev[--n]);
        }
        return add_object (
            {static_cast < ASN1_TagClass > (static_cast < uint8_t > (c) & 0xC0u),
             false,
             static_cast < uint64_t > (t)},
            b);
    }

    DER_Encoder&
    DER_Encoder::encode (int64_t v, ASN1_Type t, ASN1_Class c)
    {
        uint64_t bits = static_cast < uint64_t > (v);
        uint8_t b[8];
        for (size_t i = 0; i < 8; ++i)
        {
            b[7 - i] = bits & 0xFFu;
            bits >>= 8;
        }
        size_t first = 0;
        while (first + 1 < 8 &&
               ((b[first] == 0 && (b[first + 1] & 0x80u) == 0) || (b[first] == 0xFFu && (b[first + 1] & 0x80u) != 0)))
        {
            ++first;
        }
        return add_object (
            {static_cast < ASN1_TagClass > (static_cast < uint8_t > (c) & 0xC0u), false, static_cast < uint64_t > (t)},
            std::span < const uint8_t > (b + first, 8 - first));
    }

    DER_Encoder&
    DER_Encoder::encode (std::span < const uint8_t > v, ASN1_Type t, ASN1_Class c)
    {
        return add_object (
            {static_cast < ASN1_TagClass > (static_cast < uint8_t > (c) & 0xC0u),
             false,
             static_cast < uint64_t > (t)},
            v);
    }

    DER_Encoder&
    DER_Encoder::encode (std::string_view v, ASN1_Type t, ASN1_Class c)
    {
        return encode (std::span < const uint8_t > (reinterpret_cast < const uint8_t* > (v.data ()), v.size ()), t, c);
    }

    DER_Encoder&
    DER_Encoder::encode (const char* v, ASN1_Type t, ASN1_Class c)
    {
        if (!v)
        {
            throw ASN1_EncodingError (ASN1_ErrorCode::INVALID_ARGUMENT, "Null C string");
        }
        return encode (std::string_view (v), t, c);
    }

    DER_Encoder&
    DER_Encoder::encode (const ASN1_Object& v)
    {
        DER_Encoder child (_limits, _depth);
        v.encode_into (child);
        auto encoded = child.take_contents ();
        validate_one_der_tlv (encoded);
        append_encoded (std::move (encoded));
        return *this;
    }

    DER_Encoder&
    DER_Encoder::encode_implicit (const ASN1_Object& value, ASN1_Tag replacement, ASN1_Tag natural)
    {
        DER_Encoder child (_limits, _depth);
        value.encode_into (child);
        const std::vector < uint8_t > encoded = child.take_contents ();
        DER_Decoder decoder (encoded);
        const auto header = decoder.peek_next_header ();

        if (!header || !(header->tag == natural) || header->encoded_size != encoded.size ())
        {
            throw ASN1_EncodingError (
                ASN1_ErrorCode::INVALID_VALUE,
                "Implicitly tagged value does not use the declared natural identifier");
        }

        return add_object (
            replacement,
            std::span < const uint8_t > (encoded).subspan (header->header_size, header->length));
    }

    DER_Encoder&
    DER_Encoder::encode_choice_alternative (const ASN1_Object& value, ASN1_Tag expected)
    {
        DER_Encoder child (_limits, _depth);
        value.encode_into (child);
        std::vector < uint8_t > encoded = child.take_contents ();
        DER_Decoder decoder (encoded);
        const auto header = decoder.peek_next_header ();

        if (!header || !(header->tag == expected) || header->encoded_size != encoded.size ())
        {
            throw ASN1_EncodingError (
                ASN1_ErrorCode::INVALID_STATE,
                "Selected CHOICE value does not use its declared effective identifier");
        }

        append_encoded (std::move (encoded));
        return *this;
    }

    DER_Encoder&
    DER_Encoder::encode_null ()
    {
        return add_object ({ASN1_TagClass::UNIVERSAL, false, 5}, {});
    }

    std::vector < uint8_t >
    DER_Encoder::finalize_child ()
    {
        if (_collect_elements)
        {
            std::sort (_elements.begin (), _elements.end ());
            for (const auto& e : _elements)
            {
                _contents.insert (_contents.end (), e.begin (), e.end ());
            }
            _elements.clear ();
            _collect_elements = false;
        }
        return std::move (_contents);
    }

    BER_ObjectHeader
    DER_Encoder::validate_one_der_tlv (std::span < const uint8_t > bytes)
    {
        DER_Decoder decoder (bytes);
        BER_ObjectHeader h = decoder.validate_next_der_object ();
        if (decoder.more_items ())
        {
            throw ASN1_EncodingError (ASN1_ErrorCode::INVALID_VALUE, "Expected exactly one DER TLV");
        }
        return h;
    }

    DER_Encoder&
    DER_Encoder::append_encoded_tlv (std::span < const uint8_t > der)
    {
        validate_one_der_tlv (der);
        append_encoded (std::vector < uint8_t > (der.begin (), der.end ()));
        return *this;
    }
    
} // asn1pp
