/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <asn1pp/ber_decoder.hpp>

#include <algorithm>
#include <limits>

#include <asn1pp/asn1_object.hpp>
#include <asn1pp/asn1_time.hpp>
#include <asn1pp/der_encoder.hpp>
#include <asn1pp/ia5_string.hpp>
#include <asn1pp/printable_string.hpp>
#include <asn1pp/utf8_string.hpp>

namespace asn1pp
{

    BER_Decoder::BER_Decoder (std::span < const uint8_t > data, BER_DecoderLimits limits)
        : BER_Decoder (data, limits, false, 0)
    {}

    BER_Decoder::BER_Decoder (const std::vector < uint8_t >& data, BER_DecoderLimits limits)
        : BER_Decoder (std::span < const uint8_t > (data), limits, false, 0)
    {}

    BER_Decoder::BER_Decoder (std::span < const uint8_t > data, BER_DecoderLimits limits, bool strict)
        : BER_Decoder (data, limits, strict, 0)
    {}

    BER_Decoder::BER_Decoder (std::span < const uint8_t > data,
                              BER_DecoderLimits limits,
                              bool strict,
                              size_t base_offset)
        : _base_offset (base_offset), _offset (0), _data (data), _limits (limits), _items (0), _strict_der (strict)
    {
        if (data.size () > limits.max_input_size)
        {
            throw ASN1_DecodingError (
                ASN1_ErrorCode::LIMIT_EXCEEDED, base_offset, "Input exceeds the configured maximum size");
        }
    }

    bool
    BER_Decoder::more_items () const
    {
        return _offset < _data.size ();
    }

    size_t
    BER_Decoder::remaining () const
    {
        return _data.size () - _offset;
    }

    size_t
    BER_Decoder::offset () const noexcept
    {
        return _base_offset + _offset;
    }

    bool
    BER_Decoder::strict_der () const noexcept
    {
        return _strict_der;
    }

    bool
    BER_Decoder::is_strict_der () const noexcept
    {
        return _strict_der;
    }

    BER_Decoder::State
    BER_Decoder::save_state () const noexcept
    {
        return State{_offset, _items};
    }

    void
    BER_Decoder::restore_state (State state) noexcept
    {
        _offset = state.offset;
        _items = state.items;
    }

    ASN1_TagClass
    BER_Decoder::tag_class (ASN1_Class cls) noexcept
    {
        return static_cast < ASN1_TagClass > (static_cast < uint8_t > (cls) & 0xC0u);
    }

    void
    BER_Decoder::count_item ()
    {
        if (_items >= _limits.max_items)
        {
            throw ASN1_DecodingError (
                ASN1_ErrorCode::LIMIT_EXCEEDED, _offset, "Item count exceeds the configured limit");
        }
        ++_items;
    }

    size_t
    BER_Decoder::find_eoc (size_t content, size_t limit, size_t depth) const
    {
        if (depth > _limits.max_depth)
        {
            throw ASN1_DecodingError (
                ASN1_ErrorCode::LIMIT_EXCEEDED, content, "Nesting depth exceeds the configured limit");
        }
        size_t pos = content;
        while (true)
        {
            if (pos + 2 > limit)
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::TRUNCATED_INPUT, pos, "Missing end-of-contents marker");
            }
            if (_data[pos] == 0 && _data[pos + 1] == 0)
            {
                return pos;
            }
            BER_ObjectHeader child = parse_header (pos, limit, depth + 1, false);
            if (child.encoded_size > limit - pos)
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_LENGTH, pos, "Child value exceeds its parent");
            }
            pos += child.encoded_size;
        }
    }

    BER_ObjectHeader
    BER_Decoder::parse_header (size_t offset, size_t limit, size_t depth, bool allow_eoc) const
    {
        if (depth > _limits.max_depth)
        {
            throw ASN1_DecodingError (
                ASN1_ErrorCode::LIMIT_EXCEEDED, offset, "Nesting depth exceeds the configured limit");
        }
        if (offset >= limit)
        {
            throw ASN1_DecodingError (ASN1_ErrorCode::TRUNCATED_INPUT, offset, "Missing identifier octet");
        }
        size_t pos = offset;
        uint8_t first = _data[pos++];
        ASN1_Tag tag{static_cast < ASN1_TagClass > (first & 0xC0u),
                     (first & 0x20u) != 0,
                     static_cast < uint64_t > (first & 0x1Fu)};
        if (tag.number == 31)
        {
            tag.number = 0;
            size_t octets = 0;
            bool first_group = true;
            while (true)
            {
                if (pos >= limit)
                {
                    throw ASN1_DecodingError (
                        ASN1_ErrorCode::TRUNCATED_INPUT, pos, "Truncated high-tag-number identifier");
                }
                if (++octets > _limits.max_tag_octets)
                {
                    throw ASN1_DecodingError (
                        ASN1_ErrorCode::LIMIT_EXCEEDED, pos, "Tag identifier exceeds the configured limit");
                }
                uint8_t b = _data[pos++];
                if (first_group && (b & 0x7Fu) == 0)
                {
                    throw ASN1_DecodingError (
                        ASN1_ErrorCode::INVALID_TAG, pos - 1, "Non-minimal high-tag-number identifier");
                }
                first_group = false;
                if (tag.number > (std::numeric_limits < uint64_t >::max () >> 7))
                {
                    throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_TAG, pos - 1, "Tag number overflows uint64_t");
                }
                tag.number = (tag.number << 7) | (b & 0x7Fu);
                if ((b & 0x80u) == 0)
                {
                    break;
                }
            }
            if (tag.number < 31)
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_TAG, offset, "High-tag-number form is not minimal");
            }
        }
        if (!allow_eoc && tag.tag_class == ASN1_TagClass::UNIVERSAL && tag.number == 0)
        {
            throw ASN1_DecodingError (
                ASN1_ErrorCode::INVALID_TAG, offset, "End-of-contents is only valid inside an indefinite-length value");
        }
        if (pos >= limit)
        {
            throw ASN1_DecodingError (ASN1_ErrorCode::TRUNCATED_INPUT, pos, "Missing length octet");
        }
        uint8_t lb = _data[pos++];
        if (lb == 0x80u)
        {
            if (_strict_der)
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::NON_CANONICAL_DER, pos - 1, "DER forbids indefinite length");
            }
            if (!tag.constructed)
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::INVALID_LENGTH, pos - 1, "Primitive value uses indefinite length");
            }
            size_t end = find_eoc (pos, limit, depth + 1);
            return {tag, end - pos, pos - offset, end + 2 - offset, true};
        }
        size_t length = 0;
        if ((lb & 0x80u) == 0)
        {
            length = lb;
        }
        else
        {
            size_t count = lb & 0x7Fu;
            if (count == 0 || count > _limits.max_length_octets || count > limit - pos)
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_LENGTH, pos - 1, "Invalid long-form length");
            }
            if (_strict_der && _data[pos] == 0)
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::NON_CANONICAL_DER, pos, "DER length has a redundant leading zero");
            }
            for (size_t i = 0; i < count; ++i)
            {
                if (length > (std::numeric_limits < size_t >::max () >> 8))
                {
                    throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_LENGTH, pos, "Length overflows size_t");
                }
                length = (length << 8) | _data[pos++];
            }
            if (_strict_der && length < 128)
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::NON_CANONICAL_DER, offset, "DER length is not minimal");
            }
        }
        if (length > _limits.max_element_size)
        {
            throw ASN1_DecodingError (
                ASN1_ErrorCode::LIMIT_EXCEEDED, offset, "Element exceeds the configured size limit");
        }
        if (length > limit - pos)
        {
            throw ASN1_DecodingError (ASN1_ErrorCode::TRUNCATED_INPUT, pos, "Value exceeds available data");
        }
        if (tag.tag_class == ASN1_TagClass::UNIVERSAL && tag.number == 0 && (length != 0 || tag.constructed))
        {
            throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_TAG, offset, "Malformed end-of-contents value");
        }
        return {tag, length, pos - offset, pos - offset + length, false};
    }

    std::optional < BER_ObjectHeader >
    BER_Decoder::peek_next_header () const
    {
        if (!more_items ())
        {
            return std::nullopt;
        }
        return parse_header (_offset, _data.size (), 0, false);
    }

    BER_ValueView
    BER_Decoder::peek_value (ASN1_Tag expected, bool primitive) const
    {
        BER_ObjectHeader h = parse_header (_offset, _data.size (), 0, false);
        if (!(h.tag == expected))
        {
            throw ASN1_DecodingError (ASN1_ErrorCode::TAG_MISMATCH, _offset, "Unexpected ASN.1 identifier");
        }
        if (primitive && h.tag.constructed)
        {
            throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_TAG, _offset, "Primitive value uses constructed form");
        }
        return {h, _data.subspan (_offset + h.header_size, h.length)};
    }

    void
    BER_Decoder::commit (const BER_ValueView& view)
    {
        _offset += view.header.encoded_size;
        count_item ();
    }

    BER_ObjectHeader
    BER_Decoder::get_next_object ()
    {
        BER_ObjectHeader h = parse_header (_offset, _data.size (), 0, false);
        _offset += h.encoded_size;
        count_item ();
        return h;
    }

    std::vector < uint8_t >
    BER_Decoder::get_next_raw_tlv ()
    {
        BER_ObjectHeader h = parse_header (_offset, _data.size (), 0, false);
        std::vector < uint8_t > out (_data.begin () + _offset, _data.begin () + _offset + h.encoded_size);
        _offset += h.encoded_size;
        count_item ();
        return out;
    }

    BER_Decoder&
    BER_Decoder::decode (bool& out, ASN1_Type type, ASN1_Class cls)
    {
        State s = save_state ();
        try
        {
            auto v = peek_value ({tag_class (cls), false, static_cast < uint64_t > (type)}, true);
            if (v.value.size () != 1)
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_VALUE, _offset, "BOOLEAN must contain one octet");
            }
            if (_strict_der && v.value[0] != 0 && v.value[0] != 0xFFu)
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::NON_CANONICAL_DER, _offset, "DER TRUE must be encoded as 0xFF");
            }
            bool result = v.value[0] != 0;
            commit (v);
            out = result;
            return *this;
        }
        catch (...)
        {
            restore_state (s);
            throw;
        }
    }

    BER_Decoder&
    BER_Decoder::decode (uint64_t& out, ASN1_Type type, ASN1_Class cls)
    {
        State s = save_state ();
        try
        {
            auto v = peek_value ({tag_class (cls), false, static_cast < uint64_t > (type)}, true);
            auto b = v.value;
            if (b.empty () || (b[0] & 0x80u))
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::INVALID_VALUE, _offset, "Unsigned INTEGER is empty or negative");
            }
            if (b.size () > _limits.max_integer_octets)
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::LIMIT_EXCEEDED, _offset, "INTEGER exceeds the configured limit");
            }
            if (_strict_der && b.size () > 1 && b[0] == 0 && (b[1] & 0x80u) == 0)
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::NON_CANONICAL_DER, _offset, "INTEGER has redundant sign extension");
            }
            size_t i = 0;
            while (i + 1 < b.size () && b[i] == 0)
            {
                ++i;
            }
            if (b.size () - i > 8)
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_VALUE, _offset, "INTEGER exceeds uint64_t");
            }
            uint64_t result = 0;
            for (; i < b.size (); ++i)
            {
                result = (result << 8) | b[i];
            }
            commit (v);
            out = result;
            return *this;
        }
        catch (...)
        {
            restore_state (s);
            throw;
        }
    }

    BER_Decoder&
    BER_Decoder::decode (int64_t& out, ASN1_Type type, ASN1_Class cls)
    {
        State s = save_state ();
        try
        {
            auto v = peek_value ({tag_class (cls), false, static_cast < uint64_t > (type)}, true);
            auto b = v.value;
            if (b.empty ())
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_VALUE, _offset, "INTEGER is empty");
            }
            if (b.size () > _limits.max_integer_octets)
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::LIMIT_EXCEEDED, _offset, "INTEGER exceeds the configured limit");
            }
            if (_strict_der && b.size () > 1 &&
                ((b[0] == 0 && (b[1] & 0x80u) == 0) || (b[0] == 0xFFu && (b[1] & 0x80u) != 0)))
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::NON_CANONICAL_DER, _offset, "INTEGER has redundant sign extension");
            }
            size_t i = 0;
            while (i + 1 < b.size () &&
                   ((b[i] == 0 && (b[i + 1] & 0x80u) == 0) || (b[i] == 0xFFu && (b[i + 1] & 0x80u) != 0)))
            {
                ++i;
            }
            if (b.size () - i > 8)
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_VALUE, _offset, "INTEGER exceeds int64_t");
            }
            bool neg = b[i] & 0x80u;
            uint64_t bits = neg ? UINT64_MAX : 0;
            for (; i < b.size (); ++i)
            {
                bits = (bits << 8) | b[i];
            }
            int64_t result;
            if (neg)
            {
                uint64_t m = ~bits;
                result = m == static_cast < uint64_t > (INT64_MAX) ? INT64_MIN : -static_cast < int64_t > (m) - 1;
            }
            else
            {
                if (bits > static_cast < uint64_t > (INT64_MAX))
                {
                    throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_VALUE, _offset, "INTEGER exceeds int64_t");
                }
                result = static_cast < int64_t > (bits);
            }
            commit (v);
            out = result;
            return *this;
        }
        catch (...)
        {
            restore_state (s);
            throw;
        }
    }

    BER_Decoder&
    BER_Decoder::decode_implicit (ASN1_Object& out, ASN1_Tag expected, ASN1_Tag natural)
    {
        State state = save_state ();
        try
        {
            BER_ValueView view = peek_value (expected, false);
            DER_Encoder encoder;
            encoder.add_object (natural, view.value);
            const std::vector < uint8_t > synthetic = encoder.take_contents ();
            BER_Decoder decoder (synthetic, _limits, _strict_der, _base_offset + _offset);
            decoder.decode (out);
            if (decoder.more_items ())
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::UNCONSUMED_DATA,
                    offset (),
                    "Implicitly tagged value contains unconsumed data");
            }
            commit (view);
            return *this;
        }
        catch (...)
        {
            restore_state (state);
            throw;
        }
    }

    BER_Decoder&
    BER_Decoder::decode_view (std::span < const uint8_t >& out, ASN1_Type type, ASN1_Class cls)
    {
        auto v = peek_value ({tag_class (cls), false, static_cast < uint64_t > (type)}, true);
        commit (v);
        out = v.value;
        return *this;
    }

    BER_Decoder&
    BER_Decoder::decode (std::vector < uint8_t >& out, ASN1_Type type, ASN1_Class cls)
    {
        State s = save_state ();
        try
        {
            auto v = peek_value ({tag_class (cls), false, static_cast < uint64_t > (type)}, true);
            std::vector < uint8_t > result (v.value.begin (), v.value.end ());
            commit (v);
            out = std::move (result);
            return *this;
        }
        catch (...)
        {
            restore_state (s);
            throw;
        }
    }

    BER_Decoder&
    BER_Decoder::decode (std::string& out, ASN1_Type type, ASN1_Class cls)
    {
        State s = save_state ();
        try
        {
            auto v = peek_value ({tag_class (cls), false, static_cast < uint64_t > (type)}, true);
            std::string result (v.value.begin (), v.value.end ());
            commit (v);
            out = std::move (result);
            return *this;
        }
        catch (...)
        {
            restore_state (s);
            throw;
        }
    }

    BER_Decoder&
    BER_Decoder::decode_string_bytes (std::vector < uint8_t >& out, ASN1_Type type, ASN1_Class cls)
    {
        State state = save_state ();
        try
        {
            const auto header = peek_next_header ();
            const ASN1_TagClass expected_class = tag_class (cls);
            const uint64_t expected_number = static_cast < uint64_t > (type);
            if (!header || header->tag.tag_class != expected_class || header->tag.number != expected_number)
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::TAG_MISMATCH, offset (), "Unexpected BER string identifier");
            }
            if (!header->tag.constructed)
            {
                return decode (out, type, cls);
            }
            if (_strict_der)
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::NON_CANONICAL_DER, offset (), "DER requires a primitive string encoding");
            }
            std::vector < uint8_t > result;
            decode_constructed (
                {expected_class, true, expected_number},
                [&] (BER_Decoder& child)
                {
                    while (child.more_items ())
                    {
                        std::vector < uint8_t > fragment;
                        child.decode_string_bytes (fragment, type);
                        if (fragment.size () > _limits.max_element_size - result.size ())
                        {
                            throw ASN1_DecodingError (
                                ASN1_ErrorCode::LIMIT_EXCEEDED,
                                child.offset (),
                                "Constructed string exceeds the configured limit");
                        }
                        result.insert (result.end (), fragment.begin (), fragment.end ());
                    }
                });
            out = std::move (result);
            return *this;
        }
        catch (...)
        {
            restore_state (state);
            throw;
        }
    }

    BER_Decoder&
    BER_Decoder::decode_bit_string (
        std::vector < uint8_t >& out, uint8_t& unused_bits, ASN1_Type type, ASN1_Class cls)
    {
        State state = save_state ();
        try
        {
            const auto header = peek_next_header ();
            const ASN1_TagClass expected_class = tag_class (cls);
            const uint64_t expected_number = static_cast < uint64_t > (type);
            if (!header || header->tag.tag_class != expected_class || header->tag.number != expected_number)
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::TAG_MISMATCH, offset (), "Unexpected BIT STRING identifier");
            }
            if (!header->tag.constructed)
            {
                std::vector < uint8_t > encoded;
                decode (encoded, type, cls);
                if (encoded.empty () || encoded[0] > 7 || (encoded.size () == 1 && encoded[0] != 0))
                {
                    throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_VALUE, offset (), "Invalid BIT STRING contents");
                }
                out.assign (encoded.begin () + 1, encoded.end ());
                unused_bits = encoded[0];
                return *this;
            }
            if (_strict_der)
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::NON_CANONICAL_DER, offset (), "DER requires a primitive BIT STRING encoding");
            }
            std::vector < uint8_t > result;
            uint8_t final_unused_bits = 0;
            decode_constructed (
                {expected_class, true, expected_number},
                [&] (BER_Decoder& child)
                {
                    while (child.more_items ())
                    {
                        std::vector < uint8_t > fragment;
                        uint8_t fragment_unused_bits = 0;
                        child.decode_bit_string (fragment, fragment_unused_bits);
                        if (child.more_items () && fragment_unused_bits != 0)
                        {
                            throw ASN1_DecodingError (
                                ASN1_ErrorCode::INVALID_VALUE,
                                child.offset (),
                                "Only the final BIT STRING component may contain unused bits");
                        }
                        if (fragment.size () > _limits.max_element_size - result.size ())
                        {
                            throw ASN1_DecodingError (
                                ASN1_ErrorCode::LIMIT_EXCEEDED,
                                child.offset (),
                                "Constructed BIT STRING exceeds the configured limit");
                        }
                        result.insert (result.end (), fragment.begin (), fragment.end ());
                        final_unused_bits = fragment_unused_bits;
                    }
                });
            out = std::move (result);
            unused_bits = final_unused_bits;
            return *this;
        }
        catch (...)
        {
            restore_state (state);
            throw;
        }
    }

    BER_Decoder&
    BER_Decoder::decode (ASN1_Object& out)
    {
        State s = save_state ();
        try
        {
            out.decode_from (*this);
            return *this;
        }
        catch (...)
        {
            restore_state (s);
            throw;
        }
    }

    BER_Decoder&
    BER_Decoder::decode_null ()
    {
        auto v = peek_value ({ASN1_TagClass::UNIVERSAL, false, 5}, true);
        if (!v.value.empty ())
        {
            throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_VALUE, _offset, "NULL must be empty");
        }
        commit (v);
        return *this;
    }

    BER_Decoder&
    BER_Decoder::validate_set_of_order ()
    {
        size_t pos = _offset;
        std::span < const uint8_t > previous;
        while (pos < _data.size ())
        {
            auto h = parse_header (pos, _data.size (), 0, false);
            auto current = _data.subspan (pos, h.encoded_size);
            if (!previous.empty () &&
                std::lexicographical_compare (current.begin (), current.end (), previous.begin (), previous.end ()))
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::NON_CANONICAL_DER, pos, "SET OF elements are not in DER order");
            }
            previous = current;
            pos += h.encoded_size;
        }
        return *this;
    }
    
    void
    BER_Decoder::validate_der_primitive (const BER_ObjectHeader& header, size_t content_offset) const
    {
        const std::span < const uint8_t > value = _data.subspan (content_offset, header.length);
        if (header.tag.tag_class != ASN1_TagClass::UNIVERSAL)
        {
            return;
        }
        switch (header.tag.number)
        {
        case static_cast < uint64_t > (ASN1_Type::BOOLEAN):
            if (value.size () != 1 || (value[0] != 0x00u && value[0] != 0xFFu))
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::NON_CANONICAL_DER, content_offset, "DER BOOLEAN must use 0x00 or 0xFF");
            }
            break;
        case static_cast < uint64_t > (ASN1_Type::INTEGER):
        case static_cast < uint64_t > (ASN1_Type::ENUMERATED):
            if (value.empty ())
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_VALUE, content_offset, "INTEGER cannot be empty");
            }
            if (value.size () > 1 &&
                ((value[0] == 0 && (value[1] & 0x80u) == 0) || (value[0] == 0xFFu && (value[1] & 0x80u) != 0)))
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::NON_CANONICAL_DER, content_offset, "INTEGER has redundant sign extension");
            }
            break;
        case static_cast < uint64_t > (ASN1_Type::BIT_STRING):
            if (value.empty () || value[0] > 7 || (value.size () == 1 && value[0] != 0))
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::INVALID_VALUE, content_offset, "Invalid BIT STRING unused bits");
            }
            if (value.size () > 1 && value[0] != 0 && (value.back () & ((1u << value[0]) - 1u)) != 0)
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::NON_CANONICAL_DER, content_offset, "BIT STRING has non-zero unused bits");
            }
            break;
        case static_cast < uint64_t > (ASN1_Type::NULL_TAG):
            if (!value.empty ())
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_VALUE, content_offset, "NULL must be empty");
            }
            break;
        case static_cast < uint64_t > (ASN1_Type::OBJECT_ID):
        {
            if (value.empty ())
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::INVALID_VALUE, content_offset, "OBJECT IDENTIFIER cannot be empty");
            }
            size_t position = 0;
            while (position < value.size ())
            {
                bool first = true;
                do
                {
                    if (position >= value.size ())
                    {
                        throw ASN1_DecodingError (
                            ASN1_ErrorCode::TRUNCATED_INPUT, content_offset + position, "Truncated OBJECT IDENTIFIER");
                    }
                    uint8_t octet = value[position++];
                    if (first && octet == 0x80u)
                    {
                        throw ASN1_DecodingError (ASN1_ErrorCode::NON_CANONICAL_DER,
                                                  content_offset + position - 1,
                                                  "Non-minimal OBJECT IDENTIFIER");
                    }
                    first = false;
                    if ((octet & 0x80u) == 0)
                    {
                        break;
                    }
                } while (true);
            }
            break;
        }
        case static_cast < uint64_t > (ASN1_Type::UTF8_STRING):
            try
            {
                UTF8_String (std::string_view (reinterpret_cast < const char* > (value.data ()), value.size ()));
            }
            catch (const ASN1_InvalidArgument& error)
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_VALUE, content_offset, error.what ());
            }
            break;
        case static_cast < uint64_t > (ASN1_Type::IA5_STRING):
            try
            {
                IA5_String (std::string_view (reinterpret_cast < const char* > (value.data ()), value.size ()));
            }
            catch (const ASN1_InvalidArgument& error)
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_VALUE, content_offset, error.what ());
            }
            break;
        case static_cast < uint64_t > (ASN1_Type::PRINTABLE_STRING):
            try
            {
                Printable_String (std::string_view (reinterpret_cast < const char* > (value.data ()), value.size ()));
            }
            catch (const ASN1_InvalidArgument& error)
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_VALUE, content_offset, error.what ());
            }
            break;
        case static_cast < uint64_t > (ASN1_Type::UTC_TIME):
        case static_cast < uint64_t > (ASN1_Type::GENERALIZED_TIME):
            try
            {
                ASN1_TimeType type = header.tag.number == static_cast < uint64_t > (ASN1_Type::UTC_TIME)
                                         ? ASN1_TimeType::UTC
                                         : ASN1_TimeType::GENERALIZED;
                ASN1_Time (type, std::string_view (reinterpret_cast < const char* > (value.data ()), value.size ()));
            }
            catch (const ASN1_InvalidArgument& error)
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::NON_CANONICAL_DER, content_offset, error.what ());
            }
            break;
        case static_cast < uint64_t > (ASN1_Type::SEQUENCE):
        case static_cast < uint64_t > (ASN1_Type::SET):
            throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_TAG,
                                      content_offset - header.header_size,
                                      "SEQUENCE and SET must be constructed");
        default:
            break;
        }
    }

    BER_ObjectHeader
    BER_Decoder::validate_der_object_at (size_t offset, size_t limit, size_t depth) const
    {
        BER_ObjectHeader header = parse_header (offset, limit, depth, false);
        size_t content_offset = offset + header.header_size;
        size_t content_end = content_offset + header.length;
        if (header.tag.constructed)
        {
            size_t child_offset = content_offset;
            while (child_offset < content_end)
            {
                BER_ObjectHeader child = validate_der_object_at (child_offset, content_end, depth + 1);
                child_offset += child.encoded_size;
            }
        }
        else
        {
            validate_der_primitive (header, content_offset);
        }
        return header;
    }

    BER_ObjectHeader
    BER_Decoder::validate_next_der_object ()
    {
        State state = save_state ();
        try
        {
            if (!_strict_der)
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::INVALID_STATE, _offset, "DER validation requires DER_Decoder");
            }
            BER_ObjectHeader header = validate_der_object_at (_offset, _data.size (), 0);
            _offset += header.encoded_size;
            count_item ();
            return header;
        }
        catch (...)
        {
            restore_state (state);
            throw;
        }
    }

} // asn1pp
