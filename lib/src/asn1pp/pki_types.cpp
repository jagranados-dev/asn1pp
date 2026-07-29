/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <asn1pp/pki_types.hpp>

#include <utility>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/asn1_types.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    void
    Algorithm_Identifier::encode_into (DER_Encoder& to) const
    {
        to.encode_sequence (
            [&] (DER_Encoder& sequence)
            {
                sequence.encode (algorithm);
                sequence.encode_optional (parameters);
            });
    }

    void
    Algorithm_Identifier::decode_from (BER_Decoder& from)
    {
        OID decoded_algorithm;
        std::optional < ASN1_Any > decoded_parameters;
        from.decode_sequence (
            [&] (BER_Decoder& sequence)
            {
                sequence.decode (decoded_algorithm);
                if (sequence.more_items ())
                {
                    ASN1_Any value;
                    sequence.decode (value);
                    decoded_parameters = std::move (value);
                }
            });
        algorithm = std::move (decoded_algorithm);
        parameters = std::move (decoded_parameters);
    }

    bool
    Algorithm_Identifier::operator== (const Algorithm_Identifier& other) const
    {
        return algorithm == other.algorithm && parameters == other.parameters;
    }

    void
    Attribute::encode_into (DER_Encoder& to) const
    {
        if (values.empty ())
        {
            throw ASN1_EncodingError (ASN1_ErrorCode::INVALID_VALUE, "Attribute values cannot be empty");
        }
        to.encode_sequence (
            [&] (DER_Encoder& sequence)
            {
                sequence.encode (type);
                sequence.encode_set_of (
                    [&] (DER_Encoder& set)
                    {
                        for (const ASN1_Any& value : values)
                        {
                            set.encode (value);
                        }
                    });
            });
    }

    void
    Attribute::decode_from (BER_Decoder& from)
    {
        OID decoded_type;
        std::vector < ASN1_Any > decoded_values;
        from.decode_sequence (
            [&] (BER_Decoder& sequence)
            {
                sequence.decode (decoded_type);
                sequence.decode_set (
                    [&] (BER_Decoder& set)
                    {
                        if (set.is_strict_der ())
                        {
                            set.validate_set_of_order ();
                        }
                        while (set.more_items ())
                        {
                            ASN1_Any value;
                            set.decode (value);
                            decoded_values.push_back (std::move (value));
                        }
                    });
            });
        if (decoded_values.empty ())
        {
            throw ASN1_DecodingError (
                ASN1_ErrorCode::INVALID_VALUE, from.offset (), "Attribute values cannot be empty");
        }
        type = std::move (decoded_type);
        values = std::move (decoded_values);
    }

    bool
    Attribute::operator== (const Attribute& other) const
    {
        return type == other.type && values == other.values;
    }

    void
    Extension::set_der_value (const ASN1_Object& value)
    {
        extn_value.assign (value.DER_encode ());
    }

    ASN1_Any
    Extension::der_value () const
    {
        return ASN1_Any (extn_value.value ());
    }

    void
    Extension::encode_into (DER_Encoder& to) const
    {
        static_cast < void > (der_value ());
        to.encode_sequence (
            [&] (DER_Encoder& sequence)
            {
                sequence.encode (extn_id);
                sequence.encode_default (critical, false);
                sequence.encode (extn_value);
            });
    }

    void
    Extension::decode_from (BER_Decoder& from)
    {
        OID decoded_id;
        bool decoded_critical = false;
        Octet_String decoded_value;
        from.decode_sequence (
            [&] (BER_Decoder& sequence)
            {
                sequence.decode (decoded_id);
                sequence.decode_default (decoded_critical, false, ASN1_Type::BOOLEAN);
                sequence.decode (decoded_value);
            });
        ASN1_Any validated (decoded_value.value ());
        static_cast < void > (validated);
        extn_id = std::move (decoded_id);
        critical = decoded_critical;
        extn_value = std::move (decoded_value);
    }

    bool
    Extension::operator== (const Extension& other) const
    {
        return extn_id == other.extn_id && critical == other.critical && extn_value == other.extn_value;
    }

    void
    Content_Info::encode_into (DER_Encoder& to) const
    {
        to.encode_sequence (
            [&] (DER_Encoder& sequence)
            {
                sequence.encode (content_type);
                if (content)
                {
                    sequence.encode_constructed (
                        {ASN1_TagClass::CONTEXT_SPECIFIC, true, 0},
                        false,
                        [&] (DER_Encoder& explicit_value)
                        {
                            explicit_value.encode (*content);
                        });
                }
            });
    }

    void
    Content_Info::decode_from (BER_Decoder& from)
    {
        OID decoded_type;
        std::optional < ASN1_Any > decoded_content;
        from.decode_sequence (
            [&] (BER_Decoder& sequence)
            {
                sequence.decode (decoded_type);
                if (sequence.more_items ())
                {
                    ASN1_Any value;
                    sequence.decode_constructed (
                        {ASN1_TagClass::CONTEXT_SPECIFIC, true, 0},
                        [&] (BER_Decoder& explicit_value)
                        {
                            explicit_value.decode (value);
                        });
                    decoded_content = std::move (value);
                }
            });
        content_type = std::move (decoded_type);
        content = std::move (decoded_content);
    }

    bool
    Content_Info::operator== (const Content_Info& other) const
    {
        return content_type == other.content_type && content == other.content;
    }

} // asn1pp
