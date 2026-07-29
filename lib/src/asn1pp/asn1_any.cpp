/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <asn1pp/asn1_any.hpp>

#include <ostream>
#include <utility>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    ASN1_Any::ASN1_Any (std::span < const uint8_t > encoded)
    {
        assign (encoded);
    }

    const std::vector < uint8_t >&
    ASN1_Any::encoded_tlv () const noexcept
    {
        return _encoded;
    }

    bool
    ASN1_Any::is_der_canonical () const noexcept
    {
        return _der_canonical;
    }

    bool
    ASN1_Any::validate_der (std::span < const uint8_t > encoded)
    {
        try
        {
            DER_Decoder decoder (encoded);
            decoder.validate_next_der_object ();
            return !decoder.more_items ();
        }
        catch (const ASN1_Error&)
        {
            return false;
        }
    }

    void
    ASN1_Any::assign (std::span < const uint8_t > encoded)
    {
        if (encoded.empty ())
        {
            throw ASN1_InvalidArgument ("ANY cannot be empty");
        }
        BER_Decoder decoder (encoded);
        std::vector < uint8_t > value = decoder.get_next_raw_tlv ();
        if (decoder.more_items ())
        {
            throw ASN1_InvalidArgument ("ANY must contain exactly one BER TLV");
        }
        const bool der_canonical = validate_der (value);
        _encoded = std::move (value);
        _der_canonical = der_canonical;
    }

    void
    ASN1_Any::encode_into (DER_Encoder& to) const
    {
        if (_encoded.empty ())
        {
            throw ASN1_EncodingError (ASN1_ErrorCode::INVALID_STATE, "ANY has no value");
        }
        if (!_der_canonical)
        {
            throw ASN1_EncodingError (
                ASN1_ErrorCode::NON_CANONICAL_DER, "ANY contains BER that cannot be inserted into DER");
        }
        to.append_encoded_tlv (_encoded);
    }

    void
    ASN1_Any::decode_from (BER_Decoder& from)
    {
        std::vector < uint8_t > value = from.get_next_raw_tlv ();
        const bool der_canonical = validate_der (value);
        if (from.is_strict_der () && !der_canonical)
        {
            throw ASN1_DecodingError (
                ASN1_ErrorCode::NON_CANONICAL_DER, from.offset (), "ANY contains a non-canonical DER value");
        }
        _encoded = std::move (value);
        _der_canonical = der_canonical;
    }

    bool
    ASN1_Any::operator== (const ASN1_Any& other) const noexcept
    {
        return _encoded == other._encoded;
    }

    std::ostream&
    operator<< (std::ostream& stream, const ASN1_Any& value)
    {
        static constexpr char digits[] = "0123456789ABCDEF";
        for (uint8_t octet : value._encoded)
        {
            stream << digits[octet >> 4] << digits[octet & 0x0Fu];
        }
        return stream;
    }

} // asn1pp
