/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <asn1pp/asn1_any.hpp>

#include <ostream>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    ASN1_Any::ASN1_Any (std::span < const uint8_t > v)
    {
        assign (v);
    }

    const std::vector < uint8_t >&
    ASN1_Any::encoded_tlv () const noexcept
    {
        return _encoded;
    }

    void
    ASN1_Any::assign (std::span < const uint8_t > v)
    {
        if (v.empty ())
        {
            throw ASN1_InvalidArgument ("ANY cannot be empty");
        }
        DER_Decoder decoder (v);
        decoder.validate_next_der_object ();
        if (decoder.more_items ())
        {
            throw ASN1_InvalidArgument ("ANY must contain exactly one DER TLV");
        }
        _encoded.assign (v.begin (), v.end ());
    }

    void
    ASN1_Any::encode_into (DER_Encoder& to) const
    {
        if (_encoded.empty () )
        {
            throw ASN1_EncodingError (ASN1_ErrorCode::INVALID_STATE, "ANY has no value");
        }

        to.append_encoded_tlv (_encoded);
    }

    void
    ASN1_Any::decode_from (BER_Decoder& from)
    {
        auto raw = from.get_next_raw_tlv ();

        DER_Decoder decoder (raw);
        decoder.validate_next_der_object ();

        _encoded = std::move (raw);
    }

    bool
    ASN1_Any::operator== (const ASN1_Any& other) const noexcept
    {
        return _encoded == other._encoded;
    }

    std::ostream&
    operator<< (std::ostream& stream, const ASN1_Any& value)
    {
        static constexpr char digits[] = "0123456789ABCDEF"; for (uint8_t octet : value._encoded) { stream << digits[octet >> 4] << digits[octet & 0x0Fu]; }
        return stream;
    }

} // asn1pp
