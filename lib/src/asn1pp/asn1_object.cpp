/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <asn1pp/asn1_object.hpp>

#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    std::vector < uint8_t >
    ASN1_Object::DER_encode () const
    {
        DER_Encoder encoder;
        encode_into (encoder);
        return encoder.take_contents ();
    }

    std::vector < uint8_t >
    ASN1_Object::BER_encode () const
    {
        return DER_encode ();
    }

} // asn1pp
