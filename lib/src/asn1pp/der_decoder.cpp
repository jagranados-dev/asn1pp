/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <asn1pp/der_decoder.hpp>

namespace asn1pp
{

    DER_Decoder::DER_Decoder (std::span < const uint8_t > data, BER_DecoderLimits limits)
        : BER_Decoder (data, limits, true)
    {}

    DER_Decoder::DER_Decoder (const std::vector < uint8_t >& data, BER_DecoderLimits limits)
        : DER_Decoder (std::span < const uint8_t > (data), limits)
    {}

} // asn1pp
