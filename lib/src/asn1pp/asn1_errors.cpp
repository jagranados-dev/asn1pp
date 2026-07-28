/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <asn1pp/asn1_errors.hpp>

#include "codec_utils.hpp"

namespace asn1pp
{

    using detail::error_text;
    ASN1_Error::ASN1_Error (ASN1_ErrorCode code, size_t offset, const std::string& message)
        : std::runtime_error (message), _code (code), _offset (offset)
    {}

    ASN1_ErrorCode
    ASN1_Error::code () const noexcept
    {
        return _code;
    }

    size_t
    ASN1_Error::offset () const noexcept
    {
        return _offset;
    }

    ASN1_InvalidArgument::ASN1_InvalidArgument (const std::string& message)
        : ASN1_Error (ASN1_ErrorCode::INVALID_ARGUMENT, 0, error_text ("ASN.1 Invalid Argument: ", message))
    {}

    ASN1_EncodingError::ASN1_EncodingError (ASN1_ErrorCode code, const std::string& message)
        : ASN1_Error (code, 0, error_text ("ASN.1 Encoding Error: ", message))
    {}

    ASN1_DecodingError::ASN1_DecodingError (ASN1_ErrorCode code, size_t offset, const std::string& message)
        : ASN1_Error (code, offset, error_text ("ASN.1 Decoding Error: ", message))
    {}
    
} // asn1pp
