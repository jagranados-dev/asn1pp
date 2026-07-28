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

#ifndef __ASN1PP_ASN1_ERRORS_HPP_
#define __ASN1PP_ASN1_ERRORS_HPP_

#include <cstddef>
#include <stdexcept>
#include <string>

namespace asn1pp
{

    enum class ASN1_ErrorCode
    {
        INVALID_ARGUMENT,
        TRUNCATED_INPUT,
        INVALID_TAG,
        INVALID_LENGTH,
        TAG_MISMATCH,
        INVALID_VALUE,
        NON_CANONICAL_DER,
        LIMIT_EXCEEDED,
        UNCONSUMED_DATA,
        INVALID_STATE
    };

    class ASN1_Error : public std::runtime_error
    {
    public:
        ASN1_Error (ASN1_ErrorCode code, size_t offset, const std::string& message);
        [[nodiscard]] ASN1_ErrorCode code () const noexcept;
        [[nodiscard]] size_t offset () const noexcept;

    private:
        ASN1_ErrorCode _code;
        size_t _offset;
    };

    class ASN1_InvalidArgument : public ASN1_Error
    {
    public:
        explicit ASN1_InvalidArgument (const std::string& message);
    };

    class ASN1_EncodingError : public ASN1_Error
    {
    public:
        ASN1_EncodingError (ASN1_ErrorCode code, const std::string& message);
    };

    class ASN1_DecodingError : public ASN1_Error
    {
    public:
        ASN1_DecodingError (ASN1_ErrorCode code, size_t offset, const std::string& message);
    };
    
} // asn1pp

#endif // __ASN1PP_ASN1_ERRORS_HPP_
