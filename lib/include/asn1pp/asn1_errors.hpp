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

#include <stdexcept>
#include <string>

namespace asn1pp
{

    class ASN1_EncodingError : public std::runtime_error
    {
    public:
        explicit ASN1_EncodingError ( const std::string& msg )
            : std::runtime_error ( "ASN.1 Encoding Error: " + msg )
        {}
    };

    class ASN1_DecodingError : public std::runtime_error
    {
    public:
        explicit ASN1_DecodingError ( const std::string& msg )
            : std::runtime_error ( "ASN.1 Decoding Error: " + msg )
        {}
    };

} // asn1pp

#endif // __ASN1PP_ASN1_ERRORS_HPP_