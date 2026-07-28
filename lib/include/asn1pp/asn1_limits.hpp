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

#ifndef __ASN1PP_ASN1_LIMITS_HPP_
#define __ASN1PP_ASN1_LIMITS_HPP_

#include <cstddef>

namespace asn1pp
{

    struct BER_DecoderLimits
    {
        size_t max_input_size = 64u * 1024u * 1024u;
        size_t max_element_size = 16u * 1024u * 1024u;
        size_t max_depth = 128;
        size_t max_items = 1000000;
        size_t max_tag_octets = 10;
        size_t max_length_octets = sizeof (size_t);
        size_t max_integer_octets = 1024u * 1024u;
        size_t max_oid_arcs = 4096;
    };

    struct DER_EncoderLimits
    {
        size_t max_output_size = 64u * 1024u * 1024u;
        size_t max_depth = 128;
    };
    
} // asn1pp
#endif // __ASN1PP_ASN1_LIMITS_HPP_
