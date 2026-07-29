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

#ifndef __ASN1PP_ASN1_TYPES_HPP_
#define __ASN1PP_ASN1_TYPES_HPP_

#include <cstdint>

namespace asn1pp
{

    enum class ASN1_Type : uint64_t
    {
        EOC = 0,
        BOOLEAN = 1,
        INTEGER = 2,
        BIT_STRING = 3,
        OCTET_STRING = 4,
        NULL_TAG = 5,
        OBJECT_ID = 6,
        OBJECT_DESCRIPTOR = 7,
        EXTERNAL = 8,
        REAL = 9,
        ENUMERATED = 10,
        EMBEDDED_PDV = 11,
        UTF8_STRING = 12,
        RELATIVE_OID = 13,
        SEQUENCE = 16,
        SET = 17,
        NUMERIC_STRING = 18,
        PRINTABLE_STRING = 19,
        TELETEX_STRING = 20,
        VIDEOTEX_STRING = 21,
        IA5_STRING = 22,
        UTC_TIME = 23,
        GENERALIZED_TIME = 24,
        GRAPHIC_STRING = 25,
        VISIBLE_STRING = 26,
        GENERAL_STRING = 27,
        UNIVERSAL_STRING = 28,
        CHARACTER_STRING = 29,
        BMP_STRING = 30
    };

    enum class ASN1_TagClass : uint8_t
    {
        UNIVERSAL = 0x00,
        APPLICATION = 0x40,
        CONTEXT_SPECIFIC = 0x80,
        PRIVATE = 0xC0
    };

    enum class ASN1_Class : uint8_t
    {
        UNIVERSAL = 0x00,
        APPLICATION = 0x40,
        CONTEXT_SPECIFIC = 0x80,
        PRIVATE = 0xC0,
        CONSTRUCTED = 0x20,
        EXPLICIT = 0xA0
    };

    struct ASN1_Tag
    {
        ASN1_TagClass tag_class;
        bool constructed;
        uint64_t number;
        bool operator== (const ASN1_Tag& other) const noexcept = default;
    };

} // asn1pp

#endif // __ASN1PP_ASN1_TYPES_HPP_
