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
#include <vector>

namespace asn1pp
{

    /**
     * @brief Universal ASN.1 Type Tags (ITU-T X.680)
     */
    enum class ASN1_Type : uint8_t
    {
        EOC              = 0x00,
        BOOLEAN          = 0x01,
        INTEGER          = 0x02,
        BIT_STRING       = 0x03,
        OCTET_STRING     = 0x04,
        NULL_TAG         = 0x05,
        OBJECT_ID        = 0x06,
        ENUMERATED       = 0x0A,
        UTF8_STRING      = 0x0C,
        SEQUENCE         = 0x10,
        SET              = 0x11,
        PRINTABLE_STRING = 0x13,
        IA5_STRING       = 0x16,
        UTC_TIME         = 0x17,
        GENERALIZED_TIME = 0x18
    };

    /**
     * @brief ASN.1 Tag Classes and Construction Flags
     */
    enum class ASN1_Class : uint8_t
    {
        UNIVERSAL        = 0x00,
        APPLICATION      = 0x40,
        CONTEXT_SPECIFIC = 0x80,
        PRIVATE          = 0xC0,
        CONSTRUCTED      = 0x20,
        EXPLICIT         = 0xA0 // CONTEXT_SPECIFIC | CONSTRUCTED
    };

    inline constexpr uint8_t operator| ( ASN1_Class lhs, ASN1_Class rhs ) noexcept
    {
        return static_cast < uint8_t > ( static_cast < uint8_t > ( lhs ) | static_cast < uint8_t > ( rhs ) );
    }

    inline constexpr uint8_t operator| ( ASN1_Class lhs, uint8_t rhs ) noexcept
    {
        return static_cast < uint8_t > ( static_cast < uint8_t > ( lhs ) | rhs );
    }

    inline constexpr uint8_t operator| ( uint8_t lhs, ASN1_Class rhs ) noexcept
    {
        return static_cast < uint8_t > ( lhs | static_cast < uint8_t > ( rhs ) );
    }

} // asn1pp

#endif // __ASN1PP_ASN1_TYPES_HPP_