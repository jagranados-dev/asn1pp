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

#ifndef __ASN1PP_TEST_HELPERS_HPP_
#define __ASN1PP_TEST_HELPERS_HPP_

#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <vector>

#include <asn1pp/asn1pp.hpp>

namespace asn1pp::test
{

    inline std::vector < uint8_t >
    bytes ( std::initializer_list < uint8_t > value )
    {
        return std::vector < uint8_t > ( value );
    }

    template < typename T >
    std::vector < uint8_t >
    encode ( const T& value )
    {
        DER_Encoder encoder;
        encoder.encode ( value );
        return encoder.take_contents ();
    }

    inline bool
    equal_oid ( const OID& lhs, const OID& rhs )
    {
        return lhs.arcs () == rhs.arcs ();
    }

    inline bool
    equal_time ( const ASN1_Time& lhs, const ASN1_Time& rhs )
    {
        return lhs.type () == rhs.type () && lhs.value () == rhs.value ();
    }

} // asn1pp::test

#endif // __ASN1PP_TEST_HELPERS_HPP_
