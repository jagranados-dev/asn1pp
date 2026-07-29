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

#ifndef __ASN1PP_UTF8_STRING_HPP_
#define __ASN1PP_UTF8_STRING_HPP_

#include <iosfwd>
#include <string>
#include <string_view>

#include <asn1pp/asn1_object.hpp>

namespace asn1pp
{

    /** @brief Validated ASN.1 UTF8String value. */
    class UTF8_String : public ASN1_Object
    {
    public:
        UTF8_String () = default;
        explicit UTF8_String (std::string_view value);
        [[nodiscard]] const std::string& value () const noexcept;
        void assign (std::string_view value);
        void encode_into (DER_Encoder& to) const override;
        void decode_from (BER_Decoder& from) override;
        bool operator== (const UTF8_String& other) const noexcept;
        friend std::ostream& operator<< (std::ostream& stream, const UTF8_String& value);

    private:
        static void validate (std::string_view value);
        std::string _value;
    };

} // asn1pp

#endif // __ASN1PP_UTF8_STRING_HPP_
