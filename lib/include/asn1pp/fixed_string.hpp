/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#ifndef __ASN1PP_FIXED_STRING_HPP_
#define __ASN1PP_FIXED_STRING_HPP_

#include <cstddef>
#include <string_view>

namespace asn1pp
{

    /** @brief Structural compile-time string used by ASN.1 descriptors. */
    template < size_t Size >
    struct Fixed_String
    {
        char value[Size];

        /** @brief Constructs a compile-time string from a string literal. */
        constexpr Fixed_String (const char (&text)[Size]) noexcept
        {
            for (size_t index = 0; index < Size; ++index)
            {
                value[index] = text[index];
            }
        }

        /** @return String view excluding the terminating null character. */
        [[nodiscard]] constexpr std::string_view view () const noexcept
        {
            return std::string_view (value, Size - 1);
        }

        bool operator== (const Fixed_String& other) const noexcept = default;
    };

} // asn1pp

#endif // __ASN1PP_FIXED_STRING_HPP_
