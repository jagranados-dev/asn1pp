/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#ifndef __ASN1PP_CHOICE_ALTERNATIVE_HPP_
#define __ASN1PP_CHOICE_ALTERNATIVE_HPP_

#include <asn1pp/asn1_types.hpp>
#include <asn1pp/fixed_string.hpp>

namespace asn1pp
{

    /**
     * @brief Declares one ASN.1 CHOICE alternative.
     * @tparam T Concrete ASN.1 object type.
     * @tparam Tag Effective BER/DER identifier of the encoded alternative.
     * @tparam Name Stable logical name, reusable by future XER support.
     */
    template < typename T, ASN1_Tag Tag, Fixed_String Name >
    struct Choice_Alternative
    {
        using value_type = T;
        static constexpr ASN1_Tag tag = Tag;
        static constexpr auto name = Name;
    };

} // asn1pp

#endif // __ASN1PP_CHOICE_ALTERNATIVE_HPP_
