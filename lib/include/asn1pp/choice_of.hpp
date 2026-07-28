/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#ifndef __ASN1PP_CHOICE_OF_HPP_
#define __ASN1PP_CHOICE_OF_HPP_

#include <array>
#include <cstddef>
#include <ostream>
#include <string_view>
#include <type_traits>
#include <tuple>
#include <vector>
#include <utility>
#include <variant>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/asn1_object.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/choice_alternative.hpp>
#include <asn1pp/der_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    namespace detail
    {

        template < typename... Alternatives >
        consteval bool unique_choice_tags ()
        {
            constexpr std::array < ASN1_Tag, sizeof... (Alternatives) > tags { Alternatives::tag... };
            for (size_t left = 0; left < tags.size (); ++left)
            {
                for (size_t right = left + 1; right < tags.size (); ++right)
                {
                    if (tags[left] == tags[right])
                    {
                        return false;
                    }
                }
            }
            return true;
        }


        template < typename... Alternatives >
        consteval bool unique_choice_names ()
        {
            constexpr std::array < std::string_view, sizeof... (Alternatives) > names {
                Alternatives::name.view ()...
            };
            for (size_t left = 0; left < names.size (); ++left)
            {
                if (names[left].empty ())
                {
                    return false;
                }
                for (size_t right = left + 1; right < names.size (); ++right)
                {
                    if (names[left] == names[right])
                    {
                        return false;
                    }
                }
            }
            return true;
        }
        
    } // detail

    /**
     * @brief Type-safe ASN.1 CHOICE container selected by effective identifier.
     * @tparam Alternatives Choice_Alternative descriptors.
     */
    template < typename... Alternatives >
    class Choice_Of : public ASN1_Object
    {
        static_assert (sizeof... (Alternatives) > 0, "CHOICE requires at least one alternative");
        static_assert (detail::unique_choice_tags < Alternatives... > (),
                       "CHOICE alternatives must have unique effective identifiers");
        static_assert (detail::unique_choice_names < Alternatives... > (),
                       "CHOICE alternatives must have unique non-empty logical names");
        static_assert ((std::is_base_of_v < ASN1_Object, typename Alternatives::value_type > && ...),
                       "Every CHOICE alternative must derive from ASN1_Object");

    public:
        using variant_type = std::variant < std::monostate, typename Alternatives::value_type... >;

        Choice_Of () = default;

        template < typename T >
            requires (!std::is_same_v < std::remove_cvref_t < T >, Choice_Of >)
        explicit Choice_Of (T&& value)
        {
            set (std::forward < T > (value));
        }

        [[nodiscard]] bool has_value () const noexcept
        {
            return _value.index () != 0;
        }

        void reset () noexcept
        {
            _value.template emplace < 0 > ();
        }

        [[nodiscard]] size_t index () const noexcept
        {
            return has_value () ? _value.index () - 1 : std::variant_npos;
        }

        template < typename T >
        void set (T&& value)
        {
            using Value = std::remove_cvref_t < T >;
            static_assert ((std::is_same_v < Value, typename Alternatives::value_type > || ...),
                           "The selected type is not a CHOICE alternative");
            _value.template emplace < Value > (std::forward < T > (value));
        }

        template < typename T, typename... Arguments >
        T& emplace (Arguments&&... arguments)
        {
            static_assert ((std::is_same_v < T, typename Alternatives::value_type > || ...),
                           "The selected type is not a CHOICE alternative");
            return _value.template emplace < T > (std::forward < Arguments > (arguments)...);
        }

        template < typename T >
        [[nodiscard]] bool holds_alternative () const noexcept
        {
            return std::holds_alternative < T > (_value);
        }

        template < typename T >
        [[nodiscard]] T& get ()
        {
            return std::get < T > (_value);
        }

        template < typename T >
        [[nodiscard]] const T& get () const
        {
            return std::get < T > (_value);
        }

        [[nodiscard]] const variant_type& value () const noexcept
        {
            return _value;
        }

        void encode_into (DER_Encoder& to) const override
        {
            if (!has_value ())
            {
                throw ASN1_EncodingError (ASN1_ErrorCode::INVALID_STATE, "CHOICE has no selected alternative");
            }
            encode_selected < 0 > (to);
        }

        void decode_from (BER_Decoder& from) override
        {
            const auto header = from.peek_next_header ();
            if (!header)
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::TRUNCATED_INPUT, from.offset (), "Expected a CHOICE alternative");
            }
            if (!decode_matching < 0 > (from, header->tag))
            {
                throw ASN1_DecodingError (
                    ASN1_ErrorCode::TAG_MISMATCH, from.offset (), "No CHOICE alternative matches the next identifier");
            }
        }

        bool operator== (const Choice_Of& other) const
        {
            return _value == other._value;
        }

        friend std::ostream& operator<< (std::ostream& stream, const Choice_Of& choice)
        {
            if (!choice.has_value ())
            {
                return stream << "choice[empty]";
            }
            choice.stream_selected < 0 > (stream);
            return stream;
        }

    private:
        template < size_t Index >
        using Alternative = std::tuple_element_t < Index, std::tuple < Alternatives... > >;

        template < size_t Index >
        void encode_selected (DER_Encoder& to) const
        {
            if constexpr (Index < sizeof... (Alternatives))
            {
                if (_value.index () == Index + 1)
                {
                    const auto& selected = std::get < Index + 1 > (_value);
                    to.encode_choice_alternative (selected, Alternative < Index >::tag);
                    return;
                }
                encode_selected < Index + 1 > (to);
            }
        }

        template < size_t Index >
        bool decode_matching (BER_Decoder& from, ASN1_Tag tag)
        {
            if constexpr (Index == sizeof... (Alternatives))
            {
                return false;
            }
            else
            {
                if (Alternative < Index >::tag == tag)
                {
                    using Value = typename Alternative < Index >::value_type;
                    Value result;
                    from.decode (result);
                    _value.template emplace < Index + 1 > (std::move (result));
                    return true;
                }
                return decode_matching < Index + 1 > (from, tag);
            }
        }

        template < size_t Index >
        void stream_selected (std::ostream& stream) const
        {
            if constexpr (Index < sizeof... (Alternatives))
            {
                if (_value.index () == Index + 1)
                {
                    stream << "choice[" << Alternative < Index >::name.view () << "]="
                           << std::get < Index + 1 > (_value);
                    return;
                }
                stream_selected < Index + 1 > (stream);
            }
        }

        variant_type _value;
    };

} // asn1pp

#endif // __ASN1PP_CHOICE_OF_HPP_
