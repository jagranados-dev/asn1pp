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

#ifndef __ASN1PP_SET_OF_HPP_
#define __ASN1PP_SET_OF_HPP_

#include <algorithm>
#include <initializer_list>
#include <utility>
#include <vector>

#include <asn1pp/asn1_object.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    /**
     * @brief Represents an ASN.1 SET OF container with mandatory DER Canonical Lexicographical Sorting.
     * 
     * Strictly implements ITU-T X.690 Section 11.6: Elements are serialized and sorted in ascending
     * lexicographical order of their binary DER representation prior to emission. Shorter encodings
     * are treated as padded with trailing 0x00 bytes during comparison.
     * @tparam T The element type (must be supported by DER_Encoder/BER_Decoder or derive from ASN1_Object).
     */
    template < typename T >
    class Set_Of final : public ASN1_Object
    {
    public:
        using value_type = T;
        using iterator = typename std::vector < T >::iterator;
        using const_iterator = typename std::vector < T >::const_iterator;

        Set_Of () = default;
        explicit Set_Of ( std::vector < T > elements ) : _elements ( std::move ( elements ) ) {}
        Set_Of ( std::initializer_list < T > elements ) : _elements ( elements ) {}
        ~Set_Of () override = default;

        Set_Of ( const Set_Of& ) = default;
        Set_Of& operator= ( const Set_Of& ) = default;
        Set_Of ( Set_Of&& ) noexcept = default;
        Set_Of& operator= ( Set_Of&& ) noexcept = default;

        void encode_into ( DER_Encoder& to ) const override
        {
            std::vector < std::vector < uint8_t > > serialized_elems;
            serialized_elems.reserve ( _elements.size () );

            for ( const auto& elem : _elements )
            {
                DER_Encoder temp;
                temp.encode ( elem );
                serialized_elems.push_back ( temp.get_contents () );
            }

            // ITU-T X.690 Section 11.6 canonical lexicographical sorting rule with virtual 0x00 padding
            auto der_less = [] ( const std::vector < uint8_t >& lhs, const std::vector < uint8_t >& rhs ) -> bool
            {
                size_t min_len = std::min ( lhs.size (), rhs.size () );
                for ( size_t i = 0; i < min_len; ++i )
                {
                    if ( lhs [ i ] != rhs [ i ] )
                    {
                        return lhs [ i ] < rhs [ i ];
                    }
                }
                if ( lhs.size () < rhs.size () )
                {
                    for ( size_t i = min_len; i < rhs.size (); ++i )
                    {
                        if ( rhs [ i ] != 0x00 )
                        {
                            return 0x00 < rhs [ i ];
                        }
                    }
                }
                else if ( lhs.size () > rhs.size () )
                {
                    for ( size_t i = min_len; i < lhs.size (); ++i )
                    {
                        if ( lhs [ i ] != 0x00 )
                        {
                            return lhs [ i ] < 0x00;
                        }
                    }
                }
                return false;
            };

            std::sort ( serialized_elems.begin (), serialized_elems.end (), der_less );

            to.start_set ();
            for ( const auto& raw : serialized_elems )
            {
                to.raw_bytes ( raw );
            }
            to.end_cons ();
        }

        void decode_from ( BER_Decoder& from ) override
        {
            _elements.clear ();
            from.start_set ();
            while ( from.more_items () )
            {
                T elem;
                from.decode ( elem );
                _elements.push_back ( std::move ( elem ) );
            }
            from.end_cons ();
        }

        void push_back ( const T& elem ) { _elements.push_back ( elem ); }
        void push_back ( T&& elem ) { _elements.push_back ( std::move ( elem ) ); }

        [[nodiscard]] size_t size () const noexcept { return _elements.size (); }
        [[nodiscard]] bool empty () const noexcept { return _elements.empty (); }
        void clear () noexcept { _elements.clear (); }

        iterator begin () noexcept { return _elements.begin (); }
        iterator end () noexcept { return _elements.end (); }
        [[nodiscard]] const_iterator begin () const noexcept { return _elements.begin (); }
        [[nodiscard]] const_iterator end () const noexcept { return _elements.end (); }

        T& operator[] ( size_t idx ) { return _elements [ idx ]; }
        const T& operator[] ( size_t idx ) const { return _elements [ idx ]; }

        T& at ( size_t idx ) { return _elements.at ( idx ); }
        const T& at ( size_t idx ) const { return _elements.at ( idx ); }

        [[nodiscard]] bool operator== ( const Set_Of& other ) const noexcept { return _elements == other._elements; }
        [[nodiscard]] bool operator!= ( const Set_Of& other ) const noexcept { return !( *this == other ); }
    private:
        std::vector < T > _elements;
    };

} // asn1pp

#endif // __ASN1PP_SET_OF_HPP_