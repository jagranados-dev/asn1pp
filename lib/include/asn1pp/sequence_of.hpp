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

#ifndef __ASN1PP_SEQUENCE_OF_HPP_
#define __ASN1PP_SEQUENCE_OF_HPP_

#include <initializer_list>
#include <utility>
#include <vector>

#include <asn1pp/asn1_object.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    /**
     * @brief Represents an ASN.1 SEQUENCE OF container (Ordered collection of elements).
     * @tparam T The element type (must be supported by DER_Encoder/BER_Decoder or derive from ASN1_Object).
     */
    template < typename T >
    class Sequence_Of final : public ASN1_Object
    {
    public:
        using value_type = T;
        using iterator = typename std::vector < T >::iterator;
        using const_iterator = typename std::vector < T >::const_iterator;

        Sequence_Of () = default;
        explicit Sequence_Of ( std::vector < T > elements ) : _elements ( std::move ( elements ) ) {}
        Sequence_Of ( std::initializer_list < T > elements ) : _elements ( elements ) {}
        ~Sequence_Of () override = default;

        Sequence_Of ( const Sequence_Of& ) = default;
        Sequence_Of& operator= ( const Sequence_Of& ) = default;
        Sequence_Of ( Sequence_Of&& ) noexcept = default;
        Sequence_Of& operator= ( Sequence_Of&& ) noexcept = default;

        void encode_into ( DER_Encoder& to ) const override
        {
            to.start_sequence ();
            for ( const auto& elem : _elements )
            {
                to.encode ( elem );
            }
            to.end_cons ();
        }

        void decode_from ( BER_Decoder& from ) override
        {
            _elements.clear ();
            from.start_sequence ();
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

        [[nodiscard]] bool operator== ( const Sequence_Of& other ) const noexcept { return _elements == other._elements; }
        [[nodiscard]] bool operator!= ( const Sequence_Of& other ) const noexcept { return !( *this == other ); }
    private:
        std::vector < T > _elements;
    };

} // asn1pp

#endif // __ASN1PP_SEQUENCE_OF_HPP_