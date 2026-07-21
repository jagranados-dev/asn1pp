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

#include <asn1pp/asn1_time.hpp>

#include <iomanip>
#include <optional>
#include <ostream>
#include <sstream>
#include <stdexcept>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp 
{
    namespace
    {
        
        ASN1_Type
        auto_tag_from_time ( const std::chrono::system_clock::time_point& tp )
        {
            auto days_since_epoch = std::chrono::floor < std::chrono::days > ( tp );
            std::chrono::year_month_day ymd ( days_since_epoch );
            int year = static_cast < int > ( ymd.year () );

            // RFC 5280 / X.509 rule: 1950-2049 -> UTCTime, otherwise -> GeneralizedTime
            if ( year >= 1950 && year < 2050 )
            {
                return ASN1_Type::UTC_TIME;
            }
            return ASN1_Type::GENERALIZED_TIME;
        }

        void
        parse_time_string ( std::string_view str,
                            ASN1_Type tag,
                            std::chrono::system_clock::time_point& out_time,
                            ASN1_Type& out_tag )
        {
            if ( str.empty () || str.back () != 'Z' )
            {
                throw ASN1_InvalidArgument ( "ASN.1 time string must end with 'Z' (UTC timezone)" );
            }

            if ( tag == ASN1_Type::EOC )
            {
                if ( str.size () == 13 ) tag = ASN1_Type::UTC_TIME;
                else if ( str.size () == 15 ) tag = ASN1_Type::GENERALIZED_TIME;
                else throw ASN1_InvalidArgument ( "Invalid ASN.1 time string length for automatic tag detection" );
            }

            auto parse_two = [ & ] ( size_t idx ) -> int
            {
                if ( idx + 1 >= str.size () || str [ idx ] < '0' || str [ idx ] > '9' || str [ idx + 1 ] < '0' || str [ idx + 1 ] > '9' )
                {
                    throw ASN1_InvalidArgument ( "Invalid numeric digits in ASN.1 time string" );
                }
                return ( str [ idx ] - '0' ) * 10 + ( str [ idx + 1 ] - '0' );
            };

            size_t idx = 0;
            int year = 0;

            if ( tag == ASN1_Type::UTC_TIME )
            {
                if ( str.size () != 13 )
                {
                    throw ASN1_InvalidArgument ( "UTCTime string must be exactly 13 characters (YYMMDDhhmmssZ)" );
                }
                int yy = parse_two ( 0 );
                year = ( yy >= 50 ) ? ( 1900 + yy ) : ( 2000 + yy );
                idx = 2;
            }
            else if ( tag == ASN1_Type::GENERALIZED_TIME )
            {
                if ( str.size () < 15 )
                {
                    throw ASN1_InvalidArgument ( "GeneralizedTime string must be at least 15 characters (YYYYMMDDhhmmssZ)" );
                }
                if ( str [ 0 ] < '0' || str [ 0 ] > '9' || str [ 1 ] < '0' || str [ 1 ] > '9' ||
                     str [ 2 ] < '0' || str [ 2 ] > '9' || str [ 3 ] < '0' || str [ 3 ] > '9' )
                {
                    throw ASN1_InvalidArgument ( "Invalid 4-digit year in GeneralizedTime string" );
                }
                year = ( str [ 0 ] - '0' ) * 1000 + ( str [ 1 ] - '0' ) * 100 + ( str [ 2 ] - '0' ) * 10 + ( str [ 3 ] - '0' );
                idx = 4;
            }
            else
            {
                throw ASN1_InvalidArgument ( "Unsupported ASN1_Type tag for date parsing" );
            }

            int month = parse_two ( idx ); idx += 2;
            int day = parse_two ( idx ); idx += 2;
            int hour = parse_two ( idx ); idx += 2;
            int minute = parse_two ( idx ); idx += 2;
            int second = parse_two ( idx );

            using namespace std::chrono;
            year_month_day ymd { std::chrono::year ( year ),
                                 std::chrono::month ( static_cast < unsigned > ( month ) ),
                                 std::chrono::day ( static_cast < unsigned > ( day ) ) };
            
            if ( !ymd.ok () )
            {
                throw ASN1_InvalidArgument ( "Invalid calendar date in ASN.1 time string" );
            }

            if ( hour > 23 || minute > 59 || second > 60 ) // 60 allows leap seconds
            {
                throw ASN1_InvalidArgument ( "Time of day components out of valid range" );
            }

            sys_days days_since_epoch = ymd;
            out_time = days_since_epoch + hours ( hour ) + minutes ( minute ) + seconds ( second );
            out_tag = tag;
        }

        std::string
        format_asn1_string ( const std::chrono::system_clock::time_point& tp, ASN1_Type tag )
        {
            using namespace std::chrono;
            auto days_since_epoch = floor < days > ( tp );
            year_month_day ymd ( days_since_epoch );
            auto sec_duration = duration_cast < seconds > ( tp - days_since_epoch ).count ();

            int year = static_cast < int > ( ymd.year () );
            unsigned month = static_cast < unsigned > ( ymd.month () );
            unsigned day = static_cast < unsigned > ( ymd.day () );

            uint32_t hours_val = static_cast < uint32_t > ( sec_duration / 3600 );
            uint32_t minutes_val = static_cast < uint32_t > ( ( sec_duration % 3600 ) / 60 );
            uint32_t seconds_val = static_cast < uint32_t > ( sec_duration % 60 );

            std::ostringstream oss;
            oss << std::setfill ( '0' );

            if ( tag == ASN1_Type::UTC_TIME )
            {
                oss << std::setw ( 2 ) << ( year % 100 );
            }
            else
            {
                oss << std::setw ( 4 ) << year;
            }

            oss << std::setw ( 2 ) << month
                << std::setw ( 2 ) << day
                << std::setw ( 2 ) << hours_val
                << std::setw ( 2 ) << minutes_val
                << std::setw ( 2 ) << seconds_val
                << 'Z';

            return oss.str ();
        }

    } // namespace

    //-----------------------------------------------------------------------------

    ASN1_Time::ASN1_Time ( std::chrono::system_clock::time_point time, ASN1_Type tag )
        : _time_point ( time ), _tag ( tag )
    {
        if ( _tag == ASN1_Type::EOC )
        {
            _tag = auto_tag_from_time ( _time_point );
        }
    }

    ASN1_Time::ASN1_Time ( std::string_view time_str, ASN1_Type tag )
    {
        parse_time_string ( time_str, tag, _time_point, _tag );
    }

    void
    ASN1_Time::encode_into ( DER_Encoder& to ) const
    {
        std::string formatted = to_asn1_string ();
        to.encode ( formatted, _tag, ASN1_Class::UNIVERSAL );
    }

    void
    ASN1_Time::decode_from ( BER_Decoder& from )
    {
        auto hdr = from.peek_next_header ();
        if ( !hdr.has_value () )
        {
            throw ASN1_DecodingError ( "Attempted to read ASN1_Time past the end of the buffer" );
        }

        if ( hdr->type_tag != ASN1_Type::UTC_TIME && hdr->type_tag != ASN1_Type::GENERALIZED_TIME )
        {
            throw ASN1_DecodingError ( "Tag mismatch: expected UTC_TIME or GENERALIZED_TIME" );
        }

        std::string raw_str;
        from.decode ( raw_str, hdr->type_tag, ASN1_Class::UNIVERSAL );

        parse_time_string ( raw_str, hdr->type_tag, _time_point, _tag );
    }

    std::chrono::system_clock::time_point
    ASN1_Time::get_time_point () const noexcept
    {
        return _time_point;
    }

    ASN1_Type
    ASN1_Time::get_tag () const noexcept
    {
        return _tag;
    }

    std::string
    ASN1_Time::to_string () const
    {
        using namespace std::chrono;
        auto days_since_epoch = floor < days > ( _time_point );
        year_month_day ymd ( days_since_epoch );
        auto sec_duration = duration_cast < seconds > ( _time_point - days_since_epoch ).count ();

        int year = static_cast < int > ( ymd.year () );
        unsigned month = static_cast < unsigned > ( ymd.month () );
        unsigned day = static_cast < unsigned > ( ymd.day () );

        uint32_t hours_val = static_cast < uint32_t > ( sec_duration / 3600 );
        uint32_t minutes_val = static_cast < uint32_t > ( ( sec_duration % 3600 ) / 60 );
        uint32_t seconds_val = static_cast < uint32_t > ( sec_duration % 60 );

        std::ostringstream oss;
        oss << std::setfill ( '0' )
            << std::setw ( 4 ) << year << "-"
            << std::setw ( 2 ) << month << "-"
            << std::setw ( 2 ) << day << "T"
            << std::setw ( 2 ) << hours_val << ":"
            << std::setw ( 2 ) << minutes_val << ":"
            << std::setw ( 2 ) << seconds_val << "Z";

        return oss.str ();
    }

    std::string
    ASN1_Time::to_asn1_string () const
    {
        return format_asn1_string ( _time_point, _tag );
    }

    bool
    ASN1_Time::operator== ( const ASN1_Time& other ) const noexcept
    {
        return _time_point == other._time_point && _tag == other._tag;
    }

    bool
    ASN1_Time::operator!= ( const ASN1_Time& other ) const noexcept
    {
        return !( *this == other );
    }

    bool
    ASN1_Time::operator< ( const ASN1_Time& other ) const noexcept
    {
        return _time_point < other._time_point;
    }

    bool
    ASN1_Time::operator<= ( const ASN1_Time& other ) const noexcept
    {
        return _time_point <= other._time_point;
    }

    bool
    ASN1_Time::operator> ( const ASN1_Time& other ) const noexcept
    {
        return _time_point > other._time_point;
    }

    bool
    ASN1_Time::operator>= ( const ASN1_Time& other ) const noexcept
    {
        return _time_point >= other._time_point;
    }

    std::ostream&
    operator<< ( std::ostream& os, const ASN1_Time& time )
    {
        os << time.to_string ();
        
        if ( time.get_tag () == ASN1_Type::UTC_TIME )
        {
            os << " (UTCTime)";
        }
        else
        {
            os << " (GeneralizedTime)";
        }

        return os;
    }

} // asn1pp