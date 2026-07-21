#include <iostream>
#include <cassert>
#include <chrono>

#include <asn1pp/asn1_time.hpp>
#include <asn1pp/der_encoder.hpp>
#include <asn1pp/ber_decoder.hpp>

using namespace asn1pp;

int
main ( int, char** )
{
    std::cout << "--- Testing ASN1_Time standalone serialization ---\n";

    ASN1_Time time_2026 ( "260721173202Z" );
    std::cout << "Date 1 (< 2050): " << time_2026 << " | DER representation: " << time_2026.to_asn1_string () << "\n";
    assert ( time_2026.get_tag () == ASN1_Type::UTC_TIME );

    ASN1_Time time_2055 ( "20550101120000Z" );
    std::cout << "Date 2 (>= 2050): " << time_2055 << " | DER representation: " << time_2055.to_asn1_string () << "\n";
    assert ( time_2055.get_tag () == ASN1_Type::GENERALIZED_TIME );

    DER_Encoder encoder;
    encoder.start_sequence ()
           .encode ( time_2026 )
           .encode ( time_2055 )
           .end_cons ();

    std::vector < uint8_t > der_stream = encoder.get_contents ();
    std::cout << "Encoded sequence size: " << der_stream.size () << " bytes\n";

    ASN1_Time decoded_time_1;
    ASN1_Time decoded_time_2;

    BER_Decoder decoder ( der_stream );
    decoder.start_sequence ()
           .decode ( decoded_time_1 )
           .decode ( decoded_time_2 )
           .end_cons ();

    std::cout << "Decoded Date 1 : " << decoded_time_1 << "\n";
    std::cout << "Decoded Date 2 : " << decoded_time_2 << "\n";

    assert ( decoded_time_1 == time_2026 );
    assert ( decoded_time_2 == time_2055 );
    assert ( decoded_time_1 < decoded_time_2 );
    assert ( !decoder.more_items () );

    std::cout << "SUCCESS: ASN1_Time encoded, decoded, and auto-tagged flawlessly!\n";

    return EXIT_SUCCESS;
}