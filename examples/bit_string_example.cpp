#include <iostream>
#include <cassert>

#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/bit_string.hpp>
#include <asn1pp/der_encoder.hpp>

using namespace asn1pp;

int
main ( int, char** )
{
    std::cout << "--- Testing Bit_String standalone serialization ---\n";

    Bit_String pub_key ( { 0xDEu, 0xADu, 0xBEu, 0xEFu }, 3 );
    std::cout << "Original Bit_String: " << pub_key << "\n";

    DER_Encoder encoder;
    encoder.start_sequence ()
              .encode ( pub_key )
           .end_cons ();

    std::vector < uint8_t > der_stream = encoder.get_contents ();
    std::cout << "Encoded sequence size: " << der_stream.size () << " bytes\n";

    Bit_String decoded_key;
    BER_Decoder decoder ( der_stream );
    decoder.start_sequence ()
              .decode ( decoded_key )
           .end_cons ();

    std::cout << "Decoded Bit_String : " << decoded_key << "\n";

    assert ( decoded_key == pub_key );
    assert ( decoded_key.get_unused_bits () == 3 );
    assert ( !decoder.more_items () );

    std::cout << "SUCCESS: Bit_String encoded and decoded flawlessly!\n";

    return EXIT_SUCCESS;
}