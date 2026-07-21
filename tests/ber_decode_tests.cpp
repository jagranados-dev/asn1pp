#include <asn1pp/ber_decoder.hpp>
#include <catch2/catch_test_macros.hpp>

using namespace asn1pp;

TEST_CASE("Boolean (True) decode success", "[dec-bool-true]")
{
    bool decoded_value = false;
    const std::vector < uint8_t > test_vector = { 0x01, 0x01, 0xFF };

    BER_Decoder decoder ( test_vector );
    decoder.decode ( decoded_value );

   REQUIRE ( decoded_value == true );
}

TEST_CASE("Boolean (False) decode success", "[dec-bool-false]")
{
    bool decoded_value = false;
    const std::vector < uint8_t > test_vector = { 0x01, 0x01, 0x00 };

    BER_Decoder decoder ( test_vector );
    decoder.decode ( decoded_value );

   REQUIRE ( decoded_value == false );
}