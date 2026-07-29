# ASN.1PP Library

**A Modern, Robust, and Fluent C++20 ASN.1 (BER/DER) Encoding and Decoding Library.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Language: C++20](https://img.shields.io/badge/Language-C%2B%2B20-orange.svg)](https://isocpp.org/)
[![Build: CMake](https://img.shields.io/badge/Build-CMake-green.svg)](https://cmake.org/)
[![CI - Build and Test](https://github.com/jagranados-dev/asn1pp/actions/workflows/ci.yml/badge.svg)](https://github.com/jagranados-dev/asn1pp/actions/workflows/ci.yml)

## Overview

`asn1pp` is a lightweight, high-performance C++ library designed to provide seamless Basic Encoding Rules (**BER**) decoding and Distinguished Encoding Rules (**DER**) encoding for Abstract Syntax Notation One (**ASN.1**) data structures.

Inspired by industrial-grade cryptographic engines like **Botan 3**, `asn1pp` provides an intuitive **fluent builder pattern** with strict memory safety, non-destructive lookahead parsing, and full compliance with canonical encoding standards.

The project provides a safe binary codec, reusable ASN.1 value classes, configurable resource limits, structured errors, canonical DER validation, and a Catch2 test suite.

## Features

### BER decoder

`BER_Decoder` supports:

- definite-length BER values;
- constructed indefinite-length BER values;
- End-of-Contents processing;
- short and high-tag-number identifier forms;
- primitive and constructed values;
- transactional decoding;
- zero-copy primitive value views;
- raw TLV extraction;
- `OPTIONAL` and `DEFAULT` helpers;
- `SEQUENCE`, `SET`, and generic constructed-value callbacks;
- configurable input, element, depth, item, tag, length, integer, and OID limits.

Primitive indefinite-length encodings and standalone End-of-Contents values are rejected.

### DER decoder

`DER_Decoder` is a strict facade over the BER decoding engine. In addition to structural validation, it enforces canonical DER requirements for the supported universal types, including:

- canonical BOOLEAN values;
- minimal INTEGER and ENUMERATED representations;
- canonical short and long length forms;
- minimal high-tag-number representations;
- valid BIT STRING unused bits;
- zero-length NULL values;
- valid OBJECT IDENTIFIER base-128 subidentifiers;
- UTF8String validation;
- IA5String validation;
- PrintableString validation;
- canonical UTCTime and GeneralizedTime values;
- rejection of indefinite-length values;
- recursive validation of constructed values;
- canonical `SET OF` ordering when requested by the schema-aware container.

### DER encoder

`DER_Encoder` produces canonical DER and supports:

- BOOLEAN;
- signed and unsigned 64-bit INTEGER values;
- arbitrary byte strings;
- UTF-8 strings;
- NULL;
- short and high-tag-number identifiers;
- canonical length encoding;
- `SEQUENCE`;
- `SET`;
- canonically sorted `SET OF`;
- `OPTIONAL` values;
- `DEFAULT` values;
- polymorphic `ASN1_Object` values;
- validated insertion of one pre-encoded DER TLV;
- configurable output-size and nesting-depth limits.

## ASN.1 value classes

The library includes reusable objects derived from `ASN1_Object`:

- `Big_Int` — arbitrary-precision signed INTEGER;
- `Bit_String` — BIT STRING with explicit unused-bit tracking;
- `Octet_String` — OCTET STRING;
- `UTF8_String` — validated UTF8String;
- `IA5_String` — validated seven-bit IA5String;
- `Printable_String` — validated PrintableString;
- `ASN1_Any` — one preserved BER TLV with DER canonicality tracking;
- `ASN1_Time` — canonical UTCTime or GeneralizedTime;
- `OID` — OBJECT IDENTIFIER using numeric arcs;
- `Sequence_Of<T>` — homogeneous SEQUENCE OF container;
- `Set_Of<T>` — homogeneous SET OF container with canonical DER ordering.

Application-specific ASN.1 structures can derive from `ASN1_Object` and implement:

```cpp
void encode_into ( asn1::DER_Encoder& to ) const override;
void decode_from ( asn1::BER_Decoder& from ) override;
```

## System Requirements

To build and consume `asn1pp`, your development environment must meet the following minimum requirements:

- **C++ Compiler:** A C++20 compliant compiler (GCC 10+, Clang 11+, or MSVC 2019+).
- **Build System:** CMake 3.15 or newer.
- **Testing Framework:** Catch2 v3.15+ (automatically fetched via CMake during test builds).
- **Documentation (Optional):** Doxygen (to generate HTML/LaTeX API references).

## Building and Compiling

The project uses a standard CMake out-of-source build workflow.

### 1. Clone the Repository

```bash
git clone https://github.com/jagranados-dev/asn1pp.git
cd asn1pp
```

### 2. Configure and Build the Library

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release -j$(nproc)
```

### 3. Run the Unit Test Suite

The repository includes a comprehensive Catch2 test suite covering primitive types, constructed containers, boundary overflows, and overload resolution regression tests.

To execute the tests after compiling:

```bash
ctest --output-on-failure --build-config Release
```

Or run the test binary directly for detailed Catch2 output:

```bash
./build/tests/asn1pp_tests
```

List the available Catch2 test cases:

```bash
./build/tests/asn1_tests --list-tests
```

Run specific groups:

```bash
./build/tests/asn1_tests "[der][encoder]"
./build/tests/asn1_tests "[ber][decoder]"
./build/tests/asn1_tests "[oid]"
./build/tests/asn1_tests "[time]"
```

## Quick Start & Usage

### Encoding and Decoding Example

The following example demonstrates how to serialize and deserialize a structured ASN.1 payload:

```cpp
#include <asn1/asn1.hpp>

#include <cstdint>
#include <string>
#include <vector>

int
main ()
{
    asn1::DER_Encoder encoder;

    encoder.encode ( true )
           .encode ( uint64_t ( 65537 ) )
           .encode ( int64_t ( -129 ) )
           .encode ( std::vector < uint8_t > { 0xDE, 0xAD, 0xBE, 0xEF } )
           .encode ( std::string ( "Hello ASN.1" ) )
           .encode_null ();

    const std::vector < uint8_t > encoded =
        encoder.get_contents ();

    asn1::DER_Decoder decoder ( encoded );

    bool boolean_value = false;
    uint64_t unsigned_value = 0;
    int64_t signed_value = 0;
    std::vector < uint8_t > octets;
    std::string text;

    decoder.decode ( boolean_value )
           .decode ( unsigned_value )
           .decode ( signed_value )
           .decode ( octets )
           .decode ( text )
           .decode_null ();

    return decoder.more_items () ? 1 : 0;
}
```

Use `DER_Decoder` whenever the input is required to be canonical DER. Use `BER_Decoder` when valid BER representations, including constructed indefinite-length values, must be accepted.

## Defining an application-specific ASN.1 object

The following class models a simple ASN.1 `SEQUENCE`:

```asn1
Example ::= SEQUENCE {
    algorithm  OBJECT IDENTIFIER,
    serial      INTEGER,
    enabled     BOOLEAN DEFAULT FALSE
}
```

```cpp
class Example : public asn1::ASN1_Object
{
public:
    asn1::OID algorithm;
    asn1::Big_Int serial;
    bool enabled = false;

    void
    encode_into ( asn1::DER_Encoder& to ) const override
    {
        to.encode_sequence (
            [&] ( asn1::DER_Encoder& sequence )
            {
                sequence.encode ( algorithm );
                sequence.encode ( serial );
                sequence.encode_default ( enabled, false );
            }
        );
    }

    void
    decode_from ( asn1::BER_Decoder& from ) override
    {
        from.decode_sequence (
            [&] ( asn1::BER_Decoder& sequence )
            {
                sequence.decode ( algorithm );
                sequence.decode ( serial );
                sequence.decode_default (
                    enabled,
                    false,
                    asn1::ASN1_Type::BOOLEAN
                );
            }
        );
    }
};
```

Encode and decode it as follows:

```cpp
Example original;
original.algorithm.assign ( "1.2.840.113549.1.1.11" );
original.serial.set_decimal ( "12345678901234567890" );
original.enabled = true;

const std::vector < uint8_t > encoded =
    original.DER_encode ();

asn1::DER_Decoder decoder ( encoded );
Example decoded;
decoder.decode ( decoded );
```

## `SEQUENCE OF` and `SET OF`

`Sequence_Of<T>` preserves element order:

```cpp
asn1::Sequence_Of < asn1::IA5_String > names;
names.values.emplace_back ( "first.example" );
names.values.emplace_back ( "second.example" );
```

`Set_Of<T>` sorts complete DER element encodings canonically when encoded:

```cpp
asn1::Set_Of < asn1::Printable_String > roles;
roles.values.emplace_back ( "Signing" );
roles.values.emplace_back ( "Administrator" );
roles.values.emplace_back ( "Encryption" );
```

The stored order of a `Set_Of<T>` should not be treated as semantic ordering. After a DER round trip, values are exposed in canonical encoded order.

## Resource limits

Inputs should be treated as untrusted data. Configure limits appropriate for the application:

```cpp
asn1::BER_DecoderLimits limits;
limits.max_input_size = 4u * 1024u * 1024u;
limits.max_element_size = 1u * 1024u * 1024u;
limits.max_depth = 32;
limits.max_items = 100000;
limits.max_tag_octets = 10;
limits.max_length_octets = sizeof ( size_t );
limits.max_integer_octets = 4096;
limits.max_oid_arcs = 256;

asn1::DER_Decoder decoder ( encoded, limits );
```

The encoder also supports output limits:

```cpp
asn1::DER_EncoderLimits limits;
limits.max_output_size = 4u * 1024u * 1024u;
limits.max_depth = 32;

asn1::DER_Encoder encoder ( limits );
```

The root encoder starts at depth zero. A constructed value increments the depth inherited by its child encoder.

## Error handling

All library errors derive from `ASN1_Error`:

```cpp
try
{
    asn1::DER_Decoder decoder ( encoded );
    decoder.decode ( value );
}
catch ( const asn1::ASN1_DecodingError& error )
{
    const asn1::ASN1_ErrorCode code = error.code ();
    const size_t offset = error.offset ();
    const char* message = error.what ();
}
```

Available error categories include:

- `INVALID_ARGUMENT`;
- `TRUNCATED_INPUT`;
- `INVALID_TAG`;
- `INVALID_LENGTH`;
- `TAG_MISMATCH`;
- `INVALID_VALUE`;
- `NON_CANONICAL_DER`;
- `LIMIT_EXCEEDED`;
- `UNCONSUMED_DATA`;
- `INVALID_STATE`.

Basic decoder operations are transactional: when decoding fails, the decoder restores its previous offset and item counter.

## Input lifetime and borrowed views

`BER_Decoder` and `DER_Decoder` store a non-owning `std::span` over the supplied input.

The input buffer must therefore:

- remain alive for the complete decoder lifetime;
- not be reallocated while the decoder is in use.

Constructing a decoder from a temporary `std::vector<uint8_t>` is deliberately disabled.

`decode_view()` also returns a non-owning view into the original input buffer:

```cpp
std::span < const uint8_t > value;
decoder.decode_view ( value, asn1::ASN1_Type::OCTET_STRING );
```

The returned view follows the same lifetime rules as the decoder input.

## Standards and interoperability

The implementation is designed around:

- ITU-T X.680 — Abstract Syntax Notation One;
- ITU-T X.690 — BER and DER encoding rules;
- RFC 5280 conventions for certificate-related OBJECT IDENTIFIER and time values.

The test suite includes standards-derived vectors for:

- INTEGER boundary encodings;
- canonical BOOLEAN values;
- length determinants;
- high-tag-number identifiers;
- BIT STRING unused bits;
- OBJECT IDENTIFIER base-128 encoding;
- canonical UTCTime and GeneralizedTime forms;
- DER `SET OF` ordering.

## Current scope and limitations

The current core library does not implement:

- CER;
- PER;
- OER;
- JER;
- XER;
- ASN.1 schema parsing or C++ code generation;
- arbitrary-precision OBJECT IDENTIFIER arcs beyond `uint64_t`;
- general-purpose polymorphic equality for `ASN1_Object`.

`ASN1_Any` preserves exactly one complete BER TLV and reports whether the preserved encoding is canonical DER. DER encoding rejects non-canonical preserved values. It is not a schema-aware open-type registry.

## Documentation

Public classes and functions are documented using Doxygen comments. If the project includes a `Doxyfile`, generate the API documentation with:

```bash
doxygen Doxyfile
```

## Testing policy

Tests are a first-class part of the project. New features and bug fixes should include:

- positive round-trip tests;
- standards-derived test vectors where available;
- boundary tests;
- malformed-input tests;
- truncation tests;
- resource-limit tests;
- BER acceptance and DER rejection pairs when the rules differ;
- transactional-state tests for decoder failures.

Before submitting changes, run:

```bash
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

## License

This project is distributed under the MIT License.

Copyright © 2026 Jose Alberto Granados.

## CMake presets

For local development with Ninja:

```bash
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

For AddressSanitizer and UndefinedBehaviorSanitizer:

```bash
cmake --preset sanitize
cmake --build --preset sanitize
ctest --preset sanitize
```

For a release build:

```bash
cmake --preset release
cmake --build --preset release
```

## Installation

Install the static library, public headers, license, README, and CMake package metadata:

```bash
cmake -S . -B build/release \
    -DCMAKE_BUILD_TYPE=Release \
    -DASN1LIB_BUILD_TESTS=OFF \
    -DASN1LIB_BUILD_EXAMPLES=OFF

cmake --build build/release --parallel
cmake --install build/release --prefix /path/to/prefix
```

A consuming CMake project can then use:

```cmake
find_package(asn1 1 CONFIG REQUIRED)

target_link_libraries(application
    PRIVATE
        asn1::static
)
```

Configure the consumer with the installation prefix:

```bash
cmake -S . -B build \
    -DCMAKE_PREFIX_PATH=/path/to/prefix
```

The install tree is relocatable and exports targets through `asn1Config.cmake`, `asn1ConfigVersion.cmake`, and `asn1Targets.cmake`.

## Build options

- `ASN1LIB_BUILD_TESTS`: build Catch2 tests.
- `ASN1LIB_BUILD_EXAMPLES`: build example executables.
- `ASN1LIB_BUILD_DOCS`: generate Doxygen documentation.
- `ASN1LIB_BUILD_SHARED`: additionally build `asn1::shared`.
- `ASN1LIB_ENABLE_WARNINGS`: enable strict warnings on project targets only.
- `ASN1LIB_WARNINGS_AS_ERRORS`: promote project warnings to errors.
- `ASN1LIB_ENABLE_SANITIZERS`: enable ASan and UBSan with GCC or Clang.
- `ASN1LIB_INSTALL`: generate install and package-export rules.

These options do not inject warning or sanitizer flags into projects that consume the library.

## Consuming as a subproject

```cmake
add_subdirectory(path/to/asn1-lib)

target_link_libraries(application
    PRIVATE
        asn1::static
)
```

Tests and examples default to enabled only when this repository is the top-level project.

## Development and security

See `CONTRIBUTING.md` for build, formatting, test, and documentation requirements. See `SECURITY.md` for reporting parser, resource-exhaustion, and memory-safety issues.
