# asn1pp

**A Modern, Robust, and Fluent C++20 ASN.1 (BER/DER) Encoding and Decoding Library.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Language: C++20](https://img.shields.io/badge/Language-C%2B%2B20-orange.svg)](https://isocpp.org/)
[![Build: CMake](https://img.shields.io/badge/Build-CMake-green.svg)](https://cmake.org/)
[![CI - Build and Test](https://github.com/jagranados-dev/asn1pp/actions/workflows/ci.yml/badge.svg)](https://github.com/jagranados-dev/asn1pp/actions/workflows/ci.yml)

---

## 📖 Overview

`asn1pp` is a lightweight, high-performance C++ library designed to provide seamless Basic Encoding Rules (**BER**) decoding and Distinguished Encoding Rules (**DER**) encoding for Abstract Syntax Notation One (**ASN.1**) data structures.

Inspired by industrial-grade cryptographic engines like **Botan 3**, `asn1pp` provides an intuitive **fluent builder pattern** with strict memory safety, non-destructive lookahead parsing, and full compliance with canonical encoding standards.

---

## ✨ Key Features

- **Fluent Builder Interface:** Effortlessly construct and parse complex nested ASN.1 structures (`SEQUENCE`, `SET`) using stack-based method chaining.
- **Strict DER Canonicalization:** Automatically enforces shortest-form length encodings, proper two's-complement integer representations, and mandatory omission of default values.
- **Modern C++20 Semantics:** Built from the ground up utilizing `std::span`, `std::string_view`, and `std::optional` to eliminate unnecessary memory allocations and pointer decay vulnerabilities.
- **Advanced Tagging Support:** Full, native support for both **IMPLICIT** and **EXPLICIT** context-specific tagging (`[0] IMPLICIT`, `[1] EXPLICIT`, etc.).
- **Smart Default & Optional Handling:** Seamlessly handle `OPTIONAL` fields and fallback to `DEFAULT` values when tags are omitted from the underlying binary stream.
- **Rich Domain Objects:** Out-of-the-box support for arbitrary-precision integers (`Big_Int`), Object Identifiers (`OID`), and an extensible `ASN1_Object` interface for custom domain serialization.
- **Comprehensive Error Handling:** Safe bounds checking and strict type enforcement backed by a dedicated hierarchy of runtime exceptions (`ASN1_EncodingError`, `ASN1_DecodingError`).

---

## 🛠️ System Requirements

To build and consume `asn1pp`, your development environment must meet the following minimum requirements:

- **C++ Compiler:** A C++20 compliant compiler (GCC 10+, Clang 11+, or MSVC 2019+).
- **Build System:** CMake 3.15 or newer.
- **Testing Framework:** Catch2 v3.15+ (automatically fetched via CMake during test builds).
- **Documentation (Optional):** Doxygen (to generate HTML/LaTeX API references).

---

## 🚀 Building and Compiling

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

---

## 💻 Quick Start & Usage

### Encoding and Decoding Example

The following example demonstrates how to serialize and deserialize a structured ASN.1 payload:

```c++
#include <iostream>
#include <iomanip>
#include <cassert>

#include <asn1pp/der_encoder.hpp>
#include <asn1pp/ber_decoder.hpp>

using namespace asn1pp;

/**
 * @brief Helper function to hex dump of encoded DER stream.
 */
std::string
hex_encode ( std::span < const uint8_t > data )
{
    std::stringstream ss;
    for ( uint8_t byte : data )
    {
        ss << std::hex << std::setw ( 2 ) << std::setfill ( '0' ) << static_cast < int > ( byte ) << " ";
    }

    return ss.str ();
}

int
main ( int, char** )
{
    const std::vector < uint8_t > raw_payload = { 0xDE, 0xAD, 0xBE, 0xEF };

    // Encode a complex nested ASN.1 structure:
    // SEQUENCE {
    //   version INTEGER (1),
    //   active BOOLEAN (true),
    //   username UTF8String ("ASN1_User"),
    //   payload SEQUENCE {
    //     id INTEGER (9988776655),
    //     data OCTET STRING (0xDE, 0xAD, 0xBE, 0xEF)
    //   }
    // }
    DER_Encoder encoder;
    encoder.start_sequence ()
                .encode ( static_cast < uint64_t > ( 1 ) )
                .encode ( true )
                .encode ( "ASN1_User", ASN1_Type::UTF8_STRING )
                .start_sequence ()
                    .encode ( static_cast < uint64_t > ( 9988776655ULL ) )
                    .encode ( raw_payload, ASN1_Type::OCTET_STRING )
                .end_cons ()
           .end_cons ();

    auto encoded_data = encoder.get_contents ();

    std::cout << "Successfully encoded " << encoded_data.size () << " bytes.\n";
    std::cout << "Hex Dump: " << hex_encode ( encoded_data ) << "\n\n";

    bool active;
    uint64_t id, version;
    std::string username;
    std::vector < uint8_t > decoded_payload;

    BER_Decoder decoder ( encoded_data );
    decoder.start_sequence ()
                .decode ( version )
                .decode ( active )
                .decode ( username, ASN1_Type::UTF8_STRING )
                .start_sequence ()
                    .decode ( id )
                    .decode ( decoded_payload, ASN1_Type::OCTET_STRING )
                .end_cons ()
           .end_cons ();

    std::cout << "Decoded Values:"
              << "\n - Version : "  << version
              << "\n - Active  : "  << std::boolalpha << active
              << "\n - Username: "  << username
              << "\n - Nested ID: " << id
              << "\n - Payload : "  << hex_encode ( decoded_payload );

    return EXIT_SUCCESS;
}
```

---

## 📁 Project Structure

```
asn1pp/
├── CMakeLists.txt         # Root build configuration
├── LICENSE                # MIT License file
├── README.md              # Project documentation
├── doc/                   # Documentation and Doxygen configuration
├── examples/              # Practical usage and integration examples
├── lib/                   # Core library source code
│   ├── include/asn1pp/    # Public headers (der_encoder.hpp, ber_decoder.hpp, etc.)
│   └── src/asn1pp/        # Implementation files (.cpp)
└── tests/                 # Catch2 unit test suite
```

---

## 📄 License

This project is licensed under the MIT License. See below for details:

```
MIT License

Copyright (c) 2026 Jose Alberto Granados

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
