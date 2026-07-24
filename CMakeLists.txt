##################################################################################
# MIT License
#
# Copyright (c) 2026 Jose Alberto Granados
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
##################################################################################

cmake_minimum_required(VERSION 3.16)

# Project
project(asn1pp 
    VERSION 0.2.3
    LANGUAGES CXX
)

# C++
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Top-level/Submodule detection
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(ASN1PP_IS_TOP_LEVEL ON)
else()
    set(ASN1PP_IS_TOP_LEVEL OFF)
endif()

# Options
option(ASN1PP_BUILD_DOCS     "Build library documentation"         OFF)
option(ASN1PP_BUILD_TESTS    "Build unit tests"                    ${ASN1PP_IS_TOP_LEVEL})
option(ASN1PP_BUILD_EXAMPLES "Build example executables"           ${ASN1PP_IS_TOP_LEVEL})
option(BUILD_SHARED_LIBS     "Build shared version of the library" OFF)

# Library source
add_subdirectory(lib)

# Library unit tests
if(ASN1PP_BUILD_TESTS)
    add_subdirectory(tests)
endif()

# Library examples
if(ASN1PP_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Library optional documentation
if(ASN1PP_BUILD_DOCS)
    find_package(Doxygen REQUIRED)
    find_program(DOT_EXECUTABLE dot)

    if(DOT_EXECUTABLE)
        set(DOXYGEN_HAVE_DOT YES)
    else()
        set(DOXYGEN_HAVE_DOT NO)
        message(WARNING "Graphviz not found. Diagrams will be disabled.")
    endif()

    add_subdirectory(doc)
endif()
