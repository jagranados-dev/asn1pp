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

# File directories
file(GLOB_RECURSE LIB_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
file(GLOB_RECURSE LIB_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp)

# -----------------------------------------------------------------------------
# 1. STATIC LIBRARY TARGET
# -----------------------------------------------------------------------------
add_library(ASN1PP_STATIC_LIB STATIC ${LIB_SOURCES} ${LIB_HEADERS})

target_include_directories(ASN1PP_STATIC_LIB
   PUBLIC
      ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set_target_properties(ASN1PP_STATIC_LIB PROPERTIES OUTPUT_NAME ${PROJECT_NAME})
add_library(asn1pp::static ALIAS ASN1PP_STATIC_LIB)

# -----------------------------------------------------------------------------
# 2. SHARED LIBRARY TARGET (OPTIONAL)
# -----------------------------------------------------------------------------
if (BUILD_SHARED_LIBS)
   add_library(ASN1PP_SHARED_LIB SHARED ${LIB_SOURCES} ${LIB_HEADERS})

   target_include_directories(ASN1PP_SHARED_LIB
      PUBLIC
         ${CMAKE_CURRENT_SOURCE_DIR}/include
   )

   set_target_properties(ASN1PP_SHARED_LIB PROPERTIES OUTPUT_NAME ${PROJECT_NAME})
   add_library(asn1pp::shared ALIAS ASN1PP_SHARED_LIB)
   add_library(asn1pp::asn1pp ALIAS ASN1PP_SHARED_LIB)
else()
   add_library(asn1pp::asn1pp ALIAS ASN1PP_STATIC_LIB)
endif()