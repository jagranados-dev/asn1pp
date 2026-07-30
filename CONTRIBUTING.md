# Contributing

## 1. Purpose and authority

This document defines the complete and mandatory coding style for every production source file, test, example, and library extension created for the ASN.1 project. This guide is self-contained and is the sole authority for project formatting and style. External examples, existing repository code, IDE settings, and historical conventions are not normative.

The requirements in this document are normative. The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** have their usual requirements meaning.

## 2. Language and build requirements

- Production code MUST target C++20.
- Code MUST compile with `-Wall -Wextra -Wpedantic -Werror`.
- Modern C++ facilities MUST be preferred over manual ownership, C-style casts, raw arrays, and macros.
- Public interfaces MUST express ownership and optionality explicitly.
- Every source file MUST comply with the complete rules and examples in this guide.

## 3. Files and directory layout

- Public declarations MUST be stored in `.hpp` files.
- Definitions that do not need to be templates MUST be stored in `.cpp` files.
- One principal domain class SHOULD be defined per header/source pair.
- File names MUST use lower-case `snake_case`, for example `algorithm_identifier.hpp`.
- Tests SHOULD mirror the production component name, for example `algorithm_identifier_tests.cpp`.
- Includes MUST use forward slashes.

## 4. Header guards

Every header MUST use an include guard derived from its project-relative path below `lib/include/`.

To derive the guard:

1. remove the `lib/include/` prefix;
2. remove the `.hpp` extension;
3. replace every path separator and non-alphanumeric separator with one underscore;
4. convert the result to upper case;
5. prefix the result with two underscores;
6. append `_HPP_`;
7. repeat the complete guard in the trailing `#endif` comment.

For example, `lib/include/asn1pp/ber_decoder.hpp` becomes:

```cpp
#ifndef __ASN1PP_BER_DECODER_HPP_
#define __ASN1PP_BER_DECODER_HPP_

// Declarations.

#endif // __ASN1PP_BER_DECODER_HPP_
```

The double underscore prefix is an intentional project convention and MUST be used exactly as specified.

## 5. Include ordering

Includes MUST be grouped in this order and separated by exactly one blank line:

1. the matching project header in a `.cpp` file;
2. C standard-library headers;
3. C++ standard-library headers;
4. other project headers;
5. local headers, if any are explicitly permitted.

Within a group, includes SHOULD be alphabetically ordered.

```cpp
#include <asn1pp/ber_decoder.hpp>

#include <algorithm>
#include <limits>

#include <asn1pp/asn1_object.hpp>
#include <asn1pp/asn1_time.hpp>

#include "codec_utils.hpp"
```

## 6. Namespaces

- Namespace names MUST use lower-case `snake_case`.
- The opening namespace brace MUST be on the next declaration line.
- The closing brace MUST include a namespace comment.
- Namespace-wide `using namespace` directives MUST NOT be used in headers.
- A narrow `using namespace` directive MAY be used inside a function when it clearly improves readability.

```cpp
namespace asn1::cms
{

// Declarations.

} // asn1::cms
```

## 7. Naming

### 7.1 Classes, structs, and enums

Domain type names MUST use `PascalCase` where compatibility with the ASN.1 schema requires the RFC name, for example `ContentInfo`, `SignedData`, and `AlgorithmIdentifier`.

Existing library names such as `Big_Int`, `Octet_String`, and `DER_Encoder` MUST retain their established spelling. New low-level library types SHOULD remain consistent with that library convention.

### 7.2 Functions and methods

Functions and methods MUST use lower-case `snake_case`:

```cpp
const ContentType& content_type () const;
void set_content_type ( const ContentType& content_type );
```

### 7.3 Variables and parameters

Local variables and parameters MUST use lower-case `snake_case`.

```cpp
const std::vector < uint8_t >& encoded_content
```

### 7.4 Private data members

Private data members MUST use lower-case `snake_case` prefixed with one underscore:

```cpp
ContentType                    _content_type;
std::optional < ASN1_Any >     _content;
```

Member declarations SHOULD be vertically aligned when this improves readability, as in the supplied example.

### 7.5 Constants

Namespace-scope constants MUST use upper-case `SNAKE_CASE` when they are protocol or formatting constants:

```cpp
const uint64_t CONTENT_TAG = 0;
```

Prefer `constexpr` and strongly typed values where possible.

### 8. Whitespace, blank lines, and braces

These rules are mandatory and remove ambiguity about spacing between methods, control statements, and blocks.

### 8.1 Functions and methods

- Put exactly one space between a function or method name and `(`.
- When arguments are present, put exactly one space after `(` and before `)`.
- Empty argument lists MUST use `()` without internal spaces.

```cpp
value.assign ( encoded_tlv );
decoder.more_items ();
void assign ( std::span < const uint8_t > encoded_tlv );
```

The following forms are prohibited:

```cpp
value.assign(encoded_tlv);
decoder.more_items();
void assign(std::span<const uint8_t> encoded_tlv);
```

### 8.2 Control statements

- Put exactly one space between `if`, `else if`, `for`, `while`, `switch`, or `catch` and `(`.
- Put exactly one space immediately inside non-empty control-statement parentheses.
- Put one space after unary `!`.

```cpp
if ( !header )
{
   throw ASN1_InvalidArgument ( "Missing ASN.1 header" );
}

for ( const uint8_t octet : encoded_tlv )
{
   stream << octet;
}

catch ( const ASN1_Error& error )
{
   throw ASN1_InvalidArgument ( error.what () );
}
```

Forms such as `if(!header)`, `if (!header)`, and `for(const auto value : values)` are prohibited.

### 8.3 Braces and `else`

- Opening and closing braces MUST be on their own lines.
- `else` and `else if` MUST appear on their own line immediately after the preceding closing brace.
- Their opening brace MUST appear on the following line.
- The form `} else {` is prohibited.

```cpp
if ( value.is_der () )
{
   encoder.append_encoded_tlv ( value.encoded_tlv () );
}
else
{
   throw ASN1_EncodingError ( "The value is not canonical DER" );
}
```

### 8.4 Blank lines between declarations and definitions

- Put exactly one blank line between consecutive method or function definitions in source files.
- Apply this rule to constructors, destructors, operators, free functions, function templates, and test helpers.
- In class declarations, closely related trivial declarations MAY be grouped without blank lines when they belong to the same API family.
- Suitable groups include overloads of the same function, paired const and non-const accessors, related constructors, and short observers for the same state.
- Put exactly one blank line between different API groups, such as constructors, observers, modifiers, encoding operations, decoding operations, and comparison operations.
- Do not insert a blank line immediately after `public:`, `protected:`, or `private:`.
- Do not use multiple consecutive blank lines.

```cpp
class ContentInfo : public asn1::ASN1_Object
{
public:
   ContentInfo () = default;
   ContentInfo ( const ContentType& content_type, const asn1::ASN1_Any& content );

   [[nodiscard]] const ContentType& content_type () const;
   [[nodiscard]] bool has_content () const noexcept;

   void set_content_type ( const ContentType& content_type );
   void set_content ( const asn1::ASN1_Any& content );

   void encode_into ( asn1::DER_Encoder& to ) const override;
   void decode_from ( asn1::BER_Decoder& from ) override;
};

ASN1_Tag
BER_Any::tag () const
{
   return _tag;
}

bool
BER_Any::is_der () const noexcept
{
   return _is_der;
}
```

### 8.5 Blank lines around control-flow blocks

- Do not put a blank line between a control statement and its opening brace.
- Do not put a blank line between an `if` closing brace and its associated `else`.
- Put one blank line after a completed control-flow block when the next statement starts a logically independent operation.
- Consecutive validation blocks MAY be adjacent when they form one logical validation sequence.
- Use one blank line, never several, between logical sections inside a function.

```cpp
if ( encoded_tlv.empty () )
{
   throw ASN1_InvalidArgument ( "The encoded value cannot be empty" );
}

std::vector < uint8_t > validated = validate ( encoded_tlv );
_encoded_tlv = std::move ( validated );
```

### 8.6 Short guards

- A guard MAY use one line only when its condition and action are brief and the action is one `return`, `continue`, `break`, or `throw`.
- Non-trivial guards, multi-argument exceptions, commented guards, and code likely to grow MUST use braces.
- Equivalent guards within the same file MUST use a consistent form.

```cpp
if ( _encoded_tlv.empty () ) return false;
```

```cpp
if ( _encoded_tlv.empty () )
{
   throw ASN1_InvalidArgument (
      "BER_Any does not contain an encoded value" );
}
```

### 8.7 Lambdas

- Lambda introducers MUST NOT contain unnecessary spaces inside `[` and `]`.
- Lambda parameter lists MUST follow the same parenthesis-spacing rules as functions.
- A lambda opening brace MUST appear on the line following its declaration.
- The lambda body MUST use three-space indentation.
- A short lambda expression MUST remain on one line only when the entire enclosing statement is 150 characters or fewer and the lambda body contains one simple expression.
- A lambda used as a callback for ASN.1 encoding or decoding SHOULD use the multiline form because it usually contains protocol-significant operations.

```cpp
decoder.decode_sequence (
   [&] ( BER_Decoder& sequence )
   {
      sequence.decode ( value );
   } );
```

When the complete callback call is 150 characters or fewer and the body is one simple expression, this compact form is also permitted:

```cpp
encoder.encode_sequence ( [&] ( DER_Encoder& sequence ) { sequence.encode ( value ); } );
```

### 8.8 General rules

- Put one space around binary operators.
- Put one space around template angle brackets in the project style.
- Indent with exactly three spaces.
- Tabs and trailing whitespace are prohibited.
- Multiple statements on one line are prohibited except for an allowed short guard.

## 9. Class declarations

A class declaration MUST follow this order:

1. constructors;
2. destructor;
3. public observers;
4. public modifiers;
5. ASN.1 encoding and decoding operations;
6. comparison operations where meaningful;
7. private helpers;
8. private data members.

Closely related trivial declarations MAY remain together without blank lines. Different API groups MUST be separated by exactly one blank line. Access specifiers MUST be followed immediately by the first declaration without an intervening blank line.

```cpp
class ContentInfo : public asn1::ASN1_Object
{
public:
   ContentInfo () = default;
   ContentInfo ( const ContentType& content_type, const asn1::ASN1_Any& content );

   ~ContentInfo () override = default;

   const ContentType& content_type () const;
   void set_content_type ( const ContentType& content_type );

   void encode_into ( asn1::DER_Encoder& to ) const override;
   void decode_from ( asn1::BER_Decoder& from ) override;

private:
   ContentType                      _content_type;
   std::optional < asn1::ASN1_Any > _content;
};
```

## 10. Function definitions

For non-constructor definitions, the return type MUST appear on its own line:

```cpp
const ContentType&
ContentInfo::content_type () const
{
   return _content_type;
}
```

Constructors MUST keep the qualified constructor name and parameter list on one line when practical. Initializer lists MUST be aligned:

```cpp
ContentInfo::ContentInfo ( const ContentType& content_type, const asn1::ASN1_Any& content )
   : _content_type ( content_type ),
     _content      ( content )
{}
```

Exactly one blank line MUST separate consecutive definitions:

```cpp
const ContentType&
ContentInfo::content_type () const
{
   return _content_type;
}

void
ContentInfo::set_content_type ( const ContentType& content_type )
{
   _content_type = content_type;
}
```

## 11. Type usage and ownership

- Use `std::vector < uint8_t >` for owned octet sequences.
- Use `std::span < const uint8_t >` for non-owning read-only byte ranges.
- Use `std::string_view` for non-owning string input when lifetime is unambiguous.
- Use `std::optional < T >` for ASN.1 `OPTIONAL` fields.
- Use `std::variant` or a dedicated tagged class for ASN.1 `CHOICE` values.
- Use value semantics by default.
- Use `std::unique_ptr` only for necessary dynamic ownership or recursive type breaking.
- Raw owning pointers and manual `new`/`delete` MUST NOT be used.
- C-style casts MUST NOT be used; use C++ casts.
- `auto` MAY be used when the type is obvious from the initializer or excessively verbose, but MUST NOT hide protocol-relevant types.

## 12. Const correctness and attributes

- Observer methods MUST be `const`.
- Non-throwing trivial observers SHOULD be `noexcept`.
- Return values that must not be ignored SHOULD be marked `[[nodiscard]]`.
- Immutable local values SHOULD be declared `const`.
- Overrides MUST use `override`; redundant `virtual` SHOULD NOT be repeated.

## 13. ASN.1 implementation rules

- Every schema type with behavior MUST derive from `asn1::ASN1_Object` or be wrapped by a type that does.
- `encode_into()` MUST emit canonical DER.
- `decode_from()` MUST consume exactly one complete value and leave no unconsumed child content.
- Failed decoding MUST preserve transactional decoder behavior.
- `SET OF` MUST use canonical DER ordering.
- `OPTIONAL`, `DEFAULT`, `CHOICE`, `EXPLICIT`, and `IMPLICIT` semantics MUST be represented directly and tested.
- Open types MUST preserve exactly one validated TLV and MUST be associated with the controlling OID when the schema uses `ANY DEFINED BY` or an information object class.
- Semantic constraints from the RFC MUST be validated separately from structural BER/DER validity.
- Unknown extension values MUST be preserved when the relevant RFC permits extensibility.

## 14. Error handling

- Library and schema errors MUST use the existing `ASN1_Error` hierarchy.
- Do not use integer error codes or return `false` for exceptional parse failures.
- Error messages MUST be concise, actionable, and written in English.
- Catch exceptions only when adding meaningful context, restoring state, or translating to a more precise project error.
- Empty catch blocks MUST NOT be used.

## 15. Doxygen documentation

Every class, constructor, destructor, public or private method, free function, function template, and meaningful constant MUST have a Doxygen block written in correct English.

A declaration comment MUST describe:

- purpose using `@brief`;
- every parameter using `@param`;
- the return value using `@return` when non-void;
- exceptions using `@throws` where useful;
- protocol constraints or tagging using `@note` when needed.

```cpp
/**
 * @brief Assigns the encapsulated content.
 * @param content Canonical DER value stored in the explicit content field.
 * @throws asn1::ASN1_InvalidArgument if the value does not contain exactly one DER object.
 */
void set_content ( const asn1::ASN1_Any& content );
```

Comments MUST explain intent and protocol rules, not repeat obvious syntax.

## 16. Tests

- Tests MUST use Catch2 and `TEST_CASE`.
- Test descriptions MUST be complete English sentences or precise behavioral statements.
- Every public method of every class MUST be exercised.
- Each class MUST cover valid, invalid, and edge cases.
- Tests MUST include DER round trips and byte-exact vectors where available.
- BER acceptance and DER rejection pairs MUST be included when canonical rules differ.
- Malformed tag, length, value, truncation, unexpected trailing data, and resource-limit behavior MUST be tested where applicable.
- Test setup helpers MUST follow the same style and Doxygen rules as production code.

```cpp
TEST_CASE ( "ContentInfo preserves a known content type through a DER round trip", "[cms][content-info][der]" )
{
   // Test body.
}
```

## 17. Prohibited practices

The following are prohibited:

- unformatted generated code;
- public mutable data members in domain classes;
- raw owning pointers;
- undocumented functions or methods;
- silent acceptance of trailing ASN.1 values;
- schema types represented only as unvalidated primitive aliases when they carry constraints;
- duplicated tag-manipulation logic when a library helper exists;
- adding third-party ASN.1 dependencies;
- changing encoded wire semantics for convenience;
- weakening DER validation to accept malformed inputs.

## 18. Repository compliance policy

This style guide is the sole and authoritative coding standard for this repository.

The requirements in this document take precedence over:

- existing repository code;
- historical project conventions;
- previously written implementations;
- IDE formatting settings;
- personal coding preferences;
- examples that do not comply with this document.

Code that does not comply with this style guide MUST NOT be used as a formatting, naming, documentation, or architectural reference.

When modifying an existing file, contributors MUST inspect the affected code for violations of this style guide.

When violations are found in the affected area, contributors MUST update the code to comply with the guide whenever reasonably possible.

This includes, but is not limited to:

- formatting;
- spacing;
- indentation;
- include ordering;
- naming conventions;
- brace placement;
- namespace formatting;
- declaration ordering;
- const correctness;
- Doxygen documentation;
- ownership semantics.

Consistency with non-compliant legacy code is not a valid reason to violate this style guide.

Contributors SHOULD leave modified code in a better state than it was before the change.

The affected area SHOULD be brought into compliance even when style corrections are not directly required by the functional change.

Large-scale repository-wide reformatting SHOULD be performed as a dedicated change whenever practical.

## 19. AI-assisted development requirements

When an AI system is used to generate, modify, review, refactor, document, or analyze code, it MUST treat this document as the sole source of truth for coding style.

The AI MUST follow this style guide regardless of:

- the formatting of surrounding code;
- the formatting of nearby files;
- patterns found elsewhere in the repository;
- examples that conflict with this guide.

The AI MUST NOT infer formatting or documentation rules from existing repository code when those rules conflict with this document.

When modifying existing code, the AI MUST inspect the affected area for violations of this style guide.

If violations are discovered, the AI MUST update the affected code to comply with the guide while performing the requested change.

This includes:

- reformatting code;
- correcting spacing and indentation;
- correcting brace placement;
- correcting include ordering;
- correcting declaration ordering;
- correcting namespace formatting;
- correcting naming violations;
- improving const correctness where appropriate;
- adding missing attributes required by the guide;
- adding missing Doxygen documentation.

When existing declarations, methods, classes, or helper functions are undocumented, the AI MUST add complete Doxygen documentation that complies with this guide.

The AI MUST generate documentation in correct English.

Generated code MUST be compliant upon creation and MUST NOT require additional formatting to satisfy this guide.

The AI SHOULD apply the "leave it better than you found it" principle when modifying existing files.

The AI SHOULD reformat all affected code.

The AI MAY reformat an entire file when widespread style violations make partial cleanup impractical.

Preserving non-compliant code solely for consistency with the surrounding implementation is prohibited.

Conformance to this style guide has higher priority than consistency with non-compliant repository code.
