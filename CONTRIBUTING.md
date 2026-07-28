# Contributing

## Build and test

```bash
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

Run the sanitizer configuration before submitting parser or codec changes:

```bash
cmake --preset sanitize
cmake --build --preset sanitize
ctest --preset sanitize
```

## Change requirements

- Preserve C++20 compatibility.
- Keep public headers self-contained.
- Do not add warnings to consuming targets.
- Document every public type and function with Doxygen.
- Add positive, negative, boundary, truncation, and resource-limit tests as applicable.
- Cite the relevant ASN.1 or protocol specification for standards-derived vectors.
- Avoid incompatible public API changes outside a major release.

## Formatting

Use the repository `.clang-format` file and keep CMake formatting consistent with the existing project.
