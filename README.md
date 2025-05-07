# Bytes Utilities Library

This header-only C++ library provides simple and efficient utilities for working with byte-oriented data. It defines concepts and functions to handle any trivially copyable, 1-byte type and containers or arrays thereof. The library is lightweight, easy to use, and requires only a single header include.

## Features

- **Byte and Bytes Concepts:**
Type-safe concepts for byte types and byte containers.
- **Generic Utilities:**
Functions for size, data access, copying, comparison, and equality.
- **Stream Operators:**
Read/write byte containers to/from streams.
- **Encoding:**
Hex and Base64 encode/decode utilities.

## Concepts

- **Byte:** Any trivially copyable, 1-byte type (e.g., `std::byte`, `char`, `uint8_t`).
- **Bytes:** Any container or array of `Byte` types with `data()` and `size()` methods.

## Utility Functions

```cpp
template <typename T> constexpr std::size_t bytes_size(const T &t) noexcept;
template <typename T> constexpr auto *bytes_data(T &t) noexcept;
template <typename T> constexpr const auto *bytes_data(const T &t) noexcept;
```

- **bytes_size:** Returns the number of bytes in a byte container.
- **bytes_data:** Returns a pointer to the underlying byte data.

## Algorithms

```cpp
template <Bytes Dest, Bytes Src> void copy(Dest &dest, const Src &src);
template <Byte B, Bytes Src> void copy(std::vector<B> &dest, const Src &src);
template <Bytes T1, Bytes T2> bool equal(const T1 &a, const T2 &b) noexcept;
template <Bytes A, Bytes B> int compare(const A &a, const B &b);
```

- **copy:** Copies bytes from one container to another.
- **equal:** Checks if two byte containers are equal.
- **compare:** Lexicographically compares two byte containers similar to C's `memcmp`.

## Stream Operators

```cpp
template <Bytes T> std::ostream &operator<<(std::ostream &os, const T &t);
template <Bytes T> std::istream &operator>>(std::istream &is, T &t);
```

- **operator<< / operator>>:** Write/read bytes to/from streams.

## Encoding Utilities

```cpp
template <typename Bytes> std::string to_hex(const Bytes &data);
template <typename Bytes> void from_hex(Bytes &data, const std::string &hex);
std::string to_base64(const Bytes &data, bool url = false);
void from_base64(Bytes &data, const std::string &b64, bool url = false);
```

- **to_hex / from_hex:** Convert bytes to/from hexadecimal strings.
- **to_base64 / from_base64:** Convert bytes to/from Base64 strings (with optional URL-safe variant).

## Example Usage

```cpp
#include "ByteUtils.hpp"

std::vector<uint8_t> data = {1, 2, 3, 4};
std::string hex = to_hex(data); // "01020304"

std::vector<uint8_t> copy_data;
copy(copy_data, data);

bool is_equal = equal(data, copy_data); // true

std::string b64 = to_base64(data);
from_base64(copy_data, b64);
```

## Requirements

- C++20 or later (for concepts)
- Standard C++ library

## Author, Licence

Copyright :copyright: 2025 by Alan Tseng

MIT Licence
