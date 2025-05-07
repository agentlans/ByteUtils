#ifndef _BYTEUTILS
#define _BYTEUTILS

/*
 * ByteUtils: Simple and efficient utilities for working with byte-oriented data
 * Copyright (C) 2025 Alan Tseng
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
 * SOFTWARE.
*/

#include <array>
#include <concepts>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

// --- Byte and Bytes Concepts ---

// Helper for C++20: remove_cvref_t
template <typename T>
using remove_cvref_t = std::remove_cv_t<std::remove_reference_t<T>>;

// Generalized Byte concept: any trivially copyable, 1-byte type.
template <typename T>
concept Byte = sizeof(T) == 1 && std::is_trivially_copyable_v<T>;

// Primary template: fallback (undefined)
template <typename T, typename = void>
struct element_type_helper; // No definition

// Specialization for arrays of unknown bound
template <typename T> struct element_type_helper<T[]> {
  using type = T;
};

// Specialization for arrays of known bound
template <typename T, std::size_t N> struct element_type_helper<T[N]> {
  using type = T;
};

// Specialization for types with .data()
template <typename T>
struct element_type_helper<T, std::void_t<decltype(std::declval<T>().data())>> {
  using type = remove_cvref_t<decltype(*std::declval<T>().data())>;
};

// Alias for element_type_helper
template <typename T>
using element_type_t = typename element_type_helper<T>::type;

// Generalized Bytes concept: containers or arrays of Byte
template <typename T>
concept Bytes =
    // Container with .data() and .size()
    (requires(T t) {
      { t.data() } -> std::convertible_to<const void *>;
      { t.size() } -> std::convertible_to<std::size_t>;
    } && Byte<element_type_t<T>>) ||
    // Or array of Byte
    (std::is_array_v<T> && Byte<element_type_t<T>>);

// Examples of types that satisfy the Bytes concept:
//
// - std::vector<std::byte>
// - std::vector<unsigned char>
// - std::vector<signed char>
// - std::vector<char>
// - std::vector<std::uint8_t>
// - std::vector<std::int8_t>
// - std::array<std::byte, N>
// - std::array<unsigned char, N>
// - std::array<signed char, N>
// - std::array<char, N>
// - std::array<std::uint8_t, N>
// - std::array<std::int8_t, N>
// - std::span<std::byte>
// - std::span<unsigned char>
// - std::span<signed char>
// - std::span<char>
// - std::span<std::uint8_t>
// - std::span<std::int8_t>
// - C-style arrays: std::byte[N], unsigned char[N], etc.
//

// --- Byte Container Traits ---

template <typename T> constexpr std::size_t bytes_size(const T &t) noexcept {
  if constexpr (requires { t.size(); }) {
    return t.size();
  } else {
    return std::extent_v<T>;
  }
}

// --- bytes_data ---

template <typename T> constexpr auto *bytes_data(T &t) noexcept {
  if constexpr (requires { t.data(); }) {
    return t.data();
  } else {
    return t;
  }
}

template <typename T> constexpr const auto *bytes_data(const T &t) noexcept {
  if constexpr (requires { t.data(); }) {
    return t.data();
  } else {
    return t;
  }
}

// --- has_resize_v ---

template <typename T>
constexpr bool has_resize_v = requires(T a, std::size_t n) { a.resize(n); };

// --- has_capacity_v ---

template <typename T, typename = void> constexpr bool has_capacity_v = false;

template <typename T>
constexpr bool
    has_capacity_v<T, std::void_t<decltype(std::declval<T>().capacity())>> =
        true;

// --- Copy Implementations ---

template <Bytes Dest, Bytes Src> void copy(Dest &dest, const Src &src) {
  assert(bytes_size(dest) == bytes_size(src));
  std::memcpy(static_cast<void *>(bytes_data(dest)),
              static_cast<const void *>(bytes_data(src)), bytes_size(dest));
}

template <Byte B, Bytes Src> void copy(std::vector<B> &dest, const Src &src) {
  auto n = bytes_size(src);
  dest.resize(n);
  std::memcpy(dest.data(), bytes_data(src), n);
}

// --- Test for Equality ---

template <Bytes T1, Bytes T2> bool equal(const T1 &a, const T2 &b) noexcept {
  auto n = bytes_size(a);
  if (n != bytes_size(b))
    return false;
  return std::memcmp(bytes_data(a), bytes_data(b), n) == 0;
}

// --- Compare Implementations ---

template <Bytes A, Bytes B> int compare(const A &a, const B &b) {
  auto n = bytes_size(a);
  if (n != bytes_size(b)) {
    throw std::invalid_argument("Byte container sizes do not match");
  }
  return std::memcmp(bytes_data(a), bytes_data(b), n);
}

// --- Input and output ---

// Concept to exclude std::string, std::string_view, char pointers, and char
// arrays
template <typename T>
concept NotStringOrCharArray =
    !std::same_as<std::decay_t<T>, std::string> &&
    !std::same_as<std::decay_t<T>, std::string_view> &&
    !(std::is_pointer_v<std::decay_t<T>> &&
      std::is_same_v<std::remove_cv_t<std::remove_pointer_t<std::decay_t<T>>>,
                     char>) &&
    !(std::is_array_v<T> &&
      std::is_same_v<std::remove_cv_t<std::remove_extent_t<T>>, char>);

template <Bytes T>
  requires NotStringOrCharArray<T>
std::ostream &operator<<(std::ostream &os, const T &t) {
  const auto *data = bytes_data(t);
  const auto size = bytes_size(t);
  if (data && size > 0) {
    os.write(reinterpret_cast<const char *>(data),
             static_cast<std::streamsize>(size));
    if (!os)
      os.setstate(std::ios::failbit);
  }
  return os;
}

template <Bytes T>
  requires NotStringOrCharArray<T>
std::istream &operator>>(std::istream &is, T &t) {
  auto *data = bytes_data(t);

  if constexpr (has_resize_v<T>) {
    size_t max_bytes = 0;
    if constexpr (has_capacity_v<T>)
      max_bytes = t.capacity();
    else if constexpr (requires { t.max_size(); })
      max_bytes = t.max_size();
    else if constexpr (requires { t.size(); })
      max_bytes = t.size();
    else
      max_bytes = 1024;

    if (!data || max_bytes == 0) {
      is.setstate(std::ios::failbit);
      return is;
    }

    t.resize(max_bytes);
    is.read(reinterpret_cast<char *>(data),
            static_cast<std::streamsize>(max_bytes));
    const auto read =
        static_cast<size_t>(std::max<std::streamsize>(is.gcount(), 0));
    t.resize(read);

    if (read == 0 || !is)
      is.setstate(std::ios::failbit);

  } else {
    const auto size = bytes_size(t);
    if (!data || size == 0) {
      is.setstate(std::ios::failbit);
      return is;
    }
    is.read(reinterpret_cast<char *>(data), static_cast<std::streamsize>(size));
    if (!is)
      is.setstate(std::ios::failbit);
  }
  return is;
}

// Utilities for hex and base64 conversion

// Hex character table (lowercase)
constexpr char hex_chars[] = "0123456789abcdef";

// Convert nibble (4 bits) to hex character
constexpr char nibble_to_hex(uint8_t n) noexcept { return hex_chars[n & 0xF]; }

// Convert hex character to nibble (throws on invalid input)
constexpr uint8_t hex_to_nibble(char c) {
  if ('0' <= c && c <= '9')
    return c - '0';
  if ('a' <= c && c <= 'f')
    return c - 'a' + 10;
  if ('A' <= c && c <= 'F')
    return c - 'A' + 10;
  throw std::invalid_argument("Invalid hex character");
}

// Encode a container of bytes to a hex string
template <typename Bytes> std::string to_hex(const Bytes &data) {
  std::string out;
  out.reserve(data.size() * 2);
  for (auto byte : data) {
    uint8_t b = static_cast<uint8_t>(byte);
    out.push_back(nibble_to_hex(b >> 4));
    out.push_back(nibble_to_hex(b & 0xF));
  }
  return out;
}

// Decode a hex string into a container of bytes
template <typename Bytes> void from_hex(Bytes &data, const std::string &hex) {
  if (hex.size() % 2 != 0)
    throw std::invalid_argument("Hex length must be even");
  size_t n = hex.size() / 2;
  if constexpr (has_resize_v<Bytes>) {
    data.resize(n);
  } else if (data.size() != n) {
    throw std::length_error("Size mismatch");
  }
  for (size_t i = 0; i < n; ++i) {
    data[i] = static_cast<typename Bytes::value_type>(
        (hex_to_nibble(hex[2 * i]) << 4) | hex_to_nibble(hex[2 * i + 1]));
  }
}

// Base64 alphabets
constexpr char BASE64_STD_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr char BASE64_URL_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Selects the appropriate alphabet
constexpr const char *get_base64_alphabet(bool url) {
  return url ? BASE64_URL_ALPHABET : BASE64_STD_ALPHABET;
}

// Encoded length calculation
constexpr size_t base64_encoded_length(size_t input_length) {
  return 4 * ((input_length + 2) / 3);
}

// Decoded length calculation
inline int base64_decoded_length(const std::string &input, bool url) {
  size_t len = input.size(), pad = 0;
  if (len % 4) {
    if (!url)
      return -1;         // Invalid padding for standard base64
    pad = 4 - (len % 4); // URL-safe: pad to multiple of 4
  } else {
    if (len && input[len - 1] == '=')
      pad++;
    if (len > 1 && input[len - 2] == '=')
      pad++;
  }
  return ((len + pad) / 4) * 3 - pad;
}

// Base64 encoding
template <typename Bytes>
std::string to_base64(const Bytes &data, bool url = false) {
  const char *alphabet = get_base64_alphabet(url);
  size_t n = data.size();
  std::string out(base64_encoded_length(n), '\0');
  size_t i = 0, j = 0;

  auto get_byte = [&](size_t idx) -> uint8_t {
    if constexpr (std::is_same_v<typename Bytes::value_type, std::byte>)
      return std::to_integer<uint8_t>(data[idx]);
    else
      return static_cast<uint8_t>(data[idx]);
  };

  while (i < n) {
    uint32_t v = (i < n ? get_byte(i++) : 0) << 16;
    v |= (i < n ? get_byte(i++) : 0) << 8;
    v |= (i < n ? get_byte(i++) : 0);

    out[j++] = alphabet[(v >> 18) & 0x3F];
    out[j++] = alphabet[(v >> 12) & 0x3F];
    out[j++] = alphabet[(v >> 6) & 0x3F];
    out[j++] = alphabet[v & 0x3F];
  }

  if (!url) {
    if (n % 3 == 1)
      out[out.size() - 2] = out[out.size() - 1] = '=';
    else if (n % 3 == 2)
      out[out.size() - 1] = '=';
  } else {
    size_t pad = n % 3 == 1 ? 2 : (n % 3 == 2 ? 1 : 0);
    out.resize(out.size() - pad); // URL-safe: no '=' padding
  }
  return out;
}

// Base64 decoding
template <typename Bytes>
void from_base64(Bytes &data, const std::string &b64, bool url = false) {
  int dec_len = base64_decoded_length(b64, url);
  if (dec_len < 0)
    throw std::invalid_argument("Invalid base64 input length");

  if constexpr (has_resize_v<Bytes>)
    data.resize(dec_len);
  else if (data.size() != static_cast<size_t>(dec_len))
    throw std::length_error("Output container size mismatch");

  // Build decoding table
  std::array<uint8_t, 256> decode_table{};
  const char *alphabet = get_base64_alphabet(url);
  for (int i = 0; i < 64; ++i)
    decode_table[static_cast<uint8_t>(alphabet[i])] = i;

  size_t i = 0, j = 0, n = b64.size();
  while (i < n && j < static_cast<size_t>(dec_len)) {
    uint32_t s1 = (i < n && b64[i] != '=')
                      ? decode_table[static_cast<uint8_t>(b64[i++])]
                      : 0;
    uint32_t s2 = (i < n && b64[i] != '=')
                      ? decode_table[static_cast<uint8_t>(b64[i++])]
                      : 0;
    uint32_t s3 = (i < n && b64[i] != '=')
                      ? decode_table[static_cast<uint8_t>(b64[i++])]
                      : 0;
    uint32_t s4 = (i < n && b64[i] != '=')
                      ? decode_table[static_cast<uint8_t>(b64[i++])]
                      : 0;
    uint32_t v = (s1 << 18) | (s2 << 12) | (s3 << 6) | s4;

    auto set_byte = [&](uint32_t x) {
      if constexpr (std::is_same_v<typename Bytes::value_type, std::byte>)
        return static_cast<std::byte>(x);
      else
        return static_cast<typename Bytes::value_type>(x);
    };

    if (j < static_cast<size_t>(dec_len))
      data[j++] = set_byte((v >> 16) & 0xFF);
    if (j < static_cast<size_t>(dec_len))
      data[j++] = set_byte((v >> 8) & 0xFF);
    if (j < static_cast<size_t>(dec_len))
      data[j++] = set_byte(v & 0xFF);
  }
}

#endif
