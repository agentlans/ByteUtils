#include "ByteUtils.hpp"
#include <vector>
#include <iostream>

int main() {
  std::vector<uint8_t> data = {1, 2, 3, 4};
  std::string hex = to_hex(data);
  std::cout << "Hex: " << hex << "\n";
  
  std::string b64 = to_base64(data);
  std::cout << "Base64: " << b64 << "\n";
  std::vector<std::byte> b64_dec;
  from_base64(b64_dec, b64);
  std::cout << "Equal: " << std::boolalpha << equal(data, b64_dec) << "\n";
  
  std::vector<uint8_t> copy_data;
  copy(copy_data, data);
  std::cout << "Equal: " << std::boolalpha << equal(data, copy_data) << "\n";
  return 0;
}
