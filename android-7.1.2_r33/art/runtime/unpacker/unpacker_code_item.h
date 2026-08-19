#ifndef ART_RUNTIME_UNPACKER_CODE_ITEM_H_
#define ART_RUNTIME_UNPACKER_CODE_ITEM_H_

#include <stddef.h>
#include <stdint.h>

#include <vector>

namespace art {
namespace youpk_v1 {

namespace code_item_detail {

inline uint16_t ReadUint16(const uint8_t* data) {
  return static_cast<uint16_t>(data[0]) |
      static_cast<uint16_t>(data[1]) << 8;
}

inline uint32_t ReadUint32(const uint8_t* data) {
  return static_cast<uint32_t>(data[0]) |
      static_cast<uint32_t>(data[1]) << 8 |
      static_cast<uint32_t>(data[2]) << 16 |
      static_cast<uint32_t>(data[3]) << 24;
}

inline bool AddSize(size_t amount, size_t limit, size_t* size) {
  if (*size > limit || amount > limit - *size) {
    return false;
  }
  *size += amount;
  return true;
}

inline bool DecodeUnsignedLeb128(const uint8_t** cursor, const uint8_t* end,
                                 uint32_t* output) {
  uint32_t result = 0;
  for (uint32_t index = 0; index < 5; ++index) {
    if (*cursor == end) {
      return false;
    }
    uint8_t byte = *(*cursor)++;
    result |= static_cast<uint32_t>(byte & 0x7f) << (index * 7);
    if ((byte & 0x80) == 0 || index == 4) {
      *output = result;
      return true;
    }
  }
  return false;
}

inline bool DecodeSignedLeb128(const uint8_t** cursor, const uint8_t* end,
                               int32_t* output) {
  uint32_t result = 0;
  uint32_t shift = 0;
  for (uint32_t index = 0; index < 5; ++index) {
    if (*cursor == end) {
      return false;
    }
    uint8_t byte = *(*cursor)++;
    result |= static_cast<uint32_t>(byte & 0x7f) << shift;
    shift += 7;
    if ((byte & 0x80) == 0 || index == 4) {
      if (shift < 32 && (byte & 0x40) != 0) {
        result |= static_cast<uint32_t>(~0U) << shift;
      }
      *output = static_cast<int32_t>(result);
      return true;
    }
  }
  return false;
}

inline bool ContainsOffset(const std::vector<size_t>& offsets, uint16_t target) {
  for (size_t offset : offsets) {
    if (offset == target) {
      return true;
    }
  }
  return false;
}

}

inline bool MeasureCodeItemSize(const uint8_t* data, size_t available, size_t maximum,
                                size_t* output) {
  const size_t header_size = 16;
  const size_t try_item_size = 8;
  if (data == nullptr || output == nullptr) {
    return false;
  }
  size_t limit = available < maximum ? available : maximum;
  if (limit < header_size) {
    return false;
  }

  uint16_t tries_size = code_item_detail::ReadUint16(data + 6);
  uint32_t insns_size = code_item_detail::ReadUint32(data + 12);
  size_t size = header_size;
  if (insns_size > (limit - size) / sizeof(uint16_t) ||
      !code_item_detail::AddSize(static_cast<size_t>(insns_size) * sizeof(uint16_t),
                                limit, &size)) {
    return false;
  }
  if (tries_size == 0) {
    *output = size;
    return true;
  }
  if ((insns_size & 1U) != 0 && !code_item_detail::AddSize(sizeof(uint16_t), limit, &size)) {
    return false;
  }

  size_t tries_offset = size;
  if (tries_size > (limit - size) / try_item_size ||
      !code_item_detail::AddSize(static_cast<size_t>(tries_size) * try_item_size,
                                limit, &size)) {
    return false;
  }
  std::vector<uint16_t> referenced_handlers;
  referenced_handlers.reserve(tries_size);
  for (uint32_t index = 0; index < tries_size; ++index) {
    const uint8_t* try_item = data + tries_offset + index * try_item_size;
    uint32_t start_address = code_item_detail::ReadUint32(try_item);
    uint16_t instruction_count = code_item_detail::ReadUint16(try_item + 4);
    if (instruction_count == 0 || start_address > insns_size ||
        instruction_count > insns_size - start_address) {
      return false;
    }
    referenced_handlers.push_back(code_item_detail::ReadUint16(try_item + 6));
  }

  const uint8_t* handlers_begin = data + size;
  const uint8_t* cursor = handlers_begin;
  const uint8_t* end = data + limit;
  uint32_t handlers_size = 0;
  if (!code_item_detail::DecodeUnsignedLeb128(&cursor, end, &handlers_size) ||
      handlers_size == 0 || handlers_size > tries_size ||
      handlers_size > static_cast<size_t>(end - cursor)) {
    return false;
  }

  std::vector<size_t> handler_offsets;
  handler_offsets.reserve(handlers_size);
  for (uint32_t handler_index = 0; handler_index < handlers_size; ++handler_index) {
    handler_offsets.push_back(static_cast<size_t>(cursor - handlers_begin));
    int32_t encoded_count = 0;
    if (!code_item_detail::DecodeSignedLeb128(&cursor, end, &encoded_count) ||
        encoded_count == INT32_MIN) {
      return false;
    }
    uint32_t typed_count = encoded_count < 0
        ? static_cast<uint32_t>(-static_cast<int64_t>(encoded_count))
        : static_cast<uint32_t>(encoded_count);
    if (typed_count > static_cast<size_t>(end - cursor) / 2) {
      return false;
    }
    for (uint32_t item_index = 0; item_index < typed_count; ++item_index) {
      uint32_t type_index = 0;
      uint32_t handler_address = 0;
      if (!code_item_detail::DecodeUnsignedLeb128(&cursor, end, &type_index) ||
          !code_item_detail::DecodeUnsignedLeb128(&cursor, end, &handler_address) ||
          handler_address >= insns_size) {
        return false;
      }
    }
    if (encoded_count <= 0) {
      uint32_t catch_all_address = 0;
      if (!code_item_detail::DecodeUnsignedLeb128(&cursor, end, &catch_all_address) ||
          catch_all_address >= insns_size) {
        return false;
      }
    }
  }
  for (uint16_t handler_offset : referenced_handlers) {
    if (!code_item_detail::ContainsOffset(handler_offsets, handler_offset)) {
      return false;
    }
  }

  *output = static_cast<size_t>(cursor - data);
  return *output <= limit;
}

}
}

#endif
