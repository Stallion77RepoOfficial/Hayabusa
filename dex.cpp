#include "dex.h"
#include "tracer.h"
#include <algorithm>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>

// ULEB128 decoding
uint32_t DexParser::read_uleb128(const uint8_t *data, size_t *bytes_read) {
  uint32_t result = 0;
  int shift = 0;
  size_t count = 0;
  uint8_t byte;
  do {
    byte = data[count];
    result |= (uint32_t)(byte & 0x7F) << shift;
    shift += 7;
    count++;
  } while (byte & 0x80);
  if (bytes_read)
    *bytes_read = count;
  return result;
}

int32_t DexParser::read_sleb128(const uint8_t *data, size_t *bytes_read) {
  int32_t result = 0;
  int shift = 0;
  size_t count = 0;
  uint8_t byte;
  do {
    byte = data[count];
    result |= (int32_t)(byte & 0x7F) << shift;
    shift += 7;
    count++;
  } while (byte & 0x80);
  if ((shift < 32) && (byte & 0x40))
    result |= -(1 << shift);
  if (bytes_read)
    *bytes_read = count;
  return result;
}

bool DexParser::is_dex(const std::vector<uint8_t> &data) {
  if (data.size() < sizeof(DexHeader))
    return false;
  if (memcmp(data.data(), DEX_MAGIC, 4) != 0)
    return false;
  const DexHeader *hdr = reinterpret_cast<const DexHeader *>(data.data());
  if (hdr->file_size > data.size() * 2)
    return false;
  if (hdr->header_size < 0x70)
    return false;
  return true;
}

bool DexParser::is_compact_dex(const std::vector<uint8_t> &data) {
  if (data.size() < sizeof(CompactDexHeader))
    return false;
  return memcmp(data.data(), CDEX_MAGIC, 4) == 0;
}

bool DexParser::is_vdex(const std::vector<uint8_t> &data) {
  if (data.size() < sizeof(VdexHeader))
    return false;
  return memcmp(data.data(), VDEX_MAGIC, 4) == 0;
}

bool DexParser::is_oat(const std::vector<uint8_t> &data) {
  if (data.size() < sizeof(OatHeader))
    return false;
  return memcmp(data.data(), OAT_MAGIC, 4) == 0;
}

std::string DexParser::get_dex_version(const std::vector<uint8_t> &data) {
  if (data.size() < 8)
    return "";
  char ver[4] = {0};
  memcpy(ver, data.data() + 4, 3);
  return std::string(ver);
}

// Adler32 checksum calculation
uint32_t DexParser::calculate_adler32(const uint8_t *data, size_t len) {
  uint32_t a = 1, b = 0;
  for (size_t i = 0; i < len; i++) {
    a = (a + data[i]) % 65521;
    b = (b + a) % 65521;
  }
  return (b << 16) | a;
}

// Simple SHA1 implementation
void DexParser::calculate_sha1(const uint8_t *data, size_t len, uint8_t *out) {
  uint32_t h0 = 0x67452301;
  uint32_t h1 = 0xEFCDAB89;
  uint32_t h2 = 0x98BADCFE;
  uint32_t h3 = 0x10325476;
  uint32_t h4 = 0xC3D2E1F0;

  size_t new_len = len + 1;
  while (new_len % 64 != 56)
    new_len++;
  new_len += 8;

  std::vector<uint8_t> msg(new_len, 0);
  memcpy(msg.data(), data, len);
  msg[len] = 0x80;
  uint64_t bits = (uint64_t)len * 8;
  for (int i = 0; i < 8; i++)
    msg[new_len - 1 - i] = (bits >> (i * 8)) & 0xFF;

  for (size_t chunk = 0; chunk < new_len; chunk += 64) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
      w[i] = ((uint32_t)msg[chunk + i * 4] << 24) |
             ((uint32_t)msg[chunk + i * 4 + 1] << 16) |
             ((uint32_t)msg[chunk + i * 4 + 2] << 8) |
             ((uint32_t)msg[chunk + i * 4 + 3]);
    }
    for (int i = 16; i < 80; i++) {
      uint32_t tmp = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
      w[i] = (tmp << 1) | (tmp >> 31);
    }

    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
    for (int i = 0; i < 80; i++) {
      uint32_t f, k;
      if (i < 20) {
        f = (b & c) | ((~b) & d);
        k = 0x5A827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }
      uint32_t tmp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
      e = d;
      d = c;
      c = (b << 30) | (b >> 2);
      b = a;
      a = tmp;
    }
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
  }

  for (int i = 0; i < 4; i++) {
    out[i] = (h0 >> (24 - i * 8)) & 0xFF;
    out[4 + i] = (h1 >> (24 - i * 8)) & 0xFF;
    out[8 + i] = (h2 >> (24 - i * 8)) & 0xFF;
    out[12 + i] = (h3 >> (24 - i * 8)) & 0xFF;
    out[16 + i] = (h4 >> (24 - i * 8)) & 0xFF;
  }
}

bool DexParser::fix_checksum(std::vector<uint8_t> &data) {
  if (data.size() < sizeof(DexHeader))
    return false;

  DexHeader *hdr = reinterpret_cast<DexHeader *>(data.data());

  // Calculate and set signature (SHA1 of data after signature)
  if (data.size() > 32) {
    calculate_sha1(data.data() + 32, data.size() - 32, hdr->signature);
  }

  // Calculate and set checksum (Adler32 of data after checksum field)
  if (data.size() > 12) {
    hdr->checksum = calculate_adler32(data.data() + 12, data.size() - 12);
  }

  return true;
}

std::vector<uint8_t> DexParser::repair_dex(const std::vector<uint8_t> &data) {
  std::vector<uint8_t> result = data;

  if (!is_dex(result) && !is_compact_dex(result))
    return result;

  fix_checksum(result);
  return result;
}

std::vector<DexInfo> DexParser::find_dex_in_memory(int pid) {
  std::vector<DexInfo> dex_files;

  std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
  if (!maps)
    return dex_files;

  std::string line;
  while (std::getline(maps, line)) {
    // Look for dalvik, app, or dex regions
    bool is_dex_region = false;
    if (line.find("dalvik") != std::string::npos ||
        line.find("/data/app") != std::string::npos ||
        line.find("/data/dalvik") != std::string::npos ||
        line.find(".dex") != std::string::npos ||
        line.find(".vdex") != std::string::npos ||
        line.find(".odex") != std::string::npos ||
        line.find(".oat") != std::string::npos ||
        line.find("[anon:dalvik") != std::string::npos) {
      is_dex_region = true;
    }

    // Only scan readable regions
    if (line.find("r-") == std::string::npos &&
        line.find("r--") == std::string::npos)
      continue;

    uint64_t start, end;
    if (sscanf(line.c_str(), "%lx-%lx", (unsigned long *)&start,
               (unsigned long *)&end) != 2)
      continue;

    size_t size = end - start;
    if (size < sizeof(DexHeader) || size > 512 * 1024 * 1024)
      continue;

    // Scan for DEX magic in this region
    auto addrs = scan_for_dex_magic(pid, start, end);
    for (uint64_t addr : addrs) {
      std::vector<uint8_t> header_buf(sizeof(DexHeader));
      if (!ProcessTracer::read_memory(pid, addr, header_buf.data(),
                                      sizeof(DexHeader)))
        continue;

      DexInfo info;
      info.base_addr = addr;
      info.is_compact = is_compact_dex(header_buf);
      info.is_vdex = is_vdex(header_buf);
      info.is_oat = is_oat(header_buf);

      if (info.is_compact) {
        const CompactDexHeader *hdr =
            reinterpret_cast<const CompactDexHeader *>(header_buf.data());
        info.size = hdr->file_size;
        info.checksum = hdr->checksum;
      } else if (info.is_vdex) {
        // Read more for VDEX
        std::vector<uint8_t> vdex_buf(1024);
        if (ProcessTracer::read_memory(pid, addr, vdex_buf.data(), 1024)) {
          info.size = size; // Use region size for VDEX
        }
      } else if (is_dex(header_buf)) {
        const DexHeader *hdr =
            reinterpret_cast<const DexHeader *>(header_buf.data());
        info.size = hdr->file_size;
        info.checksum = hdr->checksum;
        info.version = get_dex_version(header_buf);
      } else {
        continue;
      }

      // Validate size
      if (info.size < sizeof(DexHeader) || info.size > 256 * 1024 * 1024)
        continue;

      // Extract location from maps line
      size_t path_pos = line.find('/');
      if (path_pos != std::string::npos) {
        info.location = line.substr(path_pos);
        size_t space_pos = info.location.find(' ');
        if (space_pos != std::string::npos)
          info.location = info.location.substr(0, space_pos);
      }

      dex_files.push_back(info);
    }
  }

  return dex_files;
}

std::vector<uint64_t> DexParser::scan_for_dex_magic(int pid, uint64_t start,
                                                    uint64_t end) {
  std::vector<uint64_t> results;
  size_t chunk_size = 4096 * 16; // 64KB chunks
  std::vector<uint8_t> buf(chunk_size);

  for (uint64_t addr = start; addr < end; addr += chunk_size) {
    size_t to_read = std::min(chunk_size, (size_t)(end - addr));
    if (!ProcessTracer::read_memory(pid, addr, buf.data(), to_read))
      continue;

    for (size_t i = 0; i + 8 <= to_read; i++) {
      // Check for DEX magic
      if (memcmp(buf.data() + i, DEX_MAGIC, 4) == 0) {
        results.push_back(addr + i);
      }
      // Check for CompactDex magic
      else if (memcmp(buf.data() + i, CDEX_MAGIC, 4) == 0) {
        results.push_back(addr + i);
      }
      // Check for VDEX magic
      else if (memcmp(buf.data() + i, VDEX_MAGIC, 4) == 0) {
        results.push_back(addr + i);
      }
    }
  }

  return results;
}

std::vector<uint8_t> DexParser::dump_dex(int pid, uint64_t addr, size_t size) {
  std::vector<uint8_t> data(size);
  if (!ProcessTracer::read_memory(pid, addr, data.data(), size))
    return {};
  return data;
}

std::vector<uint8_t> DexParser::dump_dex_by_header(int pid, uint64_t addr) {
  // Read header first
  std::vector<uint8_t> header_buf(sizeof(DexHeader));
  if (!ProcessTracer::read_memory(pid, addr, header_buf.data(),
                                  sizeof(DexHeader)))
    return {};

  size_t dex_size = 0;
  if (is_compact_dex(header_buf)) {
    const CompactDexHeader *hdr =
        reinterpret_cast<const CompactDexHeader *>(header_buf.data());
    dex_size = hdr->file_size;
  } else if (is_dex(header_buf)) {
    const DexHeader *hdr =
        reinterpret_cast<const DexHeader *>(header_buf.data());
    dex_size = hdr->file_size;
  } else {
    return {};
  }

  if (dex_size < sizeof(DexHeader) || dex_size > 256 * 1024 * 1024)
    return {};

  return dump_dex(pid, addr, dex_size);
}

std::vector<uint8_t>
DexParser::convert_compact_dex_to_dex(const std::vector<uint8_t> &cdex) {
  if (!is_compact_dex(cdex))
    return cdex;

  const CompactDexHeader *chdr =
      reinterpret_cast<const CompactDexHeader *>(cdex.data());

  // CDEX uses different encoding - need to convert properly:
  // 1. String IDs use ULEB128 delta encoding (not absolute offsets)
  // 2. All offsets need adjustment after conversion
  // 3. Data section must be copied with offset adjustments

  // First, decode all string ID deltas to get absolute offsets
  std::vector<uint32_t> string_data_offsets;
  if (chdr->string_ids_size > 0 && chdr->string_ids_off < cdex.size()) {
    const uint8_t *ptr = cdex.data() + chdr->string_ids_off;
    const uint8_t *end = cdex.data() + cdex.size();
    uint32_t current_offset = 0;

    for (uint32_t i = 0; i < chdr->string_ids_size && ptr < end; i++) {
      size_t bytes_read;
      uint32_t delta = read_uleb128(ptr, &bytes_read);
      ptr += bytes_read;
      current_offset += delta;
      string_data_offsets.push_back(current_offset);
    }
  }

  // Calculate new DEX layout
  // Standard DEX structure: Header | String IDs | Type IDs | Proto IDs | Field
  // IDs | Method IDs | Class Defs | Data

  uint32_t new_header_size = sizeof(DexHeader);

  // Calculate where each section will go
  uint32_t string_ids_off = new_header_size;
  uint32_t string_ids_size = chdr->string_ids_size * sizeof(DexStringId);

  uint32_t type_ids_off = string_ids_off + string_ids_size;
  uint32_t type_ids_size = chdr->type_ids_size * sizeof(DexTypeId);

  uint32_t proto_ids_off = type_ids_off + type_ids_size;
  uint32_t proto_ids_size = chdr->proto_ids_size * sizeof(DexProtoId);

  uint32_t field_ids_off = proto_ids_off + proto_ids_size;
  uint32_t field_ids_size = chdr->field_ids_size * sizeof(DexFieldId);

  uint32_t method_ids_off = field_ids_off + field_ids_size;
  uint32_t method_ids_size = chdr->method_ids_size * sizeof(DexMethodId);

  uint32_t class_defs_off = method_ids_off + method_ids_size;
  uint32_t class_defs_size = chdr->class_defs_size * sizeof(DexClassDef);

  uint32_t data_off = class_defs_off + class_defs_size;
  // Align data section to 4 bytes
  data_off = (data_off + 3) & ~3;

  // Calculate offset delta for data section
  // In CDEX, data starts at chdr->data_off
  // In new DEX, data starts at data_off
  int32_t data_delta = (int32_t)data_off - (int32_t)chdr->data_off;

  // Calculate total size
  uint32_t data_size = chdr->data_size;
  uint32_t file_size = data_off + data_size;

  // Allocate output buffer
  std::vector<uint8_t> dex(file_size, 0);

  // Build DEX header
  DexHeader *hdr = reinterpret_cast<DexHeader *>(dex.data());
  memcpy(hdr->magic, "dex\n039\0", 8);
  hdr->header_size = 0x70;
  hdr->endian_tag = chdr->endian_tag;
  hdr->link_size = chdr->link_size;
  hdr->link_off = chdr->link_off > 0 ? chdr->link_off + data_delta : 0;
  hdr->map_off = chdr->map_off > 0 ? chdr->map_off + data_delta : 0;
  hdr->string_ids_size = chdr->string_ids_size;
  hdr->string_ids_off = string_ids_off;
  hdr->type_ids_size = chdr->type_ids_size;
  hdr->type_ids_off = type_ids_off;
  hdr->proto_ids_size = chdr->proto_ids_size;
  hdr->proto_ids_off = proto_ids_off;
  hdr->field_ids_size = chdr->field_ids_size;
  hdr->field_ids_off = field_ids_off;
  hdr->method_ids_size = chdr->method_ids_size;
  hdr->method_ids_off = method_ids_off;
  hdr->class_defs_size = chdr->class_defs_size;
  hdr->class_defs_off = class_defs_off;
  hdr->data_size = data_size;
  hdr->data_off = data_off;
  hdr->file_size = file_size;

  // Convert string IDs from delta to absolute format
  DexStringId *str_ids =
      reinterpret_cast<DexStringId *>(dex.data() + string_ids_off);
  for (uint32_t i = 0;
       i < chdr->string_ids_size && i < string_data_offsets.size(); i++) {
    // Adjust offset from CDEX data section to new DEX data section
    uint32_t orig_off = string_data_offsets[i];
    if (orig_off >= chdr->data_off) {
      str_ids[i].string_data_off = orig_off + data_delta;
    } else {
      str_ids[i].string_data_off = orig_off;
    }
  }

  // Copy Type IDs (straight copy, no offset adjustment needed - they're
  // indices)
  if (chdr->type_ids_size > 0 &&
      chdr->type_ids_off + type_ids_size <= cdex.size()) {
    memcpy(dex.data() + type_ids_off, cdex.data() + chdr->type_ids_off,
           type_ids_size);
  }

  // Copy Proto IDs (need to adjust parameters_off)
  if (chdr->proto_ids_size > 0 &&
      chdr->proto_ids_off + proto_ids_size <= cdex.size()) {
    memcpy(dex.data() + proto_ids_off, cdex.data() + chdr->proto_ids_off,
           proto_ids_size);
    DexProtoId *protos =
        reinterpret_cast<DexProtoId *>(dex.data() + proto_ids_off);
    for (uint32_t i = 0; i < chdr->proto_ids_size; i++) {
      if (protos[i].parameters_off >= chdr->data_off) {
        protos[i].parameters_off += data_delta;
      }
    }
  }

  // Copy Field IDs (straight copy - only indices)
  if (chdr->field_ids_size > 0 &&
      chdr->field_ids_off + field_ids_size <= cdex.size()) {
    memcpy(dex.data() + field_ids_off, cdex.data() + chdr->field_ids_off,
           field_ids_size);
  }

  // Copy Method IDs (straight copy - only indices)
  if (chdr->method_ids_size > 0 &&
      chdr->method_ids_off + method_ids_size <= cdex.size()) {
    memcpy(dex.data() + method_ids_off, cdex.data() + chdr->method_ids_off,
           method_ids_size);
  }

  // Copy Class Defs (need to adjust multiple offsets)
  if (chdr->class_defs_size > 0 &&
      chdr->class_defs_off + class_defs_size <= cdex.size()) {
    memcpy(dex.data() + class_defs_off, cdex.data() + chdr->class_defs_off,
           class_defs_size);
    DexClassDef *classes =
        reinterpret_cast<DexClassDef *>(dex.data() + class_defs_off);
    for (uint32_t i = 0; i < chdr->class_defs_size; i++) {
      if (classes[i].interfaces_off >= chdr->data_off &&
          classes[i].interfaces_off != 0) {
        classes[i].interfaces_off += data_delta;
      }
      if (classes[i].annotations_off >= chdr->data_off &&
          classes[i].annotations_off != 0) {
        classes[i].annotations_off += data_delta;
      }
      if (classes[i].class_data_off >= chdr->data_off &&
          classes[i].class_data_off != 0) {
        classes[i].class_data_off += data_delta;
      }
      if (classes[i].static_values_off >= chdr->data_off &&
          classes[i].static_values_off != 0) {
        classes[i].static_values_off += data_delta;
      }
    }
  }

  // Copy data section
  if (chdr->data_off + data_size <= cdex.size()) {
    memcpy(dex.data() + data_off, cdex.data() + chdr->data_off, data_size);
  } else if (chdr->data_off < cdex.size()) {
    // Partial copy if data_size is larger than remaining file
    size_t available = cdex.size() - chdr->data_off;
    memcpy(dex.data() + data_off, cdex.data() + chdr->data_off, available);
  }

  // Fix map_list offsets if present
  if (hdr->map_off > 0 && hdr->map_off + 4 <= file_size) {
    uint32_t *map_size_ptr =
        reinterpret_cast<uint32_t *>(dex.data() + hdr->map_off);
    uint32_t map_count = *map_size_ptr;
    if (map_count < 100 &&
        hdr->map_off + 4 + map_count * sizeof(DexMapItem) <= file_size) {
      DexMapItem *items =
          reinterpret_cast<DexMapItem *>(dex.data() + hdr->map_off + 4);
      for (uint32_t i = 0; i < map_count; i++) {
        // Adjust offsets in map items
        switch (items[i].type) {
        case kDexTypeHeaderItem:
          items[i].offset = 0;
          break;
        case kDexTypeStringIdItem:
          items[i].offset = string_ids_off;
          break;
        case kDexTypeTypeIdItem:
          items[i].offset = type_ids_off;
          break;
        case kDexTypeProtoIdItem:
          items[i].offset = proto_ids_off;
          break;
        case kDexTypeFieldIdItem:
          items[i].offset = field_ids_off;
          break;
        case kDexTypeMethodIdItem:
          items[i].offset = method_ids_off;
          break;
        case kDexTypeClassDefItem:
          items[i].offset = class_defs_off;
          break;
        default:
          // Data section items
          if (items[i].offset >= chdr->data_off) {
            items[i].offset += data_delta;
          }
          break;
        }
      }
    }
  }

  // Fix checksums
  fix_checksum(dex);
  return dex;
}

std::vector<std::vector<uint8_t>>
DexParser::extract_dex_from_vdex(const std::vector<uint8_t> &vdex) {
  std::vector<std::vector<uint8_t>> dex_files;

  if (!is_vdex(vdex) || vdex.size() < 8)
    return dex_files;

  // Parse VDEX version to determine format
  // Version format: "XXX\0" where XXX is 3 digits
  int vdex_version = 0;
  if (vdex[4] >= '0' && vdex[4] <= '9' && vdex[5] >= '0' && vdex[5] <= '9' &&
      vdex[6] >= '0' && vdex[6] <= '9') {
    vdex_version =
        (vdex[4] - '0') * 100 + (vdex[5] - '0') * 10 + (vdex[6] - '0');
  }

  size_t dex_section_start = 0;
  uint32_t num_dex_files = 0;

  // Version-specific header parsing
  if (vdex_version >= 21) {
    // Android 11+ (v021-v027+) uses section-based format
    if (vdex.size() < sizeof(VdexHeader_021))
      return dex_files;

    const VdexHeader_021 *hdr =
        reinterpret_cast<const VdexHeader_021 *>(vdex.data());
    uint32_t num_sections = hdr->number_of_sections;

    if (num_sections > 10)
      num_sections = 10; // Sanity check

    // Read section headers
    size_t section_headers_off = sizeof(VdexHeader_021);
    for (uint32_t i = 0;
         i < num_sections &&
         section_headers_off + sizeof(VdexSectionHeader) <= vdex.size();
         i++) {
      const VdexSectionHeader *sec =
          reinterpret_cast<const VdexSectionHeader *>(
              vdex.data() + section_headers_off +
              i * sizeof(VdexSectionHeader));

      if (sec->section_kind == kVdexSectionDexFile) {
        dex_section_start = sec->section_offset;
        // In v021+ the DEX section contains multiple DEX files
        // We need to scan for magics within this section
        break;
      }
    }
  } else if (vdex_version >= 19) {
    // Android 10 (v019-v020)
    if (vdex.size() < sizeof(VdexHeader_019))
      return dex_files;

    const VdexHeader_019 *hdr =
        reinterpret_cast<const VdexHeader_019 *>(vdex.data());
    num_dex_files = hdr->number_of_dex_files;

    // DEX checksums follow the header
    size_t checksums_off = sizeof(VdexHeader_019);
    // DEX files start after checksums
    dex_section_start = checksums_off + num_dex_files * sizeof(uint32_t);
    // Align to 4 bytes
    dex_section_start = (dex_section_start + 3) & ~3;
  } else if (vdex_version >= 6) {
    // Android 8-9 (v006-v018)
    if (vdex.size() < sizeof(VdexHeader_006))
      return dex_files;

    const VdexHeader_006 *hdr =
        reinterpret_cast<const VdexHeader_006 *>(vdex.data());
    num_dex_files = hdr->number_of_dex_files;

    // DEX checksums follow the header
    size_t checksums_off = sizeof(VdexHeader_006);
    // DEX files start after checksums
    dex_section_start = checksums_off + num_dex_files * sizeof(uint32_t);
    // Align to 4 bytes
    dex_section_start = (dex_section_start + 3) & ~3;
  } else {
    // Unknown version, fall back to magic scan
    dex_section_start = 16;
  }

  // Scan for DEX/CDEX magics starting from dex_section_start
  for (size_t i = dex_section_start; i + sizeof(DexHeader) < vdex.size(); i++) {
    bool is_dex_magic = (memcmp(vdex.data() + i, DEX_MAGIC, 4) == 0);
    bool is_cdex_magic = (memcmp(vdex.data() + i, CDEX_MAGIC, 4) == 0);

    if (!is_dex_magic && !is_cdex_magic)
      continue;

    // Read DEX header to get size
    std::vector<uint8_t> dex_buf(vdex.begin() + i, vdex.end());

    size_t dex_size = 0;
    if (is_cdex_magic && dex_buf.size() >= sizeof(CompactDexHeader)) {
      const CompactDexHeader *dhdr =
          reinterpret_cast<const CompactDexHeader *>(dex_buf.data());
      dex_size = dhdr->file_size;
    } else if (is_dex_magic && dex_buf.size() >= sizeof(DexHeader)) {
      const DexHeader *dhdr =
          reinterpret_cast<const DexHeader *>(dex_buf.data());
      dex_size = dhdr->file_size;
    }

    // Validate size
    if (dex_size < sizeof(DexHeader) || dex_size > 256 * 1024 * 1024)
      continue;

    if (dex_size > vdex.size() - i)
      dex_size = vdex.size() - i; // Truncate to available

    // Extract DEX
    std::vector<uint8_t> dex(vdex.begin() + i, vdex.begin() + i + dex_size);

    // Convert CompactDex if needed
    if (is_cdex_magic) {
      dex = convert_compact_dex_to_dex(dex);
    }

    // Verify and fix checksum
    if (dex.size() >= sizeof(DexHeader)) {
      fix_checksum(dex);
      dex_files.push_back(dex);
    }

    // Skip past this DEX
    i += dex_size - 1;

    // Stop if we've found expected number of DEX files
    if (num_dex_files > 0 && dex_files.size() >= num_dex_files)
      break;
  }

  return dex_files;
}

std::vector<std::vector<uint8_t>>
DexParser::extract_dex_from_oat(const std::vector<uint8_t> &oat) {
  std::vector<std::vector<uint8_t>> dex_files;

  if (!is_oat(oat))
    return dex_files;

  // Scan for DEX magics within OAT
  for (size_t i = sizeof(OatHeader); i + sizeof(DexHeader) < oat.size(); i++) {
    if (memcmp(oat.data() + i, DEX_MAGIC, 4) == 0) {
      const DexHeader *dhdr =
          reinterpret_cast<const DexHeader *>(oat.data() + i);
      size_t dex_size = dhdr->file_size;

      if (dex_size > 0 && dex_size <= oat.size() - i) {
        std::vector<uint8_t> dex(oat.begin() + i, oat.begin() + i + dex_size);
        fix_checksum(dex);
        dex_files.push_back(dex);
        i += dex_size - 1;
      }
    }
  }

  return dex_files;
}

std::string DexParser::get_string_by_idx(const std::vector<uint8_t> &data,
                                         uint32_t idx) {
  if (!is_dex(data) && !is_compact_dex(data))
    return "";

  const DexHeader *hdr = reinterpret_cast<const DexHeader *>(data.data());

  if (idx >= hdr->string_ids_size)
    return "";

  uint32_t string_ids_off = hdr->string_ids_off;
  if (string_ids_off + (idx + 1) * sizeof(DexStringId) > data.size())
    return "";

  const DexStringId *string_ids =
      reinterpret_cast<const DexStringId *>(data.data() + string_ids_off);
  uint32_t string_off = string_ids[idx].string_data_off;

  if (string_off >= data.size())
    return "";

  // Read ULEB128 length
  size_t len_bytes;
  uint32_t len = read_uleb128(data.data() + string_off, &len_bytes);

  if (string_off + len_bytes + len > data.size())
    return "";

  return std::string((const char *)data.data() + string_off + len_bytes, len);
}

std::string DexParser::get_type_by_idx(const std::vector<uint8_t> &data,
                                       uint32_t idx) {
  if (!is_dex(data) && !is_compact_dex(data))
    return "";

  const DexHeader *hdr = reinterpret_cast<const DexHeader *>(data.data());

  if (idx >= hdr->type_ids_size)
    return "";

  uint32_t type_ids_off = hdr->type_ids_off;
  if (type_ids_off + (idx + 1) * sizeof(DexTypeId) > data.size())
    return "";

  const DexTypeId *type_ids =
      reinterpret_cast<const DexTypeId *>(data.data() + type_ids_off);

  return get_string_by_idx(data, type_ids[idx].descriptor_idx);
}

std::vector<DexClassInfo>
DexParser::get_classes(const std::vector<uint8_t> &data) {
  std::vector<DexClassInfo> classes;

  if (!is_dex(data) && !is_compact_dex(data))
    return classes;

  const DexHeader *hdr = reinterpret_cast<const DexHeader *>(data.data());

  if (hdr->class_defs_off + hdr->class_defs_size * sizeof(DexClassDef) >
      data.size())
    return classes;

  const DexClassDef *class_defs =
      reinterpret_cast<const DexClassDef *>(data.data() + hdr->class_defs_off);

  for (uint32_t i = 0; i < hdr->class_defs_size; i++) {
    DexClassInfo info;
    info.class_name = get_type_by_idx(data, class_defs[i].class_idx);
    info.access_flags = class_defs[i].access_flags;
    info.super_class = get_type_by_idx(data, class_defs[i].superclass_idx);
    info.class_data_off = class_defs[i].class_data_off;

    // Parse class data for method counts
    if (info.class_data_off > 0 && info.class_data_off < data.size()) {
      const uint8_t *class_data = data.data() + info.class_data_off;
      size_t bytes;
      uint32_t static_fields = read_uleb128(class_data, &bytes);
      class_data += bytes;
      uint32_t instance_fields = read_uleb128(class_data, &bytes);
      class_data += bytes;
      info.direct_methods_count = read_uleb128(class_data, &bytes);
      class_data += bytes;
      info.virtual_methods_count = read_uleb128(class_data, &bytes);
    }

    classes.push_back(info);
  }

  return classes;
}

std::vector<std::string>
DexParser::get_strings(const std::vector<uint8_t> &data) {
  std::vector<std::string> strings;

  if (!is_dex(data) && !is_compact_dex(data))
    return strings;

  const DexHeader *hdr = reinterpret_cast<const DexHeader *>(data.data());

  for (uint32_t i = 0; i < hdr->string_ids_size; i++) {
    std::string s = get_string_by_idx(data, i);
    if (!s.empty())
      strings.push_back(s);
  }

  return strings;
}

// DexDumper implementation

std::vector<DexInfo> DexDumper::scan_dex_in_memory(int pid) {
  return DexParser::find_dex_in_memory(pid);
}

std::vector<uint8_t> DexDumper::dump_dex_file(int pid, const DexInfo &info) {
  std::vector<uint8_t> data =
      DexParser::dump_dex(pid, info.base_addr, info.size);

  if (data.empty())
    return data;

  // Convert CompactDex to standard DEX
  if (info.is_compact || DexParser::is_compact_dex(data)) {
    data = DexParser::convert_compact_dex_to_dex(data);
  }

  // Extract from VDEX container
  if (info.is_vdex || DexParser::is_vdex(data)) {
    auto dex_files = DexParser::extract_dex_from_vdex(data);
    if (!dex_files.empty())
      return dex_files[0]; // Return first DEX
  }

  // Repair checksum
  DexParser::fix_checksum(data);

  return data;
}

int DexDumper::dump_all_dex(int pid, const std::string &output_dir) {
  auto dex_files = scan_dex_in_memory(pid);
  int count = 0;

  for (size_t i = 0; i < dex_files.size(); i++) {
    auto data = dump_dex_file(pid, dex_files[i]);
    if (data.empty())
      continue;

    // If VDEX, might have multiple DEX files
    if (dex_files[i].is_vdex) {
      auto vdex_data =
          DexParser::dump_dex(pid, dex_files[i].base_addr, dex_files[i].size);
      auto extracted = DexParser::extract_dex_from_vdex(vdex_data);
      for (size_t j = 0; j < extracted.size(); j++) {
        std::string filename =
            output_dir + "/classes_" + std::to_string(count++) + ".dex";
        std::ofstream f(filename, std::ios::binary);
        if (f) {
          f.write((char *)extracted[j].data(), extracted[j].size());
        }
      }
    } else {
      std::string filename =
          output_dir + "/classes_" + std::to_string(count++) + ".dex";
      std::ofstream f(filename, std::ios::binary);
      if (f) {
        f.write((char *)data.data(), data.size());
      }
    }
  }

  return count;
}

bool DexDumper::wait_for_dex_load(int pid, const std::string &dex_name,
                                  int timeout_sec) {
  time_t start = time(nullptr);

  while (time(nullptr) - start < timeout_sec) {
    auto dex_files = scan_dex_in_memory(pid);
    for (const auto &dex : dex_files) {
      if (dex.location.find(dex_name) != std::string::npos)
        return true;
    }
    usleep(100000); // 100ms
  }

  return false;
}

std::vector<uint8_t> DexDumper::dump_after_decrypt(int pid, uint64_t dex_addr,
                                                   size_t size) {
  // Wait a bit for decryption to complete
  usleep(500000); // 500ms

  auto data = DexParser::dump_dex(pid, dex_addr, size);
  if (data.empty())
    return data;

  // Repair and return
  return DexParser::repair_dex(data);
}

std::vector<std::string> DexDumper::find_vdex_files(int pid) {
  std::vector<std::string> vdex_files;

  std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
  std::string line;

  while (std::getline(maps, line)) {
    if (line.find(".vdex") != std::string::npos) {
      size_t path_pos = line.find('/');
      if (path_pos != std::string::npos) {
        std::string path = line.substr(path_pos);
        size_t space_pos = path.find(' ');
        if (space_pos != std::string::npos)
          path = path.substr(0, space_pos);

        // Avoid duplicates
        if (std::find(vdex_files.begin(), vdex_files.end(), path) ==
            vdex_files.end()) {
          vdex_files.push_back(path);
        }
      }
    }
  }

  return vdex_files;
}

std::vector<std::string> DexDumper::find_oat_files(int pid) {
  std::vector<std::string> oat_files;

  std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
  std::string line;

  while (std::getline(maps, line)) {
    if (line.find(".oat") != std::string::npos ||
        line.find(".odex") != std::string::npos) {
      size_t path_pos = line.find('/');
      if (path_pos != std::string::npos) {
        std::string path = line.substr(path_pos);
        size_t space_pos = path.find(' ');
        if (space_pos != std::string::npos)
          path = path.substr(0, space_pos);

        if (std::find(oat_files.begin(), oat_files.end(), path) ==
            oat_files.end()) {
          oat_files.push_back(path);
        }
      }
    }
  }

  return oat_files;
}

std::vector<uint64_t> DexDumper::find_dex_file_objects(int pid) {
  std::vector<uint64_t> dex_objects;

  // Use ARTHooker to find runtime and ClassLinker
  auto runtime = ARTHooker::find_art_runtime(pid);
  if (runtime.class_linker_addr == 0)
    return dex_objects;

  bool is64 = (ProcessTracer::get_arch() == ArchMode::ARM64);
  size_t ptr_size = is64 ? 8 : 4;
  int sdk = ARTHooker::get_sdk_version(pid);

  // Find libart.so base for offset discovery
  uint64_t libart_base = 0;
  auto ranges = ProcessTracer::get_library_ranges(pid);
  for (const auto &r : ranges) {
    if (r.name.find("libart.so") != std::string::npos) {
      libart_base = r.start;
      break;
    }
  }

  // Get offsets dynamically or from config/fallback
  ARTOffsets offsets = ARTOffsetFinder::discover_offsets(
      pid, runtime.runtime_addr, libart_base, sdk);

  if (!offsets.valid) {
    // If discovery failed completely, we can't proceed safely
    // But we can try fallback again just in case discover_offsets didn't return
    // them on failure (it should)
    offsets = ARTOffsetFinder::get_fallback_offsets(sdk, is64);
  }

  // Read dex_caches_
  uint64_t dex_caches_ptr = 0;
  ProcessTracer::read_memory(
      pid, runtime.class_linker_addr + offsets.classlinker_dex_caches,
      &dex_caches_ptr, ptr_size);

  if (dex_caches_ptr == 0)
    return dex_objects;

  // dex_caches_ is typically a std::list or std::vector of GcRoot<DexCache>
  // Read the size and iterate
  uint64_t caches_data = 0;
  uint64_t caches_size = 0;
  ProcessTracer::read_memory(pid, dex_caches_ptr, &caches_data, ptr_size);
  ProcessTracer::read_memory(pid, dex_caches_ptr + ptr_size, &caches_size,
                             ptr_size);

  if (caches_data == 0 || caches_size == 0 || caches_size > 10000)
    return dex_objects;

  // Iterate through DexCache entries
  for (uint64_t i = 0; i < caches_size && dex_objects.size() < 1000; i++) {
    uint64_t cache_entry = 0;
    ProcessTracer::read_memory(pid, caches_data + i * ptr_size, &cache_entry,
                               ptr_size);

    if (cache_entry == 0 || cache_entry < 0x1000)
      continue;

    // DexCache has dex_file_ pointer
    uint64_t dex_file = 0;
    ProcessTracer::read_memory(pid, cache_entry + offsets.dexcache_dex_file,
                               &dex_file, ptr_size);

    if (dex_file != 0 && dex_file > 0x1000) {
      // Validate it looks like a DexFile by reading header pointer
      // DexFile has begin_ pointer to dex header at offset 0
      uint64_t begin_ptr = 0;
      ProcessTracer::read_memory(pid, dex_file, &begin_ptr, ptr_size);

      if (begin_ptr != 0) {
        // Check for DEX magic at begin_
        uint8_t magic[4];
        if (ProcessTracer::read_memory(pid, begin_ptr, magic, 4)) {
          if (memcmp(magic, "dex\n", 4) == 0 || memcmp(magic, "cdex", 4) == 0) {
            dex_objects.push_back(dex_file);
          }
        }
      }
    }
  }

  // Also scan boot class path for additional DexFiles
  uint64_t bcp_ptr = 0;
  ProcessTracer::read_memory(
      pid, runtime.class_linker_addr + offsets.classlinker_boot_class_path,
      &bcp_ptr, ptr_size);

  if (bcp_ptr != 0) {
    uint64_t bcp_data = 0;
    uint64_t bcp_size = 0;
    ProcessTracer::read_memory(pid, bcp_ptr, &bcp_data, ptr_size);
    ProcessTracer::read_memory(pid, bcp_ptr + ptr_size, &bcp_size, ptr_size);

    for (uint64_t i = 0; i < bcp_size && i < 100; i++) {
      uint64_t dex_file = 0;
      ProcessTracer::read_memory(pid, bcp_data + i * ptr_size, &dex_file,
                                 ptr_size);
      if (dex_file != 0 && dex_file > 0x1000) {
        dex_objects.push_back(dex_file);
      }
    }
  }

  return dex_objects;
}
