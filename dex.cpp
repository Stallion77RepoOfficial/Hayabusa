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

uint32_t DexParser::read_uleb128(const uint8_t *data, size_t max_len,
                                 size_t *bytes_read) {
  uint32_t result = 0;
  int shift = 0;
  size_t count = 0;
  uint8_t byte = 0;
  while (count < max_len) {
    byte = data[count];
    result |= (uint32_t)(byte & 0x7F) << shift;
    shift += 7;
    count++;
    if ((byte & 0x80) == 0) {
      if (bytes_read)
        *bytes_read = count;
      return result;
    }
    if (shift >= 32)
      break;
  }
  if (bytes_read)
    *bytes_read = 0;
  return result;
}

int32_t DexParser::read_sleb128(const uint8_t *data, size_t max_len,
                                size_t *bytes_read) {
  int32_t result = 0;
  int shift = 0;
  size_t count = 0;
  uint8_t byte = 0;
  while (count < max_len) {
    byte = data[count];
    result |= (int32_t)(byte & 0x7F) << shift;
    shift += 7;
    count++;
    if ((byte & 0x80) == 0) {
      if ((shift < 32) && (byte & 0x40))
        result |= -(1 << shift);
      if (bytes_read)
        *bytes_read = count;
      return result;
    }
    if (shift >= 32)
      break;
  }
  if (bytes_read)
    *bytes_read = 0;
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

uint32_t DexParser::calculate_adler32(const uint8_t *data, size_t len) {
  uint32_t a = 1, b = 0;
  for (size_t i = 0; i < len; i++) {
    a = (a + data[i]) % 65521;
    b = (b + a) % 65521;
  }
  return (b << 16) | a;
}

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

  if (data.size() > 32) {
    calculate_sha1(data.data() + 32, data.size() - 32, hdr->signature);
  }

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

        std::vector<uint8_t> vdex_buf(1024);
        if (ProcessTracer::read_memory(pid, addr, vdex_buf.data(), 1024)) {
          info.size = size;
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

      if (info.size < sizeof(DexHeader) || info.size > 256 * 1024 * 1024)
        continue;

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
  size_t chunk_size = 4096 * 16;
  std::vector<uint8_t> buf(chunk_size);

  for (uint64_t addr = start; addr < end; addr += chunk_size) {
    size_t to_read = std::min(chunk_size, (size_t)(end - addr));
    if (!ProcessTracer::read_memory(pid, addr, buf.data(), to_read))
      continue;

    for (size_t i = 0; i + 8 <= to_read; i++) {

      if (memcmp(buf.data() + i, DEX_MAGIC, 4) == 0) {
        results.push_back(addr + i);
      }

      else if (memcmp(buf.data() + i, CDEX_MAGIC, 4) == 0) {
        results.push_back(addr + i);
      }

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

  std::vector<uint32_t> string_data_offsets;
  if (chdr->string_ids_size > 0 && chdr->string_ids_off < cdex.size()) {
    const uint8_t *ptr = cdex.data() + chdr->string_ids_off;
    const uint8_t *end = cdex.data() + cdex.size();
    uint32_t current_offset = 0;

    for (uint32_t i = 0; i < chdr->string_ids_size && ptr < end; i++) {
      size_t bytes_read;
      uint32_t delta = read_uleb128(ptr, end - ptr, &bytes_read);
      if (bytes_read == 0)
        break;
      ptr += bytes_read;
      current_offset += delta;
      string_data_offsets.push_back(current_offset);
    }
  }

  uint32_t new_header_size = sizeof(DexHeader);

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

  data_off = (data_off + 3) & ~3;

  int32_t data_delta = (int32_t)data_off - (int32_t)chdr->data_off;

  uint32_t data_size = chdr->data_size;
  uint32_t file_size = data_off + data_size;

  std::vector<uint8_t> dex(file_size, 0);

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

  DexStringId *str_ids =
      reinterpret_cast<DexStringId *>(dex.data() + string_ids_off);
  for (uint32_t i = 0;
       i < chdr->string_ids_size && i < string_data_offsets.size(); i++) {

    uint32_t orig_off = string_data_offsets[i];
    if (orig_off >= chdr->data_off) {
      str_ids[i].string_data_off = orig_off + data_delta;
    } else {
      str_ids[i].string_data_off = orig_off;
    }
  }

  if (chdr->type_ids_size > 0 &&
      chdr->type_ids_off + type_ids_size <= cdex.size()) {
    memcpy(dex.data() + type_ids_off, cdex.data() + chdr->type_ids_off,
           type_ids_size);
  }

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

  if (chdr->field_ids_size > 0 &&
      chdr->field_ids_off + field_ids_size <= cdex.size()) {
    memcpy(dex.data() + field_ids_off, cdex.data() + chdr->field_ids_off,
           field_ids_size);
  }

  if (chdr->method_ids_size > 0 &&
      chdr->method_ids_off + method_ids_size <= cdex.size()) {
    memcpy(dex.data() + method_ids_off, cdex.data() + chdr->method_ids_off,
           method_ids_size);
  }

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

  if (chdr->data_off + data_size <= cdex.size()) {
    memcpy(dex.data() + data_off, cdex.data() + chdr->data_off, data_size);
  } else if (chdr->data_off < cdex.size()) {

    size_t available = cdex.size() - chdr->data_off;
    memcpy(dex.data() + data_off, cdex.data() + chdr->data_off, available);
  }

  if (hdr->map_off > 0 && hdr->map_off + 4 <= file_size) {
    uint32_t *map_size_ptr =
        reinterpret_cast<uint32_t *>(dex.data() + hdr->map_off);
    uint32_t map_count = *map_size_ptr;
    if (map_count < 100 &&
        hdr->map_off + 4 + map_count * sizeof(DexMapItem) <= file_size) {
      DexMapItem *items =
          reinterpret_cast<DexMapItem *>(dex.data() + hdr->map_off + 4);
      for (uint32_t i = 0; i < map_count; i++) {

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

          if (items[i].offset >= chdr->data_off) {
            items[i].offset += data_delta;
          }
          break;
        }
      }
    }
  }

  fix_checksum(dex);
  return dex;
}

std::vector<std::vector<uint8_t>>
DexParser::extract_dex_from_vdex(const std::vector<uint8_t> &vdex) {
  std::vector<std::vector<uint8_t>> dex_files;

  if (!is_vdex(vdex) || vdex.size() < 8)
    return dex_files;

  int vdex_version = 0;
  if (vdex[4] >= '0' && vdex[4] <= '9' && vdex[5] >= '0' && vdex[5] <= '9' &&
      vdex[6] >= '0' && vdex[6] <= '9') {
    vdex_version =
        (vdex[4] - '0') * 100 + (vdex[5] - '0') * 10 + (vdex[6] - '0');
  }

  size_t dex_section_start = 0;
  uint32_t num_dex_files = 0;

  // Dynamic VDEX header detection by probing structure sizes
  // Try headers from largest to smallest to find the correct format

  // Try VdexHeader_021 format (has number_of_sections field)
  if (vdex.size() >= sizeof(VdexHeader_021)) {
    const VdexHeader_021 *hdr =
        reinterpret_cast<const VdexHeader_021 *>(vdex.data());
    uint32_t num_sections = hdr->number_of_sections;

    // Validate: section count should be reasonable (1-10)
    if (num_sections >= 1 && num_sections <= 10) {
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
          break;
        }
      }
      if (dex_section_start > 0)
        goto found_dex_section;
    }
  }

  // Try VdexHeader_019 format (has number_of_dex_files directly)
  if (vdex.size() >= sizeof(VdexHeader_019)) {
    const VdexHeader_019 *hdr =
        reinterpret_cast<const VdexHeader_019 *>(vdex.data());
    num_dex_files = hdr->number_of_dex_files;

    // Validate: dex file count should be reasonable (1-100)
    if (num_dex_files >= 1 && num_dex_files <= 100) {
      size_t checksums_off = sizeof(VdexHeader_019);
      dex_section_start = checksums_off + num_dex_files * sizeof(uint32_t);
      dex_section_start = (dex_section_start + 3) & ~3;

      // Verify: check if DEX magic exists at this offset
      if (dex_section_start + 4 <= vdex.size() &&
          vdex[dex_section_start] == 'd' &&
          vdex[dex_section_start + 1] == 'e' &&
          vdex[dex_section_start + 2] == 'x') {
        goto found_dex_section;
      }
    }
  }

  // Try VdexHeader_006 format
  if (vdex.size() >= sizeof(VdexHeader_006)) {
    const VdexHeader_006 *hdr =
        reinterpret_cast<const VdexHeader_006 *>(vdex.data());
    num_dex_files = hdr->number_of_dex_files;

    if (num_dex_files >= 1 && num_dex_files <= 100) {
      size_t checksums_off = sizeof(VdexHeader_006);
      dex_section_start = checksums_off + num_dex_files * sizeof(uint32_t);
      dex_section_start = (dex_section_start + 3) & ~3;

      if (dex_section_start + 4 <= vdex.size() &&
          vdex[dex_section_start] == 'd' &&
          vdex[dex_section_start + 1] == 'e' &&
          vdex[dex_section_start + 2] == 'x') {
        goto found_dex_section;
      }
    }
  }

  // Fallback: scan for DEX magic
  dex_section_start = 16;

found_dex_section:

  for (size_t i = dex_section_start; i + sizeof(DexHeader) < vdex.size(); i++) {
    bool is_dex_magic = (memcmp(vdex.data() + i, DEX_MAGIC, 4) == 0);
    bool is_cdex_magic = (memcmp(vdex.data() + i, CDEX_MAGIC, 4) == 0);

    if (!is_dex_magic && !is_cdex_magic)
      continue;

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

    if (dex_size < sizeof(DexHeader) || dex_size > 256 * 1024 * 1024)
      continue;

    if (dex_size > vdex.size() - i)
      dex_size = vdex.size() - i;

    std::vector<uint8_t> dex(vdex.begin() + i, vdex.begin() + i + dex_size);

    if (is_cdex_magic) {
      dex = convert_compact_dex_to_dex(dex);
    }

    if (dex.size() >= sizeof(DexHeader)) {
      fix_checksum(dex);
      dex_files.push_back(dex);
    }

    i += dex_size - 1;

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

  size_t len_bytes;
  uint32_t len = read_uleb128(data.data() + string_off,
                              data.size() - string_off, &len_bytes);
  if (len_bytes == 0)
    return "";

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

    if (info.class_data_off > 0 && info.class_data_off < data.size()) {
      const uint8_t *class_data = data.data() + info.class_data_off;
      size_t remaining = data.size() - info.class_data_off;
      auto read_field = [&](uint32_t &out) -> bool {
        size_t bytes = 0;
        out = read_uleb128(class_data, remaining, &bytes);
        if (bytes == 0 || bytes > remaining)
          return false;
        class_data += bytes;
        remaining -= bytes;
        return true;
      };

      uint32_t static_fields = 0;
      uint32_t instance_fields = 0;
      if (read_field(static_fields) && read_field(instance_fields) &&
          read_field(info.direct_methods_count) &&
          read_field(info.virtual_methods_count)) {
        (void)static_fields;
        (void)instance_fields;
      } else {
        info.direct_methods_count = 0;
        info.virtual_methods_count = 0;
      }
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

std::vector<DexInfo> DexDumper::scan_dex_in_memory(int pid) {
  return DexParser::find_dex_in_memory(pid);
}

std::vector<uint8_t> DexDumper::dump_dex_file(int pid, const DexInfo &info) {
  std::vector<uint8_t> data =
      DexParser::dump_dex(pid, info.base_addr, info.size);

  if (data.empty())
    return data;

  if (info.is_compact || DexParser::is_compact_dex(data)) {
    data = DexParser::convert_compact_dex_to_dex(data);
  }

  if (info.is_vdex || DexParser::is_vdex(data)) {
    auto dex_files = DexParser::extract_dex_from_vdex(data);
    if (!dex_files.empty())
      return dex_files[0];
  }

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
    usleep(100000);
  }

  return false;
}

std::vector<uint8_t> DexDumper::dump_after_decrypt(int pid, uint64_t dex_addr,
                                                   size_t size) {

  usleep(500000);

  auto data = DexParser::dump_dex(pid, dex_addr, size);
  if (data.empty())
    return data;

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

  auto runtime = ARTHooker::find_art_runtime(pid);
  if (runtime.class_linker_addr == 0)
    return dex_objects;

  bool is64 = (ProcessTracer::get_arch() == ArchMode::ARM64);
  size_t ptr_size = is64 ? 8 : 4;
  int sdk = ARTHooker::get_sdk_version(pid);

  uint64_t libart_base = 0;
  auto ranges = ProcessTracer::get_library_ranges(pid);
  for (const auto &r : ranges) {
    if (r.name.find("libart.so") != std::string::npos) {
      libart_base = r.start;
      break;
    }
  }

  ARTOffsets offsets = ARTOffsetFinder::discover_offsets(
      pid, runtime.runtime_addr, libart_base, sdk);

  if (!offsets.valid) {
    return dex_objects;
  }

  uint64_t dex_caches_ptr = 0;
  ProcessTracer::read_memory(
      pid, runtime.class_linker_addr + offsets.classlinker_dex_caches,
      &dex_caches_ptr, ptr_size);

  if (dex_caches_ptr == 0)
    return dex_objects;

  uint64_t caches_data = 0;
  uint64_t caches_size = 0;
  ProcessTracer::read_memory(pid, dex_caches_ptr, &caches_data, ptr_size);
  ProcessTracer::read_memory(pid, dex_caches_ptr + ptr_size, &caches_size,
                             ptr_size);

  if (caches_data == 0 || caches_size == 0 || caches_size > 10000)
    return dex_objects;

  for (uint64_t i = 0; i < caches_size && dex_objects.size() < 1000; i++) {
    uint64_t cache_entry = 0;
    ProcessTracer::read_memory(pid, caches_data + i * ptr_size, &cache_entry,
                               ptr_size);

    if (cache_entry == 0 || cache_entry < 0x1000)
      continue;

    uint64_t dex_file = 0;
    ProcessTracer::read_memory(pid, cache_entry + offsets.dexcache_dex_file,
                               &dex_file, ptr_size);

    if (dex_file != 0 && dex_file > 0x1000) {

      uint64_t begin_ptr = 0;
      ProcessTracer::read_memory(pid, dex_file, &begin_ptr, ptr_size);

      if (begin_ptr != 0) {

        uint8_t magic[4];
        if (ProcessTracer::read_memory(pid, begin_ptr, magic, 4)) {
          if (memcmp(magic, "dex\n", 4) == 0 || memcmp(magic, "cdex", 4) == 0) {
            dex_objects.push_back(dex_file);
          }
        }
      }
    }
  }

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
