#pragma once
#include <cstdint>
#include <string>
#include <vector>


static const uint8_t DEX_MAGIC[] = {'d', 'e', 'x', '\n'};
static const uint8_t CDEX_MAGIC[] = {'c', 'd', 'e', 'x'};
static const uint8_t VDEX_MAGIC[] = {'v', 'd', 'e', 'x'};
static const uint8_t OAT_MAGIC[] = {'o', 'a', 't', '\n'};


static const uint8_t DEX_VERSION_035[] = {'0', '3', '5', '\0'};
static const uint8_t DEX_VERSION_037[] = {'0', '3', '7', '\0'};
static const uint8_t DEX_VERSION_038[] = {'0', '3', '8', '\0'};
static const uint8_t DEX_VERSION_039[] = {'0', '3', '9', '\0'};
static const uint8_t DEX_VERSION_040[] = {'0', '4', '0', '\0'};


static const uint8_t CDEX_VERSION_001[] = {'0', '0', '1', '\0'};
static const uint8_t CDEX_VERSION_002[] = {'0', '0', '2', '\0'};

#pragma pack(push, 1)

struct DexHeader {
  uint8_t magic[8];
  uint32_t checksum;
  uint8_t signature[20];
  uint32_t file_size;
  uint32_t header_size;
  uint32_t endian_tag;
  uint32_t link_size;
  uint32_t link_off;
  uint32_t map_off;
  uint32_t string_ids_size;
  uint32_t string_ids_off;
  uint32_t type_ids_size;
  uint32_t type_ids_off;
  uint32_t proto_ids_size;
  uint32_t proto_ids_off;
  uint32_t field_ids_size;
  uint32_t field_ids_off;
  uint32_t method_ids_size;
  uint32_t method_ids_off;
  uint32_t class_defs_size;
  uint32_t class_defs_off;
  uint32_t data_size;
  uint32_t data_off;
};

struct CompactDexHeader {
  uint8_t magic[8];
  uint32_t checksum;
  uint8_t signature[20];
  uint32_t file_size;
  uint32_t header_size;
  uint32_t endian_tag;
  uint32_t link_size;
  uint32_t link_off;
  uint32_t map_off;
  uint32_t string_ids_size;
  uint32_t string_ids_off;
  uint32_t type_ids_size;
  uint32_t type_ids_off;
  uint32_t proto_ids_size;
  uint32_t proto_ids_off;
  uint32_t field_ids_size;
  uint32_t field_ids_off;
  uint32_t method_ids_size;
  uint32_t method_ids_off;
  uint32_t class_defs_size;
  uint32_t class_defs_off;
  uint32_t data_size;
  uint32_t data_off;
  uint32_t feature_flags;
  uint32_t debug_info_offsets_pos;
  uint32_t debug_info_offsets_table_offset;
  uint32_t debug_info_base;
  uint32_t owned_data_begin;
  uint32_t owned_data_end;
};


struct VdexHeader_006 {
  uint8_t magic[4];
  uint8_t vdex_version[4];
  uint32_t number_of_dex_files;
  uint32_t dex_size;
  uint32_t verifier_deps_size;
  uint32_t quickening_info_size;
};


struct VdexHeader_019 {
  uint8_t magic[4];
  uint8_t vdex_version[4];
  uint32_t number_of_dex_files;
  uint32_t verifier_deps_size;
};


struct VdexHeader_021 {
  uint8_t magic[4];
  uint8_t vdex_version[4];
  uint32_t number_of_sections;
};


struct VdexHeader_027 {
  uint8_t magic[4];
  uint8_t vdex_version[4];
  uint32_t number_of_dex_files;
  uint32_t verifier_deps_size;
  uint32_t bootclasspath_checksums_size;
  uint32_t class_loader_context_size;
};


struct VdexHeader {
  uint8_t magic[4];
  uint8_t vdex_version[4];
  uint32_t number_of_dex_files;
  uint32_t verifier_deps_size;
  uint32_t bootclasspath_checksums_size;
  uint32_t class_loader_context_size;
};


struct VdexSectionHeader {
  uint32_t section_kind;
  uint32_t section_offset;
  uint32_t section_size;
};


enum VdexSectionKind {
  kVdexSectionChecksum = 0,
  kVdexSectionDexFile = 1,
  kVdexSectionVerifierDeps = 2,
  kVdexSectionTypeLookupTable = 3,
  kVdexSectionNumberOfSections = 4,
};


struct VdexDexFileHeader {
  uint32_t dex_checksum;
  uint32_t dex_offset;
};


struct QuickeningInfoHeader {
  uint32_t quickening_info_size;
};

struct OatHeader {
  uint8_t magic[4];
  uint8_t version[4];
  uint32_t adler32_checksum;
  uint32_t instruction_set;
  uint32_t instruction_set_features_bitmap;
  uint32_t dex_file_count;
  uint32_t oat_dex_files_offset;
  uint32_t executable_offset;
  uint32_t jni_dlsym_lookup_trampoline_offset;
  uint32_t jni_dlsym_lookup_critical_trampoline_offset;
  uint32_t quick_generic_jni_trampoline_offset;
  uint32_t quick_imt_conflict_trampoline_offset;
  uint32_t quick_resolution_trampoline_offset;
  uint32_t quick_to_interpreter_bridge_offset;
  uint32_t key_value_store_size;
};

struct DexStringId {
  uint32_t string_data_off;
};

struct DexTypeId {
  uint32_t descriptor_idx;
};

struct DexFieldId {
  uint16_t class_idx;
  uint16_t type_idx;
  uint32_t name_idx;
};

struct DexMethodId {
  uint16_t class_idx;
  uint16_t proto_idx;
  uint32_t name_idx;
};

struct DexProtoId {
  uint32_t shorty_idx;
  uint32_t return_type_idx;
  uint32_t parameters_off;
};

struct DexClassDef {
  uint32_t class_idx;
  uint32_t access_flags;
  uint32_t superclass_idx;
  uint32_t interfaces_off;
  uint32_t source_file_idx;
  uint32_t annotations_off;
  uint32_t class_data_off;
  uint32_t static_values_off;
};

struct DexMapItem {
  uint16_t type;
  uint16_t unused;
  uint32_t size;
  uint32_t offset;
};

struct DexMapList {
  uint32_t size;
  DexMapItem list[1];
};

#pragma pack(pop)


enum DexMapItemType {
  kDexTypeHeaderItem = 0x0000,
  kDexTypeStringIdItem = 0x0001,
  kDexTypeTypeIdItem = 0x0002,
  kDexTypeProtoIdItem = 0x0003,
  kDexTypeFieldIdItem = 0x0004,
  kDexTypeMethodIdItem = 0x0005,
  kDexTypeClassDefItem = 0x0006,
  kDexTypeCallSiteIdItem = 0x0007,
  kDexTypeMethodHandleItem = 0x0008,
  kDexTypeMapList = 0x1000,
  kDexTypeTypeList = 0x1001,
  kDexTypeAnnotationSetRefList = 0x1002,
  kDexTypeAnnotationSetItem = 0x1003,
  kDexTypeClassDataItem = 0x2000,
  kDexTypeCodeItem = 0x2001,
  kDexTypeStringDataItem = 0x2002,
  kDexTypeDebugInfoItem = 0x2003,
  kDexTypeAnnotationItem = 0x2004,
  kDexTypeEncodedArrayItem = 0x2005,
  kDexTypeAnnotationsDirectoryItem = 0x2006,
  kDexTypeHiddenapiClassData = 0xF000,
};


enum DexAccessFlags {
  kAccPublic = 0x0001,
  kAccPrivate = 0x0002,
  kAccProtected = 0x0004,
  kAccStatic = 0x0008,
  kAccFinal = 0x0010,
  kAccSynchronized = 0x0020,
  kAccSuper = 0x0020,
  kAccVolatile = 0x0040,
  kAccBridge = 0x0040,
  kAccTransient = 0x0080,
  kAccVarargs = 0x0080,
  kAccNative = 0x0100,
  kAccInterface = 0x0200,
  kAccAbstract = 0x0400,
  kAccStrict = 0x0800,
  kAccSynthetic = 0x1000,
  kAccAnnotation = 0x2000,
  kAccEnum = 0x4000,
  kAccConstructor = 0x10000,
  kAccDeclaredSynchronized = 0x20000,
};

struct DexInfo {
  uint64_t base_addr;
  size_t size;
  std::string location;
  bool is_compact;
  bool is_vdex;
  bool is_oat;
  uint32_t checksum;
  std::string version;
};

struct DexClassInfo {
  std::string class_name;
  uint32_t access_flags;
  std::string super_class;
  uint32_t class_data_off;
  uint32_t direct_methods_count;
  uint32_t virtual_methods_count;
};

struct DexMethodInfo {
  std::string class_name;
  std::string method_name;
  std::string signature;
  std::string shorty;
  uint32_t access_flags;
  uint32_t code_off;
  size_t code_size;
  size_t register_count;
  size_t ins_count;
  size_t outs_count;
};

class DexParser {
public:
  
  static bool is_dex(const std::vector<uint8_t> &data);
  static bool is_compact_dex(const std::vector<uint8_t> &data);
  static bool is_vdex(const std::vector<uint8_t> &data);
  static bool is_oat(const std::vector<uint8_t> &data);
  static std::string get_dex_version(const std::vector<uint8_t> &data);

  
  static std::vector<DexInfo> find_dex_in_memory(int pid);
  static std::vector<uint64_t> scan_for_dex_magic(int pid, uint64_t start,
                                                  uint64_t end);

  
  static std::vector<uint8_t> dump_dex(int pid, uint64_t addr, size_t size);
  static std::vector<uint8_t> dump_dex_by_header(int pid, uint64_t addr);

  
  static std::vector<uint8_t>
  convert_compact_dex_to_dex(const std::vector<uint8_t> &cdex);
  static std::vector<std::vector<uint8_t>>
  extract_dex_from_vdex(const std::vector<uint8_t> &vdex);
  static std::vector<std::vector<uint8_t>>
  extract_dex_from_oat(const std::vector<uint8_t> &oat);

  
  static std::vector<uint8_t> repair_dex(const std::vector<uint8_t> &data);
  static uint32_t calculate_adler32(const uint8_t *data, size_t len);
  static void calculate_sha1(const uint8_t *data, size_t len, uint8_t *out);
  static bool fix_checksum(std::vector<uint8_t> &data);

  
  static std::vector<DexClassInfo>
  get_classes(const std::vector<uint8_t> &data);
  static std::vector<DexMethodInfo>
  get_methods(const std::vector<uint8_t> &data, const std::string &class_name);
  static std::vector<std::string> get_strings(const std::vector<uint8_t> &data);
  static std::string get_string_by_idx(const std::vector<uint8_t> &data,
                                       uint32_t idx);
  static std::string get_type_by_idx(const std::vector<uint8_t> &data,
                                     uint32_t idx);

  
  static uint32_t read_uleb128(const uint8_t *data, size_t max_len,
                               size_t *bytes_read);
  static int32_t read_sleb128(const uint8_t *data, size_t max_len,
                              size_t *bytes_read);
};

class DexDumper {
public:
  
  static std::vector<DexInfo> scan_dex_in_memory(int pid);
  static std::vector<uint8_t> dump_dex_file(int pid, const DexInfo &info);
  static int dump_all_dex(int pid, const std::string &output_dir);

  
  static bool wait_for_dex_load(int pid, const std::string &dex_name,
                                int timeout_sec);
  static std::vector<uint8_t> dump_after_decrypt(int pid, uint64_t dex_addr,
                                                 size_t size);
  static std::vector<uint8_t> dump_from_class_loader(int pid,
                                                     uint64_t class_loader);

  
  static std::vector<std::string> find_vdex_files(int pid);
  static std::vector<std::string> find_oat_files(int pid);
  static int dump_vdex_dex(int pid, const std::string &vdex_path,
                           const std::string &output_dir);
  static int dump_oat_dex(int pid, const std::string &oat_path,
                          const std::string &output_dir);

  
  static std::vector<uint64_t> find_dex_file_objects(int pid);
  static uint64_t find_class_linker(int pid);
  static std::vector<uint64_t> get_boot_class_path_dex(int pid);
};
