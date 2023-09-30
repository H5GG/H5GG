/* ldid - (Mach-O) Link-Loader Identity Editor
 * Copyright (C) 2007-2015  Jay Freeman (saurik)
*/

/* GNU Affero General Public License, Version 3 {{{ */
/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
**/
/* }}} */

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-variable"

#define LDID_NOSMIME
#define LDID_NOPLIST
#define LDID_VERSION ""

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef LDID_NOSMIME
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#endif

#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>

#define LDID_SHA1_DIGEST_LENGTH CC_SHA1_DIGEST_LENGTH
#define LDID_SHA1 CC_SHA1
#define LDID_SHA1_CTX CC_SHA1_CTX
#define LDID_SHA1_Init CC_SHA1_Init
#define LDID_SHA1_Update CC_SHA1_Update
#define LDID_SHA1_Final CC_SHA1_Final

#define LDID_SHA256_DIGEST_LENGTH CC_SHA256_DIGEST_LENGTH
#define LDID_SHA256 CC_SHA256
#define LDID_SHA256_CTX CC_SHA256_CTX
#define LDID_SHA256_Init CC_SHA256_Init
#define LDID_SHA256_Update CC_SHA256_Update
#define LDID_SHA256_Final CC_SHA256_Final
#else
#include <openssl/sha.h>

#define LDID_SHA1_DIGEST_LENGTH SHA_DIGEST_LENGTH
#define LDID_SHA1 SHA1
#define LDID_SHA1_CTX SHA_CTX
#define LDID_SHA1_Init SHA1_Init
#define LDID_SHA1_Update SHA1_Update
#define LDID_SHA1_Final SHA1_Final

#define LDID_SHA256_DIGEST_LENGTH SHA256_DIGEST_LENGTH
#define LDID_SHA256 SHA256
#define LDID_SHA256_CTX SHA256_CTX
#define LDID_SHA256_Init SHA256_Init
#define LDID_SHA256_Update SHA256_Update
#define LDID_SHA256_Final SHA256_Final
#endif

#ifndef LDID_NOPLIST
#include <plist/plist.h>
#elif __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#endif

#include "ldid.hpp"

#define _assert___(line) \
    #line
#define _assert__(line) \
    _assert___(line)

#ifndef $
#define $(value) value
#endif

#ifdef __EXCEPTIONS
#define _assert_(expr, format, ...) \
    do if (!(expr)) { \
        fprintf(stderr, $("%s(%u): _assert(): " format "\n"), __FILE__, __LINE__, ## __VA_ARGS__); \
        throw $(__FILE__ "(" _assert__(__LINE__) "): _assert(" #expr ")"); \
    } while (false)
#else
// XXX: this is not acceptable
#define _assert_(expr, format, ...) \
    do if (!(expr)) { \
        fprintf(stderr, $("%s(%u): _assert(): " format "\n"), __FILE__, __LINE__, ## __VA_ARGS__); \
        exit(-1); \
    } while (false)
#endif

#define _assert(expr) \
    _assert_(expr, "%s", $(#expr))

#define _syscall(expr, ...) [&] { for (;;) { \
    auto _value(expr); \
    if ((long) _value != -1) \
        return _value; \
    int error(errno); \
    if (error == EINTR) \
        continue; \
    /* XXX: EINTR is included in this list to fix g++ */ \
    for (auto success : (long[]) {EINTR, __VA_ARGS__}) \
        if (error == success) \
            return (decltype(expr)) -success; \
    _assert_(false, "errno=%u", error); \
} }()

#define _trace() \
    fprintf(stderr, $("_trace(%s:%u): %s\n"), __FILE__, __LINE__, $(__FUNCTION__))

#define _not(type) \
    ((type) ~ (type) 0)

#define _packed \
    __attribute__((packed))

template <typename Type_>
struct Iterator_ {
    typedef typename Type_::const_iterator Result;
};

#define _foreach(item, list) \
    for (bool _stop(true); _stop; ) \
        for (const __typeof__(list) &_list = (list); _stop; _stop = false) \
            for (Iterator_<__typeof__(list)>::Result _item = _list.begin(); _item != _list.end(); ++_item) \
                for (bool _suck(true); _suck; _suck = false) \
                    for (const __typeof__(*_item) &item = *_item; _suck; _suck = false)

class _Scope {
};

template <typename Function_>
class Scope :
    public _Scope
{
  private:
    Function_ function_;

  public:
    Scope(const Function_ &function) :
        function_(function)
    {
    }

    ~Scope() {
        function_();
    }
};

template <typename Function_>
Scope<Function_> _scope(const Function_ &function) {
    return Scope<Function_>(function);
}

#define _scope__(counter, function) \
    __attribute__((__unused__)) \
    const _Scope &_scope ## counter(_scope([&]function))
#define _scope_(counter, function) \
    _scope__(counter, function)
#define _scope(function) \
    _scope_(__COUNTER__, function)

#define CPU_ARCH_MASK  uint32_t(0xff000000)
#define CPU_ARCH_ABI64 uint32_t(0x01000000)

#define CPU_TYPE_ANY     uint32_t(-1)
#define CPU_TYPE_VAX     uint32_t( 1)
#define CPU_TYPE_MC680x0 uint32_t( 6)
#define CPU_TYPE_X86     uint32_t( 7)
#define CPU_TYPE_MC98000 uint32_t(10)
#define CPU_TYPE_HPPA    uint32_t(11)
#define CPU_TYPE_ARM     uint32_t(12)
#define CPU_TYPE_MC88000 uint32_t(13)
#define CPU_TYPE_SPARC   uint32_t(14)
#define CPU_TYPE_I860    uint32_t(15)
#define CPU_TYPE_POWERPC uint32_t(18)

#define CPU_TYPE_I386 CPU_TYPE_X86

#define CPU_TYPE_ARM64     (CPU_ARCH_ABI64 | CPU_TYPE_ARM)
#define CPU_TYPE_POWERPC64 (CPU_ARCH_ABI64 | CPU_TYPE_POWERPC)
#define CPU_TYPE_X86_64    (CPU_ARCH_ABI64 | CPU_TYPE_X86)

struct fat_header {
    uint32_t magic;
    uint32_t nfat_arch;
} _packed;

#define FAT_MAGIC 0xcafebabe
#define FAT_CIGAM 0xbebafeca

struct fat_arch {
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
} _packed;

struct mach_header {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
} _packed;

#define MH_MAGIC 0xfeedface
#define MH_CIGAM 0xcefaedfe

#define MH_MAGIC_64 0xfeedfacf
#define MH_CIGAM_64 0xcffaedfe

#define MH_DYLDLINK   0x4

#define MH_OBJECT     0x1
#define MH_EXECUTE    0x2
#define MH_DYLIB      0x6
#define MH_DYLINKER   0x7
#define MH_BUNDLE     0x8
#define MH_DYLIB_STUB 0x9

struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
} _packed;

#define LC_REQ_DYLD           uint32_t(0x80000000)

#define LC_SEGMENT            uint32_t(0x01)
#define LC_SYMTAB             uint32_t(0x02)
#define LC_DYSYMTAB           uint32_t(0x0b)
#define LC_LOAD_DYLIB         uint32_t(0x0c)
#define LC_ID_DYLIB           uint32_t(0x0d)
#define LC_SEGMENT_64         uint32_t(0x19)
#define LC_UUID               uint32_t(0x1b)
#define LC_CODE_SIGNATURE     uint32_t(0x1d)
#define LC_SEGMENT_SPLIT_INFO uint32_t(0x1e)
#define LC_REEXPORT_DYLIB     uint32_t(0x1f | LC_REQ_DYLD)
#define LC_ENCRYPTION_INFO    uint32_t(0x21)
#define LC_DYLD_INFO          uint32_t(0x22)
#define LC_DYLD_INFO_ONLY     uint32_t(0x22 | LC_REQ_DYLD)
#define LC_ENCRYPTION_INFO_64 uint32_t(0x2c)

union Version {
    struct {
        uint8_t patch;
        uint8_t minor;
        uint16_t major;
    } _packed;

    uint32_t value;
};

struct dylib {
    uint32_t name;
    uint32_t timestamp;
    uint32_t current_version;
    uint32_t compatibility_version;
} _packed;

struct dylib_command {
    uint32_t cmd;
    uint32_t cmdsize;
    struct dylib dylib;
} _packed;

struct uuid_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint8_t uuid[16];
} _packed;

struct symtab_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
} _packed;

struct dyld_info_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t rebase_off;
    uint32_t rebase_size;
    uint32_t bind_off;
    uint32_t bind_size;
    uint32_t weak_bind_off;
    uint32_t weak_bind_size;
    uint32_t lazy_bind_off;
    uint32_t lazy_bind_size;
    uint32_t export_off;
    uint32_t export_size;
} _packed;

struct dysymtab_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t ilocalsym;
    uint32_t nlocalsym;
    uint32_t iextdefsym;
    uint32_t nextdefsym;
    uint32_t iundefsym;
    uint32_t nundefsym;
    uint32_t tocoff;
    uint32_t ntoc;
    uint32_t modtaboff;
    uint32_t nmodtab;
    uint32_t extrefsymoff;
    uint32_t nextrefsyms;
    uint32_t indirectsymoff;
    uint32_t nindirectsyms;
    uint32_t extreloff;
    uint32_t nextrel;
    uint32_t locreloff;
    uint32_t nlocrel;
} _packed;

struct dylib_table_of_contents {
    uint32_t symbol_index;
    uint32_t module_index;
} _packed;

struct dylib_module {
    uint32_t module_name;
    uint32_t iextdefsym;
    uint32_t nextdefsym;
    uint32_t irefsym;
    uint32_t nrefsym;
    uint32_t ilocalsym;
    uint32_t nlocalsym;
    uint32_t iextrel;
    uint32_t nextrel;
    uint32_t iinit_iterm;
    uint32_t ninit_nterm;
    uint32_t objc_module_info_addr;
    uint32_t objc_module_info_size;
} _packed;

struct dylib_reference {
    uint32_t isym:24;
    uint32_t flags:8;
} _packed;

struct relocation_info {
    int32_t r_address;
    uint32_t r_symbolnum:24;
    uint32_t r_pcrel:1;
    uint32_t r_length:2;
    uint32_t r_extern:1;
    uint32_t r_type:4;
} _packed;

struct nlist {
    union {
        char *n_name;
        int32_t n_strx;
    } n_un;

    uint8_t n_type;
    uint8_t n_sect;
    uint8_t n_desc;
    uint32_t n_value;
} _packed;

struct segment_command {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t fileoff;
    uint32_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
} _packed;

struct segment_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
} _packed;

struct section {
    char sectname[16];
    char segname[16];
    uint32_t addr;
    uint32_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
} _packed;

struct section_64 {
    char sectname[16];
    char segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
} _packed;

struct linkedit_data_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
} _packed;

struct encryption_info_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t cryptoff;
    uint32_t cryptsize;
    uint32_t cryptid;
} _packed;

#define BIND_OPCODE_MASK                             0xf0
#define BIND_IMMEDIATE_MASK                          0x0f
#define BIND_OPCODE_DONE                             0x00
#define BIND_OPCODE_SET_DYLIB_ORDINAL_IMM            0x10
#define BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB           0x20
#define BIND_OPCODE_SET_DYLIB_SPECIAL_IMM            0x30
#define BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM    0x40
#define BIND_OPCODE_SET_TYPE_IMM                     0x50
#define BIND_OPCODE_SET_ADDEND_SLEB                  0x60
#define BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB      0x70
#define BIND_OPCODE_ADD_ADDR_ULEB                    0x80
#define BIND_OPCODE_DO_BIND                          0x90
#define BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB            0xa0
#define BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED      0xb0
#define BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB 0xc0

struct : ldid::Progress {
    virtual void operator()(const std::string &value) const {
    }

    virtual void operator()(double value) const {
    }
} dummy_;

struct Progression : ldid::Progress {
    const ldid::Progress &progress_;
    std::string name_;

    Progression(const ldid::Progress &progress, const std::string &name) :
        progress_(progress),
        name_(name)
    {
    }

    virtual void operator()(const std::string &value) const {
        return progress_(name_ + " (" + value + ")");
    }

    virtual void operator()(double value) const {
        return progress_(value);
    }
};

static std::streamsize read(std::streambuf &stream, void *data, size_t size) {
    auto writ(stream.sgetn(static_cast<char *>(data), size));
    _assert(writ >= 0);
    return writ;
}

static inline void put(std::streambuf &stream, uint8_t value) {
    _assert(stream.sputc(value) != EOF);
}

static inline void get(std::streambuf &stream, void *data, size_t size) {
    _assert(read(stream, data, size) == size);
}

static inline void put(std::streambuf &stream, const void *data, size_t size) {
    _assert(stream.sputn(static_cast<const char *>(data), size) == size);
}

static inline void put(std::streambuf &stream, const void *data, size_t size, const ldid::Progress &progress) {
    progress(0);
    for (size_t total(0); total != size;) {
        auto writ(std::min(size - total, size_t(4096 * 4)));
        _assert(stream.sputn(static_cast<const char *>(data) + total, writ) == writ);
        total += writ;
        progress(double(total) / size);
    }
}

static inline void put(std::streambuf &stream, const std::string &data) {
    return put(stream, data.data(), data.size());
}

static size_t most(std::streambuf &stream, void *data, size_t size) {
    size_t total(size);
    while (size > 0)
        if (auto writ = read(stream, data, size))
            size -= writ;
        else break;
    return total - size;
}

static inline void pad(std::streambuf &stream, size_t size) {
    char padding[size];
    memset(padding, 0, size);
    put(stream, padding, size);
}

template <typename Type_>
Type_ Align(Type_ value, size_t align) {
    value += align - 1;
    value /= align;
    value *= align;
    return value;
}

static const uint8_t PageShift_(0x0c);
static const uint32_t PageSize_(1 << PageShift_);

static inline unsigned bytes(uint64_t value) {
    return (64 - __builtin_clzll(value) + 7) / 8;
}

static void put(std::streambuf &stream, uint64_t value, size_t length) {
    length *= 8;
    do put(stream, uint8_t(value >> (length -= 8)));
    while (length != 0);
}

//static void der(std::streambuf &stream, uint64_t value) {
//    if (value < 128)
//        put(stream, value);
//    else {
//        unsigned length(bytes(value));
//        put(stream, 0x80 | length);
//        put(stream, value, length);
//    }
//}
//
//static std::string der(uint8_t tag, const char *value, size_t length) {
//    std::stringbuf data;
//    put(data, tag);
//    der(data, length);
//    put(data, value, length);
//    return data.str();
//}
//
//static std::string der(uint8_t tag, const char *value) {
//    return der(tag, value, strlen(value)); }
//static std::string der(uint8_t tag, const std::string &value) {
//    return der(tag, value.data(), value.size()); }
//
//template <typename Type_>
//static void der_(std::stringbuf &data, const Type_ &values) {
//    size_t size(0);
//    for (const auto &value : values)
//        size += value.size();
//    der(data, size);
//    for (const auto &value : values)
//        put(data, value);
//}
//
//static std::string der(const std::vector<std::string> &values) {
//    std::stringbuf data;
//    put(data, 0x30);
//    der_(data, values);
//    return data.str();
//}
//
//static std::string der(const std::multiset<std::string> &values) {
//    std::stringbuf data;
//    put(data, 0x31);
//    der_(data, values);
//    return data.str();
//}
//
//static std::string der(const std::pair<std::string, std::string> &value) {
//    const auto key(der(0x0c, value.first));
//    std::stringbuf data;
//    put(data, 0x30);
//    der(data, key.size() + value.second.size());
//    put(data, key);
//    put(data, value.second);
//    return data.str();
//}
//
//static std::string der(plist_t data) {
//    switch (const auto type = plist_get_node_type(data)) {
//        case PLIST_BOOLEAN: {
//            uint8_t value(0);
//            plist_get_bool_val(data, &value);
//
//            std::stringbuf data;
//            put(data, 0x01);
//            der(data, 1);
//            put(data, value != 0 ? 1 : 0);
//            return data.str();
//        } break;
//
//        case PLIST_UINT: {
//            uint64_t value;
//            plist_get_uint_val(data, &value);
//            const auto length(bytes(value));
//
//            std::stringbuf data;
//            put(data, 0x02);
//            der(data, length);
//            put(data, value, length);
//            return data.str();
//        } break;
//
//        case PLIST_REAL: {
//            _assert(false);
//        } break;
//
//        case PLIST_DATE: {
//            _assert(false);
//        } break;
//
//        case PLIST_DATA: {
//            char *value;
//            uint64_t length;
//            plist_get_data_val(data, &value, &length);
//            _scope({ free(value); });
//            return der(0x04, value, length);
//        } break;
//
//        case PLIST_STRING: {
//            char *value;
//            plist_get_string_val(data, &value);
//            _scope({ free(value); });
//            return der(0x0c, value);
//        } break;
//
//        case PLIST_ARRAY: {
//            std::vector<std::string> values;
//            for (auto e(plist_array_get_size(data)), i(decltype(e)(0)); i != e; ++i)
//                values.push_back(der(plist_array_get_item(data, i)));
//            return der(values);
//        } break;
//
//        case PLIST_DICT: {
//            std::multiset<std::string> values;
//
//            plist_dict_iter iterator(NULL);
//            plist_dict_new_iter(data, &iterator);
//            _scope({ free(iterator); });
//
//            for (;;) {
//                char *key(NULL);
//                plist_t value(NULL);
//                plist_dict_next_item(data, iterator, &key, &value);
//                if (key == NULL)
//                    break;
//                _scope({ free(key); });
//                values.insert(der(std::make_pair(key, der(value))));
//            }
//
//            return der(values);
//        } break;
//
//        default: {
//            _assert_(false, "unsupported plist type %d", type);
//        } break;
//    }
//}

static inline uint16_t Swap_(uint16_t value) {
    return
        ((value >>  8) & 0x00ff) |
        ((value <<  8) & 0xff00);
}

static inline uint32_t Swap_(uint32_t value) {
    value = ((value >>  8) & 0x00ff00ff) |
            ((value <<  8) & 0xff00ff00);
    value = ((value >> 16) & 0x0000ffff) |
            ((value << 16) & 0xffff0000);
    return value;
}

static inline uint64_t Swap_(uint64_t value) {
    value = (value & 0x00000000ffffffff) << 32 | (value & 0xffffffff00000000) >> 32;
    value = (value & 0x0000ffff0000ffff) << 16 | (value & 0xffff0000ffff0000) >> 16;
    value = (value & 0x00ff00ff00ff00ff) << 8  | (value & 0xff00ff00ff00ff00) >> 8;
    return value;
}

static inline int16_t Swap_(int16_t value) {
    return Swap_(static_cast<uint16_t>(value));
}

static inline int32_t Swap_(int32_t value) {
    return Swap_(static_cast<uint32_t>(value));
}

static inline int64_t Swap_(int64_t value) {
    return Swap_(static_cast<uint64_t>(value));
}

static bool little_(true);

static inline uint16_t Swap(uint16_t value) {
    return little_ ? Swap_(value) : value;
}

static inline uint32_t Swap(uint32_t value) {
    return little_ ? Swap_(value) : value;
}

static inline uint64_t Swap(uint64_t value) {
    return little_ ? Swap_(value) : value;
}

static inline int16_t Swap(int16_t value) {
    return Swap(static_cast<uint16_t>(value));
}

static inline int32_t Swap(int32_t value) {
    return Swap(static_cast<uint32_t>(value));
}

static inline int64_t Swap(int64_t value) {
    return Swap(static_cast<uint64_t>(value));
}

class Swapped {
  protected:
    bool swapped_;

    Swapped() :
        swapped_(false)
    {
    }

  public:
    Swapped(bool swapped) :
        swapped_(swapped)
    {
    }

    template <typename Type_>
    Type_ Swap(Type_ value) const {
        return swapped_ ? Swap_(value) : value;
    }
};

class Data :
    public Swapped
{
  private:
    void *base_;
    size_t size_;

  public:
    Data(void *base, size_t size) :
        base_(base),
        size_(size)
    {
    }

    void *GetBase() const {
        return base_;
    }

    size_t GetSize() const {
        return size_;
    }
};

class MachHeader :
    public Data
{
  private:
    bool bits64_;

    struct mach_header *mach_header_;
    struct load_command *load_command_;

  public:
    MachHeader(void *base, size_t size) :
        Data(base, size)
    {
        mach_header_ = (mach_header *) base;

        switch (Swap(mach_header_->magic)) {
            case MH_CIGAM:
                swapped_ = !swapped_;
            case MH_MAGIC:
                bits64_ = false;
            break;

            case MH_CIGAM_64:
                swapped_ = !swapped_;
            case MH_MAGIC_64:
                bits64_ = true;
            break;

            default:
                _assert(false);
        }

        void *post = mach_header_ + 1;
        if (bits64_)
            post = (uint32_t *) post + 1;
        load_command_ = (struct load_command *) post;

        _assert(
            Swap(mach_header_->filetype) == MH_EXECUTE ||
            Swap(mach_header_->filetype) == MH_DYLIB ||
            Swap(mach_header_->filetype) == MH_DYLINKER ||
            Swap(mach_header_->filetype) == MH_BUNDLE
        );
    }

    bool Bits64() const {
        return bits64_;
    }

    struct mach_header *operator ->() const {
        return mach_header_;
    }

    operator struct mach_header *() const {
        return mach_header_;
    }

    uint32_t GetCPUType() const {
        return Swap(mach_header_->cputype);
    }

    uint32_t GetCPUSubtype() const {
        return Swap(mach_header_->cpusubtype) & 0xff;
    }

    struct load_command *GetLoadCommand() const {
        return load_command_;
    }

    std::vector<struct load_command *> GetLoadCommands() const {
        std::vector<struct load_command *> load_commands;

        struct load_command *load_command = load_command_;
        for (uint32_t cmd = 0; cmd != Swap(mach_header_->ncmds); ++cmd) {
            load_commands.push_back(load_command);
            load_command = (struct load_command *) ((uint8_t *) load_command + Swap(load_command->cmdsize));
        }

        return load_commands;
    }

    void ForSection(const ldid::Functor<void (const char *, const char *, void *, size_t)> &code) const {
        _foreach (load_command, GetLoadCommands())
            switch (Swap(load_command->cmd)) {
                case LC_SEGMENT: {
                    auto segment(reinterpret_cast<struct segment_command *>(load_command));
                    code(segment->segname, NULL, GetOffset<void>(segment->fileoff), segment->filesize);
                    auto section(reinterpret_cast<struct section *>(segment + 1));
                    for (uint32_t i(0), e(Swap(segment->nsects)); i != e; ++i, ++section)
                        code(segment->segname, section->sectname, GetOffset<void>(segment->fileoff + section->offset), section->size);
                } break;

                case LC_SEGMENT_64: {
                    auto segment(reinterpret_cast<struct segment_command_64 *>(load_command));
                    code(segment->segname, NULL, GetOffset<void>(segment->fileoff), segment->filesize);
                    auto section(reinterpret_cast<struct section_64 *>(segment + 1));
                    for (uint32_t i(0), e(Swap(segment->nsects)); i != e; ++i, ++section)
                        code(segment->segname, section->sectname, GetOffset<void>(segment->fileoff + section->offset), section->size);
                } break;
            }
    }

    template <typename Target_>
    Target_ *GetOffset(uint32_t offset) const {
        return reinterpret_cast<Target_ *>(offset + (uint8_t *) mach_header_);
    }
};

class FatMachHeader :
    public MachHeader
{
  private:
    fat_arch *fat_arch_;

  public:
    FatMachHeader(void *base, size_t size, fat_arch *fat_arch) :
        MachHeader(base, size),
        fat_arch_(fat_arch)
    {
    }

    fat_arch *GetFatArch() const {
        return fat_arch_;
    }
};

class FatHeader :
    public Data
{
  private:
    fat_header *fat_header_;
    std::vector<FatMachHeader> mach_headers_;

  public:
    FatHeader(void *base, size_t size) :
        Data(base, size)
    {
        fat_header_ = reinterpret_cast<struct fat_header *>(base);

        if (Swap(fat_header_->magic) == FAT_CIGAM) {
            swapped_ = !swapped_;
            goto fat;
        } else if (Swap(fat_header_->magic) != FAT_MAGIC) {
            fat_header_ = NULL;
            mach_headers_.push_back(FatMachHeader(base, size, NULL));
        } else fat: {
            size_t fat_narch = Swap(fat_header_->nfat_arch);
            fat_arch *fat_arch = reinterpret_cast<struct fat_arch *>(fat_header_ + 1);
            size_t arch;
            for (arch = 0; arch != fat_narch; ++arch) {
                uint32_t arch_offset = Swap(fat_arch->offset);
                uint32_t arch_size = Swap(fat_arch->size);
                mach_headers_.push_back(FatMachHeader((uint8_t *) base + arch_offset, arch_size, fat_arch));
                ++fat_arch;
            }
        }
    }

    std::vector<FatMachHeader> &GetMachHeaders() {
        return mach_headers_;
    }

    bool IsFat() const {
        return fat_header_ != NULL;
    }

    struct fat_header *operator ->() const {
        return fat_header_;
    }

    operator struct fat_header *() const {
        return fat_header_;
    }
};

#define CSMAGIC_REQUIREMENT            uint32_t(0xfade0c00)
#define CSMAGIC_REQUIREMENTS           uint32_t(0xfade0c01)
#define CSMAGIC_CODEDIRECTORY          uint32_t(0xfade0c02)
#define CSMAGIC_EMBEDDED_SIGNATURE     uint32_t(0xfade0cc0)
#define CSMAGIC_EMBEDDED_SIGNATURE_OLD uint32_t(0xfade0b02)
#define CSMAGIC_EMBEDDED_ENTITLEMENTS  uint32_t(0xfade7171)
#define CSMAGIC_EMBEDDED_DERFORMAT     uint32_t(0xfade7172) // name?
#define CSMAGIC_DETACHED_SIGNATURE     uint32_t(0xfade0cc1)
#define CSMAGIC_BLOBWRAPPER            uint32_t(0xfade0b01)

#define CSSLOT_CODEDIRECTORY uint32_t(0x00000)
#define CSSLOT_INFOSLOT      uint32_t(0x00001)
#define CSSLOT_REQUIREMENTS  uint32_t(0x00002)
#define CSSLOT_RESOURCEDIR   uint32_t(0x00003)
#define CSSLOT_APPLICATION   uint32_t(0x00004)
#define CSSLOT_ENTITLEMENTS  uint32_t(0x00005)
#define CSSLOT_REPSPECIFIC   uint32_t(0x00006) // name?
#define CSSLOT_DERFORMAT     uint32_t(0x00007) // name?
#define CSSLOT_ALTERNATE     uint32_t(0x01000)

#define CSSLOT_SIGNATURESLOT uint32_t(0x10000)

#define CS_HASHTYPE_SHA160_160 1
#define CS_HASHTYPE_SHA256_256 2
#define CS_HASHTYPE_SHA256_160 3
#define CS_HASHTYPE_SHA386_386 4

#if 0
#define CS_EXECSEG_MAIN_BINARY     0x001 /* executable segment denotes main binary */
#define CS_EXECSEG_ALLOW_UNSIGNED  0x010 /* allow unsigned pages (for debugging) */
#define CS_EXECSEG_DEBUGGER        0x020 /* main binary is debugger */
#define CS_EXECSEG_JIT             0x040 /* JIT enabled */
#define CS_EXECSEG_SKIP_LV         0x080 /* skip library validation */
#define CS_EXECSEG_CAN_LOAD_CDHASH 0x100 /* can bless cdhash for execution */
#define CS_EXECSEG_CAN_EXEC_CDHASH 0x200 /* can execute blessed cdhash */
#else
enum SecCodeExecSegFlags {
    kSecCodeExecSegMainBinary = 0x001,
    kSecCodeExecSegAllowUnsigned = 0x010,
    kSecCodeExecSegDebugger = 0x020,
    kSecCodeExecSegJit = 0x040,
    kSecCodeExecSegSkipLibraryVal = 0x080,
    kSecCodeExecSegCanLoadCdHash = 0x100,
    kSecCodeExecSegCanExecCdHash = 0x100,
};
#endif

struct BlobIndex {
    uint32_t type;
    uint32_t offset;
} _packed;

struct Blob {
    uint32_t magic;
    uint32_t length;
} _packed;

struct SuperBlob {
    struct Blob blob;
    uint32_t count;
    struct BlobIndex index[];
} _packed;

struct CodeDirectory {
    uint32_t version;
    uint32_t flags;
    uint32_t hashOffset;
    uint32_t identOffset;
    uint32_t nSpecialSlots;
    uint32_t nCodeSlots;
    uint32_t codeLimit;
    uint8_t hashSize;
    uint8_t hashType;
    uint8_t platform;
    uint8_t pageSize;
    uint32_t spare2;
    uint32_t scatterOffset;
    uint32_t teamIDOffset;
    uint32_t spare3;
    uint64_t codeLimit64;
    uint64_t execSegBase;
    uint64_t execSegLimit;
    uint64_t execSegFlags;
#if 0 // version = 0x20500
    uint32_t runtime;
    uint32_t preEncryptOffset;
#endif
#if 0 // version = 0x20600
    uint8_t linkageHashType;
    uint8_t linkageTruncated;
    uint16_t spare4;
    uint32_t linkageOffset;
    uint32_t linkageSize;
#endif
} _packed;

enum CodeSignatureFlags {
    kSecCodeSignatureHost = 0x0001,
    kSecCodeSignatureAdhoc = 0x0002,
    kSecCodeSignatureForceHard = 0x0100,
    kSecCodeSignatureForceKill = 0x0200,
    kSecCodeSignatureForceExpiration = 0x0400,
    kSecCodeSignatureRestrict = 0x0800,
    kSecCodeSignatureEnforcement = 0x1000,
    kSecCodeSignatureLibraryValidation = 0x2000,
    kSecCodeSignatureRuntime = 0x10000,
};

enum Kind : uint32_t {
    exprForm = 1, // prefix expr form
};

enum ExprOp : uint32_t {
    opFalse, // unconditionally false
    opTrue, // unconditionally true
    opIdent, // match canonical code [string]
    opAppleAnchor, // signed by Apple as Apple's product
    opAnchorHash, // match anchor [cert hash]
    opInfoKeyValue, // *legacy* - use opInfoKeyField [key; value]
    opAnd, // binary prefix expr AND expr [expr; expr]
    opOr, // binary prefix expr OR expr [expr; expr]
    opCDHash, // match hash of CodeDirectory directly [cd hash]
    opNot, // logical inverse [expr]
    opInfoKeyField, // Info.plist key field [string; match suffix]
    opCertField, // Certificate field [cert index; field name; match suffix]
    opTrustedCert, // require trust settings to approve one particular cert [cert index]
    opTrustedCerts, // require trust settings to approve the cert chain
    opCertGeneric, // Certificate component by OID [cert index; oid; match suffix]
    opAppleGenericAnchor, // signed by Apple in any capacity
    opEntitlementField, // entitlement dictionary field [string; match suffix]
    opCertPolicy, // Certificate policy by OID [cert index; oid; match suffix]
    opNamedAnchor, // named anchor type
    opNamedCode, // named subroutine
    opPlatform, // platform constraint [integer]
    exprOpCount // (total opcode count in use)
};

enum MatchOperation {
    matchExists, // anything but explicit "false" - no value stored
    matchEqual, // equal (CFEqual)
    matchContains, // partial match (substring)
    matchBeginsWith, // partial match (initial substring)
    matchEndsWith, // partial match (terminal substring)
    matchLessThan, // less than (string with numeric comparison)
    matchGreaterThan, // greater than (string with numeric comparison)
    matchLessEqual, // less or equal (string with numeric comparison)
    matchGreaterEqual, // greater or equal (string with numeric comparison)
};

#define OID_ISO_MEMBER 42
#define OID_US OID_ISO_MEMBER, 134, 72
#define APPLE_OID OID_US, 0x86, 0xf7, 0x63
#define APPLE_ADS_OID APPLE_OID, 0x64
#define APPLE_EXTENSION_OID APPLE_ADS_OID, 6

#ifndef LDID_NOFLAGT
extern "C" uint32_t hash(uint8_t *k, uint32_t length, uint32_t initval);
#endif

struct Algorithm {
    size_t size_;
    uint8_t type_;

    Algorithm(size_t size, uint8_t type) :
        size_(size),
        type_(type)
    {
    }

    virtual const uint8_t *operator [](const ldid::Hash &hash) const = 0;

    virtual void operator ()(uint8_t *hash, const void *data, size_t size) const = 0;
    virtual void operator ()(ldid::Hash &hash, const void *data, size_t size) const = 0;
    virtual void operator ()(std::vector<char> &hash, const void *data, size_t size) const = 0;

    virtual const char *name() = 0;
};

struct AlgorithmSHA1 :
    Algorithm
{
    AlgorithmSHA1() :
        Algorithm(LDID_SHA1_DIGEST_LENGTH, CS_HASHTYPE_SHA160_160)
    {
    }

    virtual const uint8_t *operator [](const ldid::Hash &hash) const {
        return hash.sha1_;
    }

    void operator ()(uint8_t *hash, const void *data, size_t size) const {
        LDID_SHA1(static_cast<const uint8_t *>(data), size, hash);
    }

    void operator ()(ldid::Hash &hash, const void *data, size_t size) const {
        return operator()(hash.sha1_, data, size);
    }

    void operator ()(std::vector<char> &hash, const void *data, size_t size) const {
        hash.resize(LDID_SHA1_DIGEST_LENGTH);
        return operator ()(reinterpret_cast<uint8_t *>(hash.data()), data, size);
    }

    virtual const char *name() {
        return "sha1";
    }
};

struct AlgorithmSHA256 :
    Algorithm
{
    AlgorithmSHA256() :
        Algorithm(LDID_SHA256_DIGEST_LENGTH, CS_HASHTYPE_SHA256_256)
    {
    }

    virtual const uint8_t *operator [](const ldid::Hash &hash) const {
        return hash.sha256_;
    }

    void operator ()(uint8_t *hash, const void *data, size_t size) const {
        LDID_SHA256(static_cast<const uint8_t *>(data), size, hash);
    }

    void operator ()(ldid::Hash &hash, const void *data, size_t size) const {
        return operator()(hash.sha256_, data, size);
    }

    void operator ()(std::vector<char> &hash, const void *data, size_t size) const {
        hash.resize(LDID_SHA256_DIGEST_LENGTH);
        return operator ()(reinterpret_cast<uint8_t *>(hash.data()), data, size);
    }

    virtual const char *name() {
        return "sha256";
    }
};

static bool do_sha1(true);
static bool do_sha256(true);

static const std::vector<Algorithm *> &GetAlgorithms() {
    static AlgorithmSHA1 sha1;
    static AlgorithmSHA256 sha256;

    static std::vector<Algorithm *> algorithms;
    if (algorithms.empty()) {
        if (do_sha1)
            algorithms.push_back(&sha1);
        if (do_sha256)
            algorithms.push_back(&sha256);
    }

    return algorithms;
}

struct Baton {
    std::string entitlements_;
    std::string derformat_;
};

struct CodesignAllocation {
    FatMachHeader mach_header_;
    uint64_t offset_;
    uint32_t size_;
    uint64_t limit_;
    uint32_t alloc_;
    uint32_t align_;
    const char *arch_;
    Baton baton_;

    CodesignAllocation(FatMachHeader mach_header, size_t offset, size_t size, size_t limit, size_t alloc, size_t align, const char *arch, const Baton &baton) :
        mach_header_(mach_header),
        offset_(offset),
        size_(size),
        limit_(limit),
        alloc_(alloc),
        align_(align),
        arch_(arch),
        baton_(baton)
    {
    }
};

#ifndef LDID_NOTOOLS
class File {
  private:
    int file_;

  public:
    File() :
        file_(-1)
    {
    }

    ~File() {
        if (file_ != -1)
            _syscall(close(file_));
    }

    void open(const char *path, int flags) {
        _assert(file_ == -1);
        file_ = _syscall(::open(path, flags));
    }

    int file() const {
        return file_;
    }
};

class Map {
  private:
    File file_;
    void *data_;
    size_t size_;

    void clear() {
        if (data_ == NULL)
            return;
        _syscall(munmap(data_, size_));
        data_ = NULL;
        size_ = 0;
    }

  public:
    Map() :
        data_(NULL),
        size_(0)
    {
    }

    Map(const std::string &path, int oflag, int pflag, int mflag) :
        Map()
    {
        open(path, oflag, pflag, mflag);
    }

    Map(const std::string &path, bool edit) :
        Map()
    {
        open(path, edit);
    }

    ~Map() {
        clear();
    }

    bool empty() const {
        return data_ == NULL;
    }

    void open(const std::string &path, int oflag, int pflag, int mflag) {
        clear();

        file_.open(path.c_str(), oflag);
        int file(file_.file());

        struct stat stat;
        _syscall(fstat(file, &stat));
        size_ = stat.st_size;

        data_ = _syscall(mmap(NULL, size_, pflag, mflag, file, 0));
    }

    void open(const std::string &path, bool edit) {
        if (edit)
            open(path, O_RDWR, PROT_READ | PROT_WRITE, MAP_SHARED);
        else
            open(path, O_RDONLY, PROT_READ, MAP_PRIVATE);
    }

    void *data() const {
        return data_;
    }

    size_t size() const {
        return size_;
    }

    operator std::string() const {
        return std::string(static_cast<char *>(data_), size_);
    }
};
#endif

namespace ldid {

#ifndef LDID_NOPLIST
static plist_t plist(const std::string &data);
#endif

void Analyze(const MachHeader &mach_header, const Functor<void (const char *data, size_t size)> &entitle) {
    _foreach (load_command, mach_header.GetLoadCommands())
        if (mach_header.Swap(load_command->cmd) == LC_CODE_SIGNATURE) {
            auto signature(reinterpret_cast<struct linkedit_data_command *>(load_command));
            auto offset(mach_header.Swap(signature->dataoff));
            auto pointer(reinterpret_cast<uint8_t *>(mach_header.GetBase()) + offset);
            auto super(reinterpret_cast<struct SuperBlob *>(pointer));

            for (size_t index(0); index != Swap(super->count); ++index)
                if (Swap(super->index[index].type) == CSSLOT_ENTITLEMENTS) {
                    auto begin(Swap(super->index[index].offset));
                    auto blob(reinterpret_cast<struct Blob *>(pointer + begin));
                    auto writ(Swap(blob->length) - sizeof(*blob));
                    entitle(reinterpret_cast<char *>(blob + 1), writ);
                }
        }
}

std::string Analyze(const void *data, size_t size) {
    std::string entitlements;

    FatHeader fat_header(const_cast<void *>(data), size);
    _foreach (mach_header, fat_header.GetMachHeaders())
        Analyze(mach_header, fun([&](const char *data, size_t size) {
            if (entitlements.empty())
                entitlements.assign(data, size);
            else
                _assert(entitlements.compare(0, entitlements.size(), data, size) == 0);
        }));

    return entitlements;
}

static void Allocate(const void *idata, size_t isize, std::streambuf &output, const Functor<size_t (const MachHeader &, Baton &, size_t)> &allocate, const Functor<size_t (const MachHeader &, const Baton &, std::streambuf &output, size_t, size_t, size_t, const std::string &, const char *, const Progress &)> &save, const Progress &progress) {
    FatHeader source(const_cast<void *>(idata), isize);

    size_t offset(0);
    if (source.IsFat())
        offset += sizeof(fat_header) + sizeof(fat_arch) * source.Swap(source->nfat_arch);

    std::vector<CodesignAllocation> allocations;
    _foreach (mach_header, source.GetMachHeaders()) {
        struct linkedit_data_command *signature(NULL);
        struct symtab_command *symtab(NULL);

        _foreach (load_command, mach_header.GetLoadCommands()) {
            uint32_t cmd(mach_header.Swap(load_command->cmd));
            if (false);
            else if (cmd == LC_CODE_SIGNATURE)
                signature = reinterpret_cast<struct linkedit_data_command *>(load_command);
            else if (cmd == LC_SYMTAB)
                symtab = reinterpret_cast<struct symtab_command *>(load_command);
        }

        size_t size;
        if (signature == NULL)
            size = mach_header.GetSize();
        else {
            size = mach_header.Swap(signature->dataoff);
            _assert(size <= mach_header.GetSize());
        }

        if (symtab != NULL) {
            auto end(mach_header.Swap(symtab->stroff) + mach_header.Swap(symtab->strsize));
            if (symtab->stroff != 0 || symtab->strsize != 0) {
                _assert(end <= size);
                _assert(end >= size - 0x10);
                size = end;
            }
        }

        Baton baton;
        size_t alloc(allocate(mach_header, baton, size));

        auto *fat_arch(mach_header.GetFatArch());
        uint32_t align;

        if (fat_arch != NULL)
            align = source.Swap(fat_arch->align);
        else switch (mach_header.GetCPUType()) {
            case CPU_TYPE_POWERPC:
            case CPU_TYPE_POWERPC64:
            case CPU_TYPE_X86:
            case CPU_TYPE_X86_64:
                align = 0xc;
                break;
            case CPU_TYPE_ARM:
            case CPU_TYPE_ARM64:
                align = 0xe;
                break;
            default:
                align = 0x0;
                break;
        }

        const char *arch(NULL);
        switch (mach_header.GetCPUType()) {
            case CPU_TYPE_POWERPC:
                arch = "ppc";
                break;
            case CPU_TYPE_POWERPC64:
                arch = "ppc64";
                break;
            case CPU_TYPE_X86:
                arch = "i386";
                break;
            case CPU_TYPE_X86_64:
                arch = "x86_64";
                break;
            case CPU_TYPE_ARM:
                arch = "arm";
                break;
            case CPU_TYPE_ARM64:
                arch = "arm64";
                break;
        }

        offset = Align(offset, 1 << align);

        uint32_t limit(size);
        if (alloc != 0)
            limit = Align(limit, 0x10);

        allocations.push_back(CodesignAllocation(mach_header, offset, size, limit, alloc, align, arch, baton));
        offset += size + alloc;
        offset = Align(offset, 0x10);
    }

    size_t position(0);

    if (source.IsFat()) {
        fat_header fat_header;
        fat_header.magic = Swap(FAT_MAGIC);
        fat_header.nfat_arch = Swap(uint32_t(allocations.size()));
        put(output, &fat_header, sizeof(fat_header));
        position += sizeof(fat_header);

        // XXX: support fat_arch_64 (not in my toolchain)
        // probably use C++14 generic lambda (not in my toolchain)

        _assert_(![&]() {
            _foreach (allocation, allocations) {
                const auto offset(allocation.offset_);
                const auto size(allocation.limit_ + allocation.alloc_);
                if (uint32_t(offset) != offset || uint32_t(size) != size)
                    return true;
            }
            return false;
        }(), "FAT slice >=4GiB not currently supported");

        _foreach (allocation, allocations) {
            auto &mach_header(allocation.mach_header_);

            fat_arch fat_arch;
            fat_arch.cputype = Swap(mach_header->cputype);
            fat_arch.cpusubtype = Swap(mach_header->cpusubtype);
            fat_arch.offset = Swap(uint32_t(allocation.offset_));
            fat_arch.size = Swap(uint32_t(allocation.limit_ + allocation.alloc_));
            fat_arch.align = Swap(allocation.align_);
            put(output, &fat_arch, sizeof(fat_arch));
            position += sizeof(fat_arch);
        }
    }

    _foreach (allocation, allocations) {
        progress(allocation.arch_);
        auto &mach_header(allocation.mach_header_);

        pad(output, allocation.offset_ - position);
        position = allocation.offset_;

        size_t left(-1);
        size_t right(0);

        std::vector<std::string> commands;

        _foreach (load_command, mach_header.GetLoadCommands()) {
            std::string copy(reinterpret_cast<const char *>(load_command), load_command->cmdsize);

            switch (mach_header.Swap(load_command->cmd)) {
                case LC_CODE_SIGNATURE:
                    continue;
                break;

                // XXX: this is getting ridiculous: provide a better abstraction

                case LC_SEGMENT: {
                    auto segment_command(reinterpret_cast<struct segment_command *>(&copy[0]));

                    if ((segment_command->initprot & 04) != 0) {
                        auto begin(mach_header.Swap(segment_command->fileoff));
                        auto end(begin + mach_header.Swap(segment_command->filesize));
                        if (left > begin)
                            left = begin;
                        if (right < end)
                            right = end;
                    }

                    if (strncmp(segment_command->segname, "__LINKEDIT", 16) == 0) {
                        size_t size(mach_header.Swap(allocation.limit_ + allocation.alloc_ - mach_header.Swap(segment_command->fileoff)));
                        segment_command->filesize = size;
                        segment_command->vmsize = Align(size, 1 << allocation.align_);
                    }
                } break;

                case LC_SEGMENT_64: {
                    auto segment_command(reinterpret_cast<struct segment_command_64 *>(&copy[0]));

                    if ((segment_command->initprot & 04) != 0) {
                        auto begin(mach_header.Swap(segment_command->fileoff));
                        auto end(begin + mach_header.Swap(segment_command->filesize));
                        if (left > begin)
                            left = begin;
                        if (right < end)
                            right = end;
                    }

                    if (strncmp(segment_command->segname, "__LINKEDIT", 16) == 0) {
                        size_t size(mach_header.Swap(allocation.limit_ + allocation.alloc_ - mach_header.Swap(segment_command->fileoff)));
                        segment_command->filesize = size;
                        segment_command->vmsize = Align(size, 1 << allocation.align_);
                    }
                } break;
            }

            commands.push_back(copy);
        }

        if (allocation.alloc_ != 0) {
            linkedit_data_command signature;
            signature.cmd = mach_header.Swap(LC_CODE_SIGNATURE);
            signature.cmdsize = mach_header.Swap(uint32_t(sizeof(signature)));
            signature.dataoff = mach_header.Swap(allocation.limit_);
            signature.datasize = mach_header.Swap(allocation.alloc_);
            commands.push_back(std::string(reinterpret_cast<const char *>(&signature), sizeof(signature)));
        }

        size_t begin(position);

        uint32_t after(0);
        _foreach(command, commands)
            after += command.size();

        std::stringbuf altern;

        struct mach_header header(*mach_header);
        header.ncmds = mach_header.Swap(uint32_t(commands.size()));
        header.sizeofcmds = mach_header.Swap(after);
        put(output, &header, sizeof(header));
        put(altern, &header, sizeof(header));
        position += sizeof(header);

        if (mach_header.Bits64()) {
            auto pad(mach_header.Swap(uint32_t(0)));
            put(output, &pad, sizeof(pad));
            put(altern, &pad, sizeof(pad));
            position += sizeof(pad);
        }

        _foreach(command, commands) {
            put(output, command.data(), command.size());
            put(altern, command.data(), command.size());
            position += command.size();
        }

        uint32_t before(mach_header.Swap(mach_header->sizeofcmds));
        if (before > after) {
            pad(output, before - after);
            pad(altern, before - after);
            position += before - after;
        }

        auto top(reinterpret_cast<char *>(mach_header.GetBase()));

        std::string overlap(altern.str());
        overlap.append(top + overlap.size(), Align(overlap.size(), 0x1000) - overlap.size());

        put(output, top + (position - begin), allocation.size_ - (position - begin), progress);
        position = begin + allocation.size_;

        pad(output, allocation.limit_ - allocation.size_);
        position += allocation.limit_ - allocation.size_;

        size_t saved(save(mach_header, allocation.baton_, output, allocation.limit_, left, right, overlap, top, progress));
        if (allocation.alloc_ > saved)
            pad(output, allocation.alloc_ - saved);
        else
            _assert(allocation.alloc_ == saved);
        position += allocation.alloc_;
    }
}

}

typedef std::map<uint32_t, std::string> Blobs;

static void insert(Blobs &blobs, uint32_t slot, const std::stringbuf &buffer) {
    auto value(buffer.str());
    std::swap(blobs[slot], value);
}

static const std::string &insert(Blobs &blobs, uint32_t slot, uint32_t magic, const std::stringbuf &buffer) {
    auto value(buffer.str());
    Blob blob;
    blob.magic = Swap(magic);
    blob.length = Swap(uint32_t(sizeof(blob) + value.size()));
    value.insert(0, reinterpret_cast<char *>(&blob), sizeof(blob));
    auto &save(blobs[slot]);
    std::swap(save, value);
    return save;
}

static size_t put(std::streambuf &output, uint32_t magic, const Blobs &blobs) {
    size_t total(0);
    _foreach (blob, blobs)
        total += blob.second.size();

    struct SuperBlob super;
    super.blob.magic = Swap(magic);
    super.blob.length = Swap(uint32_t(sizeof(SuperBlob) + blobs.size() * sizeof(BlobIndex) + total));
    super.count = Swap(uint32_t(blobs.size()));
    put(output, &super, sizeof(super));

    size_t offset(sizeof(SuperBlob) + sizeof(BlobIndex) * blobs.size());

    _foreach (blob, blobs) {
        BlobIndex index;
        index.type = Swap(blob.first);
        index.offset = Swap(uint32_t(offset));
        put(output, &index, sizeof(index));
        offset += blob.second.size();
    }

    _foreach (blob, blobs)
        put(output, blob.second.data(), blob.second.size());

    return offset;
}

#ifndef LDID_NOSMIME
class Buffer {
  private:
    BIO *bio_;

  public:
    Buffer(BIO *bio) :
        bio_(bio)
    {
        _assert(bio_ != NULL);
    }

    Buffer() :
        bio_(BIO_new(BIO_s_mem()))
    {
    }

    Buffer(const char *data, size_t size) :
        Buffer(BIO_new_mem_buf(const_cast<char *>(data), size))
    {
    }

    Buffer(const std::string &data) :
        Buffer(data.data(), data.size())
    {
    }

    Buffer(PKCS7 *pkcs) :
        Buffer()
    {
        _assert(i2d_PKCS7_bio(bio_, pkcs) != 0);
    }

    ~Buffer() {
        BIO_free_all(bio_);
    }

    operator BIO *() const {
        return bio_;
    }

    explicit operator std::string() const {
        char *data;
        auto size(BIO_get_mem_data(bio_, &data));
        return std::string(data, size);
    }
};

class Stuff {
  private:
    PKCS12 *value_;
    EVP_PKEY *key_;
    X509 *cert_;
    STACK_OF(X509) *ca_;

  public:
    Stuff(BIO *bio) :
        value_(d2i_PKCS12_bio(bio, NULL)),
        ca_(NULL)
    {
        _assert(value_ != NULL);
        _assert(PKCS12_parse(value_, "", &key_, &cert_, &ca_) != 0);

        _assert(key_ != NULL);
        _assert(cert_ != NULL);

        if (ca_ == NULL)
            ca_ = sk_X509_new_null();
        _assert(ca_ != NULL);
    }

    Stuff(const std::string &data) :
        Stuff(Buffer(data))
    {
    }

    ~Stuff() {
        sk_X509_pop_free(ca_, X509_free);
        X509_free(cert_);
        EVP_PKEY_free(key_);
        PKCS12_free(value_);
    }

    operator PKCS12 *() const {
        return value_;
    }

    operator EVP_PKEY *() const {
        return key_;
    }

    operator X509 *() const {
        return cert_;
    }

    operator STACK_OF(X509) *() const {
        return ca_;
    }
};

class Signature {
  private:
    PKCS7 *value_;

  public:
    Signature(const Stuff &stuff, const Buffer &data, const std::string &xml) {
        value_ = PKCS7_new();
        _assert(value_ != NULL);

        _assert(PKCS7_set_type(value_, NID_pkcs7_signed));
        _assert(PKCS7_content_new(value_, NID_pkcs7_data));

        STACK_OF(X509) *certs(stuff);
        for (unsigned i(0), e(sk_X509_num(certs)); i != e; i++)
            _assert(PKCS7_add_certificate(value_, sk_X509_value(certs, e - i - 1)));

        // XXX: this is the same as PKCS7_sign_add_signer(value_, stuff, stuff, NULL, PKCS7_NOSMIMECAP)
        _assert(X509_check_private_key(stuff, stuff));
        auto info(PKCS7_add_signature(value_, stuff, stuff, EVP_sha1()));
        _assert(info != NULL);
        _assert(PKCS7_add_certificate(value_, stuff));
        _assert(PKCS7_add_signed_attribute(info, NID_pkcs9_contentType, V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data)));

        PKCS7_set_detached(value_, 1);

        ASN1_OCTET_STRING *string(ASN1_OCTET_STRING_new());
        _assert(string != NULL);
        try {
            _assert(ASN1_STRING_set(string, xml.data(), xml.size()));

            static auto nid(OBJ_create("1.2.840.113635.100.9.1", "", ""));
            _assert(PKCS7_add_signed_attribute(info, nid, V_ASN1_OCTET_STRING, string));
        } catch (...) {
            ASN1_OCTET_STRING_free(string);
            throw;
        }

        // XXX: this is the same as PKCS7_final(value_, data, PKCS7_BINARY)
        BIO *bio(PKCS7_dataInit(value_, NULL));
        _assert(bio != NULL);
        _scope({ BIO_free_all(bio); });
        SMIME_crlf_copy(data, bio, PKCS7_BINARY);
        BIO_flush(bio);
        _assert(PKCS7_dataFinal(value_, bio));
    }

    ~Signature() {
        PKCS7_free(value_);
    }

    operator PKCS7 *() const {
        return value_;
    }
};
#endif

class NullBuffer :
    public std::streambuf
{
  public:
    virtual std::streamsize xsputn(const char_type *data, std::streamsize size) {
        return size;
    }

    virtual int_type overflow(int_type next) {
        return next;
    }
};

class HashBuffer :
    public std::streambuf
{
  private:
    ldid::Hash &hash_;

    LDID_SHA1_CTX sha1_;
    LDID_SHA256_CTX sha256_;

  public:
    HashBuffer(ldid::Hash &hash) :
        hash_(hash)
    {
        LDID_SHA1_Init(&sha1_);
        LDID_SHA256_Init(&sha256_);
    }

    ~HashBuffer() {
        LDID_SHA1_Final(reinterpret_cast<uint8_t *>(hash_.sha1_), &sha1_);
        LDID_SHA256_Final(reinterpret_cast<uint8_t *>(hash_.sha256_), &sha256_);
    }

    virtual std::streamsize xsputn(const char_type *data, std::streamsize size) {
        LDID_SHA1_Update(&sha1_, data, size);
        LDID_SHA256_Update(&sha256_, data, size);
        return size;
    }

    virtual int_type overflow(int_type next) {
        if (next == traits_type::eof())
            return sync();
        char value(next);
        xsputn(&value, 1);
        return next;
    }
};

class HashProxy :
    public HashBuffer
{
  private:
    std::streambuf &buffer_;

  public:
    HashProxy(ldid::Hash &hash, std::streambuf &buffer) :
        HashBuffer(hash),
        buffer_(buffer)
    {
    }

    virtual std::streamsize xsputn(const char_type *data, std::streamsize size) {
        _assert(HashBuffer::xsputn(data, size) == size);
        return buffer_.sputn(data, size);
    }
};

#ifndef LDID_NOTOOLS
static bool Starts(const std::string &lhs, const std::string &rhs) {
    return lhs.size() >= rhs.size() && lhs.compare(0, rhs.size(), rhs) == 0;
}

class Split {
  public:
    std::string dir;
    std::string base;

    Split(const std::string &path) {
        size_t slash(path.rfind('/'));
        if (slash == std::string::npos)
            base = path;
        else {
            dir = path.substr(0, slash + 1);
            base = path.substr(slash + 1);
        }
    }
};

static void mkdir_p(const std::string &path) {
    if (path.empty())
        return;
#ifdef __WIN32__
    if (_syscall(mkdir(path.c_str()), EEXIST) == -EEXIST)
        return;
#else
    if (_syscall(mkdir(path.c_str(), 0755), EEXIST) == -EEXIST)
        return;
#endif
    auto slash(path.rfind('/', path.size() - 1));
    if (slash == std::string::npos)
        return;
    mkdir_p(path.substr(0, slash));
}

static std::string Temporary(std::filebuf &file, const Split &split) {
    std::string temp(split.dir + ".ldid." + split.base);
    mkdir_p(split.dir);
    _assert_(file.open(temp.c_str(), std::ios::out | std::ios::trunc | std::ios::binary) == &file, "open(): %s", temp.c_str());
    return temp;
}

static void Commit(const std::string &path, const std::string &temp) {
    struct stat info;
    if (_syscall(stat(path.c_str(), &info), ENOENT) == 0) {
#ifndef __WIN32__
        _syscall(chown(temp.c_str(), info.st_uid, info.st_gid));
#endif
        _syscall(chmod(temp.c_str(), info.st_mode));
    }

    _syscall(rename(temp.c_str(), path.c_str()));
}
#endif

namespace ldid {

#ifndef LDID_NOSMIME
static void get(std::string &value, X509_NAME *name, int nid) {
    auto index(X509_NAME_get_index_by_NID(name, nid, -1));
    _assert(index >= 0);
    auto next(X509_NAME_get_index_by_NID(name, nid, index));
    _assert(next == -1);
    auto entry(X509_NAME_get_entry(name, index));
    _assert(entry != NULL);
    auto asn(X509_NAME_ENTRY_get_data(entry));
    _assert(asn != NULL);
    value.assign(reinterpret_cast<char *>(ASN1_STRING_data(asn)), ASN1_STRING_length(asn));
}
#endif

static void req(std::streambuf &buffer, uint32_t value) {
    value = Swap(value);
    put(buffer, &value, sizeof(value));
}

static void req(std::streambuf &buffer, const std::string &value) {
    req(buffer, value.size());
    put(buffer, value.data(), value.size());
    static uint8_t zeros[] = {0,0,0,0};
    put(buffer, zeros, 3 - (value.size() + 3) % 4);
}

template <size_t Size_>
static void req(std::streambuf &buffer, uint8_t (&&data)[Size_]) {
    req(buffer, Size_);
    put(buffer, data, Size_);
    static uint8_t zeros[] = {0,0,0,0};
    put(buffer, zeros, 3 - (Size_ + 3) % 4);
}

Hash Sign(const void *idata, size_t isize, std::streambuf &output, const std::string &identifier, const std::string &entitlements, bool merge, const std::string &requirements, const std::string &key, const Slots &slots, uint32_t flags, bool platform, const Progress &progress) {
    Hash hash;


    std::string team;
    std::string common;

#ifndef LDID_NOSMIME
    if (!key.empty()) {
        Stuff stuff(key);
        auto name(X509_get_subject_name(stuff));
        _assert(name != NULL);
        get(team, name, NID_organizationalUnitName);
        get(common, name, NID_commonName);
    }
#endif


    std::stringbuf backing;

    if (!requirements.empty()) {
        put(backing, requirements.data(), requirements.size());
    } else {
        Blobs blobs;

        std::stringbuf requirement;
        req(requirement, exprForm);
        req(requirement, opAnd);
        req(requirement, opIdent);
        req(requirement, identifier);
        req(requirement, opAnd);
        req(requirement, opAppleGenericAnchor);
        req(requirement, opAnd);
        req(requirement, opCertField);
        req(requirement, 0);
        req(requirement, "subject.CN");
        req(requirement, matchEqual);
        req(requirement, common);
        req(requirement, opCertGeneric);
        req(requirement, 1);
        req(requirement, (uint8_t []) {APPLE_EXTENSION_OID, 2, 1});
        req(requirement, matchExists);
        insert(blobs, 3, CSMAGIC_REQUIREMENT, requirement);

        put(backing, CSMAGIC_REQUIREMENTS, blobs);
    }


    // XXX: this is just a "sufficiently large number"
    size_t certificate(0x3000);

    Allocate(idata, isize, output, fun([&](const MachHeader &mach_header, Baton &baton, size_t size) -> size_t {
        size_t alloc(sizeof(struct SuperBlob));

        uint32_t normal((size + PageSize_ - 1) / PageSize_);

        uint32_t special(0);

        _foreach (slot, slots)
            special = std::max(special, slot.first);

        mach_header.ForSection(fun([&](const char *segment, const char *section, void *data, size_t size) {
            if (strcmp(segment, "__TEXT") == 0 && section != NULL && strcmp(section, "__info_plist") == 0)
                special = std::max(special, CSSLOT_INFOSLOT);
        }));

        special = std::max(special, CSSLOT_REQUIREMENTS);
        alloc += sizeof(struct BlobIndex);
        alloc += backing.str().size();

#ifdef LDID_NOPLIST
        baton.entitlements_ = entitlements;
#else
        if (merge)
            Analyze(mach_header, fun([&](const char *data, size_t size) {
                baton.entitlements_.assign(data, size);
            }));

        if (!baton.entitlements_.empty() || !entitlements.empty()) {
            auto combined(plist(baton.entitlements_));
            _scope({ plist_free(combined); });
            _assert(plist_get_node_type(combined) == PLIST_DICT);

            auto merging(plist(entitlements));
            _scope({ plist_free(merging); });
            _assert(plist_get_node_type(merging) == PLIST_DICT);

            plist_dict_iter iterator(NULL);
            plist_dict_new_iter(merging, &iterator);
            _scope({ free(iterator); });

            for (;;) {
                char *key(NULL);
                plist_t value(NULL);
                plist_dict_next_item(merging, iterator, &key, &value);
                if (key == NULL)
                    break;
                _scope({ free(key); });
                plist_dict_set_item(combined, key, plist_copy(value));
            }

            baton.derformat_ = der(combined);

            char *xml(NULL);
            uint32_t size;
            plist_to_xml(combined, &xml, &size);
            _scope({ free(xml); });

            baton.entitlements_.assign(xml, size);
        }
#endif

        if (!baton.entitlements_.empty()) {
            special = std::max(special, CSSLOT_ENTITLEMENTS);
            alloc += sizeof(struct BlobIndex);
            alloc += sizeof(struct Blob);
            alloc += baton.entitlements_.size();
        }

        if (!baton.derformat_.empty()) {
            special = std::max(special, CSSLOT_DERFORMAT);
            alloc += sizeof(struct BlobIndex);
            alloc += sizeof(struct Blob);
            alloc += baton.derformat_.size();
        }

        size_t directory(0);

        directory += sizeof(struct BlobIndex);
        directory += sizeof(struct Blob);
        directory += sizeof(struct CodeDirectory);
        directory += identifier.size() + 1;

        if (!team.empty())
            directory += team.size() + 1;

        for (Algorithm *algorithm : GetAlgorithms())
            alloc = Align(alloc + directory + (special + normal) * algorithm->size_, 16);

#ifndef LDID_NOSMIME
        if (!key.empty()) {
            alloc += sizeof(struct BlobIndex);
            alloc += sizeof(struct Blob);
            alloc += certificate;
        }
#endif

        return alloc;
    }), fun([&](const MachHeader &mach_header, const Baton &baton, std::streambuf &output, size_t limit, size_t left, size_t right, const std::string &overlap, const char *top, const Progress &progress) -> size_t {
        Blobs blobs;

        if (true) {
            insert(blobs, CSSLOT_REQUIREMENTS, backing);
        }

        uint64_t execs(0);
        if (mach_header.Swap(mach_header->filetype) == MH_EXECUTE)
            execs |= kSecCodeExecSegMainBinary;

        if (!baton.entitlements_.empty()) {
            std::stringbuf data;
            put(data, baton.entitlements_.data(), baton.entitlements_.size());
            insert(blobs, CSSLOT_ENTITLEMENTS, CSMAGIC_EMBEDDED_ENTITLEMENTS, data);

#ifndef LDID_NOPLIST
            auto entitlements(plist(baton.entitlements_));
            _scope({ plist_free(entitlements); });
            _assert(plist_get_node_type(entitlements) == PLIST_DICT);

            const auto entitled([&](const char *key) {
                auto item(plist_dict_get_item(entitlements, key));
                if (plist_get_node_type(item) != PLIST_BOOLEAN)
                    return false;
                uint8_t value(0);
                plist_get_bool_val(item, &value);
                return value != 0;
            });

            if (entitled("get-task-allow"))
                execs |= kSecCodeExecSegAllowUnsigned;
            if (entitled("run-unsigned-code"))
                execs |= kSecCodeExecSegAllowUnsigned;
            if (entitled("com.apple.private.cs.debugger"))
                execs |= kSecCodeExecSegDebugger;
            if (entitled("dynamic-codesigning"))
                execs |= kSecCodeExecSegJit;
            if (entitled("com.apple.private.skip-library-validation"))
                execs |= kSecCodeExecSegSkipLibraryVal;
            if (entitled("com.apple.private.amfi.can-load-cdhash"))
                execs |= kSecCodeExecSegCanLoadCdHash;
            if (entitled("com.apple.private.amfi.can-execute-cdhash"))
                execs |= kSecCodeExecSegCanExecCdHash;
#endif
        }

        if (!baton.derformat_.empty()) {
            std::stringbuf data;
            put(data, baton.derformat_.data(), baton.derformat_.size());
            insert(blobs, CSSLOT_DERFORMAT, CSMAGIC_EMBEDDED_DERFORMAT, data);
        }

        Slots posts(slots);

        mach_header.ForSection(fun([&](const char *segment, const char *section, void *data, size_t size) {
            if (strcmp(segment, "__TEXT") == 0 && section != NULL && strcmp(section, "__info_plist") == 0) {
                auto &slot(posts[CSSLOT_INFOSLOT]);
                for (Algorithm *algorithm : GetAlgorithms())
                    (*algorithm)(slot, data, size);
            }
        }));

        unsigned total(0);
        for (Algorithm *pointer : GetAlgorithms()) {
            Algorithm &algorithm(*pointer);

            std::stringbuf data;

            uint32_t special(0);
            _foreach (blob, blobs)
                special = std::max(special, blob.first);
            _foreach (slot, posts)
                special = std::max(special, slot.first);
            uint32_t normal((limit + PageSize_ - 1) / PageSize_);

            CodeDirectory directory;
            directory.version = Swap(uint32_t(0x00020400));
            directory.flags = Swap(uint32_t(flags));
            directory.nSpecialSlots = Swap(special);
            directory.codeLimit = Swap(uint32_t(limit > UINT32_MAX ? UINT32_MAX : limit));
            directory.nCodeSlots = Swap(normal);
            directory.hashSize = algorithm.size_;
            directory.hashType = algorithm.type_;
            directory.platform = platform ? 0x01 : 0x00;
            directory.pageSize = PageShift_;
            directory.spare2 = Swap(uint32_t(0));
            directory.scatterOffset = Swap(uint32_t(0));
            directory.spare3 = Swap(uint32_t(0));
            directory.codeLimit64 = Swap(uint64_t(limit > UINT32_MAX ? limit : 0));
            directory.execSegBase = Swap(uint64_t(left));
            directory.execSegLimit = Swap(uint64_t(right - left));
            directory.execSegFlags = Swap(execs);

            uint32_t offset(sizeof(Blob) + sizeof(CodeDirectory));

            directory.identOffset = Swap(uint32_t(offset));
            offset += identifier.size() + 1;

            if (team.empty())
                directory.teamIDOffset = Swap(uint32_t(0));
            else {
                directory.teamIDOffset = Swap(uint32_t(offset));
                offset += team.size() + 1;
            }

            offset += special * algorithm.size_;
            directory.hashOffset = Swap(uint32_t(offset));
            offset += normal * algorithm.size_;

            put(data, &directory, sizeof(directory));

            put(data, identifier.c_str(), identifier.size() + 1);
            if (!team.empty())
                put(data, team.c_str(), team.size() + 1);

            std::vector<uint8_t> storage((special + normal) * algorithm.size_);
            auto *hashes(&storage[special * algorithm.size_]);

            memset(storage.data(), 0, special * algorithm.size_);

            _foreach (blob, blobs) {
                auto local(reinterpret_cast<const Blob *>(&blob.second[0]));
                algorithm(hashes - blob.first * algorithm.size_, local, Swap(local->length));
            }

            _foreach (slot, posts)
                memcpy(hashes - slot.first * algorithm.size_, algorithm[slot.second], algorithm.size_);

            progress(0);
            if (normal != 1)
                for (size_t i = 0; i != normal - 1; ++i) {
                    algorithm(hashes + i * algorithm.size_, (PageSize_ * i < overlap.size() ? overlap.data() : top) + PageSize_ * i, PageSize_);
                    progress(double(i) / normal);
                }
            if (normal != 0)
                algorithm(hashes + (normal - 1) * algorithm.size_, top + PageSize_ * (normal - 1), ((limit - 1) % PageSize_) + 1);
            progress(1);

            put(data, storage.data(), storage.size());

            const auto &save(insert(blobs, total == 0 ? CSSLOT_CODEDIRECTORY : CSSLOT_ALTERNATE + total - 1, CSMAGIC_CODEDIRECTORY, data));
            algorithm(hash, save.data(), save.size());

            ++total;
        }

#ifndef LDID_NOSMIME
        if (!key.empty()) {
#ifdef LDID_NOPLIST
            auto plist(CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
            _scope({ CFRelease(plist); });

            auto cdhashes(CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks));
            _scope({ CFRelease(cdhashes); });

            CFDictionarySetValue(plist, CFSTR("cdhashes"), cdhashes);
#else
            auto plist(plist_new_dict());
            _scope({ plist_free(plist); });

            auto cdhashes(plist_new_array());
            plist_dict_set_item(plist, "cdhashes", cdhashes);
#endif

            unsigned total(0);
            for (Algorithm *pointer : GetAlgorithms()) {
                Algorithm &algorithm(*pointer);
                (void) algorithm;

                const auto &blob(blobs[total == 0 ? CSSLOT_CODEDIRECTORY : CSSLOT_ALTERNATE + total - 1]);
                ++total;

                std::vector<char> hash;
                algorithm(hash, blob.data(), blob.size());
                hash.resize(20);

#ifdef LDID_NOPLIST
                auto value(CFDataCreate(kCFAllocatorDefault, reinterpret_cast<const UInt8 *>(hash.data()), hash.size()));
                _scope({ CFRelease(value); });
                CFArrayAppendValue(cdhashes, value);
#else
                plist_array_append_item(cdhashes, plist_new_data(hash.data(), hash.size()));
#endif
            }

#ifdef LDID_NOPLIST
            auto created(CFPropertyListCreateXMLData(kCFAllocatorDefault, plist));
            _scope({ CFRelease(created); });
            auto xml(reinterpret_cast<const char *>(CFDataGetBytePtr(created)));
            auto size(CFDataGetLength(created));
#else
            char *xml(NULL);
            uint32_t size;
            plist_to_xml(plist, &xml, &size);
            _scope({ free(xml); });
#endif

            std::stringbuf data;
            const std::string &sign(blobs[CSSLOT_CODEDIRECTORY]);

            Stuff stuff(key);
            Buffer bio(sign);

            Signature signature(stuff, sign, std::string(xml, size));
            Buffer result(signature);
            std::string value(result);
            put(data, value.data(), value.size());

            const auto &save(insert(blobs, CSSLOT_SIGNATURESLOT, CSMAGIC_BLOBWRAPPER, data));
            _assert(save.size() <= certificate);
        }
#endif

        return put(output, CSMAGIC_EMBEDDED_SIGNATURE, blobs);
    }), progress);

    return hash;
}

#ifndef LDID_NOTOOLS
static void Unsign(void *idata, size_t isize, std::streambuf &output, const Progress &progress) {
    Allocate(idata, isize, output, fun([](const MachHeader &mach_header, Baton &baton, size_t size) -> size_t {
        return 0;
    }), fun([](const MachHeader &mach_header, const Baton &baton, std::streambuf &output, size_t limit, size_t left, size_t right, const std::string &overlap, const char *top, const Progress &progress) -> size_t {
        return 0;
    }), progress);
}

std::string DiskFolder::Path(const std::string &path) const {
    return path_ + path;
}

DiskFolder::DiskFolder(const std::string &path) :
    path_(path)
{
    _assert_(path_.size() != 0 && path_[path_.size() - 1] == '/', "missing / on %s", path_.c_str());
}

DiskFolder::~DiskFolder() {
    if (!std::uncaught_exception())
        for (const auto &commit : commit_)
            Commit(commit.first, commit.second);
}

#ifndef __WIN32__
std::string readlink(const std::string &path) {
    for (size_t size(1024); ; size *= 2) {
        std::string data;
        data.resize(size);

        int writ(_syscall(::readlink(path.c_str(), &data[0], data.size())));
        if (size_t(writ) >= size)
            continue;

        data.resize(writ);
        return data;
    }
}
#endif

void DiskFolder::Find(const std::string &root, const std::string &base, const Functor<void (const std::string &)> &code, const Functor<void (const std::string &, const Functor<std::string ()> &)> &link) const {
    std::string path(Path(root) + base);

    DIR *dir(opendir(path.c_str()));
    _assert(dir != NULL);
    _scope({ _syscall(closedir(dir)); });

    while (auto child = readdir(dir)) {
        std::string name(child->d_name);
        if (name == "." || name == "..")
            continue;
        if (Starts(name, ".ldid."))
            continue;

        bool directory;

#ifdef __WIN32__
        struct stat info;
        _syscall(stat((path + name).c_str(), &info));
        if (false);
        else if (S_ISDIR(info.st_mode))
            directory = true;
        else if (S_ISREG(info.st_mode))
            directory = false;
        else
            _assert_(false, "st_mode=%x", info.st_mode);
#else
        switch (child->d_type) {
            case DT_DIR:
                directory = true;
                break;
            case DT_REG:
                directory = false;
                break;
            case DT_LNK:
                link(base + name, fun([&]() { return readlink(path + name); }));
                continue;
            default:
                _assert_(false, "d_type=%u", child->d_type);
        }
#endif

        if (directory)
            Find(root, base + name + "/", code, link);
        else
            code(base + name);
    }
}

void DiskFolder::Save(const std::string &path, bool edit, const void *flag, const Functor<void (std::streambuf &)> &code) {
    if (!edit) {
        // XXX: use nullbuf
        std::stringbuf save;
        code(save);
    } else {
        std::filebuf save;
        auto from(Path(path));
        commit_[from] = Temporary(save, from);
        code(save);
    }
}

bool DiskFolder::Look(const std::string &path) const {
    return _syscall(access(Path(path).c_str(), R_OK), ENOENT) == 0;
}

void DiskFolder::Open(const std::string &path, const Functor<void (std::streambuf &, size_t, const void *)> &code) const {
    std::filebuf data;
    auto result(data.open(Path(path).c_str(), std::ios::binary | std::ios::in));
    _assert_(result == &data, "DiskFolder::Open(%s)", Path(path).c_str());

    auto length(data.pubseekoff(0, std::ios::end, std::ios::in));
    data.pubseekpos(0, std::ios::in);
    code(data, length, NULL);
}

void DiskFolder::Find(const std::string &path, const Functor<void (const std::string &)> &code, const Functor<void (const std::string &, const Functor<std::string ()> &)> &link) const {
    Find(path, "", code, link);
}
#endif

SubFolder::SubFolder(Folder &parent, const std::string &path) :
    parent_(parent),
    path_(path)
{
    _assert_(path_.size() == 0 || path_[path_.size() - 1] == '/', "missing / on %s", path_.c_str());
}

std::string SubFolder::Path(const std::string &path) const {
    return path_ + path;
}

void SubFolder::Save(const std::string &path, bool edit, const void *flag, const Functor<void (std::streambuf &)> &code) {
    return parent_.Save(Path(path), edit, flag, code);
}

bool SubFolder::Look(const std::string &path) const {
    return parent_.Look(Path(path));
}

void SubFolder::Open(const std::string &path, const Functor<void (std::streambuf &, size_t, const void *)> &code) const {
    return parent_.Open(Path(path), code);
}

void SubFolder::Find(const std::string &path, const Functor<void (const std::string &)> &code, const Functor<void (const std::string &, const Functor<std::string ()> &)> &link) const {
    return parent_.Find(Path(path), code, link);
}

std::string UnionFolder::Map(const std::string &path) const {
    auto remap(remaps_.find(path));
    if (remap == remaps_.end())
        return path;
    return remap->second;
}

void UnionFolder::Map(const std::string &path, const Functor<void (const std::string &)> &code, const std::string &file, const Functor<void (const Functor<void (std::streambuf &, size_t, const void *)> &)> &save) const {
    if (file.size() >= path.size() && file.substr(0, path.size()) == path)
        code(file.substr(path.size()));
}

UnionFolder::UnionFolder(Folder &parent) :
    parent_(parent)
{
}

void UnionFolder::Save(const std::string &path, bool edit, const void *flag, const Functor<void (std::streambuf &)> &code) {
    return parent_.Save(Map(path), edit, flag, code);
}

bool UnionFolder::Look(const std::string &path) const {
    auto file(resets_.find(path));
    if (file != resets_.end())
        return true;
    return parent_.Look(Map(path));
}

void UnionFolder::Open(const std::string &path, const Functor<void (std::streambuf &, size_t, const void *)> &code) const {
    auto file(resets_.find(path));
    if (file == resets_.end())
        return parent_.Open(Map(path), code);
    auto &entry(file->second);

    auto &data(*entry.data_);
    auto length(data.pubseekoff(0, std::ios::end, std::ios::in));
    data.pubseekpos(0, std::ios::in);
    code(data, length, entry.flag_);
}

void UnionFolder::Find(const std::string &path, const Functor<void (const std::string &)> &code, const Functor<void (const std::string &, const Functor<std::string ()> &)> &link) const {
    for (auto &reset : resets_)
        Map(path, code, reset.first, fun([&](const Functor<void (std::streambuf &, size_t, const void *)> &code) {
            auto &entry(reset.second);
            auto &data(*entry.data_);
            auto length(data.pubseekoff(0, std::ios::end, std::ios::in));
            data.pubseekpos(0, std::ios::in);
            code(data, length, entry.flag_);
        }));

    for (auto &remap : remaps_)
        Map(path, code, remap.first, fun([&](const Functor<void (std::streambuf &, size_t, const void *)> &code) {
            parent_.Open(remap.second, fun([&](std::streambuf &data, size_t length, const void *flag) {
                code(data, length, flag);
            }));
        }));

    parent_.Find(path, fun([&](const std::string &name) {
        if (deletes_.find(path + name) == deletes_.end())
            code(name);
    }), fun([&](const std::string &name, const Functor<std::string ()> &read) {
        if (deletes_.find(path + name) == deletes_.end())
            link(name, read);
    }));
}

#ifndef LDID_NOTOOLS
static void copy(std::streambuf &source, std::streambuf &target, size_t length, const Progress &progress) {
    progress(0);
    size_t total(0);
    for (;;) {
        char data[4096 * 4];
        size_t writ(source.sgetn(data, sizeof(data)));
        if (writ == 0)
            break;
        _assert(target.sputn(data, writ) == writ);
        total += writ;
        progress(double(total) / length);
    }
}

#ifndef LDID_NOPLIST
static plist_t plist(const std::string &data) {
    if (data.empty())
        return plist_new_dict();
    plist_t plist(NULL);
    if (Starts(data, "bplist00"))
        plist_from_bin(data.data(), data.size(), &plist);
    else
        plist_from_xml(data.data(), data.size(), &plist);
    _assert(plist != NULL);
    return plist;
}

static void plist_d(std::streambuf &buffer, size_t length, const Functor<void (plist_t)> &code) {
    std::stringbuf data;
    copy(buffer, data, length, dummy_);
    auto node(plist(data.str()));
    _scope({ plist_free(node); });
    _assert(plist_get_node_type(node) == PLIST_DICT);
    code(node);
}

static std::string plist_s(plist_t node) {
    _assert(node != NULL);
    _assert(plist_get_node_type(node) == PLIST_STRING);
    char *data;
    plist_get_string_val(node, &data);
    _scope({ free(data); });
    return data;
}
#endif

enum Mode {
    NoMode,
    OptionalMode,
    OmitMode,
    NestedMode,
    TopMode,
};

class Expression {
  private:
    regex_t regex_;
    std::vector<std::string> matches_;

  public:
    Expression(const std::string &code) {
        _assert_(regcomp(&regex_, code.c_str(), REG_EXTENDED) == 0, "regcomp()");
        matches_.resize(regex_.re_nsub + 1);
    }

    ~Expression() {
        regfree(&regex_);
    }

    bool operator ()(const std::string &data) {
        regmatch_t matches[matches_.size()];
        auto value(regexec(&regex_, data.c_str(), matches_.size(), matches, 0));
        if (value == REG_NOMATCH)
            return false;
        _assert_(value == 0, "regexec()");
        for (size_t i(0); i != matches_.size(); ++i)
            matches_[i].assign(data.data() + matches[i].rm_so, matches[i].rm_eo - matches[i].rm_so);
        return true;
    }

    const std::string &operator [](size_t index) const {
        return matches_[index];
    }
};

struct Rule {
    unsigned weight_;
    Mode mode_;
    std::string code_;

    mutable std::auto_ptr<Expression> regex_;

    Rule(unsigned weight, Mode mode, const std::string &code) :
        weight_(weight),
        mode_(mode),
        code_(code)
    {
    }

    Rule(const Rule &rhs) :
        weight_(rhs.weight_),
        mode_(rhs.mode_),
        code_(rhs.code_)
    {
    }

    void Compile() const {
        regex_.reset(new Expression(code_));
    }

    bool operator ()(const std::string &data) const {
        _assert(regex_.get() != NULL);
        return (*regex_)(data);
    }

    bool operator <(const Rule &rhs) const {
        if (weight_ > rhs.weight_)
            return true;
        if (weight_ < rhs.weight_)
            return false;
        return mode_ > rhs.mode_;
    }
};

struct RuleCode {
    bool operator ()(const Rule *lhs, const Rule *rhs) const {
        return lhs->code_ < rhs->code_;
    }
};

#ifndef LDID_NOPLIST
static Hash Sign(const uint8_t *prefix, size_t size, std::streambuf &buffer, Hash &hash, std::streambuf &save, const std::string &identifier, const std::string &entitlements, bool merge, const std::string &requirements, const std::string &key, const Slots &slots, size_t length, uint32_t flags, bool platform, const Progress &progress) {
    // XXX: this is a miserable fail
    std::stringbuf temp;
    put(temp, prefix, size);
    copy(buffer, temp, length - size, progress);
    // XXX: this is a stupid hack
    pad(temp, 0x10 - (length & 0xf));
    auto data(temp.str());

    HashProxy proxy(hash, save);
    return Sign(data.data(), data.size(), proxy, identifier, entitlements, merge, requirements, key, slots, flags, platform, progress);
}

struct State {
    std::map<std::string, Hash> files;
    std::map<std::string, std::string> links;

    void Merge(const std::string &root, const State &state) {
        for (const auto &entry : state.files)
            files[root + entry.first] = entry.second;
        for (const auto &entry : state.links)
            links[root + entry.first] = entry.second;
    }
};

Bundle Sign(const std::string &root, Folder &parent, const std::string &key, State &remote, const std::string &requirements, const Functor<std::string (const std::string &, const std::string &)> &alter, const Progress &progress) {
    std::string executable;
    std::string identifier;

    bool mac(false);

    std::string info("Info.plist");

    SubFolder folder(parent, [&]() {
        if (parent.Look(info))
            return "";
        mac = true;
        if (false);
        else if (parent.Look("Contents/" + info))
            return "Contents/";
        else if (parent.Look("Resources/" + info)) {
            info = "Resources/" + info;
            return "";
        } else _assert_(false, "cannot find Info.plist");
    }());

    folder.Open(info, fun([&](std::streambuf &buffer, size_t length, const void *flag) {
        plist_d(buffer, length, fun([&](plist_t node) {
            executable = plist_s(plist_dict_get_item(node, "CFBundleExecutable"));
            identifier = plist_s(plist_dict_get_item(node, "CFBundleIdentifier"));
        }));
    }));

    if (mac && info == "Info.plist")
        executable = "MacOS/" + executable;

    progress(root + "*");

    std::string entitlements;
    folder.Open(executable, fun([&](std::streambuf &buffer, size_t length, const void *flag) {
        // XXX: this is a miserable fail
        std::stringbuf temp;
        copy(buffer, temp, length, progress);
        // XXX: this is a stupid hack
        pad(temp, 0x10 - (length & 0xf));
        auto data(temp.str());
        entitlements = alter(root, Analyze(data.data(), data.size()));
    }));

    static const std::string directory("_CodeSignature/");
    static const std::string signature(directory + "CodeResources");

    std::map<std::string, std::multiset<Rule>> versions;

    auto &rules1(versions[""]);
    auto &rules2(versions["2"]);

    const std::string resources(mac ? "Resources/" : "");

    if (true) {
        rules1.insert(Rule{1, NoMode, "^" + (resources == "" ? ".*" : resources)});
        rules1.insert(Rule{1000, OptionalMode, "^" + resources + ".*\\.lproj/"});
        rules1.insert(Rule{1100, OmitMode, "^" + resources + ".*\\.lproj/locversion.plist$"});
        rules1.insert(Rule{1010, NoMode, "^" + resources + "Base\\.lproj/"});
        rules1.insert(Rule{1, NoMode, "^version.plist$"});
    }

    if (true) {
        rules2.insert(Rule{11, NoMode, ".*\\.dSYM($|/)"});
        if (mac) rules2.insert(Rule{20, NoMode, "^" + resources});
        rules2.insert(Rule{2000, OmitMode, "^(.*/)?\\.DS_Store$"});
        if (mac) rules2.insert(Rule{10, NestedMode, "^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(Automator|Spotlight|LoginItems))/"});
        rules2.insert(Rule{1, NoMode, "^.*"});
        rules2.insert(Rule{1000, OptionalMode, "^" + resources + ".*\\.lproj/"});
        rules2.insert(Rule{1100, OmitMode, "^" + resources + ".*\\.lproj/locversion.plist$"});
        if (!mac) rules2.insert(Rule{1010, NoMode, "^Base\\.lproj/"});
        rules2.insert(Rule{20, OmitMode, "^Info\\.plist$"});
        rules2.insert(Rule{20, OmitMode, "^PkgInfo$"});
        if (mac) rules2.insert(Rule{10, NestedMode, "^[^/]+$"});
        rules2.insert(Rule{20, NoMode, "^embedded\\.provisionprofile$"});
        if (mac) rules2.insert(Rule{1010, NoMode, "^" + resources + "Base\\.lproj/"});
        rules2.insert(Rule{20, NoMode, "^version\\.plist$"});
    }

    State local;

    std::string failure(mac ? "Contents/|Versions/[^/]*/Resources/" : "");
    Expression nested("^(Frameworks/[^/]*\\.framework|PlugIns/[^/]*\\.appex(()|/[^/]*.app))/(" + failure + ")Info\\.plist$");
    std::map<std::string, Bundle> bundles;

    folder.Find("", fun([&](const std::string &name) {
        if (!nested(name))
            return;
        auto bundle(root + Split(name).dir);
        if (mac) {
            _assert(!bundle.empty());
            bundle = Split(bundle.substr(0, bundle.size() - 1)).dir;
        }
        SubFolder subfolder(folder, bundle);

        bundles[nested[1]] = Sign(bundle, subfolder, key, local, "", Starts(name, "PlugIns/") ? alter :
            static_cast<const Functor<std::string (const std::string &, const std::string &)> &>(fun([&](const std::string &, const std::string &) -> std::string { return entitlements; }))
        , progress);
    }), fun([&](const std::string &name, const Functor<std::string ()> &read) {
    }));

    std::set<std::string> excludes;

    auto exclude([&](const std::string &name) {
        // BundleDiskRep::adjustResources -> builder.addExclusion
        if (name == executable || Starts(name, directory) || Starts(name, "_MASReceipt/") || name == "CodeResources")
            return true;

        for (const auto &bundle : bundles)
            if (Starts(name, bundle.first + "/")) {
                excludes.insert(name);
                return true;
            }

        return false;
    });

    folder.Find("", fun([&](const std::string &name) {
        if (exclude(name))
            return;

        if (local.files.find(name) != local.files.end())
            return;
        auto &hash(local.files[name]);

        folder.Open(name, fun([&](std::streambuf &data, size_t length, const void *flag) {
            progress(root + name);

            union {
                struct {
                    uint32_t magic;
                    uint32_t count;
                };

                uint8_t bytes[8];
            } header;

            auto size(most(data, &header.bytes, sizeof(header.bytes)));

            if (name != "_WatchKitStub/WK" && size == sizeof(header.bytes))
                switch (Swap(header.magic)) {
                    case FAT_MAGIC:
                        // Java class file format
                        if (Swap(header.count) >= 40)
                            break;
                    case FAT_CIGAM:
                    case MH_MAGIC: case MH_MAGIC_64:
                    case MH_CIGAM: case MH_CIGAM_64:
                        folder.Save(name, true, flag, fun([&](std::streambuf &save) {
                            Slots slots;
                            Sign(header.bytes, size, data, hash, save, identifier, "", false, "", key, slots, length, 0, false, Progression(progress, root + name));
                        }));
                        return;
                }

            folder.Save(name, false, flag, fun([&](std::streambuf &save) {
                HashProxy proxy(hash, save);
                put(proxy, header.bytes, size);
                copy(data, proxy, length - size, progress);
            }));
        }));
    }), fun([&](const std::string &name, const Functor<std::string ()> &read) {
        if (exclude(name))
            return;

        local.links[name] = read();
    }));

    auto plist(plist_new_dict());
    _scope({ plist_free(plist); });

    for (const auto &version : versions) {
        auto files(plist_new_dict());
        plist_dict_set_item(plist, ("files" + version.first).c_str(), files);

        for (const auto &rule : version.second)
            rule.Compile();

        bool old(&version.second == &rules1);

        for (const auto &hash : local.files)
            for (const auto &rule : version.second)
                if (rule(hash.first)) {
                    if (!old && mac && excludes.find(hash.first) != excludes.end());
                    else if (old && rule.mode_ == NoMode)
                        plist_dict_set_item(files, hash.first.c_str(), plist_new_data(reinterpret_cast<const char *>(hash.second.sha1_), sizeof(hash.second.sha1_)));
                    else if (rule.mode_ != OmitMode) {
                        auto entry(plist_new_dict());
                        plist_dict_set_item(entry, "hash", plist_new_data(reinterpret_cast<const char *>(hash.second.sha1_), sizeof(hash.second.sha1_)));
                        if (!old)
                            plist_dict_set_item(entry, "hash2", plist_new_data(reinterpret_cast<const char *>(hash.second.sha256_), sizeof(hash.second.sha256_)));
                        if (rule.mode_ == OptionalMode)
                            plist_dict_set_item(entry, "optional", plist_new_bool(true));
                        plist_dict_set_item(files, hash.first.c_str(), entry);
                    }

                    break;
                }

        if (!old)
            for (const auto &link : local.links)
                for (const auto &rule : version.second)
                    if (rule(link.first)) {
                        if (rule.mode_ != OmitMode) {
                            auto entry(plist_new_dict());
                            plist_dict_set_item(entry, "symlink", plist_new_string(link.second.c_str()));
                            if (rule.mode_ == OptionalMode)
                                plist_dict_set_item(entry, "optional", plist_new_bool(true));
                            plist_dict_set_item(files, link.first.c_str(), entry);
                        }

                        break;
                    }

        if (!old && mac)
            for (const auto &bundle : bundles) {
                auto entry(plist_new_dict());
                plist_dict_set_item(entry, "cdhash", plist_new_data(reinterpret_cast<const char *>(bundle.second.hash.sha256_), sizeof(bundle.second.hash.sha256_)));
                plist_dict_set_item(entry, "requirement", plist_new_string("anchor apple generic"));
                plist_dict_set_item(files, bundle.first.c_str(), entry);
            }
    }

    for (const auto &version : versions) {
        auto rules(plist_new_dict());
        plist_dict_set_item(plist, ("rules" + version.first).c_str(), rules);

        std::multiset<const Rule *, RuleCode> ordered;
        for (const auto &rule : version.second)
            ordered.insert(&rule);

        for (const auto &rule : ordered)
            if (rule->weight_ == 1 && rule->mode_ == NoMode)
                plist_dict_set_item(rules, rule->code_.c_str(), plist_new_bool(true));
            else {
                auto entry(plist_new_dict());
                plist_dict_set_item(rules, rule->code_.c_str(), entry);

                switch (rule->mode_) {
                    case NoMode:
                        break;
                    case OmitMode:
                        plist_dict_set_item(entry, "omit", plist_new_bool(true));
                        break;
                    case OptionalMode:
                        plist_dict_set_item(entry, "optional", plist_new_bool(true));
                        break;
                    case NestedMode:
                        plist_dict_set_item(entry, "nested", plist_new_bool(true));
                        break;
                    case TopMode:
                        plist_dict_set_item(entry, "top", plist_new_bool(true));
                        break;
                }

                if (rule->weight_ >= 10000)
                    plist_dict_set_item(entry, "weight", plist_new_uint(rule->weight_));
                else if (rule->weight_ != 1)
                    plist_dict_set_item(entry, "weight", plist_new_real(rule->weight_));
            }
    }

    folder.Save(signature, true, NULL, fun([&](std::streambuf &save) {
        HashProxy proxy(local.files[signature], save);
        char *xml(NULL);
        uint32_t size;
        plist_to_xml(plist, &xml, &size);
        _scope({ free(xml); });
        put(proxy, xml, size);
    }));

    Bundle bundle;
    bundle.path = folder.Path(executable);

    folder.Open(executable, fun([&](std::streambuf &buffer, size_t length, const void *flag) {
        progress(root + executable);
        folder.Save(executable, true, flag, fun([&](std::streambuf &save) {
            Slots slots;
            slots[1] = local.files.at(info);
            slots[3] = local.files.at(signature);
            bundle.hash = Sign(NULL, 0, buffer, local.files[executable], save, identifier, entitlements, false, requirements, key, slots, length, 0, false, Progression(progress, root + executable));
        }));
    }));

    remote.Merge(root, local);
    return bundle;
}

Bundle Sign(const std::string &root, Folder &folder, const std::string &key, const std::string &requirements, const Functor<std::string (const std::string &, const std::string &)> &alter, const Progress &progress) {
    State local;
    return Sign(root, folder, key, local, requirements, alter, progress);
}
#endif

#endif
}

std::string Hex(const uint8_t *data, size_t size) {
    std::string hex;
    hex.reserve(size * 2);
    for (size_t i(0); i != size; ++i) {
        hex += "0123456789abcdef"[data[i] >> 4];
        hex += "0123456789abcdef"[data[i] & 0xf];
    }
    return hex;
}

static void usage(const char *argv0) {
    fprintf(stderr, "Link Identity Editor %s\n\n", LDID_VERSION);
    fprintf(stderr, "usage: %s -S[entitlements.xml] <binary>\n", argv0);
    fprintf(stderr, "   %s -e MobileSafari\n", argv0);
    fprintf(stderr, "   %s -S cat\n", argv0);
    fprintf(stderr, "   %s -Stfp.xml gdb\n", argv0);
    fprintf(stderr, "\n");
    fprintf(stderr, "Other Options\n");
    fprintf(stderr, "   -Kkey.p12     Sign using private key in key.p12\n");
    fprintf(stderr, "   -M            Merge entitlements with any existing\n");
    fprintf(stderr, "   -h            Print CDHash of file\n");
}

#ifndef LDID_NOTOOLS
int ldid_main(int argc, char *argv[]) {
#ifndef LDID_NOSMIME
    OpenSSL_add_all_algorithms();
#endif

    union {
        uint16_t word;
        uint8_t byte[2];
    } endian = {1};

    little_ = endian.byte[0];

    bool flag_r(false);
    bool flag_e(false);
    bool flag_q(false);

    bool flag_H(false);
    bool flag_h(false);

#ifndef LDID_NOFLAGT
    bool flag_T(false);
#endif

    bool flag_S(false);
    bool flag_s(false);

    bool flag_D(false);
    bool flag_d(false);

    bool flag_A(false);
    bool flag_a(false);

    bool flag_u(false);

    bool flag_M(false);

    uint32_t flags(0);
    bool platform(false);

    uint32_t flag_CPUType(_not(uint32_t));
    uint32_t flag_CPUSubtype(_not(uint32_t));

    const char *flag_I(NULL);

#ifndef LDID_NOFLAGT
    bool timeh(false);
    uint32_t timev(0);
#endif

    Map entitlements;
    Map requirements;
    Map key;
    ldid::Slots slots;

    std::vector<std::string> files;

    if (argc == 1) {
        usage(argv[0]);
        return 0;
    }

    for (int argi(1); argi != argc; ++argi)
        if (argv[argi][0] != '-')
            files.push_back(argv[argi]);
        else switch (argv[argi][1]) {
            case 'r':
                _assert(!flag_s);
                _assert(!flag_S);
                flag_r = true;
            break;

            case 'e': flag_e = true; break;

            case 'E': {
                const char *string = argv[argi] + 2;
                const char *colon = strchr(string, ':');
                _assert(colon != NULL);
                Map file(colon + 1, O_RDONLY, PROT_READ, MAP_PRIVATE);
                char *arge;
                unsigned number(strtoul(string, &arge, 0));
                _assert(arge == colon);
                auto &slot(slots[number]);
                for (Algorithm *algorithm : GetAlgorithms())
                    (*algorithm)(slot, file.data(), file.size());
            } break;

            case 'q': flag_q = true; break;

            case 'H': {
                const char *hash = argv[argi] + 2;

                if (!flag_H) {
                    flag_H = true;

                    do_sha1 = false;
                    do_sha256 = false;

                    fprintf(stderr, "WARNING: -H is only present for compatibility with a fork of ldid\n");
                    fprintf(stderr, "         you should NOT be manually specifying the hash algorithm\n");
                }

                if (false);
                else if (strcmp(hash, "sha1") == 0)
                    do_sha1 = true;
                else if (strcmp(hash, "sha256") == 0)
                    do_sha256 = true;
                else _assert(false);
            } break;

            case 'h': flag_h = true; break;

            case 'Q': {
                const char *xml = argv[argi] + 2;
                requirements.open(xml, O_RDONLY, PROT_READ, MAP_PRIVATE);
            } break;

            case 'D': flag_D = true; break;
            case 'd': flag_d = true; break;

            case 'a': flag_a = true; break;

            case 'A':
                _assert(!flag_A);
                flag_A = true;
                if (argv[argi][2] != '\0') {
                    const char *cpu = argv[argi] + 2;
                    const char *colon = strchr(cpu, ':');
                    _assert(colon != NULL);
                    char *arge;
                    flag_CPUType = strtoul(cpu, &arge, 0);
                    _assert(arge == colon);
                    flag_CPUSubtype = strtoul(colon + 1, &arge, 0);
                    _assert(arge == argv[argi] + strlen(argv[argi]));
                }
            break;

            case 'C': {
                const char *name = argv[argi] + 2;
                if (false);
                else if (strcmp(name, "host") == 0)
                    flags |= kSecCodeSignatureHost;
                else if (strcmp(name, "adhoc") == 0)
                    flags |= kSecCodeSignatureAdhoc;
                else if (strcmp(name, "hard") == 0)
                    flags |= kSecCodeSignatureForceHard;
                else if (strcmp(name, "kill") == 0)
                    flags |= kSecCodeSignatureForceKill;
                else if (strcmp(name, "expires") == 0)
                    flags |= kSecCodeSignatureForceExpiration;
                else if (strcmp(name, "restrict") == 0)
                    flags |= kSecCodeSignatureRestrict;
                else if (strcmp(name, "enforcement") == 0)
                    flags |= kSecCodeSignatureEnforcement;
                else if (strcmp(name, "library-validation") == 0)
                    flags |= kSecCodeSignatureLibraryValidation;
                else if (strcmp(name, "runtime") == 0)
                    flags |= kSecCodeSignatureRuntime;
                else _assert(false);
            } break;

            case 'P':
                platform = true;
            break;

            case 's':
                _assert(!flag_r);
                _assert(!flag_S);
                flag_s = true;
            break;

            case 'S':
                _assert(!flag_r);
                _assert(!flag_s);
                flag_S = true;
                if (argv[argi][2] != '\0') {
                    const char *xml = argv[argi] + 2;
                    entitlements.open(xml, O_RDONLY, PROT_READ, MAP_PRIVATE);
                }
            break;

            case 'M':
                flag_M = true;
            break;

            case 'K':
                if (argv[argi][2] != '\0')
                    key.open(argv[argi] + 2, O_RDONLY, PROT_READ, MAP_PRIVATE);
            break;

#ifndef LDID_NOFLAGT
            case 'T': {
                flag_T = true;
                if (argv[argi][2] == '-')
                    timeh = true;
                else {
                    char *arge;
                    timev = strtoul(argv[argi] + 2, &arge, 0);
                    _assert(arge == argv[argi] + strlen(argv[argi]));
                }
            } break;
#endif

            case 'u': {
                flag_u = true;
            } break;

            case 'I': {
                flag_I = argv[argi] + 2;
            } break;

            default:
                usage(argv[0]);
                return 1;
            break;
        }

    _assert(flag_S || key.empty());
    _assert(flag_S || flag_I == NULL);

    if (flag_d && !flag_h) {
        flag_h = true;
        fprintf(stderr, "WARNING: -d also (temporarily) does the behavior of -h for compatibility with a fork of ldid\n");
    }

    if (files.empty())
        return 0;

    size_t filei(0), filee(0);
    _foreach (file, files) try {
        std::string path(file);

        struct stat info;
        _syscall(stat(path.c_str(), &info));

        if (S_ISDIR(info.st_mode)) {
            _assert(flag_S);
#ifndef LDID_NOPLIST
            ldid::DiskFolder folder(path + "/");
            path += "/" + Sign("", folder, key, requirements, ldid::fun([&](const std::string &, const std::string &) -> std::string { return entitlements; }), dummy_).path;
#else
            _assert(false);
#endif
        } else if (flag_S || flag_r) {
            Map input(path, O_RDONLY, PROT_READ, MAP_PRIVATE);

            std::filebuf output;
            Split split(path);
            auto temp(Temporary(output, split));

            if (flag_r)
                ldid::Unsign(input.data(), input.size(), output, dummy_);
            else {
                std::string identifier(flag_I ?: split.base.c_str());
                ldid::Sign(input.data(), input.size(), output, identifier, entitlements, flag_M, requirements, key, slots, flags, platform, dummy_);
            }

            Commit(path, temp);
        }

        bool modify(false);
#ifndef LDID_NOFLAGT
        if (flag_T)
            modify = true;
#endif
        if (flag_s)
            modify = true;

        Map mapping(path, modify);
        FatHeader fat_header(mapping.data(), mapping.size());

        _foreach (mach_header, fat_header.GetMachHeaders()) {
            struct linkedit_data_command *signature(NULL);
            struct encryption_info_command *encryption(NULL);

            if (flag_A) {
                if (mach_header.GetCPUType() != flag_CPUType)
                    continue;
                if (mach_header.GetCPUSubtype() != flag_CPUSubtype)
                    continue;
            }

            if (flag_a)
                printf("cpu=0x%x:0x%x\n", mach_header.GetCPUType(), mach_header.GetCPUSubtype());

            _foreach (load_command, mach_header.GetLoadCommands()) {
                uint32_t cmd(mach_header.Swap(load_command->cmd));

                if (false);
                else if (cmd == LC_CODE_SIGNATURE)
                    signature = reinterpret_cast<struct linkedit_data_command *>(load_command);
                else if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64)
                    encryption = reinterpret_cast<struct encryption_info_command *>(load_command);
                else if (cmd == LC_LOAD_DYLIB) {
                    volatile struct dylib_command *dylib_command(reinterpret_cast<struct dylib_command *>(load_command));
                    const char *name(reinterpret_cast<const char *>(load_command) + mach_header.Swap(dylib_command->dylib.name));

                    if (strcmp(name, "/System/Library/Frameworks/UIKit.framework/UIKit") == 0) {
                        if (flag_u) {
                            Version version;
                            version.value = mach_header.Swap(dylib_command->dylib.current_version);
                            printf("uikit=%u.%u.%u\n", version.major, version.minor, version.patch);
                        }
                    }
                }
#ifndef LDID_NOFLAGT
                else if (cmd == LC_ID_DYLIB) {
                    volatile struct dylib_command *dylib_command(reinterpret_cast<struct dylib_command *>(load_command));

                    if (flag_T) {
                        uint32_t timed;

                        if (!timeh)
                            timed = timev;
                        else {
                            dylib_command->dylib.timestamp = 0;
                            timed = hash(reinterpret_cast<uint8_t *>(mach_header.GetBase()), mach_header.GetSize(), timev);
                        }

                        dylib_command->dylib.timestamp = mach_header.Swap(timed);
                    }
                }
#endif
            }

            if (flag_d && encryption != NULL) {
                printf("cryptid=%d\n", mach_header.Swap(encryption->cryptid));
            }

            if (flag_D) {
                _assert(encryption != NULL);
                encryption->cryptid = mach_header.Swap(0);
            }

            if (flag_e) {
                _assert(signature != NULL);

                uint32_t data = mach_header.Swap(signature->dataoff);

                uint8_t *top = reinterpret_cast<uint8_t *>(mach_header.GetBase());
                uint8_t *blob = top + data;
                struct SuperBlob *super = reinterpret_cast<struct SuperBlob *>(blob);

                for (size_t index(0); index != Swap(super->count); ++index)
                    if (Swap(super->index[index].type) == CSSLOT_ENTITLEMENTS) {
                        uint32_t begin = Swap(super->index[index].offset);
                        struct Blob *entitlements = reinterpret_cast<struct Blob *>(blob + begin);
                        fwrite(entitlements + 1, 1, Swap(entitlements->length) - sizeof(*entitlements), stdout);
                    }
            }

            if (flag_q) {
                _assert(signature != NULL);

                uint32_t data = mach_header.Swap(signature->dataoff);

                uint8_t *top = reinterpret_cast<uint8_t *>(mach_header.GetBase());
                uint8_t *blob = top + data;
                struct SuperBlob *super = reinterpret_cast<struct SuperBlob *>(blob);

                for (size_t index(0); index != Swap(super->count); ++index)
                    if (Swap(super->index[index].type) == CSSLOT_REQUIREMENTS) {
                        uint32_t begin = Swap(super->index[index].offset);
                        struct Blob *requirement = reinterpret_cast<struct Blob *>(blob + begin);
                        fwrite(requirement, 1, Swap(requirement->length), stdout);
                    }
            }

            if (flag_s) {
                _assert(signature != NULL);

                uint32_t data = mach_header.Swap(signature->dataoff);

                uint8_t *top = reinterpret_cast<uint8_t *>(mach_header.GetBase());
                uint8_t *blob = top + data;
                struct SuperBlob *super = reinterpret_cast<struct SuperBlob *>(blob);

                for (size_t index(0); index != Swap(super->count); ++index)
                    if (Swap(super->index[index].type) == CSSLOT_CODEDIRECTORY) {
                        uint32_t begin = Swap(super->index[index].offset);
                        struct CodeDirectory *directory = reinterpret_cast<struct CodeDirectory *>(blob + begin + sizeof(Blob));

                        uint8_t (*hashes)[LDID_SHA1_DIGEST_LENGTH] = reinterpret_cast<uint8_t (*)[LDID_SHA1_DIGEST_LENGTH]>(blob + begin + Swap(directory->hashOffset));
                        uint32_t pages = Swap(directory->nCodeSlots);

                        if (pages != 1)
                            for (size_t i = 0; i != pages - 1; ++i)
                                LDID_SHA1(top + PageSize_ * i, PageSize_, hashes[i]);
                        if (pages != 0)
                            LDID_SHA1(top + PageSize_ * (pages - 1), ((data - 1) % PageSize_) + 1, hashes[pages - 1]);
                    }
            }

            if (flag_h) {
                _assert(signature != NULL);

                auto algorithms(GetAlgorithms());

                uint32_t data = mach_header.Swap(signature->dataoff);

                uint8_t *top = reinterpret_cast<uint8_t *>(mach_header.GetBase());
                uint8_t *blob = top + data;
                struct SuperBlob *super = reinterpret_cast<struct SuperBlob *>(blob);

                struct Candidate {
                    CodeDirectory *directory_;
                    size_t size_;
                    Algorithm &algorithm_;
                    std::string hash_;
                };

                std::map<uint8_t, Candidate> candidates;

                for (size_t index(0); index != Swap(super->count); ++index) {
                    auto type(Swap(super->index[index].type));
                    if ((type == CSSLOT_CODEDIRECTORY || type >= CSSLOT_ALTERNATE) && type != CSSLOT_SIGNATURESLOT) {
                        uint32_t begin = Swap(super->index[index].offset);
                        uint32_t end = index + 1 == Swap(super->count) ? Swap(super->blob.length) : Swap(super->index[index + 1].offset);
                        struct CodeDirectory *directory = reinterpret_cast<struct CodeDirectory *>(blob + begin + sizeof(Blob));
                        auto type(directory->hashType);
                        _assert(type > 0 && type <= algorithms.size());
                        auto &algorithm(*algorithms[type - 1]);
                        uint8_t hash[algorithm.size_];
                        algorithm(hash, blob + begin, end - begin);
                        candidates.insert({type, {directory, end - begin, algorithm, Hex(hash, 20)}});
                    }
                }

                _assert(!candidates.empty());
                auto best(candidates.end());
                --best;

                const auto directory(best->second.directory_);
                const auto flags(Swap(directory->flags));

                std::string names;
                if (flags & kSecCodeSignatureHost)
                    names += ",host";
                if (flags & kSecCodeSignatureAdhoc)
                    names += ",adhoc";
                if (flags & kSecCodeSignatureForceHard)
                    names += ",hard";
                if (flags & kSecCodeSignatureForceKill)
                    names += ",kill";
                if (flags & kSecCodeSignatureForceExpiration)
                    names += ",expires";
                if (flags & kSecCodeSignatureRestrict)
                    names += ",restrict";
                if (flags & kSecCodeSignatureEnforcement)
                    names += ",enforcement";
                if (flags & kSecCodeSignatureLibraryValidation)
                    names += ",library-validation";
                if (flags & kSecCodeSignatureRuntime)
                    names += ",runtime";

                printf("CodeDirectory v=%x size=%zd flags=0x%x(%s) hashes=%d+%d location=embedded\n",
                    Swap(directory->version), best->second.size_, flags, names.empty() ? "none" : names.c_str() + 1, Swap(directory->nCodeSlots), Swap(directory->nSpecialSlots));
                printf("Hash type=%s size=%d\n", best->second.algorithm_.name(), directory->hashSize);

                std::string choices;
                for (const auto &candidate : candidates) {
                    auto choice(candidate.second.algorithm_.name());
                    choices += ',';
                    choices += choice;
                    printf("CandidateCDHash %s=%s\n", choice, candidate.second.hash_.c_str());
                }
                printf("Hash choices=%s\n", choices.c_str() + 1);

                printf("CDHash=%s\n", best->second.hash_.c_str());
            }
        }

        ++filei;
    } catch (const char *) {
        ++filee;
        ++filei;
    }

    return filee;
}
#endif
