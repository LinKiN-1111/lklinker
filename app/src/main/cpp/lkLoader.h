//
// Created by linkin on 2025/7/29.
//

#ifndef LKLINKER_LKLOADER_H
#define LKLINKER_LKLOADER_H

#include <sys/mman.h>
#include <link.h>
#include <string>
#include "original/linker_soinfo.h"
#include "log.h"
#include "gnu_helper.h"

#define R_AARCH64_TLS_TPREL64           1030
#define R_AARCH64_TLS_DTPREL32          1031

//重定位表相关
#define R_GENERIC_NONE 0
#define R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define R_GENERIC_GLOB_DAT  R_AARCH64_GLOB_DAT
#define R_GENERIC_RELATIVE  R_AARCH64_RELATIVE
#define R_GENERIC_IRELATIVE R_AARCH64_IRELATIVE

#define FLAG_LINKER           0x00000010 // The linker itself
#define FLAG_GNU_HASH         0x00000040 // uses gnu hash
#define SUPPORTED_DT_FLAGS_1 (DF_1_NOW | DF_1_GLOBAL | DF_1_NODELETE | DF_1_PIE)

#define PAGE_START(x) ((x) & PAGE_MASK)
#define PAGE_END(x) PAGE_START((x) + (PAGE_SIZE-1))
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)
#define MAYBE_MAP_FLAG(x, from, to)  (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))
#define powerof2(x) ((((x)-1)&(x))==0)
#if defined(__LP64__)
#define ELFW(what) ELF64_ ## what
#else
#define ELFW(what) ELF32_ ## what
#endif

class lkLoader {
private:
    int fd_;        //目标elf的fd
    off64_t file_offset_;   //当前的文件偏移
    off64_t file_size_;     //elf文件在磁盘中的大小
    ElfW(Ehdr) header_;    //不是指针，作为结构体存储了elt头的内容
    size_t phdr_num_;      //程序头表的数量
    const ElfW(Phdr)* phdr_table_;   //存放从内存中读入的一份程序头表,自己mmap了一份存储
    size_t shdr_num_;
    const ElfW(Shdr)* shdr_table_;
    const ElfW(Dyn)* dynamic_;
    const char* strtab_;  //strtab的起始地址
    size_t strtab_size_;  //statab的大小
    std::string name_;    //elf文件的路径
    void* load_start_;    //加载段起始地址
    size_t load_size_;    //加载段大小
    ElfW(Addr) load_bias_;  //加载段的实际偏移
    void* start_addr_;      //读入内存后elf文件在内存中的起始位置
    const ElfW(Phdr)* loaded_phdr_;
    soinfo* si_;            //指向自己在系统linker中的so
public:
    lkLoader(): fd_(-1), file_offset_(0), file_size_(0), phdr_num_(0),
                phdr_table_(nullptr), shdr_table_(nullptr), shdr_num_(0), dynamic_(nullptr), strtab_(nullptr),
                strtab_size_(0), load_start_(nullptr), load_size_(0) {
    }
    size_t phdr_count() const { return phdr_num_; }
    ElfW(Addr) load_start() const { return reinterpret_cast<ElfW(Addr)>(load_start_); }
    size_t load_size() const { return load_size_; }
    ElfW(Addr) load_bias() const { return load_bias_; }
    const ElfW(Phdr)* loaded_phdr() const { return loaded_phdr_; }


public:
    void lkload_library(const char* path);
    bool lkRead_DISK_ELF(const char* name,int fd,off64_t file_offset,off64_t file_size);
    bool lkReadElfHeader();
    bool lkReadProgramHeaders();
    bool lkLoad();
    //保留足够的虚拟地址,用于存放所有可加载段
    bool ReserveAddressSpace();
    //获取可加载段的最低地址和可加载段的页对齐后的大小
    size_t phdr_table_get_load_size(const ElfW(Phdr)* phdr_table, size_t phdr_count,ElfW(Addr)* out_min_vaddr);
    //分配内存,将加载段放入内存中
    bool LoadSegments();

    //就是在找PT_PHDR段并检查，此段指定了段表本身的位置和大小
    bool FindPhdr();
    bool CheckPhdr(ElfW(Addr) loaded);
};


class plain_reloc_iterator {
#if defined(USE_RELA)
    typedef ElfW(Rela) rel_t;
#else
    typedef ElfW(Rel) rel_t;
#endif
public:
    plain_reloc_iterator(rel_t* rel_array, size_t count)
            : begin_(rel_array), end_(begin_ + count), current_(begin_) {}

    bool has_next() {
        return current_ < end_;
    }

    rel_t* next() {
        return current_++;
    }
private:
    rel_t* const begin_;
    rel_t* const end_;
    rel_t* current_;

};

class sleb128_decoder {
public:
    sleb128_decoder(const uint8_t* buffer, size_t count)
            : current_(buffer), end_(buffer+count) { }

    size_t pop_front() {
        size_t value = 0;
        static const size_t size = CHAR_BIT * sizeof(value);

        size_t shift = 0;
        uint8_t byte;

        do {
            if (current_ >= end_) {
                LOGE("sleb128_decoder ran out of bounds");
            }
            byte = *current_++;
            value |= (static_cast<size_t>(byte & 127) << shift);
            shift += 7;
        } while (byte & 128);

        if (shift < size && (byte & 64)) {
            value |= -(static_cast<size_t>(1) << shift);
        }

        return value;
    }

private:
    const uint8_t* current_;
    const uint8_t* const end_;
};

#endif //LKLINKER_LKLOADER_H
