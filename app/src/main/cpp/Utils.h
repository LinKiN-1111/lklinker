//
// Created by linkin on 2025/7/29.
//

#ifndef LKLINKER_UTILS_H
#define LKLINKER_UTILS_H

#include <stdlib.h>
#include <link.h>
#include "original/linker_soinfo.h"
#include "log.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include "elf.h"
#include <unistd.h>
struct Module {
    ElfW(Addr) base;
    size_t size;
};

class Utils {
public:
    static void load_modules();
    //这个函数的目的是将整个程序头表映射到另外一片mmap的内存,为了页面对齐复制了比较多,返回值为新的程序头指针
    static void* getMapData(int fd, off64_t base_offset, size_t elf_offset, size_t size);
    //防止地址加上一个大小后越界,out作为数据返回,bool判断是否越界
    static bool safe_add(off64_t* out, off64_t a, size_t b);
    //获取该偏移的页起始地址
    static off64_t page_start(off64_t offset);
    //获取该偏移在页中的偏移地址
    static size_t page_offset(off64_t offset);
    //获取当前linker的soinfo
    static soinfo* get_soinfo(const char* so_name);
    //自己解析内存elf文件找到导出函数,绕过系统的dlopen限制
    static ElfW(Addr)  get_export_func(char* path, char* func_name);

    //获取重定位的类别
    static ElfW(Addr) get_addend(ElfW(Rela)* rela, ElfW(Addr) reloc_addr __unused);

    //获取传入参数的函数指针?
    static ElfW(Addr) call_ifunc_resolver(ElfW(Addr) resolver_addr);

    //找动态段
    static void phdr_table_get_dynamic_section(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                               ElfW(Addr) load_bias, ElfW(Dyn)** dynamic,
                                               ElfW(Word)* dynamic_flags) ;

    static int phdr_table_set_gnu_relro_prot(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                             ElfW(Addr) load_bias, int prot_flags);

};


#endif //LKLINKER_UTILS_H
