//
// Created by linkin on 2025/7/29.
//

#include "Utils.h"
#include <unordered_map>
#include <string>
#include <sys/mman.h>
#define PAGE_START(x) ((x) & PAGE_MASK)
#define PAGE_END(x) PAGE_START((x) + (PAGE_SIZE-1))
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)
#define MAYBE_MAP_FLAG(x, from, to)  (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))

extern std::unordered_map<std::string, Module> g_modules;
//下面的举个例子： PAGE_SIZE是0x1000，PAGE_SIZE-1 = 0xfff,取反就是0xfffff000
constexpr off64_t kPageMask = ~static_cast<off64_t>(PAGE_SIZE-1);

std::string extract_soname(const std::string& path) {
    // 查找最后一个 '/' 的位置
    size_t pos = path.find_last_of('/');
    // 返回从该位置后的子字符串
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

//遍历maps文件，找到所有加载的so，存放到g_module这个maps中
void Utils::load_modules() {
    g_modules.clear();
    char line[1024];
    ElfW(Addr) base = 0; //ElfW很简单，就是直接在前面添加前缀
    FILE *fp = fopen("/proc/self/maps", "r");

    while (fgets(line, sizeof(line), fp)) {
        char path[0x100] = {0};
        char* addr;
        std::string soname;

        sscanf(line, "%s %s %s %s %s %s", path, path, path, path, path, path);
        addr = strtok(line, "-");
        base = strtoull(addr, NULL, 16);

        soname = extract_soname(path);
        if (!path[0] || g_modules.count(soname) != 0) continue;
//        LOGD("[load_modules] %s -> 0x%lx", soname.c_str(), base);
        // size暫時無用, 先不獲取
        g_modules[soname] = {.base = base, .size = 0};
    }
}

void* Utils::getMapData(int fd, off64_t base_offset, size_t elf_offset, size_t size) {
    //offset就是程序头表的起始地址
    off64_t offset;
    safe_add(&offset, base_offset, elf_offset);
    //获取这个偏移的页起始地址
    off64_t page_min = page_start(offset);

    off64_t end_offset;
    //获取这片数据的结束位置
    safe_add(&end_offset, offset, size);  //获取程序头表的结束地址
    safe_add(&end_offset, end_offset, page_offset(offset));
    size_t map_size = static_cast<size_t>(end_offset - page_min);

    uint8_t* map_start = static_cast<uint8_t*>(
            mmap64(nullptr, map_size, PROT_READ, MAP_PRIVATE, fd, page_min));
    if (map_start == MAP_FAILED) {
        return nullptr;
    }
    //返回指向新的一片程序头表的指针
    return map_start + page_offset(offset);
}
bool Utils::safe_add(off64_t* out, off64_t a, size_t b) {
    if (static_cast<uint64_t>(INT64_MAX - a) < b) {
        return false;
    }
    *out = a + b;
    return true;
}
size_t Utils::page_offset(off64_t offset) {
    return static_cast<size_t>(offset & (PAGE_SIZE-1));
}
off64_t Utils::page_start(off64_t offset) {
    return offset & kPageMask;
}

//找到目标的soinfo
soinfo* Utils::get_soinfo(const char* so_name) {
    typedef soinfo* (*FunctionPtr)(ElfW(Addr));

    ElfW(Addr) linker_base;
    ElfW(Addr) so_addr;

    linker_base = g_modules["linker64"].base;
    if (g_modules.count(so_name) == 0) {
        Utils::load_modules();
    }
    so_addr = g_modules[so_name].base;

//    ElfW(Addr) func_offset = Utils::get_export_func("/system/bin/linker64", "find_containing_library");
    ElfW(Addr) func_offset = Utils::get_export_func("/apex/com.android.runtime/bin/linker64", "find_containing_library");
    if(!func_offset) {
        LOGE("func_offset == 0? check it ---> get_soinfo");
        return nullptr;
    }
//    ElfW(Addr) find_containing_library_addr =  static_cast<ElfW(Addr)>(linker_base + 0x9AB0);
    ElfW(Addr) find_containing_library_addr =  static_cast<ElfW(Addr)>(linker_base + func_offset);
    FunctionPtr find_containing_library = reinterpret_cast<FunctionPtr>(find_containing_library_addr);
    //估计这个函数是通过地址来查找目标的soinfo的?
    return find_containing_library(so_addr);
}
//自己解析内存elf文件找到导出函数,绕过系统的dlopen限制
ElfW(Addr) Utils::get_export_func(char* path, char* func_name) {

    struct stat sb;
    int fd = open(path, O_RDONLY);
    fstat(fd, &sb);
    void* base = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    // 讀取elf header
    ElfW(Ehdr) header;
    memcpy(&(header), base, sizeof(header));

    // 讀取Section header table
    size_t size = header.e_shnum * sizeof(ElfW(Shdr));
    void* tmp = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); // 注: 必須要 MAP_ANONYMOUS
    LOGD("error: %s", strerror(errno));
    ElfW(Shdr)* shdr_table;
    memcpy(tmp, (void*)((ElfW(Off))base + header.e_shoff), size);
    shdr_table = static_cast<ElfW(Shdr)*>(tmp);

    char* shstrtab = reinterpret_cast<char*>(shdr_table[header.e_shstrndx].sh_offset + (ElfW(Off))base);

    void* symtab = nullptr;
    char* strtab = nullptr;
    uint32_t symtab_size = 0;

    // 遍歷獲取.symtab和.strtab節
    for (size_t i = 0; i < header.e_shnum; ++i) {
        const ElfW(Shdr) *shdr = &shdr_table[i];
        char* section_name = shstrtab + shdr->sh_name;
        if(!strcmp(section_name, ".symtab")) {
//            LOGD("[test] %d: shdr->sh_name = %s", i, (shstrtab + shdr->sh_name));
            symtab = reinterpret_cast<void*>(shdr->sh_offset + (ElfW(Off))base);
            symtab_size = shdr->sh_size;
        }
        if(!strcmp(section_name, ".strtab")) {
//            LOGD("[test] %d: shdr->sh_name = %s", i, (shstrtab + shdr->sh_name));
            strtab = reinterpret_cast<char*>(shdr->sh_offset + (ElfW(Off))base);
        }

        if(strtab && symtab)break;
    }

    // 讀取 Symbol table
    ElfW(Sym)* sym_table;
    tmp = mmap(nullptr, symtab_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(tmp, symtab, symtab_size);
    sym_table = static_cast<ElfW(Sym)*>(tmp);

    int sym_num = symtab_size / sizeof(ElfW(Sym));

    // 遍歷 Symbol table
    for(int i = 0; i < sym_num; i++) {
        const ElfW(Sym) *sym = &sym_table[i];
        char* sym_name = strtab + sym->st_name;
        if(strstr(sym_name, func_name)) {
            return sym->st_value;
        }
    }
    return 0;
}

ElfW(Addr) Utils::get_addend(ElfW(Rela)* rela, ElfW(Addr) reloc_addr __unused) {
    return rela->r_addend;
}

int Utils::phdr_table_set_gnu_relro_prot(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                         ElfW(Addr) load_bias, int prot_flags) {
    const ElfW(Phdr)* phdr = phdr_table;
    const ElfW(Phdr)* phdr_limit = phdr + phdr_count;

    for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_GNU_RELRO) {
            continue;
        }
        ElfW(Addr) seg_page_start = PAGE_START(phdr->p_vaddr) + load_bias;
        ElfW(Addr) seg_page_end   = PAGE_END(phdr->p_vaddr + phdr->p_memsz) + load_bias;

        int ret = mprotect(reinterpret_cast<void*>(seg_page_start),
                           seg_page_end - seg_page_start,
                           prot_flags);
        if (ret < 0) {
            return -1;
        }
    }
    return 0;
}

void Utils::phdr_table_get_dynamic_section(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                           ElfW(Addr) load_bias, ElfW(Dyn)** dynamic,
                                           ElfW(Word)* dynamic_flags){
    *dynamic = nullptr;
    for (size_t i = 0; i<phdr_count; ++i) {
        const ElfW(Phdr)& phdr = phdr_table[i];
        if (phdr.p_type == PT_DYNAMIC) {
            *dynamic = reinterpret_cast<ElfW(Dyn)*>(load_bias + phdr.p_vaddr);
            if (dynamic_flags) {
                *dynamic_flags = phdr.p_flags;
            }
            return;
        }
    }
}

//返回一个函数指针的地址?
ElfW(Addr) call_ifunc_resolver(ElfW(Addr) resolver_addr) {
    typedef ElfW(Addr) (*ifunc_resolver_t)(void);
    ifunc_resolver_t ifunc_resolver = reinterpret_cast<ifunc_resolver_t>(resolver_addr);
    ElfW(Addr) ifunc_addr = ifunc_resolver();

    return ifunc_addr;
}
