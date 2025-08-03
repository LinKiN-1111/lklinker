//
// Created by linkin on 2025/7/29.
//

#include "lkLoader.h"
#include <cstdio>
#include "Utils.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "log.h"
#include <sys/prctl.h>
#include <dlfcn.h>
#include "original/linker_soinfo.h"
#include "original/linker_block_allocator.h"
int myneed[20];
uint32_t needed_count = 0;
std::unordered_map<std::string, Module> g_modules;
struct stat sb;

void lkLoader::lkload_library(const char *path) {
    int fd;
    struct stat sb;
    //-1.先将目标读入内存
    fd = open(path, O_RDONLY);
    fstat(fd, &sb);
    start_addr_ = static_cast<void **>(mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));

    // 0. 預加載一些用到的模塊
    Utils::load_modules();

    //1.读取so文件,存了一些数据到结构体中,具体没做什么实事...
    if(!this->lkRead_DISK_ELF(path, fd, 0, sb.st_size)){
        LOGD("Read so failed");
        munmap(start_addr_, sb.st_size);
        close(fd);
    }

    // 2. 載入so
    if(!lkLoad()) {
        LOGD("Load so failed");
        munmap(start_addr_, sb.st_size);
        close(fd);
    }

    // 使被加載的so有執行權限, 否則在調用.init_array時會報錯
    mprotect(reinterpret_cast<void *>(load_bias_), sb.st_size, PROT_READ | PROT_WRITE | PROT_EXEC);

    // 3. 預鏈接, 主要處理 .dynamic節
    si_->prelink_image();

    // 4. 正式鏈接, 在這裡處理重定位的信息
    si_->link_image();

    // 5. 調用.init和.init_array
    si_->call_constructors();

    close(fd);
}
const char* soinfo::get_realpath() const{
    return "";
}
const char* soinfo::get_string(ElfW(Word) index) const {
    return strtab_ + index;
}

bool soinfo::protect_relro() {
    if (Utils::phdr_table_set_gnu_relro_prot(phdr, phnum, load_bias, PROT_READ) < 0) {
        LOGE("can't enable GNU RELRO protection for \"%s\": %s",
             get_realpath(), strerror(errno));
        return false;
    }
    return true;
}

bool soinfo::prelink_image() {
//    if (flags_ & FLAG_PRELINKED) return true;
    /* Extract dynamic section */
    ElfW(Word) dynamic_flags = 0;
    //找动态段，并赋值到dynamic中
    Utils::phdr_table_get_dynamic_section(phdr, phnum, load_bias, &dynamic, &dynamic_flags);

//    /* We can't log anything until the linker is relocated */
//    bool relocating_linker = (flags_ & FLAG_LINKER) != 0;
//    if (!relocating_linker) {
//        LOGD("[ Linking \"%s\" ]", get_realpath());
//        LOGD("si->base = %p si->flags = 0x%08x", reinterpret_cast<void*>(base), flags_);
//    }

//    if (dynamic == nullptr) {
//        if (!relocating_linker) {
//            LOGE("missing PT_DYNAMIC in \"%s\"", get_realpath());
//        }
//        return false;
//    } else {
//        if (!relocating_linker) {
//            LOGD("dynamic = %p", dynamic);
//        }
//    }

#if defined(__arm__)
    (void) phdr_table_get_arm_exidx(phdr, phnum, load_bias,
                                  &ARM_exidx, &ARM_exidx_count);
#endif

//    TlsSegment tls_segment;
//    if (__bionic_get_tls_segment(phdr, phnum, load_bias, &tls_segment)) {
//        if (!__bionic_check_tls_alignment(&tls_segment.alignment)) {
//            if (!relocating_linker) {
//                LOGE("TLS segment alignment in \"%s\" is not a power of 2: %zu",
//                       get_realpath(), tls_segment.alignment);
//            }
//            return false;
//        }
//        tls_ = std::make_unique<soinfo_tls>();
//        tls_->segment = tls_segment;
//    }

    // Extract useful information from dynamic section.
    // Note that: "Except for the DT_NULL element at the end of the array,
    // and the relative order of DT_NEEDED elements, entries may appear in any order."
    //
    // source: http://www.sco.com/developers/gabi/1998-04-29/ch5.dynamic.html
    uint32_t needed_count = 0;
    for (ElfW(Dyn)* d = dynamic; d->d_tag != DT_NULL; ++d) {
        LOGD("d = %p, d[0](tag) = %p d[1](val) = %p",
              d, reinterpret_cast<void*>(d->d_tag), reinterpret_cast<void*>(d->d_un.d_val));
        switch (d->d_tag) {
            case DT_SONAME:
                // this is parsed after we have strtab initialized (see below).
                break;

            case DT_HASH:
                nbucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[0];
                nchain_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[1];
                bucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr + 8);
                chain_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr + 8 + nbucket_ * 4);
                break;

            case DT_GNU_HASH:
                gnu_nbucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[0];
                // skip symndx
                gnu_maskwords_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[2];
                gnu_shift2_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[3];

                gnu_bloom_filter_ = reinterpret_cast<ElfW(Addr)*>(load_bias + d->d_un.d_ptr + 16);
                gnu_bucket_ = reinterpret_cast<uint32_t*>(gnu_bloom_filter_ + gnu_maskwords_);
                // amend chain for symndx = header[1]
                gnu_chain_ = gnu_bucket_ + gnu_nbucket_ -
                             reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[1];

                if (!powerof2(gnu_maskwords_)) {
                    LOGE("invalid maskwords for gnu_hash = 0x%x, in \"%s\" expecting power to two",
                           gnu_maskwords_, get_realpath());
                    return false;
                }
                --gnu_maskwords_;

                flags_ |= FLAG_GNU_HASH;
                break;

            case DT_STRTAB:
                strtab_ = reinterpret_cast<const char*>(load_bias + d->d_un.d_ptr);
                break;

            case DT_STRSZ:
                strtab_size_ = d->d_un.d_val;
                break;

            case DT_SYMTAB:
                symtab_ = reinterpret_cast<ElfW(Sym)*>(load_bias + d->d_un.d_ptr);
                break;

            case DT_SYMENT:
                if (d->d_un.d_val != sizeof(ElfW(Sym))) {
                    LOGE("invalid DT_SYMENT: %zd in \"%s\"",
                           static_cast<size_t>(d->d_un.d_val), get_realpath());
                    return false;
                }
                break;

            case DT_PLTREL:
#if defined(USE_RELA)
                if (d->d_un.d_val != DT_RELA) {
          LOGE("unsupported DT_PLTREL in \"%s\"; expected DT_RELA", get_realpath());
          return false;
        }
#else
                if (d->d_un.d_val != DT_REL) {
                    LOGE("unsupported DT_PLTREL in \"%s\"; expected DT_REL", get_realpath());
                    return false;
                }
#endif
                break;

            case DT_JMPREL:
#if defined(USE_RELA)
                plt_rela_ = reinterpret_cast<ElfW(Rela)*>(load_bias + d->d_un.d_ptr);
#else
                plt_rel_ = reinterpret_cast<ElfW(Rel)*>(load_bias + d->d_un.d_ptr);
#endif
                break;

            case DT_PLTRELSZ:
#if defined(USE_RELA)
                plt_rela_count_ = d->d_un.d_val / sizeof(ElfW(Rela));
#else
                plt_rel_count_ = d->d_un.d_val / sizeof(ElfW(Rel));
#endif
                break;

            case DT_PLTGOT:
                // Ignored (because RTLD_LAZY is not supported).
                break;
            //这里大佬直接跳过了这个的加载
            case DT_DEBUG:
                // Set the DT_DEBUG entry to the address of _r_debug for GDB
                // if the dynamic table is writable
                if ((dynamic_flags & PF_W) != 0) {
                    LOGD("pass code: d->d_un.d_val = reinterpret_cast<uintptr_t>(&_r_debug);");
//                    d->d_un.d_val = reinterpret_cast<uintptr_t>(&_r_debug);
                }
                break;
#if defined(USE_RELA)
                case DT_RELA:
        rela_ = reinterpret_cast<ElfW(Rela)*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_RELASZ:
        rela_count_ = d->d_un.d_val / sizeof(ElfW(Rela));
        break;

      case DT_ANDROID_RELA:
        android_relocs_ = reinterpret_cast<uint8_t*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_ANDROID_RELASZ:
        android_relocs_size_ = d->d_un.d_val;
        break;

      case DT_ANDROID_REL:
        LOGE("unsupported DT_ANDROID_REL in \"%s\"", get_realpath());
        return false;

      case DT_ANDROID_RELSZ:
        LOGE("unsupported DT_ANDROID_RELSZ in \"%s\"", get_realpath());
        return false;

      case DT_RELAENT:
        if (d->d_un.d_val != sizeof(ElfW(Rela))) {
          LOGE("invalid DT_RELAENT: %zd", static_cast<size_t>(d->d_un.d_val));
          return false;
        }
        break;

      // Ignored (see DT_RELCOUNT comments for details).
      case DT_RELACOUNT:
        break;

      case DT_REL:
        LOGE("unsupported DT_REL in \"%s\"", get_realpath());
        return false;

      case DT_RELSZ:
        LOGE("unsupported DT_RELSZ in \"%s\"", get_realpath());
        return false;

#else
            case DT_REL:
                rel_ = reinterpret_cast<ElfW(Rel)*>(load_bias + d->d_un.d_ptr);
                break;

            case DT_RELSZ:
                rel_count_ = d->d_un.d_val / sizeof(ElfW(Rel));
                break;

            case DT_RELENT:
                if (d->d_un.d_val != sizeof(ElfW(Rel))) {
                    LOGE("invalid DT_RELENT: %zd", static_cast<size_t>(d->d_un.d_val));
                    return false;
                }
                break;

            case DT_ANDROID_REL:
                android_relocs_ = reinterpret_cast<uint8_t*>(load_bias + d->d_un.d_ptr);
                break;

            case DT_ANDROID_RELSZ:
                android_relocs_size_ = d->d_un.d_val;
                break;

            case DT_ANDROID_RELA:
                LOGE("unsupported DT_ANDROID_RELA in \"%s\"", get_realpath());
                return false;

            case DT_ANDROID_RELASZ:
                LOGE("unsupported DT_ANDROID_RELASZ in \"%s\"", get_realpath());
                return false;

                // "Indicates that all RELATIVE relocations have been concatenated together,
                // and specifies the RELATIVE relocation count."
                //
                // TODO: Spec also mentions that this can be used to optimize relocation process;
                // Not currently used by bionic linker - ignored.
            case DT_RELCOUNT:
                break;

            case DT_RELA:
                LOGE("unsupported DT_RELA in \"%s\"", get_realpath());
                return false;

            case DT_RELASZ:
                LOGE("unsupported DT_RELASZ in \"%s\"", get_realpath());
                return false;

#endif
            case DT_RELR:
            case DT_ANDROID_RELR:
                relr_ = reinterpret_cast<ElfW(Relr)*>(load_bias + d->d_un.d_ptr);
                break;


            case DT_RELRSZ:
            case DT_ANDROID_RELRSZ:
                relr_count_ = d->d_un.d_val / sizeof(ElfW(Relr));
                break;

            case DT_RELRENT:
            case DT_ANDROID_RELRENT:
                if (d->d_un.d_val != sizeof(ElfW(Relr))) {
                    LOGE("invalid DT_RELRENT: %zd", static_cast<size_t>(d->d_un.d_val));
                    return false;
                }
                break;

                // Ignored (see DT_RELCOUNT comments for details).
                // There is no DT_RELRCOUNT specifically because it would only be ignored.
            case DT_ANDROID_RELRCOUNT:
                break;

            case DT_INIT:
                init_func_ = reinterpret_cast<linker_ctor_function_t>(load_bias + d->d_un.d_ptr);
                LOGD("%s constructors (DT_INIT) found at %p", get_realpath(), init_func_);
                break;

            case DT_FINI:
                fini_func_ = reinterpret_cast<linker_dtor_function_t>(load_bias + d->d_un.d_ptr);
                LOGD("%s destructors (DT_FINI) found at %p", get_realpath(), fini_func_);
                break;

            case DT_INIT_ARRAY:
                init_array_ = reinterpret_cast<linker_ctor_function_t*>(load_bias + d->d_un.d_ptr);
                LOGD("%s constructors (DT_INIT_ARRAY) found at %p", get_realpath(), init_array_);
                break;

            case DT_INIT_ARRAYSZ:
                init_array_count_ = static_cast<uint32_t>(d->d_un.d_val) / sizeof(ElfW(Addr));
                break;

            case DT_FINI_ARRAY:
                fini_array_ = reinterpret_cast<linker_dtor_function_t*>(load_bias + d->d_un.d_ptr);
                LOGD("%s destructors (DT_FINI_ARRAY) found at %p", get_realpath(), fini_array_);
                break;

            case DT_FINI_ARRAYSZ:
                fini_array_count_ = static_cast<uint32_t>(d->d_un.d_val) / sizeof(ElfW(Addr));
                break;

            case DT_PREINIT_ARRAY:
                preinit_array_ = reinterpret_cast<linker_ctor_function_t*>(load_bias + d->d_un.d_ptr);
                LOGD("%s constructors (DT_PREINIT_ARRAY) found at %p", get_realpath(), preinit_array_);
                break;

            case DT_PREINIT_ARRAYSZ:
                preinit_array_count_ = static_cast<uint32_t>(d->d_un.d_val) / sizeof(ElfW(Addr));
                break;

            case DT_TEXTREL:
#if defined(__LP64__)
                LOGE("\"%s\" has text relocations", get_realpath());
        return false;
#else
                has_text_relocations = true;
                break;
#endif

            case DT_SYMBOLIC:
                has_DT_SYMBOLIC = true;
                break;

            case DT_NEEDED:
                ++needed_count;
                break;

            case DT_FLAGS:
                if (d->d_un.d_val & DF_TEXTREL) {
#if defined(__LP64__)
                    LOGE("\"%s\" has text relocations", get_realpath());
          return false;
#else
                    has_text_relocations = true;
#endif
                }
                if (d->d_un.d_val & DF_SYMBOLIC) {
                    has_DT_SYMBOLIC = true;
                }
                break;

            case DT_FLAGS_1:
                set_dt_flags_1(d->d_un.d_val);

                if ((d->d_un.d_val & ~SUPPORTED_DT_FLAGS_1) != 0) {
                    LOGE("Warning: \"%s\" has unsupported flags DT_FLAGS_1=%p "
                            "(ignoring unsupported flags)",
                            get_realpath(), reinterpret_cast<void*>(d->d_un.d_val));
                }
                break;

                // Ignored: "Its use has been superseded by the DF_BIND_NOW flag"
            case DT_BIND_NOW:
                break;

            case DT_VERSYM:
                versym_ = reinterpret_cast<ElfW(Versym)*>(load_bias + d->d_un.d_ptr);
                break;

            case DT_VERDEF:
                verdef_ptr_ = load_bias + d->d_un.d_ptr;
                break;
            case DT_VERDEFNUM:
                verdef_cnt_ = d->d_un.d_val;
                break;

            case DT_VERNEED:
                verneed_ptr_ = load_bias + d->d_un.d_ptr;
                break;

            case DT_VERNEEDNUM:
                verneed_cnt_ = d->d_un.d_val;
                break;

            case DT_RUNPATH:
                // this is parsed after we have strtab initialized (see below).
                break;

            case DT_TLSDESC_GOT:
            case DT_TLSDESC_PLT:
                // These DT entries are used for lazy TLSDESC relocations. Bionic
                // resolves everything eagerly, so these can be ignored.
                break;

            default:
//                if (!relocating_linker) {
                    const char* tag_name;
                    if (d->d_tag == DT_RPATH) {
                        tag_name = "DT_RPATH";
                    } else if (d->d_tag == DT_ENCODING) {
                        tag_name = "DT_ENCODING";
                    } else if (d->d_tag >= DT_LOOS && d->d_tag <= DT_HIOS) {
                        tag_name = "unknown OS-specific";
                    } else if (d->d_tag >= DT_LOPROC && d->d_tag <= DT_HIPROC) {
                        tag_name = "unknown processor-specific";
                    } else {
                        tag_name = "unknown";
                    }
                    LOGE("Warning: \"%s\" unused DT entry: %s (type %p arg %p) (ignoring)",
                            get_realpath(),
                            tag_name,
                            reinterpret_cast<void*>(d->d_tag),
                            reinterpret_cast<void*>(d->d_un.d_val));
//                }
                break;
        }
    }

    LOGD("si->base = %p, si->strtab = %p, si->symtab = %p",
          reinterpret_cast<void*>(base), strtab_, symtab_);

    // Sanity checks.
//    if (relocating_linker && needed_count != 0) {
//        LOGE("linker cannot have DT_NEEDED dependencies on other libraries");
//        return false;
//    }
    if (nbucket_ == 0 && gnu_nbucket_ == 0) {
        LOGE("empty/missing DT_HASH/DT_GNU_HASH in \"%s\" "
               "(new hash type from the future?)", get_realpath());
        return false;
    }
    if (strtab_ == nullptr) {
        LOGE("empty/missing DT_STRTAB in \"%s\"", get_realpath());
        return false;
    }
    if (symtab_ == nullptr) {
        LOGE("empty/missing DT_SYMTAB in \"%s\"", get_realpath());
        return false;
    }

    // second pass - parse entries relying on strtab
    for (ElfW(Dyn)* d = dynamic; d->d_tag != DT_NULL; ++d) {
        switch (d->d_tag) {
            case DT_SONAME:
//                set_soname(get_string(d->d_un.d_val));
                break;
            case DT_RUNPATH:
//                set_dt_runpath(get_string(d->d_un.d_val));
                break;
        }
    }
    //下面这部分应该是安卓6以下才操作的，这里跳过。。。
    // Before M release linker was using basename in place of soname.
    // In the case when dt_soname is absent some apps stop working
    // because they can't find dt_needed library by soname.
    // This workaround should keep them working. (Applies only
    // for apps targeting sdk version < M.) Make an exception for
    // the main executable and linker; they do not need to have dt_soname.
    // TODO: >= O the linker doesn't need this workaround.
//    if (soname_ == nullptr &&
//        this != solist_get_somain() &&
//        (flags_ & FLAG_LINKER) == 0 &&
//        get_application_target_sdk_version() < 23) {
//        soname_ = basename(realpath_.c_str());
//        LOGE("missing-soname-enforced-for-api-level-23",
//                                  "\"%s\" has no DT_SONAME (will use %s instead)",
//                                  get_realpath(), soname_);
//
//        // Don't call add_dlwarning because a missing DT_SONAME isn't important enough to show in the UI
//    }

    // Validate each library's verdef section once, so we don't have to validate
    // it each time we look up a symbol with a version.
//    if (!validate_verdef_section(this)) return false;

    flags_ |= FLAG_PRELINKED;
    return true;
}

bool soinfo::link_image() {
    local_group_root_ = this;

    if (android_relocs_ != nullptr) {
        LOGD("android_relocs_ 不用處理?");

    } else {
        LOGE("bad android relocation header.");
//        return false;
    }

#if defined(USE_RELA)
    if (rela_ != nullptr) {
        LOGD("[ relocating %s ]", get_realpath());
        if (!relocate(plain_reloc_iterator(rela_, rela_count_))) {
          LOGE("relocate error!");
          return false;
        }
    }
    if (plt_rela_ != nullptr) {
        LOGD("[ relocating %s plt ]", get_realpath());
        if (!relocate(plain_reloc_iterator(plt_rela_, plt_rela_count_))) {
          LOGE("relocate error!");
          return false;
        }
    }
#else
    LOGE("TODO: !defined(USE_RELA) ");
#endif

    LOGD("[ finished linking %s ]", get_realpath());

    // We can also turn on GNU RELRO protection if we're not linking the dynamic linker
    // itself --- it can't make system calls yet, and will have to call protect_relro later.
    if (!((flags_ & FLAG_LINKER) != 0) && !protect_relro()) {
        return false;
    }

    return true;
}

void soinfo::set_dt_flags_1(uint32_t dt_flags_1) {
    if (has_min_version(1)) {
        if ((dt_flags_1 & DF_1_GLOBAL) != 0) {
            rtld_flags_ |= RTLD_GLOBAL;
        }

        if ((dt_flags_1 & DF_1_NODELETE) != 0) {
            rtld_flags_ |= RTLD_NODELETE;
        }

        dt_flags_1_ = dt_flags_1;
    }
}
bool soinfo::is_gnu_hash() const {
    return (flags_ & FLAG_GNU_HASH) != 0;
}

template<typename ElfRelIteratorT>
bool soinfo::relocate(ElfRelIteratorT&& rel_iterator) {
    for (size_t idx = 0; rel_iterator.has_next(); ++idx) {
        const auto rel = rel_iterator.next();
        if (rel == nullptr) {
            return false;
        }


        ElfW(Word) type = ELFW(R_TYPE)(rel->r_info);
        ElfW(Word) sym = ELFW(R_SYM)(rel->r_info);

        // reloc 指向需要重定向的內容, 根據type來決定重定向成什麼
        ElfW(Addr) reloc = static_cast<ElfW(Addr)>(rel->r_offset + load_bias);
        ElfW(Addr) sym_addr = 0;
        const char* sym_name = nullptr;
        soinfo* lsi = nullptr;
        ElfW(Addr) addend = Utils::get_addend(rel, reloc);

//        LOGD("Processing \"%s\" relocation at index %zd", get_realpath(), idx);
        if (type == R_GENERIC_NONE) {
            continue;
        }

        const ElfW(Sym)* s = nullptr;

        if (sym != 0) {

            sym_name = get_string(symtab_[sym].st_name);
//            LOGD("sym = %lx   sym_name: %s   st_value: %lx", sym, sym_name, symtab_[sym].st_value);

            if(soinfo_do_lookup(sym_name, &lsi, &s)) {
                sym_addr = lsi->resolve_symbol_address(s);
            } else {
                for(int s = 0; s < needed_count; s++) {
                    void* handle = dlopen(get_string(myneed[s]),RTLD_NOW);
                    sym_addr = reinterpret_cast<Elf64_Addr>(dlsym(handle, sym_name));
                    if(sym_addr) break;
                }
            }

            LOGD("sym_addr: 0x%lx (by dlsym)", sym_addr);


            if(!sym_addr) {
                if(symtab_[sym].st_value != 0) {
                    sym_addr = load_bias + symtab_[sym].st_value;
                }else {
                    LOGE("%s find addr fail (sym: %lx)", sym_name, sym);
                }

            }else {
                LOGD("%s find addr success : %lx", sym_name, sym_addr);
            }
        }


        switch (type) {
            case R_GENERIC_JUMP_SLOT:
                *reinterpret_cast<ElfW(Addr)*>(reloc) = (sym_addr + addend);
                break;
            case R_GENERIC_GLOB_DAT:
                *reinterpret_cast<ElfW(Addr)*>(reloc) = (sym_addr + addend);
                break;
            case R_GENERIC_RELATIVE:
                *reinterpret_cast<ElfW(Addr)*>(reloc) = (load_bias + addend);
                break;
            case R_GENERIC_IRELATIVE:
            {

                ElfW(Addr) ifunc_addr = call_ifunc_resolver(load_bias + addend);
                *reinterpret_cast<ElfW(Addr)*>(reloc) = ifunc_addr;
            }
                break;

#if defined(__aarch64__)
                case R_AARCH64_ABS64:
    *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend;
    break;
  case R_AARCH64_ABS32:
    {
      const ElfW(Addr) min_value = static_cast<ElfW(Addr)>(INT32_MIN);
      const ElfW(Addr) max_value = static_cast<ElfW(Addr)>(UINT32_MAX);
      if ((min_value <= (sym_addr + addend)) &&
          ((sym_addr + addend) <= max_value)) {
        *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend;
      } else {
        LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
               sym_addr + addend, min_value, max_value);
        return false;
      }
    }
    break;
  case R_AARCH64_ABS16:
    {
      const ElfW(Addr) min_value = static_cast<ElfW(Addr)>(INT16_MIN);
      const ElfW(Addr) max_value = static_cast<ElfW(Addr)>(UINT16_MAX);
      if ((min_value <= (sym_addr + addend)) &&
          ((sym_addr + addend) <= max_value)) {
        *reinterpret_cast<ElfW(Addr)*>(reloc) = (sym_addr + addend);
      } else {
        LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
               sym_addr + addend, min_value, max_value);
        return false;
      }
    }
    break;
  case R_AARCH64_PREL64:
    *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend - rel->r_offset;
    break;
  case R_AARCH64_PREL32:
    {
      const ElfW(Addr) min_value = static_cast<ElfW(Addr)>(INT32_MIN);
      const ElfW(Addr) max_value = static_cast<ElfW(Addr)>(UINT32_MAX);
      if ((min_value <= (sym_addr + addend - rel->r_offset)) &&
          ((sym_addr + addend - rel->r_offset) <= max_value)) {
        *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend - rel->r_offset;
      } else {
        LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
               sym_addr + addend - rel->r_offset, min_value, max_value);
        return false;
      }
    }
    break;
  case R_AARCH64_PREL16:
    {
      const ElfW(Addr) min_value = static_cast<ElfW(Addr)>(INT16_MIN);
      const ElfW(Addr) max_value = static_cast<ElfW(Addr)>(UINT16_MAX);
      if ((min_value <= (sym_addr + addend - rel->r_offset)) &&
          ((sym_addr + addend - rel->r_offset) <= max_value)) {
        *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend - rel->r_offset;
      } else {
        LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
               sym_addr + addend - rel->r_offset, min_value, max_value);
        return false;
      }
    }
    break;

  case R_AARCH64_COPY:
    LOGE("%s R_AARCH64_COPY relocations are not supported", get_realpath());
    return false;
  case R_AARCH64_TLS_TPREL64:
    LOGD("RELO TLS_TPREL64 *** %16llx <- %16llx - %16llx\n",
               reloc, (sym_addr + addend), rel->r_offset);
    break;
  case R_AARCH64_TLS_DTPREL32:
      LOGD("RELO TLS_DTPREL32 *** %16llx <- %16llx - %16llx\n",
               reloc, (sym_addr + addend), rel->r_offset);
    break;
#endif
            default:
                LOGE("unknown reloc type %d @ %p (%zu)  sym_name: %s", type, rel, idx, sym_name);
                return false;
        }
//    */
    }
    return true;
}

void soinfo::call_constructors() const {
    // 對於so文件來說, 由於沒有_start函數
    // 因此init_func_和init_array_都無法傳參, 只能是默認值
    LOGE("call_constructors!");
    if(init_func_) {
        LOGD("init func: %p", init_func_);
        init_func_(0, nullptr, nullptr);
    }
    if(init_array_) {
        for(int i = 0; i < init_array_count_; i++) {
            if(!init_array_[i])continue;
            init_array_[i](0, nullptr, nullptr);
        }
    }
    LOGD("init_array_count_ = %d", init_array_count_);
}


bool lkLoader::lkRead_DISK_ELF(const char* name,int fd,off64_t file_offset,off64_t file_size){
    bool res = false;
    name_ = name;
    fd_ = fd;
    file_offset_ = file_offset;
    file_size_ = file_size;
    if (lkReadElfHeader() &&
        lkReadProgramHeaders()) {
        res = true;
    }
    return res;
}
bool lkLoader::lkReadElfHeader() {
    return memcpy(&header_, start_addr_, sizeof(header_));
}
bool lkLoader::lkReadProgramHeaders() {
    phdr_num_ = header_.e_phnum;
    size_t size = phdr_num_ * sizeof(ElfW(Phdr));
    void* data = Utils::getMapData(fd_, file_offset_, header_.e_phoff, size);
    if(data == nullptr) {
        LOGE("ProgramHeader mmap failed");
        return false;
    }
    phdr_table_ = static_cast<ElfW(Phdr)*>(data);
    return true;
}

bool lkLoader::lkLoad() {
    bool res = false;
    //做三个操作
    if (ReserveAddressSpace() &&
        LoadSegments() &&
        FindPhdr()) {
        LOGD("Load Done.........");
        res = true;
    }

    // 獲取當前so (加載器的so)
//    si_ = Utils::get_soinfo("liblklinker.so");
//(android_namespace_t* ns, const char* realpath,
//               const struct stat* file_stat, off64_t file_offset,
//               int rtld_flags
    //自行构造一个soinfo，然后不修复linker中的soinfo，也可以执行里面的函数，但是应该就不能dlopen找到这个句柄了
    si_ = new soinfo(nullptr, "", nullptr, 0, RTLD_NOW);

    if(!si_) {
        LOGE("si_ return nullptr");
        return false;
    }
    LOGD("si_ -> base: %lx", si_->base);

    // 使si_可以被修改
    // fix bug: 由於不同Android版本的soinfo變化較大, 因此size設置大些會好點, 以前設置為0x1000, 在aosp8能用, 但aosp10會crash, 因此改為0x2000
    mprotect((void*) PAGE_START(reinterpret_cast<ElfW(Addr)>(si_)), 0x2000, PROT_READ | PROT_WRITE);
    // 修正so
    si_->base = load_start();
    si_->size = load_size();
//            si_->set_mapped_by_caller(elf_reader.is_mapped_by_caller());
    si_->load_bias = load_bias();
    si_->phnum = phdr_count();
    si_->phdr = loaded_phdr();


    return res;
}
bool lkLoader::ReserveAddressSpace() {
    ElfW(Addr) min_vaddr;
    //min_vaddr记录加载段最小的逻辑地址,load_size_记录目标so的大小
    load_size_ = phdr_table_get_load_size(phdr_table_, phdr_num_, &min_vaddr);
    LOGD("load_size_: %x", load_size_);
    if (load_size_ == 0) {
        LOGE("\"%s\" has no loadable segments", name_.c_str());
        return false;
    }
    //将这个地址转化为指针,最小的偏移
    uint8_t* addr = reinterpret_cast<uint8_t*>(min_vaddr);

    void* start;

    // Assume position independent executable by default.应该没用,直接用NULL也行吧
    void* mmap_hint = nullptr;

    //分配load_size_这么大小的地址,为空
    start = mmap(mmap_hint, load_size_, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    //加载段起始地址
    load_start_ = start;
    //这里需要注意一下，start为我们映射出来的那块内存的起始地址，按理说它就是我们So加载的一个起始地址
    //那这里又计算了一个load_bias_是什么意思呢？
    //So文件并没有对p_vaddr有特殊要求，所以它可以是任意地址，如果它指定了一个最小的虚拟地址不为0
    //那么文件中的关于地址的引用就是根据它指定的虚拟地址来的
    //所以我们在后面进行对地址修正的时候，就要计算 start - min_addr来得到正确的值
    //所以这里计算了load_bias_， 后面关于地址引用的地方，我们都用这个load_bias_就可以了
    //举个例子：假设一个So中的PT_LOAD段指定的最小虚拟地址min_vaddr = 0x100
    //那么如果这个So中的一个函数中引用了一个地址为0x300地方的字符串
    //那这个字符串在实际文件中的偏移就是0x200 = 0x300 - 0x100
    //当So加载到内存中，需要对这个函数中的引用做重定位的时候，就应该这样计算
    //start + 0x300 - 0x100 <==> start - 0x100  + 0x300
    //每次在计算的时候都要-0x100，所以这里就计算了一个load_bias_ = start - 0x100
    //后面直接用这个load_bias_ + 0x300(地址引用偏移) 就可以了
    load_bias_ = reinterpret_cast<uint8_t*>(start) - addr;

    return true;
}

bool lkLoader::LoadSegments() {
    // 在這個函數中會往 ReserveAddressSpace
    // 裡mmap的那片內存填充數據
    for (size_t i = 0; i < phdr_num_; ++i) {
        const ElfW(Phdr)* phdr = &phdr_table_[i];

        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        // Segment addresses in memory.
        //这里用的是load_bias_而不是load_start_,说明了load_start的位置对应的就是vaddr_start
        //有一些vaddr不是从0开始的,所以通过load_bias_进行修正...
        ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
        ElfW(Addr) seg_end   = seg_start + phdr->p_memsz;

        ElfW(Addr) seg_page_start = PAGE_START(seg_start);
        ElfW(Addr) seg_page_end   = PAGE_END(seg_end);

        ElfW(Addr) seg_file_end   = seg_start + phdr->p_filesz;

        // File offsets.
        ElfW(Addr) file_start = phdr->p_offset;
        ElfW(Addr) file_end   = file_start + phdr->p_filesz;

        ElfW(Addr) file_page_start = PAGE_START(file_start);
        ElfW(Addr) file_length = file_end - file_page_start;

        if (file_size_ <= 0) {
            LOGE("\"%s\" invalid file size: %", name_.c_str(), file_size_);
            return false;
        }

        if (file_end > static_cast<size_t>(file_size_)) {
            LOGE("invalid ELF file");
            return false;
        }

        if (file_length != 0) {
            //将该PT_LOAD段的实际内容页对齐后映射到内存中
            // 按AOSP裡那樣用mmap會有問題, 因此改為直接 memcpy
//            mprotect(reinterpret_cast<void *>(seg_page_start), seg_page_end - seg_page_start, PROT_WRITE);
//            void* c = (char*)start_addr_ + file_page_start;
//            void* res = memcpy(reinterpret_cast<void *>(seg_page_start), c, file_length);
            int prot = PFLAGS_TO_PROT(phdr->p_flags);
            void* seg_addr = mmap64(reinterpret_cast<void*>(seg_page_start),
                                    file_length,
                                    prot,
                                    MAP_FIXED|MAP_PRIVATE,
                                    fd_,
                                    file_offset_ + file_page_start);
//            LOGD("[LoadSeg] %s  seg_page_start: %lx   c : %lx", strerror(errno), seg_page_start, c);
        }

        //如果该段的权限可写且该段指定的文件大小并不是页边界对齐的，就要对页内没有文件与之对应的区域置0
        if ((phdr->p_flags & PF_W) != 0 && PAGE_OFFSET(seg_file_end) > 0) {
            memset(reinterpret_cast<void*>(seg_file_end), 0, PAGE_SIZE - PAGE_OFFSET(seg_file_end));
        }

        seg_file_end = PAGE_END(seg_file_end);

        // seg_file_end is now the first page address after the file
        // content. If seg_end is larger, we need to zero anything
        // between them. This is done by using a private anonymous
        // map for all extra pages.. //将中间的位置清空
        if (seg_page_end > seg_file_end) {
            size_t zeromap_size = seg_page_end - seg_file_end;
            void* zeromap = mmap(reinterpret_cast<void*>(seg_file_end),
                                 zeromap_size,
                                 PFLAGS_TO_PROT(phdr->p_flags),
                                 MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE,
                                 -1,
                                 0);
            if (zeromap == MAP_FAILED) {
                LOGE("couldn't zero fill \"%s\" gap: %s", name_.c_str(), strerror(errno));
                return false;
            }

            // 分配.bss節
            prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, zeromap, zeromap_size, ".bss");
        }
    }
    return true;
}

bool lkLoader::FindPhdr(){
    const ElfW(Phdr)* phdr_limit = phdr_table_ + phdr_num_;

    // If there is a PT_PHDR, use it directly.
    for (const ElfW(Phdr)* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_PHDR) {
            return CheckPhdr(load_bias_ + phdr->p_vaddr);
        }
    }

    // Otherwise, check the first loadable segment. If its file offset
    // is 0, it starts with the ELF header, and we can trivially find the
    // loaded program header from it.
    for (const ElfW(Phdr)* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_LOAD) {
            if (phdr->p_offset == 0) {
                ElfW(Addr)  elf_addr = load_bias_ + phdr->p_vaddr;
                const ElfW(Ehdr)* ehdr = reinterpret_cast<const ElfW(Ehdr)*>(elf_addr);
                ElfW(Addr)  offset = ehdr->e_phoff;
                return CheckPhdr(reinterpret_cast<ElfW(Addr)>(ehdr) + offset);
            }
            break;
        }
    }

    return false;
}

bool lkLoader::CheckPhdr(ElfW(Addr) loaded) {
    const ElfW(Phdr)* phdr_limit = phdr_table_ + phdr_num_;
    ElfW(Addr) loaded_end = loaded + (phdr_num_ * sizeof(ElfW(Phdr)));
    for (const ElfW(Phdr)* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
        ElfW(Addr) seg_end = phdr->p_filesz + seg_start;
        if (seg_start <= loaded && loaded_end <= seg_end) {
            loaded_phdr_ = reinterpret_cast<const ElfW(Phdr)*>(loaded);
            return true;
        }
    }
    return false;
}

size_t lkLoader::phdr_table_get_load_size(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                          ElfW(Addr)* out_min_vaddr) {

    ElfW(Addr) min_vaddr = UINTPTR_MAX;
    ElfW(Addr) max_vaddr = 0;

    bool found_pt_load = false;
    //遍历程序头表
    for (size_t i = 0; i < phdr_count; ++i) {
        const ElfW(Phdr)* phdr = &phdr_table[i];

        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        found_pt_load = true;
        //找到最小加载的vaddr
        if (phdr->p_vaddr < min_vaddr) {
            min_vaddr = phdr->p_vaddr;
        }
        //找到最大加载的vaddr
        if (phdr->p_vaddr + phdr->p_memsz > max_vaddr) {
            max_vaddr = phdr->p_vaddr + phdr->p_memsz;
        }
    }
    //如果没有找到,返回false
    if (!found_pt_load) {
        min_vaddr = 0;
    }
    //页对齐
    min_vaddr = PAGE_START(min_vaddr);
    max_vaddr = PAGE_END(max_vaddr);

    //返回最小的加载段的逻辑地址
    if (out_min_vaddr != nullptr) {
        *out_min_vaddr = min_vaddr;
    }

    //返回页对齐后的加载段的大小
    return max_vaddr - min_vaddr;
}

//=====试下不修正会怎么样
soinfo::soinfo(android_namespace_t* ns, const char* realpath,
               const struct stat* file_stat, off64_t file_offset,
               int rtld_flags) {
    memset(this, 0, sizeof(*this));

    if (realpath != nullptr) {
        realpath_ = realpath;
    }

    flags_ = FLAG_NEW_SOINFO;
    version_ = SOINFO_VERSION;

    if (file_stat != nullptr) {
        this->st_dev_ = file_stat->st_dev;
        this->st_ino_ = file_stat->st_ino;
        this->file_offset_ = file_offset;
    }

    this->rtld_flags_ = rtld_flags;
    this->primary_namespace_ = ns;
}
soinfo::~soinfo() {
    memset(this, 0, sizeof(*this));
}
static LinkerTypeAllocator<soinfo> g_soinfo_allocator;
static LinkerTypeAllocator<LinkedListEntry<soinfo>> g_soinfo_links_allocator;

static LinkerTypeAllocator<android_namespace_t> g_namespace_allocator;
static LinkerTypeAllocator<LinkedListEntry<android_namespace_t>> g_namespace_list_allocator;


LinkedListEntry<soinfo>* SoinfoListAllocator::alloc() {
    return g_soinfo_links_allocator.alloc();
}

void SoinfoListAllocator::free(LinkedListEntry<soinfo>* entry) {
    g_soinfo_links_allocator.free(entry);
}

LinkedListEntry<android_namespace_t>* NamespaceListAllocator::alloc() {
    return g_namespace_list_allocator.alloc();
}

void NamespaceListAllocator::free(LinkedListEntry<android_namespace_t>* entry) {
    g_namespace_list_allocator.free(entry);
}

