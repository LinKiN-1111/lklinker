//
// Created by MSI-PC on 2025/6/5.
//

#pragma once

#include "Utils.h"
extern std::unordered_map<std::string, Module> g_modules;

static bool is_symbol_global_and_defined(const soinfo* si, const ElfW(Sym)* s) {
    if (ELF_ST_BIND(s->st_info) == STB_GLOBAL ||
        ELF_ST_BIND(s->st_info) == STB_WEAK) {
        return s->st_shndx != SHN_UNDEF;
    } else if (ELF_ST_BIND(s->st_info) != STB_LOCAL) {
        LOGE("Warning: unexpected ST_BIND value: %d for \"%s\" in \"%s\" (ignoring)",
                ELF_ST_BIND(s->st_info), si->get_string(s->st_name), si->get_realpath());
    }

    return false;
}


static uint32_t gnu_hash(const char* sym_name) {
    uint32_t h = 5381;
    const uint8_t* name = reinterpret_cast<const uint8_t*>(sym_name);
    while (*name != 0) {
        h += (h << 5) + *name++; // h*33 + c = h + h * 32 + c = h + h << 5 + c
    }
    return h;
}

static bool gnu_lookup(soinfo* si, const char* sym_name, uint32_t* symbol_index) {
    uint32_t hash = gnu_hash(sym_name);
    uint32_t h2 = hash >> si->gnu_shift2_;
//    LOGD("hash -> 0x%lx", hash);
    uint32_t bloom_mask_bits = sizeof(ElfW(Addr))*8;
    uint32_t word_num = (hash / bloom_mask_bits) & si->gnu_maskwords_;
    ElfW(Addr) bloom_word = si->gnu_bloom_filter_[word_num];

    *symbol_index = 0;

    // test against bloom filter
    if ((1 & (bloom_word >> (hash % bloom_mask_bits)) & (bloom_word >> (h2 % bloom_mask_bits))) == 0) {
//        LOGD("NOT FOUND %s in %s", sym_name, si->get_realpath());
        return true;
    }
    // bloom test says "probably yes"...
    uint32_t n = si->gnu_bucket_[hash % si->gnu_nbucket_];
    LOGD("n -> 0x%lx", n);
    if (n == 0) {
//        LOGD("NOT FOUND %s in %s", sym_name, si->get_realpath());
        return true;
    }

    do {
        ElfW(Sym)* s = si->symtab_ + n;

        if (((si->gnu_chain_[n] ^ hash) >> 1) == 0 &&
            strcmp(si->get_string(s->st_name), sym_name) == 0 &&
            is_symbol_global_and_defined(si, s)) {
//            LOGD("FOUND %s in %s (%p) %zd",
//                       sym_name, si->get_realpath(), reinterpret_cast<void*>(s->st_value),
//                       static_cast<size_t>(s->st_size));
            *symbol_index = n;
//            LOGD("symbol_index => 0x%lx", symbol_index);
            return true;
        }
    } while ((si->gnu_chain_[n++] & 1) == 0);

//    LOGD("NOT FOUND %s in %s", sym_name, si->get_realpath());
    return true;
}

static bool find_symbol_by_name(soinfo* si, const char* sym_name, const ElfW(Sym)** symbol) {
    uint32_t symbol_index = 0;
    bool success =
            si->is_gnu_hash() ?
            gnu_lookup(si, sym_name, &symbol_index) :
            true;

    if (success) {
        *symbol = symbol_index == 0 ? nullptr : si->symtab_ + symbol_index;
    }

    return success;
}


static bool soinfo_do_lookup(const char* sym_name, soinfo** si_found_in, const ElfW(Sym)** s) {
    typedef soinfo* (*FunctionPtr2)();

    soinfo* so_head;
//    ElfW(Addr) solist_get_head_off = Utils::get_export_func("/system/bin/linker64", "__dl__Z15solist_get_headv");
    ElfW(Addr) solist_get_head_off = Utils::get_export_func("/apex/com.android.runtime/bin/linker64", "__dl__Z15solist_get_headv");
    if (!solist_get_head_off) {
        LOGE("get_head_off == null");
        return false;
    }

    ElfW(Addr) solist_get_head_addr =  static_cast<ElfW(Addr)>(g_modules["linker64"].base + solist_get_head_off);

    FunctionPtr2 solist_get_head = reinterpret_cast<FunctionPtr2>(solist_get_head_addr);
    so_head = solist_get_head();


    while (so_head) {
//        LOGD("[soinfo_do_lookup] si: 0x%lx", so_head);
        find_symbol_by_name(so_head, sym_name, s);
        if (*s) {
            LOGD("(*s)->st_value: 0x%lx", (*s)->st_value);
            *si_found_in = so_head;
            return true;
        }
        so_head = so_head->next;
    }

    return false;
}

