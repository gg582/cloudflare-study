/*
 * TBPF (Transparent BPF) Library
 * * Rationale for Improvements:
 * 1. Architecture Safety: Uses 'uintptr_t' for pointer-to-64bit conversion, 
 * ensuring safety on both 32-bit and 64-bit systems.
 * 2. Sockmap Compatibility: Added 'expected_attach_type', which is critical 
 * for BPF_PROG_TYPE_SK_MSG or SK_SKB to pass the kernel verifier.
 * 3. Verifier Insights: Improved log handling to capture detailed error 
 * messages when a BPF program fails to load.
 */

#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "tbpf.h"

/**
 * sys_bpf - Low-level wrapper for the bpf() system call.
 * Kernel API Reference: /include/uapi/linux/bpf.h (union bpf_attr)
 */
static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    /* The 'size' argument allows the kernel to handle different versions 
       of the bpf_attr struct (Forward/Backward Compatibility). */
    return syscall(__NR_bpf, cmd, attr, size);
}

/**
 * tbpf_create_map - Creates an eBPF map (e.g., BPF_MAP_TYPE_SOCKMAP).
 * Kernel API Reference: /kernel/bpf/syscall.c -> map_create()
 */
int tbpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
                    int max_entries, uint32_t map_flags)
{
    union bpf_attr attr = {
        .map_type    = map_type,
        .key_size    = key_size,
        .value_size  = value_size,
        .max_entries = max_entries,
        .map_flags   = map_flags,
    };

    return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

/**
 * tbpf_load_program - Loads BPF instructions into the kernel.
 * @expected_attach_type: For Sockmap, use BPF_SK_MSG_VERDICT or BPF_SK_SKB_STREAM_VERDICT.
 * Kernel API Reference: /kernel/bpf/verifier.c (Verifier logic)
 */
int tbpf_load_program(enum bpf_prog_type prog_type,
                      enum bpf_attach_type expected_attach_type,
                      const struct bpf_insn *insns, size_t insns_cnt,
                      const char *license, uint32_t kern_version, 
                      char *log_buf, size_t log_buf_sz)
{
    union bpf_attr attr = {
        .prog_type = prog_type,
        .expected_attach_type = expected_attach_type, // Critical for Sockmap
        .insns = (uintptr_t)insns,
        .insn_cnt = (uint32_t)insns_cnt,
        .license = (uintptr_t)license,
        .kern_version = kern_version,
    };

    /* Attempt 1: Fast load without logging */
    int fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    
    /* Attempt 2: If failed, retry with logging enabled to diagnose Verifier errors */
    if (fd < 0 && log_buf && log_buf_sz > 0) {
        attr.log_buf = (uintptr_t)log_buf;
        attr.log_size = (uint32_t)log_buf_sz;
        attr.log_level = 1; // Level 1: Basic verifier log, Level 2: More verbose
        log_buf[0] = 0;
        fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    }
    return fd;
}

/**
 * tbpf_prog_attach - Attaches a loaded BPF program to a target (Map, Cgroup, etc).
 * Kernel API Reference: /kernel/bpf/syscall.c -> bpf_prog_attach()
 */
int tbpf_prog_attach(int prog_fd, int target_fd, enum bpf_attach_type type,
                     unsigned int flags)
{
    union bpf_attr attr = {
        .target_fd     = (uint32_t)target_fd, // For Sockmap, this is the Map FD
        .attach_bpf_fd = (uint32_t)prog_fd,
        .attach_type   = type,
        .attach_flags  = flags,
    };

    return sys_bpf(BPF_PROG_ATTACH, &attr, sizeof(attr));
}

/**
 * tbpf_map_update_elem - Updates a map entry (e.g., adding a socket FD to a Sockmap).
 * Kernel API Reference: /net/core/sock_map.c (For sockmap specifics)
 */
int tbpf_map_update_elem(int fd, const void *key, const void *value,
                         uint64_t flags)
{
    union bpf_attr attr = {
        .map_fd = (uint32_t)fd,
        .key    = (uintptr_t)key,
        .value  = (uintptr_t)value,
        .flags  = flags,
    };

    return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

/**
 * tbpf_map_lookup_elem - Retrieves a value from a map by key.
 */
int tbpf_map_lookup_elem(int fd, const void *key, void *value)
{
    union bpf_attr attr = {
        .map_fd = (uint32_t)fd,
        .key    = (uintptr_t)key,
        .value  = (uintptr_t)value,
    };

    return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

/**
 * tbpf_map_delete_elem - Removes an entry from a map.
 */
int tbpf_map_delete_elem(int fd, const void *key)
{
    union bpf_attr attr = {
        .map_fd = (uint32_t)fd,
        .key    = (uintptr_t)key,
    };

    return sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

/**
 * tbpf_fill_symbol - Fixup relocations in eBPF bytecode.
 * Used when the compiler leaves placeholders for Map FDs.
 */
int tbpf_fill_symbol(struct bpf_insn *insns, struct tbpf_reloc *relocs,
                     const char *symbol, int32_t value)
{
    int count = 0;
    while (relocs && relocs->name && relocs->name[0] != '\x00') {
        if (strcmp(relocs->name, symbol) == 0) {
            switch (relocs->type) {
            case 1: // Standard Map FD relocation
                insns[relocs->offset].src_reg = 1; // BPF_PSEUDO_MAP_FD
                insns[relocs->offset].imm = value;
                count++;
                break;
            default:
                fprintf(stderr, "FATAL: Unsupported relocation type %d\n", relocs->type);
                abort();
            }
        }
        relocs++;
    }
    return count;
}
