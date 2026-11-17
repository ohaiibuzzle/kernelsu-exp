/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifdef __aarch64__

#include "../patch_memory.h"
#include "klog.h" // IWYU pragma: keep
#include "linux/cpumask.h"
#include "linux/gfp.h" // IWYU pragma: keep
#include "linux/init.h" // IWYU pragma: keep
#include "linux/uaccess.h"
#include "linux/stop_machine.h"
#include "asm/cacheflush.h"
#include "asm-generic/fixmap.h"
#include "infra/symbol_resolver.h"

// https://github.com/fuqiuluo/ovo/blob/f7da411458e87d32438dc14fce5a3313ed0c967e/ovo/mmuhack.c#L21

// Translate a kernel virtual address to a physical address by walking the
// init_mm page tables. Returns the physical address on success, or writes
// a non-zero error to *err. Callers must check *err before using the result,
// since physical address 0 is a valid address.
unsigned long phys_from_virt(unsigned long addr, int *err)
{
    struct mm_struct *mm = &init_mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    *err = 0;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        goto fail;

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto fail;
#if defined(p4d_leaf)
    if (p4d_leaf(*p4d)) {
        return __p4d_to_phys(*p4d) + ((addr & ~P4D_MASK));
    }
#endif

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud))
        goto fail;
#if defined(pud_leaf)
    if (pud_leaf(*pud)) {
        return __pud_to_phys(*pud) + ((addr & ~PUD_MASK));
    }
#endif

    pmd = pmd_offset(pud, addr);
#if defined(pmd_leaf)
    if (pmd_leaf(*pmd)) {
        return __pmd_to_phys(*pmd) + ((addr & ~PMD_MASK));
    }
#endif

    if (pmd_none(*pmd) || pmd_bad(*pmd))
        goto fail;

    pte = pte_offset_kernel(pmd, addr);
    if (!pte)
        goto fail;
    if (!pte_present(*pte))
        goto fail;

    return __pte_to_phys(*pte) + ((addr & ~PAGE_MASK));

fail:
    *err = -ENOENT;
    return 0;
}

/*
 * Runtime-resolved kernel-image physical translation.
 *
 * phys_from_virt() walks init_mm with the pgtable layout COMPILED IN from
 * the build tree; on a module built against a different tree (different
 * CONFIG_PGTABLE_LEVELS / VA_BITS) the walk can resolve a kernel-image
 * address to a wrong -- but valid and mapped -- physical page, and the
 * fixmap poke then corrupts it: a hard crash with no error path.
 *
 * Instead, resolve the kernel's own kimage_voffset once at init (the same
 * constant __aarch64_text_write uses) and translate image-span addresses
 * with plain arithmetic. The image span [_text, _end) comes from kallsyms
 * as well, so a translation landing outside the image's physical span is
 * refused instead of poked.
 */
static unsigned long ksu_kimage_voffset;
static unsigned long ksu_virt_image_start;
static unsigned long ksu_virt_image_end;

int __init ksu_patch_phys_init(void)
{
    unsigned long kv_addr;

    kv_addr = (unsigned long)ksu_resolve_symbol_for_functable_hook("kimage_voffset");
    if (!kv_addr) {
        pr_err("patch_memory: kimage_voffset not resolvable\n");
        return -ENOENT;
    }
    ksu_kimage_voffset = *(volatile unsigned long *)kv_addr;

    ksu_virt_image_start = (unsigned long)ksu_resolve_symbol_for_functable_hook("_text");
    ksu_virt_image_end = (unsigned long)ksu_resolve_symbol_for_functable_hook("_end");
    if (!ksu_virt_image_start || ksu_virt_image_end <= ksu_virt_image_start) {
        pr_err("patch_memory: bad image span 0x%lx-0x%lx\n",
               ksu_virt_image_start, ksu_virt_image_end);
        ksu_kimage_voffset = 0;
        return -ENOENT;
    }

    if (ksu_virt_image_start <= ksu_kimage_voffset ||
        ksu_virt_image_start - ksu_kimage_voffset > (1UL << 40)) {
        pr_err("patch_memory: insane kv 0x%lx for _text 0x%lx\n",
               ksu_kimage_voffset, ksu_virt_image_start);
        ksu_kimage_voffset = 0;
        return -EINVAL;
    }

    pr_info("patch_memory: kv=0x%lx image [0x%lx,0x%lx) phys [0x%lx,0x%lx)\n",
            ksu_kimage_voffset, ksu_virt_image_start, ksu_virt_image_end,
            ksu_virt_image_start - ksu_kimage_voffset,
            ksu_virt_image_end - ksu_kimage_voffset);
    return 0;
}

// This function appears in 5.14:
// https://github.com/torvalds/linux/commit/fade9c2c6ee2baea7df8e6059b3f143c681e5ce4#diff-fc9ef24572e183c6c049b5ae8029762159787f8669d909452bdf40db748f94a7L52
// https://github.com/torvalds/linux/commit/814b186079cd54d3fe3b6b8ab539cbd44705ef9d#diff-fc9ef24572e183c6c049b5ae8029762159787f8669d909452bdf40db748f94a7R53
// However, it's backport to android13-5.10 but not to android12-5.10.
// https://cs.android.com/android/_/android/kernel/common/+/6d9f07d8f1ffc310a6877153fe882f35ae380799
// So we need to grep kernel source code to detect which one to use.
#if KSU_NEW_DCACHE_FLUSH
#define ksu_flush_dcache(start, sz)                                                                                    \
    ({                                                                                                                 \
        unsigned long __start = (start);                                                                               \
        unsigned long __end = __start + (sz);                                                                          \
        dcache_clean_inval_poc(__start, __end);                                                                        \
    })
#define ksu_flush_icache(start, end) caches_clean_inval_pou(start, end)
#else
#define ksu_flush_dcache(start, sz) __flush_dcache_area((void *)start, sz)
#define ksu_flush_icache(start, end) __flush_icache_range(start, end)
#endif

struct patch_text_info {
    void *dst;
    void *src;
    size_t len;
    atomic_t cpu_count;
    int flags;
};

// Implementation of arbitrary kernel address modification.
// We could certainly modify the PTE of the target address to make it writable,
// but this would violate the protection mechanisms of some vendor components
// (such as MTK's MKP, see ^1) at higher EL levels. Fortunately, the kernel's
// `aarch64_insn_write` function works fine, which I believe is achieved by
// modifying memory using fixmaps (MKP's kernel module reports the fixmap address
// to its hypervisor, which might be used to determine whether such memory
// modification is "normal" kernel behavior, see ^1). However, we cannot use the
// `aarch64_insn_write` function directly. First, it can only write 4 bytes
// at a time. Secondly, there's a bug in modifying the kernel's rodata (in our
// case, syscall table). The `patch_map` function uses `vmalloc_to_page` to
// obtain the target's physical address, but `vmalloc_to_page` doesn't handle
// huge page mapping correctly (before version 5.13, see ^2).
// Therefore, we need to obtain the target's physical address and use `fixmap` to
// map and poke it manually. Currently, no patch_lock is held, since I think it's
// not a big problem because we are in stop_machine.
// ^1: https://github.com/NothingOSS/android_kernel_device_modules_6.1_nothing_mt6878/blob/957dac185efe46cbf6336b0fff9516d84c8cd78f/drivers/misc/mediatek/mkp/mkp_main.c#L29
// ^2: https://github.com/torvalds/linux/commit/c0eb315ad9719e41ce44708455cc69df7ac9f3f8
// Runs under stop_machine; propagate errors without console output.
//
// Translation order of preference:
//   1. kernel image span + runtime-resolved kimage_voffset arithmetic,
//      bounds-checked against the image's physical span;
//   2. the compiled-in init_mm walk (vmalloc/module targets, or when
//      ksu_patch_phys_init() could not resolve the constants).
// Either way the fixmap alias is read back and compared with the direct
// mapping before any write, so a wrong-but-mapped physical page fails
// with -EFAULT instead of being corrupted.
static int ksu_patch_text_nosync(void *dst, void *src, size_t len, int flags)
{
    unsigned long p = (unsigned long)dst;
    unsigned long phy;
    int ret;
    void *map;

    if (ksu_kimage_voffset && p >= ksu_virt_image_start && p < ksu_virt_image_end) {
        phy = p - ksu_kimage_voffset;
        if (phy < ksu_virt_image_start - ksu_kimage_voffset ||
            phy + len > ksu_virt_image_end - ksu_kimage_voffset)
            return -ERANGE;
    } else {
        int phy_err;

        phy = phys_from_virt(p, &phy_err);
        if (phy_err)
            return phy_err;
    }

    map = set_fixmap_offset(FIX_TEXT_POKE0, phy);

    {
        unsigned long direct = 0, alias = 0;
        size_t vlen = len < sizeof(direct) ? len : sizeof(direct);

        ret = (int)copy_from_kernel_nofault(&direct, dst, vlen);
        if (!ret)
            ret = (int)copy_from_kernel_nofault(&alias, map, vlen);
        if (ret || direct != alias) {
            clear_fixmap(FIX_TEXT_POKE0);
            return -EFAULT;
        }
    }

    ret = (int)copy_to_kernel_nofault(map, src, len);

    clear_fixmap(FIX_TEXT_POKE0);

    if (!ret) {
        if (flags & KSU_PATCH_TEXT_FLUSH_ICACHE)
            ksu_flush_icache((uintptr_t)dst, (uintptr_t)dst + len);
        if (flags & KSU_PATCH_TEXT_FLUSH_DCACHE)
            ksu_flush_dcache(dst, len);
    }

    return ret;
}

static int ksu_patch_text_cb(void *arg)
{
    struct patch_text_info *pp = arg;
    void *dst = pp->dst, *src = pp->src;
    size_t len = pp->len;
    int flags = pp->flags;

    int ret = 0;

    /* The last CPU becomes master */
    if (atomic_inc_return(&pp->cpu_count) == num_online_cpus()) {
        ret = ksu_patch_text_nosync(dst, src, len, flags);
        /* Notify other processors with an additional increment. */
        atomic_inc(&pp->cpu_count);
    } else {
        while (atomic_read(&pp->cpu_count) <= num_online_cpus())
            cpu_relax();
        isb();
    }

    return ret;
}

int ksu_patch_text(void *dst, void *src, size_t len, int flags)
{
    int ret;
    struct patch_text_info info = {
        .dst = dst,
        .src = src,
        .len = len,
        .cpu_count = ATOMIC_INIT(0),
        .flags = flags,
    };

    ret = stop_machine(ksu_patch_text_cb, &info, cpu_online_mask);
    if (ret)
        pr_err("failed to patch kernel address 0x%lx: %d\n", (unsigned long)dst, ret);
    return ret;
}

/*
 * Scan the memory region [start, start+size) for a BL instruction whose
 * branch target equals `target`.  Returns the address of the first matching
 * instruction, or NULL if none is found.
 *
 * AArch64 BL encoding: bits[31:26] = 0b100101, bits[25:0] = imm26.
 * Branch target = PC + SignExtend(imm26, 26) * 4.
 */
void *scan_call_to(void *start, size_t size, void *target)
{
    const uint32_t *insn = (const uint32_t *)start;
    size_t count = size / sizeof(uint32_t);
    size_t i;

    for (i = 0; i < count; i++) {
        int32_t imm26;
        void *branch_target;

        /* Check BL opcode: bits[31:26] == 0b100101 */
        if ((insn[i] & 0xFC000000U) != 0x94000000U)
            continue;

        /* Sign-extend the 26-bit immediate to 32 bits */
        imm26 = (int32_t)((insn[i] & 0x03FFFFFFU) << 6) >> 6;

        /* Branch target = PC + imm26 * 4 */
        branch_target = (void *)((uintptr_t)(&insn[i]) + ((int64_t)imm26 << 2));

        if (branch_target == target)
            return (void *)&insn[i];
    }

    return NULL;
}

#endif /* __aarch64__ */
