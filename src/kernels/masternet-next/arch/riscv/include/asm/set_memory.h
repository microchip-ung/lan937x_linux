/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2019 SiFive
 */

#ifndef _ASM_RISCV_SET_MEMORY_H
#define _ASM_RISCV_SET_MEMORY_H

#ifndef __ASSEMBLY__
/*
 * Functions to change memory attributes.
 */
#ifdef CONFIG_MMU
int set_memory_ro(unsigned long addr, int numpages);
int set_memory_rw(unsigned long addr, int numpages);
int set_memory_x(unsigned long addr, int numpages);
int set_memory_nx(unsigned long addr, int numpages);
#else
static inline int set_memory_ro(unsigned long addr, int numpages) { return 0; }
static inline int set_memory_rw(unsigned long addr, int numpages) { return 0; }
static inline int set_memory_x(unsigned long addr, int numpages) { return 0; }
static inline int set_memory_nx(unsigned long addr, int numpages) { return 0; }
#endif

#ifdef CONFIG_STRICT_KERNEL_RWX
void set_kernel_text_ro(void);
void set_kernel_text_rw(void);
#else
static inline void set_kernel_text_ro(void) { }
static inline void set_kernel_text_rw(void) { }
#endif

int set_direct_map_invalid_noflush(struct page *page);
int set_direct_map_default_noflush(struct page *page);

#endif /* __ASSEMBLY__ */

#ifdef CONFIG_ARCH_HAS_STRICT_KERNEL_RWX
#ifdef CONFIG_64BIT
#define SECTION_ALIGN (1 << 21)
#else
#define SECTION_ALIGN (1 << 22)
#endif
#else /* !CONFIG_ARCH_HAS_STRICT_KERNEL_RWX */
#define SECTION_ALIGN L1_CACHE_BYTES
#endif /* CONFIG_ARCH_HAS_STRICT_KERNEL_RWX */

#endif /* _ASM_RISCV_SET_MEMORY_H */
