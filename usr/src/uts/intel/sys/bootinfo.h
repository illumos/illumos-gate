/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_BOOTINFO_H
#define	_SYS_BOOTINFO_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This is used by bootfs and dboot.  It should be at least as large as the
 * number of modules that bootloaders (e.g., grub) can support.  This figure
 * has been chosen to match grub's value exactly.
 */
#define	MAX_BOOT_MODULES	99

/*
 * The 32-bit kernel loader code needs to build several structures that the
 * kernel is expecting. They will contain native sized pointers for the
 * target kernel.
 */

#if defined(_BOOT_TARGET_amd64)

typedef uint64_t native_ptr_t;

#elif defined(_BOOT_TARGET_i386)

typedef uint32_t native_ptr_t;

#elif defined(_KERNEL)

typedef void *native_ptr_t;

#endif

typedef enum boot_module_type {
	BMT_ROOTFS,
	BMT_FILE,
	BMT_HASH,
	BMT_ENV
} boot_module_type_t;

struct boot_memlist {
	uint64_t	addr;
	uint64_t	size;
	native_ptr_t	next;
	native_ptr_t	prev;
};

/*
 * The kernel needs to know how to find its modules.
 */
struct boot_modules {
	native_ptr_t		bm_addr;
	native_ptr_t		bm_name;
	native_ptr_t		bm_hash;
	uint32_t		bm_size;
	boot_module_type_t	bm_type;
};

/*
 *
 */
#pragma pack(1)
struct xboot_info {
	uint64_t	bi_next_paddr;	/* next physical address not used */
	native_ptr_t	bi_next_vaddr;	/* next virtual address not used */
	native_ptr_t	bi_cmdline;
	native_ptr_t	bi_phys_install;
	native_ptr_t	bi_rsvdmem;
	native_ptr_t	bi_pcimem;
	native_ptr_t	bi_modules;
	uint32_t	bi_module_cnt;
	uint32_t	bi_use_largepage;	/* MMU uses large pages */
	uint32_t	bi_use_pae;	/* MMU uses PAE mode (8 byte PTES) */
	uint32_t	bi_use_nx;	/* MMU uses NX bit in PTEs */
	uint32_t	bi_use_pge;	/* MMU uses Page Global Enable */
	native_ptr_t	bi_pt_window;
	native_ptr_t	bi_pte_to_pt_window;
	native_ptr_t	bi_kseg_size;	/* size used for kernel nucleus pages */
	uint64_t	bi_top_page_table;
#if defined(__xpv)
	native_ptr_t	bi_xen_start_info;
	native_ptr_t	bi_shared_info;		/* VA for shared_info */
#else
	native_ptr_t	bi_mb_info;		/* multiboot 1 or 2 info */
	int		bi_mb_version;		/* multiboot version */
	native_ptr_t	bi_acpi_rsdp;
#endif
};
#pragma pack()

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_BOOTINFO_H */
