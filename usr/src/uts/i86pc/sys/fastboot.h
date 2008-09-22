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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FASTBOOT_H
#define	_SYS_FASTBOOT_H


/*
 * Platform dependent instruction sequences for fast reboot
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef	_ASM
#include <sys/types.h>
#include <sys/mach_mmu.h>
#endif	/* _ASM */

#define	FASTBOOT_NAME_UNIX		0
#define	FASTBOOT_NAME_BOOTARCHIVE	1

#define	FASTBOOT_MAX_FILES_MAP	2 /* max number of files that needs mapping */
#define	FASTBOOT_MAX_FILES_TOTAL	3 /* max number of files */

#define	FASTBOOT_SWTCH_PA		0x5000	/* low memory */
#define	FASTBOOT_STACK_OFFSET		0xe00	/* where the stack starts */
#define	FASTBOOT_MAGIC			('F' << 24 | 'A' << 16 | 'S' << 8 | 'T')

#define	FASTBOOT_UNIX		0
#define	FASTBOOT_BOOTARCHIVE	1
#define	FASTBOOT_SWTCH		2

/*
 * Default sizes for varies information we have to save across boot for
 * fast reboot.  If the actual size is bigger than what we saved, abort
 * fast reboot.
 */
#define	FASTBOOT_SAVED_MMAP_COUNT	32
#define	FASTBOOT_SAVED_DRIVES_COUNT	9
#define	FASTBOOT_SAVED_CMDLINE_LEN	MMU_PAGESIZE


/*
 * dboot entry address comes from
 * usr/src/uts/i86pc/conf/Mapfile and Mapfile.64.
 */
#define	DBOOT_ENTRY_ADDRESS	0xc00000

/*
 * Fake starting virtual address for creating mapping for the new kernel
 * and boot_archive.
 */
#define	FASTBOOT_FAKE_VA	(2ULL << 30)

#define	FASTBOOT_TERMINATE	0xdeadbee0	/* Terminating PTEs */

#ifndef	_ASM

#define	MAX_ELF32_LOAD_SECTIONS 3

/*
 * Data structure for specifying each section in a 32-bit ELF file.
 */
typedef struct fastboot_section
{
	uint32_t		fb_sec_offset;	/* offset */
	uint32_t		fb_sec_paddr;	/* physical address */
	uint32_t		fb_sec_size;	/* size */
	uint32_t		fb_sec_bss_size;	/* section bss size */
} fastboot_section_t;

/*
 * Data structure for describing each file that needs to be relocated from high
 * memory to low memory for fast reboot.  Currently these files are unix, the
 * boot_archive, and the relocation function itself.
 */
typedef struct _fastboot_file {
	uintptr_t		fb_va;	/* virtual address */
	x86pte_t		*fb_pte_list_va;	/* VA for PTE list */
	paddr_t			fb_pte_list_pa;		/* PA for PTE list */
	uintptr_t		fb_dest_pa;	/* destination PA */
	size_t			fb_size;	/* file size */
	uintptr_t		fb_next_pa;
	fastboot_section_t	fb_sections[MAX_ELF32_LOAD_SECTIONS];
	int			fb_sectcnt;	/* actual number of sections */
} fastboot_file_t;

/*
 * Data structure containing all the information the switching routine needs
 * for fast rebooting to the new kernel.
 */
typedef struct _fastboot_info {
	uint32_t		fi_magic; /* magic for fast reboot */
	fastboot_file_t		fi_files[FASTBOOT_MAX_FILES_TOTAL];
	int			fi_has_pae;
	uintptr_t		fi_pagetable_va;
	paddr_t			fi_pagetable_pa;
	paddr_t			fi_last_table_pa;
	paddr_t			fi_new_mbi_pa;	/* new multiboot info PA */
	int			fi_valid;	/* is the new kernel valid */
	uintptr_t		fi_next_table_va;
	paddr_t			fi_next_table_pa;
	uint_t			*fi_shift_amt;
	uint_t			fi_ptes_per_table;
	uint_t			fi_lpagesize;
	int			fi_top_level;	/* top level of page tables */
} fastboot_info_t;

extern void fast_reboot();
extern void load_kernel(char *);

extern int fastreboot_capable;
extern int force_fastreboot;

#endif	/* _ASM */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_FASTBOOT_H */
