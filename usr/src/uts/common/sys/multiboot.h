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

#ifndef	_MULTIBOOT_H
#define	_MULTIBOOT_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Definitions of structures/data for using a multiboot compliant OS loader.
 */
#define	MB_HEADER_MAGIC		 0x1BADB002	/* magic */

/* The 32-bit kernel does not require the use of the AOUT kludge */
#define	MB_HEADER_FLAGS_32	 0x00000003	/* flags we use */
#define	MB_HEADER_CHECKSUM_32	-0x1BADB005	/* -(magic + flag) */

#define	MB_HEADER_FLAGS_64	 0x00010003	/* flags we use */
#define	MB_HEADER_CHECKSUM_64	-0x1BAEB005	/* -(magic + flag) */

/*
 * passed by boot loader to kernel
 */
#define	MB_BOOTLOADER_MAGIC	0x2BADB002

#ifndef _ASM		/* excluded from assembly routines */

#include <sys/types.h>
#include <sys/types32.h>

/*
 * The Multiboot header must be somewhere in the 1st 8K of the image that
 * the loader loads into memory.
 */
typedef struct multiboot_header {
	uint32_t	magic;
	uint32_t	flags;
	uint32_t	checksum;
	caddr32_t	header_addr;	/* use as (mutliboot_header_t *) */
	caddr32_t	load_addr;
	caddr32_t	load_end_addr;
	caddr32_t	bss_end_addr;
	caddr32_t	entry_addr;
} multiboot_header_t;

/* The section header table for ELF. */
typedef struct mb_elf_shtable {
	uint32_t num;
	uint32_t size;
	uint32_t addr;
	uint32_t shndx;
} mb_elf_shtable_t;

/* The module structure. */
typedef struct mb_module {
	caddr32_t	mod_start;
	caddr32_t	mod_end;
	caddr32_t	mod_name;	/* use as (char *) */
	uint32_t	reserved;
} mb_module_t;

/*
 * Memory map data structure. Walked in a bizarre way - see mutltiboot
 * documentation for example.
 */
typedef struct mb_memory_map {
	uint32_t	size;
	uint32_t	base_addr_low;
	uint32_t	base_addr_high;
	uint32_t	length_low;
	uint32_t	length_high;
	uint32_t	type;		/* only value of 1 is RAM */
} mb_memory_map_t;


/*
 * The Multiboot information. This is supplied by the multiboot loader
 * for the OS.
 *
 * The flag bit fields defined what multiboot info the boot
 * loader (see struct multiboot_info below) supplied:
 *	flag[0]		mem_upper, mem_loader
 *	flag[1]		boot_device
 *	flag[2]		cmdline (for launching kernel)
 *	flag[3]		mods_count, mods_addr
 *	flag[4]		symbol table for a.out
 *	flag[5]		symbol table for elf
 *	flag[6]		mmap_length, mmap_addr
 *	flag[7]		drives_length, drivers_addr
 *	flag[8]		config_table
 *	flag[9]		boot_loader_name
 *	flag[10]	apm_table
 *	flag[11]	vbe_control_info
 *			vbe_mode_info
 *			vbe_mode
 *			vbe_interface_seg
 *			vbe_interface_off
 *			vbe_interface_len
 */
typedef struct multiboot_info {
	uint32_t	flags;
	uint32_t	mem_lower;	/* # of pages below 1Meg */
	uint32_t	mem_upper;	/* # of pages above 1Meg */
	uint32_t	boot_device;
	caddr32_t	cmdline;	/* use as (char *) */
	uint32_t	mods_count;
	caddr32_t	mods_addr;	/* use as (mb_module_t *) */
	mb_elf_shtable_t elf_sec;
	uint32_t	mmap_length;
	caddr32_t	mmap_addr;	/* use as (mb_memory_map_t *) */
	uint32_t	drives_length;
	caddr32_t	drives_addr;
	caddr32_t	config_table;
	caddr32_t	boot_loader_name;
	caddr32_t	apm_table;
	uint32_t	vbe_control_info;
	uint32_t	vbe_mode_info;
	uint16_t	vbe_mode;
	uint16_t	vbe_interface_seg;
	uint16_t	vbe_interface_off;
	uint16_t	vbe_interface_len;
} multiboot_info_t;

/*
 * netinfo for Solaris diskless booting
 * XXX - not part of multiboot spec
 */
struct sol_netinfo {
	uint8_t sn_infotype;
	uint8_t sn_mactype;
	uint8_t sn_maclen;
	uint8_t sn_padding;
	uint32_t sn_ciaddr;
	uint32_t sn_siaddr;
	uint32_t sn_giaddr;
	uint32_t sn_netmask;
	uint8_t sn_macaddr[1];
};

/* identify bootp/dhcp reply or rarp/ifconfig */
#define	SN_TYPE_BOOTP   2
#define	SN_TYPE_RARP    0xf0


#endif /* _ASM */


#ifdef	__cplusplus
}
#endif

#endif	/* _MULTIBOOT_H */
