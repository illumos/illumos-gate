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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MULTIBOOT_H
#define	_MULTIBOOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Multiboot header must be present withing the first
 * 8192 bytes of the elf executable. The flag bit fields
 * are defined to request multiboot info from the boot
 * loader (see struct multiboot_info below):
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

#define	MB_HEADER_MAGIC		0x1BADB002	/* magic */
#define	MB_HEADER_FLAGS		0x00000003	/* flag */
#define	MB_HEADER_CHECKSUM	-0x1BADB005	/* -(magic + flag) */

/* passed by boot loader to kernel */
#define	MB_BOOTLOADER_MAGIC	0x2BADB002

#define	MB_NETWORK_DRIVE	0x20	/* not clear if part of spec */

#define	STACK_SIZE	0x4000

#ifndef _ASM		/* excluded from assembly routines */

#include <sys/types.h>

/* The Multiboot header. */
typedef struct multiboot_header {
	ulong_t magic;
	ulong_t flags;
	ulong_t checksum;
	ulong_t header_addr;
	ulong_t load_addr;
	ulong_t load_end_addr;
	ulong_t bss_end_addr;
	ulong_t entry_addr;
} multiboot_header_t;

/* The section header table for ELF. */
typedef struct mb_elf_shtable {
	ulong_t num;
	ulong_t size;
	ulong_t addr;
	ulong_t shndx;
} mb_elf_shtable_t;

/* The Multiboot information. */
typedef struct multiboot_info {
	ulong_t flags;
	ulong_t mem_lower;
	ulong_t mem_upper;
	ulong_t boot_device;
	ulong_t cmdline;
	ulong_t mods_count;
	ulong_t mods_addr;
	mb_elf_shtable_t elf_sec;
	ulong_t mmap_length;
	ulong_t mmap_addr;
	ulong_t drives_length;	/* overload with dhcpack */
	ulong_t drives_addr;
	ulong_t config_table;
	ulong_t boot_loader_name;
	ulong_t apm_table;
	ulong_t vbe_control_info;
	ulong_t vbe_mode_info;
	ushort_t vbe_mode;
	ushort_t vbe_interface_seg;
	ushort_t vbe_interface_off;
	ushort_t vbe_interface_len;
	ulong_t efi_systab;
	ulong_t acpi_root_tab;
} multiboot_info_t;

/* The module structure. */
typedef struct mb_module {
	ulong_t mod_start;
	ulong_t mod_end;
	ulong_t string;
	ulong_t reserved;
} mb_module_t;

/*
 * The memory map. Be careful that the offset 0 is base_addr_low
 * but no size.
 */
typedef struct mb_memory_map {
	ulong_t size;
	ulong_t base_addr_low;
	ulong_t base_addr_high;
	ulong_t length_low;
	ulong_t length_high;
	ulong_t type;
} mb_memory_map_t;

/*
 * netinfo for Solaris diskless booting
 * XXX - not part of multiboot spec
 */
struct sol_netinfo {
	uint8_t sn_infotype;
	uint8_t sn_mactype;
	uint8_t sn_maclen;
	uint8_t sn_padding;
	ulong_t sn_ciaddr;
	ulong_t sn_siaddr;
	ulong_t sn_giaddr;
	ulong_t sn_netmask;
	uint8_t sn_macaddr[1];
};

/* identify bootp/dhcp reply or rarp/ifconfig */
#define	SN_TYPE_BOOTP	2
#define	SN_TYPE_RARP	0xf0

/* Check if the bit BIT in FLAGS is set. */
#define	MB_CHECK_FLAG(flags, bit)   ((flags) & (1 << (bit)))

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _MULTIBOOT_H */
