/*
 * Copyright (C) 1999,2003,2007,2008,2009,2010  Free Software Foundation, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL ANY
 * DEVELOPER OR DISTRIBUTOR BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
 * IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/*
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 */

/*
 * This header contains definitions for Multiboot 2 boot protocol, based on
 * the reference implementation by grub 2.
 *
 * At the time this was written (Jan 2017), the Multiboot 2 documentation is in
 * process of being rewritten and the information in the specification is not
 * entirely correct. Instead, you must rely on grub 2 source code.
 *
 * This header provides essential support for the Multiboot 2 specification
 * for illumos and makes it possible to pass the needed structures from the
 * boot loader to the kernel.
 */

#ifndef	_SYS_MULTIBOOT2_H
#define	_SYS_MULTIBOOT2_H

#ifdef	__cplusplus
extern "C" {
#endif

/* How many bytes from the start of the file we search for the header.  */
#define	MULTIBOOT_SEARCH			32768
#define	MULTIBOOT_HEADER_ALIGN			8

/* The magic field should contain this.  */
#define	MULTIBOOT2_HEADER_MAGIC			0xe85250d6

/* This should be in %eax.  */
#define	MULTIBOOT2_BOOTLOADER_MAGIC		0x36d76289

/* Alignment of multiboot modules.  */
#if defined(__i386) || defined(__amd64)
#define	MULTIBOOT_MOD_ALIGN			0x00001000
#else
#error No architecture defined
#endif

/* Alignment of the multiboot info structure.  */
#define	MULTIBOOT_INFO_ALIGN			0x00000008

/* Flags set in the 'flags' member of the multiboot header.  */

#define	MULTIBOOT_TAG_ALIGN			8
#define	MULTIBOOT_TAG_TYPE_END			0
#define	MULTIBOOT_TAG_TYPE_CMDLINE		1
#define	MULTIBOOT_TAG_TYPE_BOOT_LOADER_NAME	2
#define	MULTIBOOT_TAG_TYPE_MODULE		3
#define	MULTIBOOT_TAG_TYPE_BASIC_MEMINFO	4
#define	MULTIBOOT_TAG_TYPE_BOOTDEV		5
#define	MULTIBOOT_TAG_TYPE_MMAP			6
#define	MULTIBOOT_TAG_TYPE_VBE			7
#define	MULTIBOOT_TAG_TYPE_FRAMEBUFFER		8
#define	MULTIBOOT_TAG_TYPE_ELF_SECTIONS		9
#define	MULTIBOOT_TAG_TYPE_APM			10
#define	MULTIBOOT_TAG_TYPE_EFI32		11
#define	MULTIBOOT_TAG_TYPE_EFI64		12
#define	MULTIBOOT_TAG_TYPE_SMBIOS		13
#define	MULTIBOOT_TAG_TYPE_ACPI_OLD		14
#define	MULTIBOOT_TAG_TYPE_ACPI_NEW		15
#define	MULTIBOOT_TAG_TYPE_NETWORK		16
#define	MULTIBOOT_TAG_TYPE_EFI_MMAP		17
#define	MULTIBOOT_TAG_TYPE_EFI_BS		18
#define	MULTIBOOT_TAG_TYPE_EFI32_IH		19
#define	MULTIBOOT_TAG_TYPE_EFI64_IH		20
#define	MULTIBOOT_TAG_TYPE_LOAD_BASE_ADDR	21

#define	MULTIBOOT_HEADER_TAG_END			0
#define	MULTIBOOT_HEADER_TAG_INFORMATION_REQUEST	1
#define	MULTIBOOT_HEADER_TAG_ADDRESS			2
#define	MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS		3
#define	MULTIBOOT_HEADER_TAG_CONSOLE_FLAGS		4
#define	MULTIBOOT_HEADER_TAG_FRAMEBUFFER		5
#define	MULTIBOOT_HEADER_TAG_MODULE_ALIGN		6
#define	MULTIBOOT_HEADER_TAG_EFI_BS			7
#define	MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS_EFI32	8
#define	MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS_EFI64	9
#define	MULTIBOOT_HEADER_TAG_RELOCATABLE		10

#define	MULTIBOOT_ARCHITECTURE_I386	0
#define	MULTIBOOT_ARCHITECTURE_MIPS32	4
#define	MULTIBOOT_HEADER_TAG_OPTIONAL	1

/* Hints for relocatable kernel load preference */
#define	MULTIBOOT_LOAD_PREFERENCE_NONE	0
#define	MULTIBOOT_LOAD_PREFERENCE_LOW	1
#define	MULTIBOOT_LOAD_PREFERENCE_HIGH	2

/* Values for console_flags field in tag multiboot_header_tag_console_flags. */
#define	MULTIBOOT_CONSOLE_FLAGS_CONSOLE_REQUIRED	1
#define	MULTIBOOT_CONSOLE_FLAGS_EGA_TEXT_SUPPORTED	2

#ifndef _ASM

#include <sys/stdint.h>

#pragma pack(1)

typedef struct multiboot_header_tag {
	uint16_t mbh_type;
	uint16_t mbh_flags;
	uint32_t mbh_size;
} multiboot_header_tag_t;

typedef struct multiboot2_header {
	/* Must be MULTIBOOT2_MAGIC - see above.  */
	uint32_t mb2_magic;

	/* ISA */
	uint32_t mb2_architecture;

	/* Total header length.  */
	uint32_t mb2_header_length;

	/* The above fields plus this one must equal 0 mod 2^32. */
	uint32_t mb2_checksum;
	multiboot_header_tag_t mb2_tags[];
} multiboot2_header_t;

typedef struct multiboot_header_tag_information_request {
	uint16_t mbh_type;
	uint16_t mbh_flags;
	uint32_t mbh_size;
	uint32_t mbh_requests[];
} multiboot_header_tag_information_request_t;

typedef struct multiboot_header_tag_address {
	uint16_t mbh_type;
	uint16_t mbh_flags;
	uint32_t mbh_size;
	uint32_t mbh_header_addr;
	uint32_t mbh_load_addr;
	uint32_t mbh_load_end_addr;
	uint32_t mbh_bss_end_addr;
} multiboot_header_tag_address_t;

typedef struct multiboot_header_tag_entry_address {
	uint16_t mbh_type;
	uint16_t mbh_flags;
	uint32_t mbh_size;
	uint32_t mbh_entry_addr;
} multiboot_header_tag_entry_address_t;

typedef struct multiboot_header_tag_console_flags {
	uint16_t mbh_type;
	uint16_t mbh_flags;
	uint32_t mbh_size;
	uint32_t mbh_console_flags;
} multiboot_header_tag_console_flags_t;

typedef struct multiboot_header_tag_framebuffer {
	uint16_t mbh_type;
	uint16_t mbh_flags;
	uint32_t mbh_size;
	uint32_t mbh_width;
	uint32_t mbh_height;
	uint32_t mbh_depth;
} multiboot_header_tag_framebuffer_t;

typedef struct multiboot_header_tag_module_align {
	uint16_t mbh_type;
	uint16_t mbh_flags;
	uint32_t mbh_size;
} multiboot_header_tag_module_align_t;

typedef struct multiboot_header_tag_relocatable {
	uint16_t mbh_type;
	uint16_t mbh_flags;
	uint32_t mbh_size;
	uint32_t mbh_min_addr;
	uint32_t mbh_max_addr;
	uint32_t mbh_align;
	uint32_t mbh_preference;
} multiboot_header_tag_relocatable_t;

typedef struct multiboot_color {
	uint8_t mb_red;
	uint8_t mb_green;
	uint8_t mb_blue;
} multiboot_color_t;

typedef struct multiboot_mmap_entry {
	uint64_t mmap_addr;
	uint64_t mmap_len;
#define	MULTIBOOT_MEMORY_AVAILABLE		1
#define	MULTIBOOT_MEMORY_RESERVED		2
#define	MULTIBOOT_MEMORY_ACPI_RECLAIMABLE	3
#define	MULTIBOOT_MEMORY_NVS			4
#define	MULTIBOOT_MEMORY_BADRAM			5
	uint32_t mmap_type;
	uint32_t mmap_reserved;
} multiboot_mmap_entry_t;

typedef struct multiboot_tag {
	uint32_t mb_type;
	uint32_t mb_size;
} multiboot_tag_t;

typedef struct multiboot2_info_header {
	uint32_t mbi_total_size;
	uint32_t mbi_reserved;
	multiboot_tag_t mbi_tags[];
} multiboot2_info_header_t;

typedef struct multiboot_tag_string {
	uint32_t mb_type;
	uint32_t mb_size;
	char mb_string[];
} multiboot_tag_string_t;

typedef struct multiboot_tag_module {
	uint32_t mb_type;
	uint32_t mb_size;
	uint32_t mb_mod_start;
	uint32_t mb_mod_end;
	char mb_cmdline[];
} multiboot_tag_module_t;

typedef struct multiboot_tag_basic_meminfo {
	uint32_t mb_type;
	uint32_t mb_size;
	uint32_t mb_mem_lower;
	uint32_t mb_mem_upper;
} multiboot_tag_basic_meminfo_t;

typedef struct multiboot_tag_bootdev {
	uint32_t mb_type;
	uint32_t mb_size;
	uint32_t mb_biosdev;
	uint32_t mb_slice;
	uint32_t mb_part;
} multiboot_tag_bootdev_t;

typedef struct multiboot_tag_mmap {
	uint32_t mb_type;
	uint32_t mb_size;
	uint32_t mb_entry_size;
	uint32_t mb_entry_version;
	uint8_t mb_entries[];
} multiboot_tag_mmap_t;

struct multiboot_vbe_info_block {
	uint8_t vbe_external_specification[512];
};

struct multiboot_vbe_mode_info_block {
	uint8_t vbe_external_specification[256];
};

typedef struct multiboot_tag_vbe {
	uint32_t mb_type;
	uint32_t mb_size;

	uint16_t vbe_mode;
	uint16_t vbe_interface_seg;
	uint16_t vbe_interface_off;
	uint16_t vbe_interface_len;

	struct multiboot_vbe_info_block vbe_control_info;
	struct multiboot_vbe_mode_info_block vbe_mode_info;
} multiboot_tag_vbe_t;

struct multiboot_tag_framebuffer_common {
	uint32_t mb_type;
	uint32_t mb_size;

	uint64_t framebuffer_addr;
	uint32_t framebuffer_pitch;
	uint32_t framebuffer_width;
	uint32_t framebuffer_height;
	uint8_t framebuffer_bpp;
#define	MULTIBOOT_FRAMEBUFFER_TYPE_INDEXED	0
#define	MULTIBOOT_FRAMEBUFFER_TYPE_RGB		1
#define	MULTIBOOT_FRAMEBUFFER_TYPE_EGA_TEXT	2
	uint8_t framebuffer_type;
	uint16_t mb_reserved;
};

typedef struct multiboot_tag_framebuffer {
	struct multiboot_tag_framebuffer_common framebuffer_common;

	union {
		struct {
			uint16_t framebuffer_palette_num_colors;
			multiboot_color_t framebuffer_palette[];
		} fb1;
		struct {
			uint8_t framebuffer_red_field_position;
			uint8_t framebuffer_red_mask_size;
			uint8_t framebuffer_green_field_position;
			uint8_t framebuffer_green_mask_size;
			uint8_t framebuffer_blue_field_position;
			uint8_t framebuffer_blue_mask_size;
		} fb2;
	} u;
} multiboot_tag_framebuffer_t;

typedef struct multiboot_tag_elf_sections {
	uint32_t mb_type;
	uint32_t mb_size;
	uint32_t mb_num;
	uint32_t mb_entsize;
	uint32_t mb_shndx;
	char mb_sections[];
} multiboot_tag_elf_sections_t;

typedef struct multiboot_tag_apm {
	uint32_t mb_type;
	uint32_t mb_size;
	uint16_t mb_version;
	uint16_t mb_cseg;
	uint32_t mb_offset;
	uint16_t mb_cseg_16;
	uint16_t mb_dseg;
	uint16_t mb_flags;
	uint16_t mb_cseg_len;
	uint16_t mb_cseg_16_len;
	uint16_t mb_dseg_len;
} multiboot_tag_apm_t;

typedef struct multiboot_tag_efi32 {
	uint32_t mb_type;
	uint32_t mb_size;
	uint32_t mb_pointer;
} multiboot_tag_efi32_t;

typedef struct multiboot_tag_efi64 {
	uint32_t mb_type;
	uint32_t mb_size;
	uint64_t mb_pointer;
} multiboot_tag_efi64_t;

typedef struct multiboot_tag_smbios {
	uint32_t mb_type;
	uint32_t mb_size;
	uint8_t mb_major;
	uint8_t mb_minor;
	uint8_t mb_reserved[6];
	uint8_t mb_tables[];
} multiboot_tag_smbios_t;

typedef struct multiboot_tag_old_acpi {
	uint32_t mb_type;
	uint32_t mb_size;
	uint8_t mb_rsdp[];
} multiboot_tag_old_acpi_t;

typedef struct multiboot_tag_new_acpi {
	uint32_t mb_type;
	uint32_t mb_size;
	uint8_t mb_rsdp[];
} multiboot_tag_new_acpi_t;

typedef struct multiboot_tag_network {
	uint32_t mb_type;
	uint32_t mb_size;
	uint8_t mb_dhcpack[];
} multiboot_tag_network_t;

typedef struct multiboot_tag_efi_mmap {
	uint32_t mb_type;
	uint32_t mb_size;
	uint32_t mb_descr_size;
	uint32_t mb_descr_vers;
	uint8_t mb_efi_mmap[];
} multiboot_tag_efi_mmap_t;

typedef struct multiboot_tag_efi32_ih {
	uint32_t mb_type;
	uint32_t mb_size;
	uint32_t mb_pointer;
} multiboot_tag_efi32_ih_t;

typedef struct multiboot_tag_efi64_ih {
	uint32_t mb_type;
	uint32_t mb_size;
	uint64_t mb_pointer;
} multiboot_tag_efi64_ih_t;

typedef struct multiboot_tag_load_base_addr {
	uint32_t mb_type;
	uint32_t mb_size;
	uint32_t mb_load_base_addr;
} multiboot_tag_load_base_addr_t;

#pragma pack()

#endif /* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif /* !_SYS_MULTIBOOT2_H */
