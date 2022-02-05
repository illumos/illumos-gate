/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Toomas Soome <tsoome@me.com>
 */

#ifndef _LINUX_H
#define	_LINUX_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ASM_FILE
/* For the Linux/i386 boot protocol version 2.10.  */
struct linux_kernel_header
{
  uint8_t code1[0x0020];
  uint16_t cl_magic;               /* Magic number 0xA33F */
  uint16_t cl_offset;              /* The offset of command line */
  uint8_t code2[0x01F1 - 0x0020 - 2 - 2];
  uint8_t setup_sects;             /* The size of the setup in sectors */
  uint16_t root_flags;             /* If the root is mounted readonly */
  uint16_t syssize;                /* obsolete */
  uint16_t swap_dev;               /* obsolete */
  uint16_t ram_size;               /* obsolete */
  uint16_t vid_mode;               /* Video mode control */
  uint16_t root_dev;               /* Default root device number */
  uint16_t boot_flag;              /* 0xAA55 magic number */
  uint16_t jump;                   /* Jump instruction */
  uint32_t header;                 /* Magic signature "HdrS" */
  uint16_t version;                /* Boot protocol version supported */
  uint32_t realmode_swtch;         /* Boot loader hook */
  uint16_t start_sys;              /* The load-low segment (obsolete) */
  uint16_t kernel_version;         /* Points to kernel version string */
  uint8_t type_of_loader;          /* Boot loader identifier */
  uint8_t loadflags;               /* Boot protocol option flags */
  uint16_t setup_move_size;        /* Move to high memory size */
  uint32_t code32_start;           /* Boot loader hook */
  uint32_t ramdisk_image;          /* initrd load address */
  uint32_t ramdisk_size;           /* initrd size */
  uint32_t bootsect_kludge;        /* obsolete */
  uint16_t heap_end_ptr;           /* Free memory after setup end */
  uint16_t pad1;                   /* Unused */
  uint32_t cmd_line_ptr;           /* Points to the kernel command line */
  uint32_t initrd_addr_max;        /* Highest address for initrd */
  uint32_t kernel_alignment;
  uint8_t relocatable;
  uint8_t min_alignment;
  uint8_t pad[2];
  uint32_t cmdline_size;
  uint32_t hardware_subarch;
  uint64_t hardware_subarch_data;
  uint32_t payload_offset;
  uint32_t payload_length;
  uint64_t setup_data;
  uint64_t pref_address;
  uint32_t init_size;
} __attribute__ ((packed));
#endif

#define	LINUX_VID_MODE_NORMAL		0xFFFF
#define	LINUX_VID_MODE_EXTENDED		0xFFFE
#define	LINUX_VID_MODE_ASK		0xFFFD

#define	BOOTSEC_SIGNATURE		0xAA55
#define	LINUX_BOOT_LOADER_TYPE		0x72
#define	LINUX_BZIMAGE_ADDR		0x100000
#define	LINUX_CL_END_OFFSET		0x90FF
#define	LINUX_CL_MAGIC			0xA33F
#define	LINUX_CL_OFFSET			0x9000
#define	LINUX_DEFAULT_SETUP_SECTS	4
#define	LINUX_ESP			0x9000
#define	LINUX_FLAG_BIG_KERNEL		0x1
#define	LINUX_FLAG_CAN_USE_HEAP		0x80
#define	LINUX_HEAP_END_OFFSET		(0x9000 - 0x200)
#define	LINUX_MAGIC_SIGNATURE		0x53726448
#define	LINUX_MAX_SETUP_SECTS		64
#define	LINUX_OLD_REAL_MODE_ADDR	0x90000
#define	LINUX_SETUP_MOVE_SIZE		0x9100
#define	LINUX_ZIMAGE_ADDR		0x10000
#define	LINUX_INITRD_MAX_ADDRESS	0x38000000

#ifdef __cplusplus
}
#endif

#endif /* _LINUX_H */
