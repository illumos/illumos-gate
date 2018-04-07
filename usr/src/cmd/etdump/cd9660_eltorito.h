/*
 * $NetBSD: cd9660_eltorito.h,v 1.6 2017/01/24 11:22:43 nonaka Exp $
 */

/*
 * SPDX-License-Identifier: BSD-2-Clause-NetBSD
 *
 * Copyright (c) 2005 Daniel Watt, Walter Deignan, Ryan Gabrys, Alan
 * Perez-Rathke and Ram Vedam.  All rights reserved.
 *
 * This code was written by Daniel Watt, Walter Deignan, Ryan Gabrys,
 * Alan Perez-Rathke and Ram Vedam.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY DANIEL WATT, WALTER DEIGNAN, RYAN
 * GABRYS, ALAN PEREZ-RATHKE AND RAM VEDAM ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL DANIEL WATT, WALTER DEIGNAN, RYAN
 * GABRYS, ALAN PEREZ-RATHKE AND RAM VEDAM BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE,DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#ifndef _CD9660_ELTORITO_H_
#define	_CD9660_ELTORITO_H_

#include <sys/types.h>
#include <sys/queue.h>

/* Boot defines */
#define	ET_ID		"EL TORITO SPECIFICATION"
#define	ET_SYS_X86	0
#define	ET_SYS_PPC	1
#define	ET_SYS_MAC	2
#define	ET_SYS_EFI	0xef	/* Platform ID at section header entry */

#define	ET_BOOT_ENTRY_SIZE 0x20

#define	ET_BOOTABLE		0x88
#define	ET_NOT_BOOTABLE		0

#define	ET_MEDIA_NOEM			0
#define	ET_MEDIA_12FDD			1
#define	ET_MEDIA_144FDD			2
#define	ET_MEDIA_288FDD			3
#define	ET_MEDIA_HDD			4

#define	ET_INDICATOR_HEADERMORE	0x90
#define	ET_INDICATOR_HEADERLAST	0x91
#define	ET_INDICATOR_EXTENSION	0x44

/* Boot Structures */

#define	ISODCL(from, to) (to - from + 1)

typedef struct _boot_volume_descriptor {
	uchar_t boot_record_indicator	[ISODCL(0x00, 0x00)];
	uchar_t identifier		[ISODCL(0x01, 0x05)];
	uchar_t version			[ISODCL(0x06, 0x06)];
	uchar_t boot_system_identifier	[ISODCL(0x07, 0x26)];
	uchar_t unused1			[ISODCL(0x27, 0x46)];
	uchar_t boot_catalog_pointer	[ISODCL(0x47, 0x4A)];
	uchar_t unused2			[ISODCL(0x4B, 0x7FF)];
} boot_volume_descriptor;

typedef struct _boot_catalog_validation_entry {
	uchar_t header_id		[ISODCL(0x00, 0x00)];
	uchar_t platform_id		[ISODCL(0x01, 0x01)];
	uchar_t reserved1		[ISODCL(0x02, 0x03)];
	uchar_t manufacturer		[ISODCL(0x04, 0x1B)];
	uchar_t checksum		[ISODCL(0x1C, 0x1D)];
	uchar_t key			[ISODCL(0x1E, 0x1F)];
} boot_catalog_validation_entry;

typedef struct _boot_catalog_initial_entry {
	uchar_t boot_indicator		[ISODCL(0x00, 0x00)];
	uchar_t media_type		[ISODCL(0x01, 0x01)];
	uchar_t load_segment		[ISODCL(0x02, 0x03)];
	uchar_t system_type		[ISODCL(0x04, 0x04)];
	uchar_t unused_1		[ISODCL(0x05, 0x05)];
	uchar_t sector_count		[ISODCL(0x06, 0x07)];
	uchar_t load_rba		[ISODCL(0x08, 0x0B)];
	uchar_t unused_2		[ISODCL(0x0C, 0x1F)];
} boot_catalog_initial_entry;

#define	ET_SECTION_HEADER_MORE		0x90
#define	ET_SECTION_HEADER_LAST		0x91

typedef struct _boot_catalog_section_header {
	uchar_t header_indicator	[ISODCL(0x00, 0x00)];
	uchar_t platform_id		[ISODCL(0x01, 0x01)];
	uchar_t num_section_entries	[ISODCL(0x02, 0x03)];
	uchar_t id_string		[ISODCL(0x04, 0x1F)];
} boot_catalog_section_header;

typedef struct _boot_catalog_section_entry {
	uchar_t boot_indicator		[ISODCL(0x00, 0x00)];
	uchar_t media_type		[ISODCL(0x01, 0x01)];
	uchar_t load_segment		[ISODCL(0x02, 0x03)];
	uchar_t system_type		[ISODCL(0x04, 0x04)];
	uchar_t unused_1		[ISODCL(0x05, 0x05)];
	uchar_t sector_count		[ISODCL(0x06, 0x07)];
	uchar_t load_rba		[ISODCL(0x08, 0x0B)];
	uchar_t selection_criteria	[ISODCL(0x0C, 0x0C)];
	uchar_t vendor_criteria		[ISODCL(0x0D, 0x1F)];
} boot_catalog_section_entry;

typedef struct _boot_catalog_section_entry_extension {
	uchar_t extension_indicator	[ISODCL(0x00, 0x00)];
	uchar_t flags			[ISODCL(0x01, 0x01)];
	uchar_t vendor_criteria		[ISODCL(0x02, 0x1F)];
} boot_catalog_section_entry_extension;

#define	ET_ENTRY_VE 1
#define	ET_ENTRY_IE 2
#define	ET_ENTRY_SH 3
#define	ET_ENTRY_SE 4
#define	ET_ENTRY_EX 5

struct boot_catalog_entry {
	char entry_type;
	union {
		boot_catalog_validation_entry		VE;
		boot_catalog_initial_entry		IE;
		boot_catalog_section_header		SH;
		boot_catalog_section_entry		SE;
		boot_catalog_section_entry_extension	EX;
	} entry_data;

	LIST_ENTRY(boot_catalog_entry) ll_struct;
};

/* Temporary structure */
struct cd9660_boot_image {
	char *filename;
	int size;
	int sector;			/* copied to LoadRBA */
	int num_sectors;
	unsigned int loadSegment;
	uchar_t targetMode;
	uchar_t system;
	uchar_t bootable;
	uchar_t platform_id;		/* for section header entry */
	/*
	 * If the boot image exists in the filesystem
	 * already, this is a pointer to that node. For the sake
	 * of simplicity in future versions, this pointer is only
	 * to the node in the primary volume. This SHOULD be done
	 * via a hashtable lookup.
	 */
	struct _cd9660node *boot_image_node;
	TAILQ_ENTRY(cd9660_boot_image) image_list;
	int serialno;
};

void cd9660_721(uint16_t, unsigned char *);

static __inline uint16_t
isonum_721(const unsigned char *p)
{

	return (p[0] | p[1] << 8);
}

static __inline uint32_t
isonum_731(const unsigned char *p)
{

	return (p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24);
}

#endif /* _CD9660_ELTORITO_H_ */
