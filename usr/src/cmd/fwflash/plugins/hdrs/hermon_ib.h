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

#ifndef _HDRS_HERMON_IB_H
#define	_HDRS_HERMON_IB_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ConnectX (hermon) specific definitions.
 */

/*
 * The reference for the definitions in this file is the
 *
 *	Mellanox HCA Flash Programming Application Note
 * (Mellanox document number 2205AN)
 * rev 1.45, 2007. Chapter 4 in particular.
 */

#include <sys/types.h>
#include <sys/ib/adapters/hermon/hermon_ioctl.h>
#include "MELLANOX.h"

#define	FWFLASH_IB_HERMON_DRIVER	"hermon"

/*
 * Image Info section: Refer Mellanox App note 1.45, Section 4.4
 *
 * The Image Info section contains management information about the
 * firmware image. It consists of a series of consecutive data tags.
 * Each tag contains a 32-bit header, providing a TagID which indicates
 * the data type, and the size of the data in the tag.
 */
#define	MLX_MASK_TAGID		0xff000000
#define	MLX_MASK_TAGSIZE	0x00ffffff

enum tag_ids {
	CNX_IMAGE_INFO_REV	= 0,	/* IMAGE_INFO format revision */
	CNX_FW_VER		= 1,	/* Firmware Version */
	CNX_FW_BUILD_TIME	= 2,	/* Firmware Build Time */
	CNX_DEV_TYPE		= 3,	/* Device Type */
	CNX_PSID		= 4,	/* Parameter Set IDentification */
	CNX_VSD			= 5,	/* Vendor Specific Data */
	CNX_RES1		= 6,	/* reserved */
	CNX_RES2		= 7,	/* reserved */
	CNX_VSD_VENDOR_ID	= 8,	/* PCISIG vendor ID */
	/* 0x9 - 0xFE are reserved */
	CNX_END_TAG		= 0xff	/* END tag */
};

enum tag_sizes {
	CNX_IMAGE_INFO_REV_SZ	= 4,
	CNX_FW_VER_SZ		= 8,
	CNX_FW_BUILD_TIME_SZ	= 8,
	CNX_DEV_TYPE_SZ		= 4,
	CNX_PSID_SZ		= 16,
	CNX_VSD_SZ		= 208,
	CNX_VSD_VENDOR_ID_SZ	= 4,
	CNX_END_TAG_SZ		= 0
};

/*
 * Image Info Format revision (TagID - CNX_IMAGE_INFO_REV).
 * Provides the format revision of the Image Info section. Currently it is 0x1
 */
#define	CNX_IMAGE_INFO_VER	1

/*
 * Firmware Version (TagID - CNX_FW_VER)
 * Provides the major, minor and sub-minor versions of the firmware image.
 */
#define	CNX_MASK_FW_VER_MAJ	0xffff0000
#define	CNX_MASK_FW_VER_MIN	CNX_MASK_FW_VER_MAJ
#define	CNX_MASK_FW_VER_SUBMIN	0x0000ffff

typedef struct cnx_fw_rev_s {
	uint16_t	major;
	uint16_t	reserved;
	uint16_t	minor;
	uint16_t	subminor;
} cnx_fw_rev_t;


/*
 * Firmware Build Time (TagID - CNX_FW_BUILD_TIME)
 * Provides the data and time of the firmware image build.
 */
#define	CNX_MASK_FW_BUILD_HOUR	0x00ff0000
#define	CNX_MASK_FW_BUILD_MIN	0x0000ff00
#define	CNX_MASK_FW_BUILD_SEC	0x000000ff
#define	CNX_MASK_FW_BUILD_YEAR	0xffff0000
#define	CNX_MASK_FW_BUILD_MON	0x0000ff00
#define	CNX_MASK_FW_BUILD_DAY	0x000000ff

typedef struct cnx_fw_build_time_tag {
	uint8_t		reserved;
	uint8_t		hour;
	uint8_t		minute;
	uint8_t		second;
	uint16_t	year;
	uint8_t		month;
	uint8_t		day;
} cnx_fw_build_time_t;

/*
 * Device Type (TagID - CNX_DEV_TYPE)
 * The device type tag is only 4 bytes long, so we don't bother to
 * declare a separate struct for it.
 *
 * The CNX_MASK_DEV_TYPE_REV provides the mask to extract the hardware
 * device's PCI Revision ID.
 * The CNX_MASK_DEV_TYPE_ID provides the mask to extract the hardware
 * device's PCI Device ID.
 */
#define	CNX_MASK_DEV_TYPE_REV	0x00ff0000
#define	CNX_MASK_DEV_TYPE_ID	0x0000ffff

/*
 * The PSID (TagID - CNX_PSID) and VSD (TagID - CNX_VSD) tag contents are
 * just bytes without any specific structure, so we'll declare their sizes
 * but nothing else.
 */
#define	CNX_TAG_PSID_SIZE		0x10
#define	CNX_TAG_VSD_SIZE		0xD0

/*
 * VSD Vendor ID (TagID - CNX_VSD_VENDOR_ID)
 * The VSD Vendor ID tag holds the PCISIG vendor ID of the vendor that
 * fills the VSD tag.
 */
#define	CNX_MASK_VSD_VENDORID		0x00ff

typedef struct cnx_img_info_s {
	cnx_fw_rev_t		fw_rev;
	cnx_fw_build_time_t	fw_buildtime;
	uint16_t		dev_id;
	uint16_t		vsd_vendor_id;
	uint8_t			psid[CNX_PSID_SZ];
	uint8_t			vsd[CNX_VSD_SZ];
} cnx_img_info_t;

/*
 * ConnectX Devices Firmware Image Format
 */
typedef struct mlx_cnx_xfi {			/* Byte Offset */
	uint32_t	magic_pattern[4];	/* 0x00 - 0x0F */
	uint8_t		xfiresv1[24];		/* 0x10 - 0x27 */
	uint32_t	failsafechunkinfo;	/* 0x28 - 0x2B */
	uint32_t	imageinfoptr;		/* 0x2C - 0x2F */
	uint32_t	fwimagesz;		/* 0x30 - 0x33 */
	uint32_t	nguidptr;		/* 0x34 - 0x37 */
	uint8_t		*xfiremainder;
} mlx_cnx_xfi_t;

uint32_t	cnx_magic_pattern[4] = {
			0x4D544657,
			0x8CDFD000,
			0xDEAD9270,
			0x4154BEEF };

#define	CNX_XFI_IMGINFO_CKSUM_MASK	0xFF000000
#define	CNX_XFI_IMGINFO_PTR_MASK	0x00FFFFFF

#define	CNX_HWVER_OFFSET		0x20
#define	CNX_HWVER_MASK			0xFF000000

#define	CNX_CHUNK_SIZE_OFFSET		0x28
#define	CNX_IMG_INF_PTR_OFFSET		0x2C
#define	CNX_IMG_INF_SZ_OFFSET		-0x0C
#define	CNX_IMG_SIZE_OFFSET		0x30
#define	CNX_NGUIDPTR_OFFSET		0x34

/*
 * ConnectX Devices GUID Section Structure.
 *
 * Of all the structures we poke around with, we're packing
 * these because we frequently have to operate on them as
 * plain old byte arrays. If we don't pack it then the compiler
 * will "properly" align it for us - which results in a
 * structure that's a l l  s p r e a d  o u t.
 */
#pragma pack(1)
typedef struct mlx_cnx_guid_sect {	/* Byte Offset */
	uint8_t		guidresv[16];	/* 0x00 - 0x0F */
	uint64_t	nodeguid;	/* 0x10 - 0x17 */
	uint64_t	port1guid;	/* 0x18 - 0x1F */
	uint64_t	port2guid;	/* 0x20 - 0x27 */
	uint64_t	sysimguid;	/* 0x28 - 0x2F */
	uint64_t	port1_mac; 	/* 0x30 - 0x31 - rsvd - must be zero */
					/* 0x32 - 0x37 - Port1 MAC [47:0] */
	uint64_t	port2_mac; 	/* 0x38 - 0x39 - rsvd - must be zero */
					/* 0x3A - 0x3F - Port2 MAC [47:0] */
	uint16_t	guidresv2;	/* 0x40 - 0x41 */
	uint16_t	guidcrc;	/* 0x42 - 0x43 */
} mlx_cnx_guid_sect_t;
#pragma pack()

#define	CNX_NGUID_OFFSET		0x10
#define	CNX_P1GUID_OFFSET		0x18
#define	CNX_P2GUID_OFFSET		0x20
#define	CNX_SYSIMGUID_OFFSET		0x28
#define	CNX_P1MAC_OFFSET		0x32
#define	CNX_P2MAC_OFFSET		0x3A
#define	CNX_GUID_CRC16_SIZE		0x40	/* 00-3F */
#define	CNX_GUID_CRC16_OFFSET		0x42


/* we hook this struct into vpr->encap_ident */
typedef struct ib_cnx_encap_ident_s {
	uint_t		magic;		/* FWFLASH_IB_MAGIC_NUMBER */
	int		fd;		/* fd of hermon device */
	int		cmd_set;	/* COMMAND SET */
	int		pn_len;		/* Part# Length */
	int		hwfw_match;	/* 1 = match, 0 - nomatch */
					/* Used during write for validation */
	cnx_img_info_t	hwfw_img_info;	/* HW Image Info Section */
	cnx_img_info_t	file_img_info;	/* Image File's Image Info Section */
	mlx_mdr_t	info;		/* Details of HW part#, name, */
	uint32_t	*fw;		/* this where image is read to */
	uint32_t	hwrev;		/* H/W revision. ex: A0, A1 */
	uint32_t	fw_sz;		/* FW image size */
	uint32_t	sector_sz;	/* FW sector size */
	uint32_t	device_sz;	/* FW device size */
	uint32_t	state;
	uint64_t	ibguids[4];	/* HW's GUIDs backup info */
	uint64_t	ib_mac[2];	/* HW's MAC backup info */
	uint32_t	log2_chunk_sz;	/* FW chunk size */
	uint32_t	img2_start_addr;	/* Boot Address, 0 - Pri */
} ib_cnx_encap_ident_t;

/*
 * Common Flash Interface data.
 */
typedef union cfi_u {
	uchar_t		cfi_char[HERMON_CFI_INFO_SIZE];
	uint32_t	cfi_int[HERMON_CFI_INFO_QSIZE];
} cfi_t;

/* used by both identify and verifier plugin */
uint16_t cnx_crc16(uint8_t *image, uint32_t size, int is_image);
int cnx_is_magic_pattern_present(int *data, int hwim_or_fwim);
int cnx_parse_img_info(int *buf, uint32_t byte_size, cnx_img_info_t *img_info,
    int is_image);

#define	CNX_FILE_IMG	1	/* Processing File Image */
#define	CNX_HW_IMG	2	/* Processing Hardware Image */

/* Validate the handle */
#define	CNX_I_CHECK_HANDLE(s)	\
	((s == NULL) || ((s)->magic != FWFLASH_IB_MAGIC_NUMBER))

#ifdef __cplusplus
}
#endif

#endif /* _HDRS_HERMON_IB_H */
