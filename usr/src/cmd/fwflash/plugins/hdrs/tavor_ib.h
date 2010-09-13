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

#ifndef _TAVOR_IB_H
#define	_TAVOR_IB_H

/*
 * tavor_ib.h
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ib/adapters/tavor/tavor_ioctl.h>

#define	FWFLASH_IB_DRIVER_NAME		"tavor"

#define	NODE_GUID_OFFSET		0x0
#define	PORT1_GUID_OFFSET		0x08
#define	PORT2_GUID_OFFSET		0x10
#define	FLASH_SIZE_OFFSET		0x20
#define	FLASH_GUID_PTR			0x24

typedef struct fw_rev_s {
	uint32_t	major;
	uint32_t	minor;
	uint32_t	subminor;
	uint32_t	holder;
} fw_rev_t;


typedef struct mlx_is {
	uint8_t		isresv1[16];
	uint8_t		hwrev; /* hardware version */
	uint8_t		isver; /* Invariant Sector version */
	uint32_t	isresv2;
	/* offset from 0x32 to get log2sectsz */
	uint16_t	log2sectszp;
	/*
	 * 3rd lot of reserved bytes CAN BE variable length,
	 * but defaults to 0x18 bytes
	 */
	uint8_t		isresv3[0x18];
	uint16_t	log2sectsz; /* log_2 of flash sector size */
	uint8_t		*isresv4; /* remainder of IS */
} mlx_is_t;

typedef struct mlx_xps {
	uint32_t	fia; /* fw image addr */
	uint32_t	fis; /* fw image size */
	uint32_t	signature; /* firmware signature */
	uint8_t		xpsresv1[20];
	uint8_t		vsdpsid[224]; /* VSD and PSID */
	uint32_t	xpsresv2;
	uint16_t	xpsresv3; /* MUST be zero */
	uint16_t	crc16;
	uint8_t		*xpsresv4; /* from 0x108 to END OF SECTOR */
} mlx_xps_t;


#define	XFI_IMGINFO_OFFSET	28
#define	XFI_IMGINFO_CKSUM_MASK	0xFF000000
#define	XFI_IMGINFO_PTR_MASK	0x00FFFFFF

typedef struct mlx_xfi {
	uint8_t		xfiresv1[28];
	uint32_t	imageinfoptr;
	uint32_t	xfiresv2;
	uint32_t	nguidptr;
	uint8_t		*xfiremainder;
} mlx_xfi_t;

/*
 * Of all the structures we poke around with, we're packing
 * these because we frequently have to operate on them as
 * plain old byte arrays. If we don't pack it then the compiler
 * will "properly" align it for us - which results in a
 * structure that's a l l  s p r e a d  o u t.
 */
#pragma pack(1)
typedef struct mlx_guid_sect
{
	uint8_t		guidresv[16];
	uint64_t	nodeguid;
	uint64_t	port1guid;
	uint64_t	port2guid;
	uint64_t	sysimguid;
	uint16_t	guidresv2;
	uint16_t	guidcrc;
} mlx_guid_sect_t;
#pragma pack()

/* this is 13x 32bit words */
#define	GUIDSECTION_SZ	sizeof (struct mlx_guid_sect)

/* we hook this struct into vpr->encap_ident */
typedef struct ib_encap_ident {
	uint_t		magic;
	int		fd;
	fw_rev_t	fw_rev;
	uint32_t	hwrev;
	uint32_t	sector_sz;
	uint32_t	device_sz;
	uint32_t	state;
	int		cmd_set;
	mlx_mdr_t	info;
	int		pn_len;
	int		hwfw_match;
	uint32_t	pfi_guid_addr; /* addr of the offset */
	uint32_t	sfi_guid_addr;
	uint32_t	pri_guid_section[GUIDSECTION_SZ];
	uint32_t	sec_guid_section[GUIDSECTION_SZ];
	uint64_t	ibguids[4];
	uint8_t		*inv; /* Invariant Sector */
	uint8_t		*pps; /* Primary Pointer Sector */
	uint8_t		*sps; /* Secondary Pointer Sector */
	uint8_t		*pfi; /* Primary Firmware Image */
	uint8_t		*sfi; /* Secondary Firmware Image */
	uint8_t		mlx_psid[16];
	uint8_t		mlx_vsd[208];
} ib_encap_ident_t;

#define	FLASH_PS_SIGNATURE				0x5a445a44

#define	FLASH_IS_SECTOR_SIZE_OFFSET			0x32
#define	FLASH_IS_SECTOR_SIZE_MASK			0x0000FFFF
#define	FLASH_IS_HWVER_OFFSET				0x10
#define	FLASH_IS_HWVER_MASK				0xFF000000
#define	FLASH_IS_ISVER_MASK				0x00FF0000

#define	FLASH_IS_SECT_SIZE_PTR				0x16
#define	FLASH_IS_SECT_SIZE_PTR_MASK			0x0000FFFF

#define	FLASH_PS_FI_ADDR_OFFSET				0x00
#define	FLASH_PS_FW_SIZE_OFFSET				0x04
#define	FLASH_PS_SIGNATURE_OFFSET			0x08
/* Vendor Specific Data (VSD) */
#define	FLASH_PS_VSD_OFFSET				0x20
/* VSD length in bytes */
#define	FLASH_PS_VSD_LENGTH				0xE0
#define	FLASH_PS_VSD_LENGTH_4				0x38
/* PSID is the last 16B of VSD */
#define	FLASH_PS_PSID_OFFSET				0xF0

/* For use with Cisco's VSD */
#define	FLASH_VSD_CISCO_SIGNATURE			0x05ad
#define	FLASH_VSD_CISCO_BOOT_OPTIONS			0x00000004
#define	FLASH_VSD_CISCO_FLAG_AUTOUPGRADE		0x01000000
#define	FLASH_VSD_CISCO_FLAG_BOOT_ENABLE_PORT_1		0x00010000
#define	FLASH_VSD_CISCO_FLAG_BOOT_ENABLE_PORT_2		0x00020000
#define	FLASH_VSD_CISCO_FLAG_BOOT_ENABLE_SCAN		0x00040000
#define	FLASH_VSD_CISCO_FLAG_BOOT_TYPE_WELL_KNOWN	0x00000000
#define	FLASH_VSD_CISCO_FLAG_BOOT_TRY_FOREVER		0x00001000
#define	FLASH_VSD_CISCO_BOOT_VERSION			2
/* For use with Cisco's VSD */

#define	MLX_CISCO_CHECK					1
#define	MLX_CISCO_SET					2

#define	FLASH_PS_CRC16_SIZE				0x104
#define	FLASH_PS_CRC16_OFFSET				0x106

#define	FLASH_FI_NGUID_OFFSET				0x0
#define	FLASH_FI_P1GUID_OFFSET				0x08
#define	FLASH_FI_P2GUID_OFFSET				0x10
#define	FLASH_FI_SYSIMGUID_OFFSET			0x18
#define	FLASH_GUID_CRC16_SIZE				0x30
#define	FLASH_GUID_CRC16_OFFSET				0x32
#define	FLASH_GUID_SIZE					0x34

#define	FLASH_GUID_CRC_LEN				0x2F
/*
 * Used during read/write ioctl calls to setup the offset into the firmware
 * image memory for that particular sector.
 */
#define	FLASH_SECTOR_OFFSET(fw, sect, sz)		\
	(caddr_t)((uintptr_t)fw + (sect << sz))

/*
 * Vital System Data from PCI config space.
 */
uint32_t vsd_int[FLASH_PS_VSD_LENGTH_4];


/*
 * Common Flash Interface data.
 */
typedef union cfi_u {
	uchar_t cfi_char[TAVOR_CFI_INFO_SIZE];
	uint32_t cfi_int[TAVOR_CFI_INFO_QSIZE];
} cfi_t;


#ifdef __cplusplus
}
#endif




#endif /* _TAVOR_IB_H */
