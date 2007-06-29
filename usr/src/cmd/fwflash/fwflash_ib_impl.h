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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FWFLASH_IB_IMPL_H
#define	_FWFLASH_IB_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * fwflash_ib_impl.h
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	FLASH_PS_SIGNATURE				0x5a445a44

#define	FLASH_IS_SECTOR_SIZE_OFFSET			0x30
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
#define	FLASH_PS_VSD_LENGTH				0xe0
/* PSID is the last 16B of VSD */
#define	FLASH_PS_PSID_OFFSET				0xf0

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

#define	FLASH_PS_CRC16_SIZE				0x104
#define	FLASH_PS_CRC16_OFFSET				0x106

#define	FLASH_FI_NGUID_OFFSET				0x0
#define	FLASH_FI_P1GUID_OFFSET				0x08
#define	FLASH_FI_P2GUID_OFFSET				0x10
#define	FLASH_FI_SYSIMGUID_OFFSET			0x18
#define	FLASH_GUID_CRC16_SIZE				0x30
#define	FLASH_GUID_CRC16_OFFSET				0x32
#define	FLASH_GUID_SIZE					0x34

/*
 * Used during read/write ioctl calls to setup the offset into the firmware
 * image memory for that particular sector.
 */
#define	FLASH_SECTOR_OFFSET(fw, sect, sz)		\
	(caddr_t)((uintptr_t)fw + (sect << sz))

/*
 * Vital System Data from PCI config space.
 */
typedef union vsd_u {
	uchar_t vsd_char[FLASH_PS_VSD_LENGTH];
	uint32_t vsd_int[FLASH_PS_VSD_LENGTH / 4];
} vsd_t;

/*
 * Common Flash Interface data.
 */
typedef union cfi_u {
	uchar_t cfi_char[TAVOR_FLASH_CFI_SIZE];
	uint32_t cfi_int[TAVOR_FLASH_CFI_SIZE_QUADLET];
} cfi_t;

#ifdef __cplusplus
}
#endif

#endif /* _FWFLASH_IB_IMPL_H */
