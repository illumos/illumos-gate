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
 *
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * ATAPI-7 Definitions (subset) that include Serial ATA
 * ATA/ATAPI-7 V3 (d1532v3r4b-ATA-ATAPI-7)
 */
#ifndef	_ATAPI7V3_H
#define	_ATAPI7V3_H
#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Register - Host to Device FIS
 */
typedef struct {
	uint8_t 	fis_type;
	uint8_t 	idcbits;
	uint8_t		cmd;
	uint8_t		features;
#define	FEATURE_LBA	0x40
	uint8_t		lba_low;
	uint8_t		lba_mid;
	uint8_t		lba_hi;
	uint8_t		device;
	uint8_t		lba_low_exp;
	uint8_t		lba_mid_exp;
	uint8_t		lba_hi_exp;
	uint8_t		features_exp;
	uint8_t		sector_count;
	uint8_t		sector_count_exp;
	uint8_t		reserved0;
	uint8_t		control;
	uint8_t		reserved1[4];
} register_h2d_fis_t;

/*
 * Register - Device to Host FIS
 */
typedef struct {
	uint8_t		fis_type;
	uint8_t		idcbits;
	uint8_t		status;
	uint8_t		error;
	uint8_t		lba_low;
	uint8_t		lba_mid;
	uint8_t		lba_hi;
	uint8_t		device;
	uint8_t		lba_low_exp;
	uint8_t		lba_mid_exp;
	uint8_t		lba_hi_exp;
	uint8_t		reserved0;
	uint8_t		sector_count;
	uint8_t		sector_count_exp;
	uint8_t		reserved1[6];
} register_d2h_fis_t;

typedef struct {
	uint8_t		fis_type;
	uint8_t		idcbits;
	uint8_t		status_bits;
#define	STATUS_HI_MASK	0xE
#define	STATUS_HI_SHIFT	4
#define	STATUS_LO_MASK	0x7
	uint8_t		error;
	uint8_t		reserved;
} set_device_bits_fis_t;

typedef struct {
	uint8_t		fis_type;
	uint8_t		reserved[3];
} dma_activate_fis_type;

typedef struct {
	uint8_t		fis_type;
	uint8_t		idcbits;
	uint8_t		reserved0[2];
	uint32_t	dma_buffer_id_lo;
	uint32_t	dma_buffer_id_hi;
	uint32_t	reserved1;
	uint32_t	dma_buffer_offset;
	uint32_t	dma_buffer_count;
	uint32_t	reserved2;
} dma_fpactivate_fis_t;

typedef struct {
	uint8_t		fis_type;
	uint8_t		reserved0;
	uint8_t		bist_bits;
	uint8_t		reserved1;
	uint8_t		data[8];
} bist_activate_fis_t;
#define	BIST_T	0x80
#define	BIST_A	0x40
#define	BIST_S	0x20
#define	BIST_L	0x10
#define	BIST_F	0x08
#define	BIST_P	0x04
#define	BIST_V	0x01

typedef struct {
	uint8_t		fis_type;
	uint8_t		idcbits;
	uint8_t		status;
	uint8_t		error;
	uint8_t		lba_low;
	uint8_t		lba_mid;
	uint8_t		lba_high;
	uint8_t		device;
	uint8_t		lba_low_exp;
	uint8_t		lba_mid_exp;
	uint8_t		lba_high_exp;
	uint8_t		reserved0;
	uint8_t		sector_count;
	uint8_t		sector_count_exp;
	uint8_t		reserved1;
	uint8_t		E_status;
	uint16_t	transfer_count;
	uint16_t	reserved2;
} pio_setup_fis_t;

typedef struct {
	uint8_t		fis_type;
	uint32_t	dwords[1];
} bidirectional_fis_t;

/*
 * FIS Types
 */

#define	FIS_REG_H2DEV		0x27	/* 5 DWORDS */
#define	FIS_REG_D2H		0x34	/* 5 DWORDS */
#define	FIS_SET_DEVICE_BITS	0xA1	/* 2 DWORDS */
#define	FIS_DMA_ACTIVATE	0x39	/* 1 DWORD */
#define	FIS_DMA_FPSETUP		0x41	/* 7 DWORDS */
#define	FIS_BIST_ACTIVATE	0x58	/* 3 DWORDS */
#define	FIS_PIO_SETUP		0x5F	/* 5 DWORDS */
#define	FIS_BI			0x46	/* 1 DWORD min, 2048 DWORD max */

/*
 * IDC bits
 */
#define	C_BIT	0x80
#define	I_BIT	0x40
#define	D_BIT	0x20

/*
 * 28-Bit Command Mapping from ACS to FIS
 *
 * ACS Field       	FIS Field
 * --------------------------------------
 * Feature (7:0)	-> Feature
 * Count (7:0)		-> Sector Count
 * LBA (7:0)		-> LBA Low
 * LBA (15:8)		-> LBA Mid
 * LBA (23:16)		-> LBA High
 * LBA (27:24)		-> Device (3:0)
 * Device (15:12)	-> Device (7:4)
 * Command		-> Command
 *
 * 48- Bit Command Mapping from ACS to FIS
 *
 * ACS Field       	FIS Field
 * --------------------------------------
 * Feature (7:0)	-> Feature
 * Feature (15:8)	-> Feature (exp)
 * Count (7:0)		-> Sector Count
 * Count (15:8)		-> Sector Count (exp)
 * LBA (7:0)		-> LBA Low
 * LBA (15:8)		-> LBA Mid
 * LBA (23:16)		-> LBA High
 * LBA (31:24)		-> LBA Low (exp)
 * LBA (39:32)		-> LBA Mid (exp)
 * LBA (47:40)		-> LBA High (exp)
 * Device (15:12)	-> Device (7:4)
 * Command		-> Command
 *
 * FIS (FIS_REG_H2DEV) layout:
 *
 * 31.........24 23...........16 15....................8.7.............0
 * FEATURE	| COMMAND	| C R R RESERVED	| FIS TYPE 0x27
 * DEVICE   	| LBA HIGH	| LBA MID		| LBA LOW
 * FEATURE(exp)	| LBA HIGH(exp)	| LBA MID(exp)		| LBA LOW(exp)
 * CONTROL	| RESERVED	| Sector Count(exp)	| Sector Count
 * RESERVED 	| RESERVED	| RESERVED		| RESERVED
 *
 * FIS (FIS_REG_D2H) layout:
 *
 * 31.........24 23...........16 15....................8.7.............0
 * ERROR        | STATUS        | R I R RESERVED	| FIS TYPE 0x34
 * DEVICE   	| LBA HIGH	| LBA MID		| LBA LOW
 * RESERVED	| LBA HIGH(exp)	| LBA MID(exp)		| LBA LOW(exp)
 * RESERVED 	| RESERVED	| Sector Count(exp)	| Sector Count
 * RESERVED 	| RESERVED	| RESERVED		| RESERVED
 */


/*
 * Reasonable size to reserve for holding the most common FIS types.
 */
typedef	uint32_t fis_t[5];

#ifdef	__cplusplus
}
#endif
#endif	/* _ATAPI7V3_H */
