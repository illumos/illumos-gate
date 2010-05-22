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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _HDRS_MELLANOX_H
#define	_HDRS_MELLANOX_H


#ifdef __cplusplus
extern "C" {
#endif

/*
 * MELLANOX.h
 *
 * This file contain common information related to Mellanox technologies
 * HCA cards.
 */
#define	SUNW_OUI		0x0003baULL
#define	MLX_OUI			0x0002c9ULL
#define	MLX_DEFAULT_NODE_GUID	0x2c9000100d050ULL
#define	MLX_DEFAULT_P1_GUID	0x2c9000100d051ULL
#define	MLX_DEFAULT_P2_GUID	0x2c9000100d052ULL
#define	MLX_DEFAULT_SYSIMG_GUID	0x2c9000100d053ULL

/* How many bits to shift and leave just the OUI */
#define	OUISHIFT		40

#define	MLX_VPR_VIDLEN		9	/* "MELLANOX" + '\0' */
#define	MLX_VPR_REVLEN		21	/* "%04x.%04x.%04x: %04x" + '\0' */

#define	FWFLASH_IB_MAGIC_NUMBER		0xF00B0021

/* Numerically largest OUI that's presently assigned */
#define	TAVOR_MAX_OUI			0xacde48

#define	FWFLASH_IB_STATE_NONE		0x00
#define	FWFLASH_IB_STATE_IMAGE_PRI	0x01
#define	FWFLASH_IB_STATE_IMAGE_SEC	0x02
#define	FWFLASH_IB_STATE_MMAP		0x04
#define	FWFLASH_IB_STATE_GUIDN		0x10
#define	FWFLASH_IB_STATE_GUID1		0x20
#define	FWFLASH_IB_STATE_GUID2		0x40
#define	FWFLASH_IB_STATE_GUIDS		0x80

#define	FWFLASH_IB_STATE_IMAGE		FWFLASH_IB_STATE_IMAGE_PRI

#define	FWFLASH_IB_STATE_PFI_IMAGE	FWFLASH_IB_STATE_IMAGE_PRI
#define	FWFLASH_IB_STATE_SFI_IMAGE	FWFLASH_IB_STATE_IMAGE_SEC

/*
 * Structure to hold the part number, PSID, and string ID
 * for an HCA card.
 */
typedef struct mlx_mdr_s {
	char *mlx_pn;
	char *mlx_psid;
	char *mlx_id;
} mlx_mdr_t;

/*
 * Magic decoder ring for matching HCA hardware/firmware.
 * Part Number / PSID / String ID
 */
mlx_mdr_t mlx_mdr[] = {
	/* Part No		PSID			Card ID */
	{ "MHEA28-XS",		"MT_0250000001",	"Lion mini" },
	{ "MHEA28-XSC",		"MT_0390110001",	"Lion mini" },
	{ "MHEA28-XT",		"MT_0150000001",	"Lion mini" },
	{ "MHEA28-XTC",		"MT_0370110001",	"Lion mini" },
	{ "MHGA28-XT",		"MT_0150000002",	"Lion mini" },
	{ "MHGA28-XTC",		"MT_0370110002",	"Lion mini" },
	{ "MHGA28-XTC",		"MT_0370130002",	"Lion mini" },
	{ "MHGA28-XS",		"MT_0250000002",	"Lion mini" },
	{ "MHGA28-XSC",		"MT_0390110002",	"Lion mini" },
	{ "MHGA28-XSC",		"MT_0390130002",	"Lion mini" },
	{ "MHEL-CF128",		"MT_0190000001",	"Lion cub" },
	{ "MHEL-CF128-T",	"MT_00A0000001",	"Lion cub" },
	{ "MTLP25208-CF128T",	"MT_00A0000001",	"Lion cub" },
	{ "MHEL-CF128-TC",	"MT_00A0010001",	"Lion cub" },
	{ "MHEL-CF128-TC",	"MT_0140010001",	"Lion cub" },
	{ "MHEL-CF128-SC",	"MT_0190010001",	"Lion cub" },
	{ "MHEA28-1TC",		"MT_02F0110001",	"Lion cub" },
	{ "MHEA28-1SC",		"MT_0330110001",	"Lion cub" },
	{ "MHGA28-1T",		"MT_0200000001",	"Lion cub" },
	{ "MHGA28-1TC",		"MT_02F0110002",	"Lion cub" },
	{ "MHGA28-1SC",		"MT_0330110002",	"Lion cub" },
	{ "MHGA28-1S",		"MT_0430000001",	"Lion cub" },
	{ "MHEL-CF256-T",	"MT_00B0000001",	"Lion cub" },
	{ "MTLP25208-CF256T",	"MT_00B0000001",	"Lion cub" },
	{ "MHEL-CF256-TC",	"MT_00B0010001",	"Lion cub" },
	{ "MHEA28-2TC",		"MT_0300110001",	"Lion cub" },
	{ "MHEA28-2SC",		"MT_0340110001",	"Lion cub" },
	{ "MHGA28-2T",		"MT_0210000001",	"Lion cub" },
	{ "MHGA28-2TC",		"MT_0300110002",	"Lion cub" },
	{ "MHGA28-2SC",		"MT_0340110002",	"Lion cub" },
	{ "MHEL-CF512-T",	"MT_00C0000001",	"Lion cub" },
	{ "MTLP25208-CF512T",	"MT_00C0000001",	"Lion cub" },
	{ "MHGA28-5T",		"MT_0220000001",	"Lion cub" },
	{ "375-3382-01",	"SUN0030000001",	"Sun Lion cub DDR" },
	{ "MHES14-XSC",		"MT_0410110001",	"Tiger" },
	{ "MHES14-XT",		"MT_01F0000001",	"Tiger" },
	{ "MHES14-XTC",		"MT_03F0110001",	"Tiger" },
	{ "MHES18-XS",		"MT_0260000001",	"Cheetah" },
	{ "MHES18-XS",		"MT_0260010001",	"Cheetah" },
	{ "MHES18-XSC",		"MT_03D0110001",	"Cheetah" },
	{ "MHES18-XSC",		"MT_03D0120001",	"Cheetah" },
	{ "MHES18-XSC",		"MT_03D0130001",	"Cheetah" },
	{ "MHES18-XT",		"MT_0230000002",	"Cheetah" },
	{ "MHES18-XT",		"MT_0230010002",	"Cheetah" },
	{ "MHES18-XTC",		"MT_03B0110001",	"Cheetah" },
	{ "MHES18-XTC",		"MT_03B0120001",	"Cheetah" },
	{ "MHES18-XTC",		"MT_03B0140001",	"Cheetah" },
	{ "MHGS18-XS",		"MT_0260000002",	"Cheetah" },
	{ "MHGS18-XSC",		"MT_03D0110002",	"Cheetah" },
	{ "MHGS18-XSC",		"MT_03D0120002",	"Cheetah" },
	{ "MHGS18-XSC",		"MT_03D0130002",	"Cheetah" },
	{ "MHGS18-XT",		"MT_0230000001",	"Cheetah" },
	{ "MHGS18-XTC",		"MT_03B0110002",	"Cheetah" },
	{ "MHGS18-XTC",		"MT_03B0120002",	"Cheetah" },
	{ "MHGS18-XTC",		"MT_03B0140002",	"Cheetah" },
	{ "MHXL-CF128",		"MT_0180000001",	"Cougar Cub 128" },
	{ "MHXL-CF128-T",	"MT_0030000001",	"Cougar Cub 128" },
	{ "MTLP23108-CF128T",	"MT_0030000001",	"Cougar Cub 128" },
	{ "MHET2X-1SC",		"MT_0280110001",	"Cougar Cub 128" },
	{ "MHET2X-1SC",		"MT_0280120001",	"Cougar Cub 128" },
	{ "MHET2X-1TC",		"MT_0270110001",	"Cougar Cub 128" },
	{ "MHET2X-1TC",		"MT_0270120001",	"Cougar Cub 128" },
	{ "MHXL-CF256-T",	"MT_0040000001",	"Cougar Cub 256" },
	{ "MHET2X-2SC",		"MT_02D0110001",	"Cougar Cub 256" },
	{ "MHET2X-2SC",		"MT_02D0120001",	"Cougar Cub 256" },
	{ "MHET2X-2TC",		"MT_02B0110001",	"Cougar Cub 256" },
	{ "MHET2X-2TC",		"MT_02B0120001",	"Cougar Cub 256" },
	{ "375-3481-01",	"SUN0040000001",	"Sun Cougar Cub SDR" },
	{ "375-3259-01",	"SUN0010000001",	"Sun Cougar Cub 256" },
	{ "375-3259-03",	"SUN0010000001",	"Sun Cougar Cub 256" },
	{ "375-3260-03",	"SUN0020000001",	"Sun Cougar Cub 256" },
	{ "MHX-CE128-T",	"MT_0000000001",	"Cougar 128" },
	{ "MTPB23108-CE128",	"MT_0000000001",	"Cougar 128" },
	{ "MHX-CE256-T",	"MT_0010000001",	"Cougar 256" },
	{ "MTPB23108-CE256",	"MT_0010000001",	"Cougar 256" },
	{ "MHX-CE512-T",	"MT_0050000001",	"Cougar 512" },
	{ "MTPB23108-CE512",	"MT_0050000001",	"Cougar 512" },
	{ "MHEH28-XSC",		"MT_04C0110001",	"Eagle SDR" },
	{ "MHEH28-XSC",		"MT_04C0130005",	"Eagle SDR" },
	{ "MHEH28-XTC",		"MT_04A0110001",	"Eagle SDR" },
	{ "MHEH28-XTC",		"MT_04A0130005",	"Eagle SDR" },
	{ "MHGH28-XSC",		"MT_04C0110002",	"Eagle DDR" },
	{ "MHGH28-XSC",		"MT_04C0120002",	"Eagle DDR" },
	{ "MHGH28-XSC",		"MT_04C0140005",	"Eagle DDR" },
	{ "MHGH28-XTC",		"MT_04A0110002",	"Eagle DDR" },
	{ "MHGH28-XTC",		"MT_04A0120002",	"Eagle DDR" },
	{ "MHGH28-XTC",		"MT_04A0140005",	"Eagle DDR" },
	{ "X1289A-Z",		"SUN0010010001",	"Sun IB NEM DDR" },
	{ "375-3548-01",	"SUN0060000001", "Sun IB EM DDR X4216A-Z" },
	{ "375-3549-01",	"SUN0070000001", "Sun PCIe DDR X4217A" },
	{ "375-3549-01",	"SUN0070130001", "Sun Eagle DDR" },
	{ "375-3481-01",	"SUN0050000001",	"Sun PCIe EM SDR" },
	{ "375-3439-01",	"SUN0051000001",	"Sun PUMA" },
	{ "MHGH29-XSC",		"MT_0A60110002", "Eagle DDR PCIe Gen 2.0" },
	{ "MHGH29-XSC",		"MT_0A60120005", "Eagle DDR PCIe Gen 2.0" },
	{ "MHGH29-XTC",		"MT_0A50110002", "Eagle DDR PCIe Gen 2.0" },
	{ "MHGH29-XTC",		"MT_0A50120005", "Eagle DDR PCIe Gen 2.0" },
	{ "375-3605-01",	"SUN0160000001",	"Sun Mirage QDR" },
	{ "375-3606-01",	"SUN0150000001",	"Sun Falcon QDR" },
	{ "375-3606-02",	"SUN0150000009",	"Sun Falcon QDR" },
	{ "375-3606-03",	"SUN0150000009",	"Sun Falcon QDR" },
	{ "MHJH29-XTC",		"MT_04E0110003",	"Eagle QDR" },
	{ "MHJH29-XSC",		"MT_0500120005", "Eagle QDR PCIe Gen 2.0" },
	{ "MHQH29-XTC",		"MT_04E0120005", "Eagle QDR PCIe Gen 2.0" },
	{ "MHQH19-XTC",		"MT_0C40110009", "Falcon QDR PCIe Gen 2.0" },
	{ "MHQH29-XTC",		"MT_0BB0110003", "Falcon QDR PCIe Gen 2.0" },
	{ "MHQH29-XTC",		"MT_0BB0120003", "Falcon QDR PCIe Gen 2.0" },
	{ "375-3551-05",	"SUN0080000001",	"Sun C48-IB-NEM" },
	{ "MHEH28B-XSR",	"MT_0D10110001", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MHEH28B-XTR",	"MT_0D20110001", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MHGH28B-XSR",	"MT_0D10110002", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MHGH28B-XTR",	"MT_0D20110002", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MHGH18B-XTR",	"MT_0D30110002", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MNEH28B-XSR",	"MT_0D40110004", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MNEH28B-XTR",	"MT_0D50110004", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MNEH29B-XSR",	"MT_0D40110010", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MNEH29B-XTR",	"MT_0D50110010", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MHGH29B-XSR",	"MT_0D10110008", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MHGH29B-XTR",	"MT_0D20110008", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MHJH29B-XSR",	"MT_0D10110009", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MHJH29B-XTR",	"MT_0D20110009", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MHGH19B-XSR",	"MT_0D60110008", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MHGH19B-XTR",	"MT_0D30110008", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MHJH19B-XTR",	"MT_0D30110009", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MHQH29B-XSR",	"MT_0D70110009", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MHQH29B-XTR",	"MT_0D80110009", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MHRH29B-XSR",	"MT_0D70110008", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MHRH29B-XTR",	"MT_0D80110008", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MHQH19B-XTR",	"MT_0D90110009", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MHRH19B-XTR",	"MT_0D90110008", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MNPH28C-XSR",	"MT_0DA0110004", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MNPH28C-XTR",	"MT_0DB0110004", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MNPH29C-XSR",	"MT_0DA0110010", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MNPH29C-XTR",	"MT_0DB0110010", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MNZH29-XSR",		"MT_0DC0110009", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MNZH29-XTR",		"MT_0DD0110009", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MHQH19B-XNR",	"MT_0DF0110009", "Osprey CX-2 PCIe Gen 2.0" },
	{ "MNQH19-XTR",		"MT_0D80110017", "Osprey CX-2 PCIe Gen 2.0" }
};

/* Get mlx_mdr[] array size */
#define	MLX_SZ_MLX_MDR		sizeof (mlx_mdr)
#define	MLX_SZ_MLX_MDR_STRUCT	sizeof (mlx_mdr[0])

#define	MLX_MAX_ID		MLX_SZ_MLX_MDR/MLX_SZ_MLX_MDR_STRUCT
#define	MLX_PSID_SZ		16
#define	MLX_STR_ID_SZ		64

#ifdef __cplusplus
}
#endif

#endif /* _HDRS_MELLANOX_H */
