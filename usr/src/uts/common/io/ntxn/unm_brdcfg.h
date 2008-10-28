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
 * Copyright 2008 NetXen, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef __UNM_BRDINFO_H
#define	__UNM_BRDINFO_H

/* The version of the main data structure */
#define	UNM_BDINFO_VERSION 1

/* Magic number to let user know flash is programmed */
#define	UNM_BDINFO_MAGIC 0x12345678

#define	P2_CHIP 2
#define	P3_CHIP 3
#define	NX_P2_C0		0x24
#define	NX_P2_C1		0x25
#define	NX_P3_A0		0x30
#define	NX_P3_A2		0x32
#define	NX_P3_B0		0x40
#define	NX_P3_B1		0x41
#define	NX_P3_B2		0x42

#define	NX_IS_REVISION_P2(REVISION)	(REVISION <= NX_P2_C1)
#define	NX_IS_REVISION_P3(REVISION)	(REVISION >= NX_P3_A0)

typedef enum {
    UNM_BRDTYPE_P1_BD   = 0x0000,
    UNM_BRDTYPE_P1_SB   = 0x0001,
    UNM_BRDTYPE_P1_SMAX = 0x0002,
    UNM_BRDTYPE_P1_SOCK = 0x0003,

    UNM_BRDTYPE_P2_SOCK_31  =  0x0008,
    UNM_BRDTYPE_P2_SOCK_35  =  0x0009,
    UNM_BRDTYPE_P2_SB35_4G  =  0x000a,
    UNM_BRDTYPE_P2_SB31_10G =  0x000b,
    UNM_BRDTYPE_P2_SB31_2G  =  0x000c,

    UNM_BRDTYPE_P2_SB31_10G_IMEZ =  0x000d,
    UNM_BRDTYPE_P2_SB31_10G_HMEZ =  0x000e,
    UNM_BRDTYPE_P2_SB31_10G_CX4  =  0x000f,

	/* Reference quad gig */
	UNM_BRDTYPE_P3_REF_QG		=	0x0021,
	UNM_BRDTYPE_P3_HMEZ			=	0x0022,
	/* Dual CX4 - Low Profile - Red card */
	UNM_BRDTYPE_P3_10G_CX4_LP	=  0x0023,
	UNM_BRDTYPE_P3_4_GB			=	0x0024,
	UNM_BRDTYPE_P3_IMEZ			=	0x0025,
	UNM_BRDTYPE_P3_10G_SFP_PLUS	=	0x0026,
	UNM_BRDTYPE_P3_10000_BASE_T	=	0x0027,
	UNM_BRDTYPE_P3_XG_LOM		=	0x0028,

	UNM_BRDTYPE_P3_4_GB_MM		=	0x0029,
	UNM_BRDTYPE_P3_10G_CX4		=	0x0031, /* Reference CX4 */
	UNM_BRDTYPE_P3_10G_XFP		=	0x0032, /* Reference XFP */

    UNM_BRDTYPE_P3_10G_TRP	 =  0x0080,

} unm_brdtype_t;

typedef enum {
	NX_UNKNOWN_TYPE_ROMIMAGE = 0,
	NX_P2_MN_TYPE_ROMIMAGE = 1,
	NX_P3_CT_TYPE_ROMIMAGE,
	NX_P3_MN_TYPE_ROMIMAGE,
	NX_P3_MS_TYPE_ROMIMAGE,
	NX_UNKNOWN_TYPE_ROMIMAGE_LAST,
} nx_fw_type_t;

/* board type specific information */
typedef struct {
	unm_brdtype_t	brdtype; /* type of board */
	long			ports; /* max no of physical ports */
	nx_fw_type_t	fwtype; /* The FW Associated with board type */
	char			*short_name;
} unm_brdinfo_t;

#define	NUM_SUPPORTED_BOARDS (sizeof (unm_boards)/sizeof (unm_brdinfo_t))

#define	GET_BRD_NAME_BY_TYPE(type, name)            \
{                                                   \
	int i, found = 0;                               \
	for (i = 0; i < NUM_SUPPORTED_BOARDS; ++i) {    \
		if (unm_boards[i].brdtype == type) {        \
			name = unm_boards[i].short_name;        \
			found = 1;                              \
			break;                                  \
		}                                           \
	}                                               \
	if (!found)                                   \
	name = "Unknown";                           \
}

typedef struct {
    __uint32_t header_version;

    __uint32_t board_mfg;
    __uint32_t board_type;
    __uint32_t board_num;
    __uint32_t chip_id;
    __uint32_t chip_minor;
    __uint32_t chip_major;
    __uint32_t chip_pkg;
    __uint32_t chip_lot;


	__uint32_t port_mask; /* available niu ports */
	__uint32_t peg_mask; /* available pegs */
	__uint32_t icache_ok; /* can we run with icache? */
	__uint32_t dcache_ok; /* can we run with dcache? */
	__uint32_t casper_ok;

	/* unm_eth_addr_t  mac_address[MAX_PORTS]; */
    __uint32_t mac_addr_lo_0;
    __uint32_t mac_addr_lo_1;
    __uint32_t mac_addr_lo_2;
    __uint32_t mac_addr_lo_3;

	/* MN-related config */
    __uint32_t mn_sync_mode;    /* enable/ sync shift cclk/ sync shift mclk */
    __uint32_t mn_sync_shift_cclk;
    __uint32_t mn_sync_shift_mclk;
    __uint32_t mn_wb_en;
    __uint32_t mn_crystal_freq; /* in MHz */
    __uint32_t mn_speed; /* in MHz */
    __uint32_t mn_org;
    __uint32_t mn_depth;
    __uint32_t mn_ranks_0; /* ranks per slot */
    __uint32_t mn_ranks_1; /* ranks per slot */
    __uint32_t mn_rd_latency_0;
    __uint32_t mn_rd_latency_1;
    __uint32_t mn_rd_latency_2;
    __uint32_t mn_rd_latency_3;
    __uint32_t mn_rd_latency_4;
    __uint32_t mn_rd_latency_5;
    __uint32_t mn_rd_latency_6;
    __uint32_t mn_rd_latency_7;
    __uint32_t mn_rd_latency_8;
    __uint32_t mn_dll_val[18];
    __uint32_t mn_mode_reg; /* See MIU DDR Mode Register */
    __uint32_t mn_ext_mode_reg; /* See MIU DDR Extended Mode Register */
    __uint32_t mn_timing_0; /* See MIU Memory Control Timing Rgister */
    __uint32_t mn_timing_1; /* See MIU Extended Memory Ctrl Timing Register */
    __uint32_t mn_timing_2; /* See MIU Extended Memory Ctrl Timing2 Register */

	/* SN-related config */
    __uint32_t sn_sync_mode; /* enable/ sync shift cclk / sync shift mclk */
    __uint32_t sn_pt_mode; /* pass through mode */
    __uint32_t sn_ecc_en;
    __uint32_t sn_wb_en;
    __uint32_t sn_crystal_freq;
    __uint32_t sn_speed;
    __uint32_t sn_org;
    __uint32_t sn_depth;
    __uint32_t sn_dll_tap;
    __uint32_t sn_rd_latency;

    __uint32_t mac_addr_hi_0;
    __uint32_t mac_addr_hi_1;
    __uint32_t mac_addr_hi_2;
    __uint32_t mac_addr_hi_3;

    __uint32_t magic; /* indicates flash has been initialized */

    __uint32_t mn_rdimm;
    __uint32_t mn_dll_override;
    __uint32_t coreclock_speed;
}  unm_board_info_t;

#define	FLASH_NUM_PORTS		4

typedef struct {
    __uint32_t flash_addr[32];
} unm_flash_mac_addr_t;

/* flash user area */
typedef struct {
    __uint8_t  flash_md5[16];
    __uint8_t  crbinit_md5[16];
    __uint8_t  brdcfg_md5[16];
	/* bootloader */
    __uint32_t bootld_version;
    __uint32_t bootld_size;
    __uint8_t  bootld_md5[16];
	/* image */
    __uint32_t image_version;
    __uint32_t image_size;
    __uint8_t  image_md5[16];
	/* primary image status */
    __uint32_t primary_status;
    __uint32_t secondary_present;

	/* MAC address , 4 ports */
    unm_flash_mac_addr_t mac_addr[FLASH_NUM_PORTS];

	/* Any user defined data */
} unm_old_user_info_t;

#define	FLASH_NUM_MAC_PER_PORT		32
typedef struct {
    __uint8_t  flash_md5[16 * 64];
	// __uint8_t  crbinit_md5[16];
	// __uint8_t  brdcfg_md5[16];
	/* bootloader */
    __uint32_t bootld_version;
    __uint32_t bootld_size;
	// __uint8_t  bootld_md5[16];
	/* image */
    __uint32_t image_version;
    __uint32_t image_size;
	// U8  image_md5[16];
	/* primary image status */
    __uint32_t primary_status;
    __uint32_t secondary_present;

	/* MAC address , 4 ports, 32 address per port */
    __uint64_t mac_addr[FLASH_NUM_PORTS * FLASH_NUM_MAC_PER_PORT];
    __uint32_t sub_sys_id;
    __uint8_t  serial_num[32];
	__uint32_t bios_version;
    __uint32_t pxe_enable;  /* bitmask, per port */
    __uint32_t vlan_tag[FLASH_NUM_PORTS];

	/* Any user defined data */
} unm_user_info_t;

/* Flash memory map */
typedef enum {
    CRBINIT_START   = 0,		/* Crbinit section */
    BRDCFG_START    = 0x4000,	/* board config */
    INITCODE_START  = 0x6000,	/* pegtune code */
    BOOTLD_START    = 0x10000,	/* bootld */
    BOOTLD1_START   = 0x14000,	/* Start of booloader 1 */
	IMAGE_START		= 0x43000,	/* compressed image */
    SECONDARY_START = 0x200000,	/* backup images */
    PXE_FIRST_STAGE_INTEL = 0x3C0000, /* Intel First Stage info */
    PXE_FIRST_STAGE_PPC = 0x3C4000, /* PPC First Stage info */
    PXE_SECOND_STAGE_INTEL = 0x3B0000, /* Intel Second Stage info */
    PXE_SECOND_STAGE_PPC = 0x3A0000, /* Intel Second Stage info */
//    LICENSE_TIME_START = 0x3C0000, /* license expiry time info */
	PXE_START		= 0x3D0000,   /* PXE image area */
    DEFAULT_DATA_START = 0x3e0000, /* where we place default factory data */
	/* User defined region for new boards */
	USER_START		= 0x3E8000,
    VPD_START		= 0x3E8C00,   /* Vendor private data */
    LICENSE_START	= 0x3E9000,   /* Firmware License */
    FIXED_START		= 0x3F0000    /* backup of crbinit */
} unm_flash_map_t;

#define	USER_START_OLD		PXE_START /* for backward compatibility */

#endif	/* !__UNM_BRDINFO_H */
