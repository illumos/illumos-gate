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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * DDR3 SPD tests
 */

#include <libjedec.h>
#include "libjedec_hex2spd.h"

const hex2spd_test_t samsung_ddr3_rdimm = {
	.ht_file = "ddr3/M393B4G70BM0-CMA09",
	.ht_checks = { {
		.hs_key = SPD_KEY_DRAM_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DT_DDR3_SDRAM }
	}, {
		.hs_key = SPD_KEY_MOD_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_MOD_TYPE_RDIMM }
	}, {
		.hs_key = SPD_KEY_NBYTES_TOTAL,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 256 }
	}, {
		.hs_key = SPD_KEY_NBYTES_USED,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 176 }
	}, {
		.hs_key = SPD_KEY_CRC_DDR3_LEN,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 117 }
	}, {
		.hs_key = SPD_KEY_REV_ENC,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_REV_ADD,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_DIE_SIZE,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 4ULL * 1024ULL * 1024ULL * 1024ULL }
	}, {
		.hs_key = SPD_KEY_NBGRP_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 0 }
	}, {
		.hs_key = SPD_KEY_NBANK_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 3 }
	}, {
		.hs_key = SPD_KEY_NROW_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 16 }
	}, {
		.hs_key = SPD_KEY_NCOL_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 11 }
	}, {
		.hs_key = SPD_KEY_NOM_VDD,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 1, .ha_vals = { 1500 } } },
	}, {
		.hs_key = SPD_KEY_DRAM_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 4 }
	}, {
		.hs_key = SPD_KEY_NRANKS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 4 }
	}, {
		.hs_key = SPD_KEY_NSUBCHAN,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 },
	}, {
		.hs_key = SPD_KEY_DRAM_NCHAN,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 },
	}, {
		.hs_key = SPD_KEY_DATA_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 64 },
	}, {
		.hs_key = SPD_KEY_ECC_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 8 },
	}, {
		.hs_key = SPD_KEY_FTB,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 },
	}, {
		.hs_key = SPD_KEY_MTB,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 125 },
	}, {
		.hs_key = SPD_KEY_TCKAVG_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 1071 },
	}, {
		.hs_key = SPD_KEY_CAS,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 7,
		    .ha_vals = { 6, 7, 8, 9, 10, 11, 13 } } },
	}, {
		.hs_key = SPD_KEY_TAA_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 13125 },
	}, {
		.hs_key = SPD_KEY_TWR_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 15000 },
	}, {
		.hs_key = SPD_KEY_TRCD_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 13125 },
	}, {
		.hs_key = SPD_KEY_TRRD_L_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 5000 },
	}, {
		.hs_key = SPD_KEY_TRP_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 13125 },
	}, {
		.hs_key = SPD_KEY_TRAS_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 34000 },
	}, {
		.hs_key = SPD_KEY_TRC_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 47125 },
	}, {
		.hs_key = SPD_KEY_TRFC1_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 260000 },
	}, {
		.hs_key = SPD_KEY_TWTRS_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 7500 },
	}, {
		.hs_key = SPD_KEY_TRTP,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 7500 },
	}, {
		.hs_key = SPD_KEY_TFAW,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 27000 },
	}, {
		.hs_key = SPD_KEY_DDR3_FEAT,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DDR3_FEAT_DLL_OFF |
		    SPD_DDR3_FEAT_RZQ_7 | SPD_DDR3_FEAT_RZQ_6 },
	}, {
		.hs_key = SPD_KEY_DEVS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DEVICE_SPD | SPD_DEVICE_TEMP_1 |
		    SPD_DEVICE_HS | SPD_DEVICE_RCD }
	}, {
		.hs_key = SPD_KEY_MOD_OPER_TEMP,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = JEDEC_TEMP_CASE_XT },
	}, {
		.hs_key = SPD_KEY_PKG_NOT_MONO,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = true }
	}, {
		.hs_key = SPD_KEY_MOD_HEIGHT,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 30 }
	}, {
		.hs_key = SPD_KEY_MOD_FRONT_THICK,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 4 }
	}, {
		.hs_key = SPD_KEY_MOD_FRONT_THICK,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 4 }
	}, {
		/*
		 * The datasheet comment has a hex value of 0x25, but says it's
		 * revision 1, card AB, which would have a value of 0x35. As
		 * such we treat this as a datasheet bug and use the hex value
		 * which means card F.
		 */
		.hs_key = SPD_KEY_MOD_REF_DESIGN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "F" }
	}, {
		.hs_key = SPD_KEY_MOD_DESIGN_REV,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_MOD_NROWS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_MOD_NREGS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_DEV_RCD_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Marvell (Inphi)" }
	}, {
		.hs_key = SPD_KEY_DEV_RCD_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "21" }
	}, {
		.hs_key = SPD_KEY_DEV_RCD_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_RCD_T_SSTE32882 }
	}, {
		.hs_key = SPD_KEY_DDR3_RCD_DS_CAA,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DRIVE_MODERATE }
	}, {
		.hs_key = SPD_KEY_DDR3_RCD_DS_CAB,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DRIVE_MODERATE }
	}, {
		.hs_key = SPD_KEY_DDR3_RCD_DS_CTLA,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DRIVE_LIGHT }
	}, {
		.hs_key = SPD_KEY_DDR3_RCD_DS_CTLB,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DRIVE_LIGHT }
	}, {
		.hs_key = SPD_KEY_DDR3_RCD_DS_Y0,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DRIVE_MODERATE }
	}, {
		.hs_key = SPD_KEY_DDR3_RCD_DS_Y1,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DRIVE_MODERATE }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Samsung" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_LOC_ID,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_YEAR,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "12" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_WEEK,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "19" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_SN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "A22B2E95" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_PN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "M393B4G70BM0-CMA" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "FEEF" }
	}, {
		.hs_key = SPD_KEY_MFG_DRAM_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Samsung" }
	}, {
		.hs_key = NULL,
	} }
};

const hex2spd_test_t micron_ddr3_lrdimm = {
	.ht_file = "ddr3/MT36KSZF2G72LDZ-1G6E2A7",
	.ht_checks = { {
		.hs_key = SPD_KEY_DRAM_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DT_DDR3_SDRAM }
	}, {
		.hs_key = SPD_KEY_MOD_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_MOD_TYPE_LRDIMM }
	}, {
		.hs_key = SPD_KEY_NBYTES_TOTAL,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 256 }
	}, {
		.hs_key = SPD_KEY_NBYTES_USED,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 176 }
	}, {
		.hs_key = SPD_KEY_CRC_DDR3_LEN,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 117 }
	}, {
		.hs_key = SPD_KEY_REV_ENC,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_REV_ADD,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_DIE_SIZE,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 4ULL * 1024ULL * 1024ULL * 1024ULL }
	}, {
		.hs_key = SPD_KEY_NBGRP_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 0 }
	}, {
		.hs_key = SPD_KEY_NBANK_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 3 }
	}, {
		.hs_key = SPD_KEY_NROW_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 16 }
	}, {
		.hs_key = SPD_KEY_NCOL_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 10 }
	}, {
		.hs_key = SPD_KEY_NOM_VDD,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 2,
		    .ha_vals = { 1500, 1350 } } },
	}, {
		.hs_key = SPD_KEY_DRAM_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 8 }
	}, {
		.hs_key = SPD_KEY_NRANKS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 4 }
	}, {
		.hs_key = SPD_KEY_NSUBCHAN,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 },
	}, {
		.hs_key = SPD_KEY_DRAM_NCHAN,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 },
	}, {
		.hs_key = SPD_KEY_DATA_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 64 },
	}, {
		.hs_key = SPD_KEY_ECC_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 8 },
	}, {
		.hs_key = SPD_KEY_FTB,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 },
	}, {
		.hs_key = SPD_KEY_MTB,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 125 },
	}, {
		.hs_key = SPD_KEY_TCKAVG_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 1250 },
	}, {
		.hs_key = SPD_KEY_CAS,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 7,
		    .ha_vals = { 5, 6, 7, 8, 9, 10, 11 } } },
	}, {
		.hs_key = SPD_KEY_TAA_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 13125 },
	}, {
		.hs_key = SPD_KEY_TWR_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 15000 },
	}, {
		.hs_key = SPD_KEY_TRCD_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 13125 },
	}, {
		.hs_key = SPD_KEY_TRRD_L_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 6000 },
	}, {
		.hs_key = SPD_KEY_TRP_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 13125 },
	}, {
		.hs_key = SPD_KEY_TRAS_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 35000 },
	}, {
		.hs_key = SPD_KEY_TRC_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 48125 },
	}, {
		.hs_key = SPD_KEY_TRFC1_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 260000 },
	}, {
		.hs_key = SPD_KEY_TWTRS_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 7500 },
	}, {
		.hs_key = SPD_KEY_TRTP,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 7500 },
	}, {
		.hs_key = SPD_KEY_TFAW,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 30000 },
	}, {
		.hs_key = SPD_KEY_DDR3_FEAT,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DDR3_FEAT_DLL_OFF |
		    SPD_DDR3_FEAT_RZQ_7 | SPD_DDR3_FEAT_RZQ_6 |
		    SPD_DDR3_FEAT_ASR },
	}, {
		.hs_key = SPD_KEY_DEVS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DEVICE_SPD | SPD_DEVICE_TEMP_1 |
		    SPD_DEVICE_HS | SPD_DEVICE_DB }
	}, {
		.hs_key = SPD_KEY_MOD_OPER_TEMP,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = JEDEC_TEMP_CASE_XT },
	}, {
		.hs_key = SPD_KEY_PKG_NOT_MONO,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = false }
	}, {
		.hs_key = SPD_KEY_MAC,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 300000 },
	}, {
		.hs_key = SPD_KEY_MAW,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 8192 },
	}, {
		.hs_key = SPD_KEY_MOD_HEIGHT,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 31 }
	}, {
		.hs_key = SPD_KEY_MOD_FRONT_THICK,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 4 }
	}, {
		.hs_key = SPD_KEY_MOD_FRONT_THICK,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 4 }
	}, {
		.hs_key = SPD_KEY_MOD_EDGE_MIRROR,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = true }
	}, {
		.hs_key = SPD_KEY_MOD_NROWS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_DEV_DB_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "22" }
	}, {
		.hs_key = SPD_KEY_DDR3_MB_ORIENT,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_ORNT_VERTICAL }
	}, {
		.hs_key = SPD_KEY_DEV_DB_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Marvell (Inphi)" }
	}, {
		.hs_key = SPD_KEY_DDR3_MB_DS_CA,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DRIVE_MODERATE }
	}, {
		.hs_key = SPD_KEY_DDR3_MB_DS_CS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DRIVE_MODERATE }
	}, {
		.hs_key = SPD_KEY_DDR3_MB_DS_Y0,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DRIVE_MODERATE }
	}, {
		.hs_key = SPD_KEY_DDR3_MB_DS_Y1,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DRIVE_MODERATE }
	}, {
		.hs_key = SPD_KEY_DDR3_MB_DS_CKE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DRIVE_LIGHT }
	}, {
		.hs_key = SPD_KEY_DDR3_MB_DS_ODT,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DRIVE_LIGHT }
	}, {
		.hs_key = SPD_KEY_DDR3_MDQ_DS,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 3,
		    .ha_vals = { 34, 34, 34 } } },
	}, {
		.hs_key = SPD_KEY_DDR3_MDQ_ODT,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 3,
		    .ha_vals = { 120, 60, 60 } } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R0_ODT0_RD,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_FALSE, B_FALSE, B_FALSE } } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R0_ODT1_RD,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_TRUE, B_TRUE, B_TRUE} } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R1_ODT0_RD,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_TRUE, B_TRUE, B_TRUE} } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R1_ODT1_RD,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_FALSE, B_FALSE, B_FALSE } } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R0_ODT0_WR,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_TRUE, B_TRUE, B_TRUE} } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R0_ODT1_WR,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_TRUE, B_TRUE, B_TRUE} } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R0_ODT0_WR,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_TRUE, B_TRUE, B_TRUE} } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R1_ODT0_WR,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_TRUE, B_TRUE, B_TRUE} } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R2_ODT0_RD,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_TRUE, B_TRUE, B_TRUE} } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R2_ODT1_RD,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_FALSE, B_FALSE, B_FALSE } } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R3_ODT0_RD,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_FALSE, B_FALSE, B_FALSE } } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R3_ODT1_RD,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_TRUE, B_TRUE, B_TRUE} } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R2_ODT0_WR,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_TRUE, B_TRUE, B_TRUE} } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R2_ODT1_WR,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_FALSE, B_FALSE, B_FALSE } } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R3_ODT0_WR,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_FALSE, B_FALSE, B_FALSE } } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R3_ODT1_WR,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_TRUE, B_TRUE, B_TRUE} } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R4_ODT0_RD,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_FALSE, B_FALSE, B_FALSE } } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R5_ODT1_RD,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_FALSE, B_FALSE, B_FALSE } } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R6_ODT1_WR,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_FALSE, B_FALSE, B_FALSE } } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_R7_ODT0_WR,
		.hs_type = DATA_TYPE_BOOLEAN_ARRAY,
		.hs_val = { .hs_ba = { .ha_nval = 3,
		    .ha_vals = { B_FALSE, B_FALSE, B_FALSE } } },
	}, {
		.hs_key = SPD_KEY_DDR3_DRAM_DS,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 3,
		    .ha_vals = { 34, 34, 34 } } },
	}, {
		.hs_key = SPD_KEY_DDR3_RTT_NOM,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 3,
		    .ha_vals = { 60, 40, 40 } } },
	}, {
		.hs_key = SPD_KEY_DDR3_RTT_WRT,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 3,
		    .ha_vals = { 120, 120, 120 } } },
	}, {
		.hs_key = SPD_KEY_DDR3_MOD_MIN_DELAY,
		.hs_type = DATA_TYPE_UINT64_ARRAY,
		.hs_val = { .hs_u64a = { .ha_nval = 3,
		    .ha_vals = { 0, 8750, 8125 } } },
	}, {
		.hs_key = SPD_KEY_DDR3_MOD_MAX_DELAY,
		.hs_type = DATA_TYPE_UINT64_ARRAY,
		.hs_val = { .hs_u64a = { .ha_nval = 3,
		    .ha_vals = { 0, 9875, 9125 } } },
	}, {
		.hs_key = SPD_KEY_DDR3_MB_PERS,
		.hs_type = DATA_TYPE_UINT8_ARRAY,
		.hs_val = { .hs_u8a = { .ha_nval = 15,
		    .ha_vals = { 0x0b, 0x20, 0xe0, 0x01, 0x21, 0x20, 0x01, 0xff,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
	}, {
		.hs_key = SPD_KEY_MFG_MOD_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Micron Technology" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_LOC_ID,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 3 }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_YEAR,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "09" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_WEEK,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "04" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_SN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "CC94AB07" }
	}, {
		/*
		 * The Micron online SPD information for this part transformed
		 * the part number into the form below, eliminating the hyphen,
		 * the leading MT, etc.
		 */
		.hs_key = SPD_KEY_MFG_MOD_PN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "36KSZ2G72LD1G6E2A7" },
	}, {
		.hs_key = SPD_KEY_MFG_MOD_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "4532" }
	}, {
		.hs_key = SPD_KEY_MFG_DRAM_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Micron Technology" }
	}, {
		.hs_key = NULL,
	} }
};
