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
 * DDR4 SPD tests
 */

#include <libjedec.h>
#include "libjedec_hex2spd.h"

const hex2spd_test_t micron_ddr4_rdimm = {
	.ht_file = "ddr4/36ASF8G72PZ-3G2E1",
	.ht_checks = { {
		.hs_key = SPD_KEY_DRAM_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DT_DDR4_SDRAM }
	}, {
		.hs_key = SPD_KEY_MOD_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_MOD_TYPE_RDIMM }
	}, {
		.hs_key = SPD_KEY_PKG_NOT_MONO,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = false }
	}, {
		.hs_key = SPD_KEY_TAA_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 0x35b6 }
	}, {
		.hs_key = SPD_KEY_TRC_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 0xb2b6 }
	}, {
		.hs_key = SPD_KEY_TRAS_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 0x7d00 }
	}, {
		.hs_key = SPD_KEY_TCKAVG_MAX,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 0x640 }
	}, {
		.hs_key = SPD_KEY_TRFC1_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 0x55730 }
	}, {
		.hs_key = SPD_KEY_TRFC2_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 0x3f7a0 }
	}, {
		.hs_key = SPD_KEY_TWTRS_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 0x9c4 }
	}, {
		.hs_key = SPD_KEY_TWTRL_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 0x1d4c }
	}, {
		.hs_key = SPD_KEY_DIE_SIZE,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 16ULL * 1024ULL * 1024ULL * 1024ULL }
	}, {
		.hs_key = SPD_KEY_DRAM_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 4 },
	}, {
		.hs_key = SPD_KEY_DATA_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 64 },
	}, {
		.hs_key = SPD_KEY_NSUBCHAN,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 },
	},  {
		.hs_key = SPD_KEY_ECC_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 8 },
	}, {
		.hs_key = SPD_KEY_NRANKS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 },
	}, {
		.hs_key = SPD_KEY_DEV_TEMP_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_TEMP_T_TSE2004av },
	}, {
		.hs_key = SPD_KEY_MFG_MOD_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Micron Technology" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_SN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "32297BC1" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_PN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "36ASF8G72PZ-3G2E1" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "31" }
	}, {
		.hs_key = SPD_KEY_MFG_DRAM_STEP,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "45" }
	}, {
		.hs_key = SPD_KEY_MOD_REF_DESIGN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "B" }
	}, {
		.hs_key = SPD_KEY_MOD_DESIGN_REV,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 4 }
	}, {
		.hs_key = SPD_KEY_DEV_RCD_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Montage Technology Group" }
	}, {
		.hs_key = SPD_KEY_DDR4_RCD_DS_ODT,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_SLEW_MODERATE },
	}, {
		.hs_key = NULL,
	} }
};

const hex2spd_test_t samsung_ddr4_lrdimm = {
	.ht_file = "ddr4/M386AAK40B40-CWD70",
	.ht_checks = { {
		.hs_key = SPD_KEY_DRAM_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DT_DDR4_SDRAM }
	}, {
		.hs_key = SPD_KEY_MOD_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_MOD_TYPE_LRDIMM }
	}, {
		.hs_key = SPD_KEY_REV_ENC,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_REV_ADD,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_NROW_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 17 }
	}, {
		.hs_key = SPD_KEY_NCOL_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 10 }
	}, {
		.hs_key = SPD_KEY_NBANK_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_PKG_SL,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_SL_3DS }
	}, {
		.hs_key = SPD_KEY_PKG_NDIE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 4 }
	}, {
		.hs_key = SPD_KEY_NBGRP_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_TRFC1_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 0x55730 }
	}, {
		.hs_key = SPD_KEY_TRFC2_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 0x3f7a0 }
	}, {
		.hs_key = SPD_KEY_TRFC4_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 0x27100 }
	}, {
		.hs_key = SPD_KEY_TFAW,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 0x2ee0 }
	}, {
		.hs_key = SPD_KEY_TRRD_S_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 0xbb8 }
	}, {
		.hs_key = SPD_KEY_TRRD_L_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 0x1324 }
	}, {
		.hs_key = SPD_KEY_TCCD_L_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 0x1388 }
	}, {
		.hs_key = SPD_KEY_MOD_HEIGHT,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 32 }
	}, {
		.hs_key = SPD_KEY_MOD_FRONT_THICK,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_MOD_BACK_THICK,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_MOD_NREGS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_MOD_NROWS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_DEV_RCD_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "IDT" }
	}, {
		.hs_key = SPD_KEY_DEV_RCD_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "51" }
	}, {
		.hs_key = SPD_KEY_DEV_DB_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "IDT" }
	}, {
		.hs_key = SPD_KEY_DEV_DB_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "B0" }
	}, {
		.hs_key = SPD_KEY_DDR4_VREFDQ_R0,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 6975 }
	}, {
		.hs_key = SPD_KEY_DDR4_VREFDQ_R1,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 6975 }
	}, {
		.hs_key = SPD_KEY_DDR4_VREFDQ_R2,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 6000 }
	}, {
		.hs_key = SPD_KEY_DDR4_VREFDQ_R3,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 6000 }
	}, {
		.hs_key = SPD_KEY_DDR4_VREFDQ_DB,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 7170 }
	}, {
		.hs_key = SPD_KEY_DDR4_MDQ_RTT,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 3,
		    .ha_vals = { 48, 48, 48 } } },
	}, {
		.hs_key = SPD_KEY_DDR4_MDQ_DS,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 3,
		    .ha_vals = { 34, 34, 34 } } },
	}, {
		.hs_key = SPD_KEY_DDR4_DRAM_DS,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 3,
		    .ha_vals = { 34, 34, 34 } } },
	}, {
		.hs_key = SPD_KEY_DDR4_RTT_WR,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 3,
		    .ha_vals = { 240, 240, 240 } } },
	}, {
		.hs_key = SPD_KEY_DDR4_RTT_NOM,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 3,
		    .ha_vals = { 240, 240, 240 } } },
	}, {
		.hs_key = SPD_KEY_MFG_MOD_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Samsung" }
	}, {
		.hs_key = SPD_KEY_MFG_DRAM_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Samsung" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_YEAR,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "23" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_WEEK,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "24" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_PN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "M386AAK40B40-CWD" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_SN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "BAADCAFE" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "72" }
	}, {
		.hs_key = SPD_KEY_MFG_DRAM_STEP,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "27" }
	}, {
		.hs_key = NULL,
	} }
};

const hex2spd_test_t advantech_ddr4_sodimm = {
	.ht_file = "ddr4/AQD-SD4U16GN32-SE1",
	.ht_checks = { {
		.hs_key = SPD_KEY_DRAM_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DT_DDR4_SDRAM }
	}, {
		.hs_key = SPD_KEY_MOD_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_MOD_TYPE_SODIMM }
	}, {
		.hs_key = SPD_KEY_DIE_SIZE,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 8ULL * 1024ULL * 1024ULL * 1024ULL }
	}, {
		.hs_key = SPD_KEY_NROW_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 16 }
	}, {
		.hs_key = SPD_KEY_NCOL_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 10 }
	}, {
		.hs_key = SPD_KEY_NBANK_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_NBGRP_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_NRANKS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_DRAM_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 8 }
	}, {
		.hs_key = SPD_KEY_DRAM_NCHAN,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_DATA_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 64 }
	}, {
		.hs_key = SPD_KEY_ECC_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 0 }
	}, {
		.hs_key = SPD_KEY_CAS,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 15,
		    .ha_vals = { 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		    21, 22, 23, 24 } } }
	}, {
		.hs_key = SPD_KEY_TCKAVG_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 625 },
	}, {
		.hs_key = SPD_KEY_TCKAVG_MAX,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 1600 },
	}, {
		.hs_key = SPD_KEY_TAA_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 13750 },
	}, {
		.hs_key = SPD_KEY_TRAS_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 32000 },
	}, {
		.hs_key = SPD_KEY_TRC_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 45750 },
	}, {
		.hs_key = SPD_KEY_DDR4_MAP_DQ0,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 4,
		    .ha_vals = { 1, 3, 0, 2 } } },
	}, {
		.hs_key = SPD_KEY_DDR4_MAP_DQ44,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 4,
		    .ha_vals = { 7, 5, 4, 6 } } },
	}, {
		.hs_key = SPD_KEY_MOD_REF_DESIGN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "E" }
	}, {
		.hs_key = SPD_KEY_MOD_EDGE_MIRROR,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = true },
	}, {
		.hs_key = SPD_KEY_MFG_MOD_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Advantech Co Ltd" }
	}, {
		.hs_key = SPD_KEY_MFG_DRAM_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Advantech Co Ltd" }
	}, {
		.hs_key = NULL,
	} }
};

const hex2spd_test_t advantech_ddr4_udimm = {
	.ht_file = "ddr4/AQD-D4U32N32-SBW",
	.ht_checks = { {
		.hs_key = SPD_KEY_DRAM_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DT_DDR4_SDRAM }
	}, {
		.hs_key = SPD_KEY_MOD_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_MOD_TYPE_UDIMM }
	}, {
		.hs_key = SPD_KEY_NBYTES_USED,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 384 }
	}, {
		.hs_key = SPD_KEY_NBYTES_USED,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 384 }
	}, {
		.hs_key = SPD_KEY_DIE_SIZE,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 16ULL * 1024ULL * 1024ULL * 1024ULL }
	}, {
		.hs_key = SPD_KEY_REV_ENC,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_REV_ADD,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_MOD_HYBRID_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_MOD_NOT_HYBRID }
	}, {
		.hs_key = SPD_KEY_NROW_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 17 }
	}, {
		.hs_key = SPD_KEY_NCOL_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 10 }
	}, {
		.hs_key = SPD_KEY_NBANK_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_NBGRP_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_PPR,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_PPR_F_HARD_PPR | SPD_PPR_F_SOFT_PPR }
	}, {
		.hs_key = SPD_KEY_NOM_VDD,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 1, .ha_vals = { 1200 } } },
	}, {
		.hs_key = SPD_KEY_NRANKS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_DRAM_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 8 }
	}, {
		.hs_key = SPD_KEY_DRAM_NCHAN,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_DATA_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 64 }
	}, {
		.hs_key = SPD_KEY_ECC_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 0 }
	}, {
		.hs_key = SPD_KEY_TRFC1_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 550000 }
	}, {
		.hs_key = SPD_KEY_TRFC2_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 350000 }
	}, {
		.hs_key = SPD_KEY_TRFC4_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 260000 }
	}, {
		.hs_key = SPD_KEY_TRRD_L_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 4900 }
	}, {
		.hs_key = SPD_KEY_MOD_REF_DESIGN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "B" }
	}, {
		.hs_key = SPD_KEY_MOD_EDGE_MIRROR,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = true },
	}, {
		.hs_key = SPD_KEY_MFG_MOD_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Apacer Technology" }
	}, {
		.hs_key = SPD_KEY_MFG_DRAM_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "IBM" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_SN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "99887766" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_PN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "AQD-D4U32N32-SBW" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "2B" }
	}, {
		.hs_key = SPD_KEY_MFG_DRAM_STEP,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "95" }
	}, {
		.hs_key = NULL,
	} }
};
