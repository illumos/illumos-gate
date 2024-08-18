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
 * DDR5 SPD tests
 */

#include <libjedec.h>
#include "libjedec_hex2spd.h"

const hex2spd_test_t micron_ddr5_rdimm = {
	.ht_file = "ddr5/MTC40F2046S1RC48BA1",
	.ht_checks = { {
		.hs_key = SPD_KEY_DRAM_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DT_DDR5_SDRAM }
	}, {
		.hs_key = SPD_KEY_MOD_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_MOD_TYPE_RDIMM }
	}, {
		.hs_key = SPD_KEY_NBYTES_TOTAL,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1024 }
	}, {
		.hs_key = SPD_KEY_REV_ENC,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_REV_ADD,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 0 }
	}, {
		.hs_key = SPD_KEY_BETA,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 0 }
	}, {
		.hs_key = SPD_KEY_MOD_REV_ENC,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_MOD_REV_ADD,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 0 }
	}, {
		.hs_key = SPD_KEY_PKG_NOT_MONO,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = false }
	}, {
		.hs_key = SPD_KEY_NROW_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 16 },
	}, {
		.hs_key = SPD_KEY_NCOL_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 11 },
	}, {
		.hs_key = SPD_KEY_NBGRP_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 3 },
	}, {
		.hs_key = SPD_KEY_NBANK_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 },
	}, {
		.hs_key = SPD_KEY_DIE_SIZE,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 16ULL * 1024ULL * 1024ULL * 1024ULL },
	}, {
		.hs_key = SPD_KEY_DRAM_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 4 }
	}, {
		.hs_key = SPD_KEY_PPR,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_PPR_F_HARD_PPR | SPD_PPR_F_SOFT_PPR |
		    SPD_PPR_F_PPR_UNDO }
	}, {
		.hs_key = SPD_KEY_PPR_GRAN,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_PPR_GRAN_BANK },
	}, {
		.hs_key = SPD_KEY_DDR5_BL32,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = false }
	}, {
		.hs_key = SPD_KEY_DDR_PASR,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = false }
	}, {
		.hs_key = SPD_KEY_DDR5_DCA,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DCA_1_OR_2_PHASE },
	}, {
		.hs_key = SPD_KEY_DDR5_WIDE_TS,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = false }
	}, {
		.hs_key = SPD_KEY_DDR5_FLT,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_FLT_WRSUP_MR15 | SPD_FLT_BOUNDED },
	}, {
		.hs_key = SPD_KEY_NOM_VDD,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 1, .ha_vals = { 1100 } } },
	}, {
		.hs_key = SPD_KEY_NOM_VDDQ,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 1, .ha_vals = { 1100 } } },
	}, {
		.hs_key = SPD_KEY_NOM_VPP,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 1, .ha_vals = { 1800 } } },
	}, {
		.hs_key = SPD_KEY_TCKAVG_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 416 },
	}, {
		.hs_key = SPD_KEY_TCKAVG_MAX,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 1010 },
	}, {
		.hs_key = SPD_KEY_DEV_SPD_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "IDT" }
	}, {
		.hs_key = SPD_KEY_DEV_SPD_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_SPD_T_SPD5118 },
	}, {
		.hs_key = SPD_KEY_DEV_SPD_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "2.1" }
	}, {
		.hs_key = SPD_KEY_DEV_PMIC0_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "IDT" }
	}, {
		.hs_key = SPD_KEY_DEV_PMIC0_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_PMIC_T_PMIC5000 },
	}, {
		.hs_key = SPD_KEY_DEV_PMIC0_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "4.0" }
	}, {
		.hs_key = SPD_KEY_DEV_TEMP_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "IDT" }
	}, {
		.hs_key = SPD_KEY_DEV_TEMP_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_TEMP_T_TS5111 },
	}, {
		.hs_key = SPD_KEY_DEV_TEMP_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "1.2" }
	}, {
		.hs_key = SPD_KEY_DEVS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DEVICE_TEMP_1 | SPD_DEVICE_TEMP_2 |
		    SPD_DEVICE_PMIC_0 | SPD_DEVICE_RCD | SPD_DEVICE_SPD }
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
		.hs_val = { .hs_u32 = 3 }
	}, {
		.hs_key = SPD_KEY_MOD_REF_DESIGN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "A" }
	}, {
		.hs_key = SPD_KEY_MOD_DESIGN_REV,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 0 }
	}, {
		.hs_key = SPD_KEY_MOD_OPER_TEMP,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = JEDEC_TEMP_CASE_XT }
	}, {
		.hs_key = SPD_KEY_MOD_NROWS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_NRANKS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_NSUBCHAN,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_DATA_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 32 }
	}, {
		.hs_key = SPD_KEY_ECC_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 8 }
	}, {
		.hs_key = SPD_KEY_DEV_RCD_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Montage Technology Group" }
	}, {
		.hs_key = SPD_KEY_DEV_RCD_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_RCD_T_DDR5RCD01 },
	}, {
		.hs_key = SPD_KEY_DEV_RCD_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "2.2" }
	}, {
		.hs_key = SPD_KEY_DDR5_RCD_QACK_EN,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = true }
	}, {
		.hs_key = SPD_KEY_DDR5_RCD_QBCK_EN,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = true }
	}, {
		.hs_key = SPD_KEY_DDR5_RCD_QCCK_EN,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = true }
	}, {
		.hs_key = SPD_KEY_DDR5_RCD_QDCK_EN,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = true }
	}, {
		.hs_key = SPD_KEY_DDR5_RCD_QACK_DS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DRIVE_MODERATE },
	}, {
		.hs_key = SPD_KEY_DDR5_RCD_QBCK_DS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DRIVE_MODERATE },
	}, {
		.hs_key = SPD_KEY_DDR5_RCD_QCCK_DS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DRIVE_MODERATE },
	}, {
		.hs_key = SPD_KEY_DDR5_RCD_QDCK_DS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DRIVE_MODERATE },
	}, {
		.hs_key = NULL
	} }
};

const hex2spd_test_t advantech_ddr5_rdimm = {
	.ht_file = "ddr5/AQD-D5V16GR48-SB",
	.ht_checks = { {
		.hs_key = SPD_KEY_DRAM_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DT_DDR5_SDRAM }
	}, {
		.hs_key = SPD_KEY_MOD_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_MOD_TYPE_RDIMM }
	}, {
		.hs_key = SPD_KEY_NBYTES_TOTAL,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1024 }
	}, {
		.hs_key = SPD_KEY_REV_ENC,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_REV_ADD,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 0 }
	}, {
		.hs_key = SPD_KEY_BETA,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 0 }
	}, {
		.hs_key = SPD_KEY_MOD_REV_ENC,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_MOD_REV_ADD,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 0 }
	}, {
		.hs_key = SPD_KEY_PKG_NOT_MONO,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = false }
	}, {
		.hs_key = SPD_KEY_NROW_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 16 },
	}, {
		.hs_key = SPD_KEY_NCOL_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 10 },
	}, {
		.hs_key = SPD_KEY_NBGRP_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 3 },
	}, {
		.hs_key = SPD_KEY_NBANK_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 },
	}, {
		.hs_key = SPD_KEY_DIE_SIZE,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 16ULL * 1024ULL * 1024ULL * 1024ULL },
	}, {
		.hs_key = SPD_KEY_DDR5_BL32,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = true }
	}, {
		.hs_key = SPD_KEY_DDR_PASR,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = false }
	}, {
		.hs_key = SPD_KEY_DDR5_DCA,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DCA_4_PHASE },
	}, {
		.hs_key = SPD_KEY_PPR,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_PPR_F_HARD_PPR | SPD_PPR_F_SOFT_PPR }
	}, {
		.hs_key = SPD_KEY_NOM_VDD,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 1, .ha_vals = { 1100 } } },
	}, {
		.hs_key = SPD_KEY_NOM_VDDQ,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 1, .ha_vals = { 1100 } } },
	}, {
		.hs_key = SPD_KEY_NOM_VPP,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 1, .ha_vals = { 1800 } } },
	}, {
		.hs_key = SPD_KEY_TCKAVG_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 416 },
	}, {
		.hs_key = SPD_KEY_TCKAVG_MAX,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 1010 },
	}, {
		.hs_key = SPD_KEY_CAS,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 8,
		    .ha_vals = { 22, 26, 28, 30, 32, 36, 40, 42 } } },
	}, {
		.hs_key = SPD_KEY_TAA_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 16000 },
	}, {
		.hs_key = SPD_KEY_TRCD_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 16000 },
	}, {
		.hs_key = SPD_KEY_TRP_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 16000 },
	}, {
		.hs_key = SPD_KEY_TRAS_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 32000 },
	}, {
		.hs_key = SPD_KEY_TRC_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 48000 },
	}, {
		.hs_key = SPD_KEY_TWR_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 30000 },
	}, {
		.hs_key = SPD_KEY_TRFC1_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 295000 }
	}, {
		.hs_key = SPD_KEY_TRFC2_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 160000 }
	}, {
		.hs_key = SPD_KEY_TRFCSB,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 130000 }
	}, {
		.hs_key = SPD_KEY_TRRD_L_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 5000 }
	}, {
		.hs_key = SPD_KEY_TRRD_L_NCK,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u64 = 8 }
	}, {
		.hs_key = SPD_KEY_TCCD_L_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 5000 }
	}, {
		.hs_key = SPD_KEY_TCCD_L_NCK,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u64 = 8 }
	}, {
		.hs_key = SPD_KEY_TCCDLWR,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 20000 }
	}, {
		.hs_key = SPD_KEY_TCCDLWR_NCK,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u64 = 32 }
	}, {
		.hs_key = SPD_KEY_TCCDLWR2,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 10000 }
	}, {
		.hs_key = SPD_KEY_TCCDLWR2_NCK,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u64 = 16 }
	}, {
		.hs_key = SPD_KEY_TFAW,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 13333 }
	}, {
		.hs_key = SPD_KEY_TFAW_NCK,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u64 = 32 }
	}, {
		.hs_key = SPD_KEY_TCCDLWTR,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 10000 }
	}, {
		.hs_key = SPD_KEY_TCCDLWTR_NCK,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u64 = 16 }
	}, {
		.hs_key = SPD_KEY_TCCDSWTR,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 2500 }
	}, {
		.hs_key = SPD_KEY_TCCDSWTR_NCK,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u64 = 4 }
	}, {
		.hs_key = SPD_KEY_TRTP,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 7500 }
	}, {
		.hs_key = SPD_KEY_TRTP_NCK,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u64 = 12 }
	}, {
		.hs_key = SPD_KEY_DEV_SPD_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Montage Technology Group" }
	}, {
		.hs_key = SPD_KEY_DEV_SPD_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_SPD_T_SPD5118 },
	}, {
		.hs_key = SPD_KEY_DEV_SPD_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "1.5" }
	}, {
		.hs_key = SPD_KEY_DEV_PMIC0_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Montage Technology Group" }
	}, {
		.hs_key = SPD_KEY_DEV_PMIC0_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_PMIC_T_PMIC5010 },
	}, {
		.hs_key = SPD_KEY_DEV_PMIC0_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "3.3" }
	}, {
		.hs_key = SPD_KEY_DEV_TEMP_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Montage Technology Group" }
	}, {
		.hs_key = SPD_KEY_DEV_TEMP_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_TEMP_T_TS5110 },
	}, {
		.hs_key = SPD_KEY_DEV_TEMP_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "1.3" }
	}, {
		.hs_key = SPD_KEY_DEVS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DEVICE_TEMP_1 | SPD_DEVICE_TEMP_2 |
		    SPD_DEVICE_PMIC_0 | SPD_DEVICE_RCD | SPD_DEVICE_SPD }
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
		.hs_val = { .hs_u32 = 3 }
	}, {
		.hs_key = SPD_KEY_MOD_REF_DESIGN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "D" }
	}, {
		.hs_key = SPD_KEY_MOD_DESIGN_REV,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 0 }
	}, {
		.hs_key = SPD_KEY_MOD_OPER_TEMP,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = JEDEC_TEMP_CASE_XT }
	}, {
		.hs_key = SPD_KEY_MOD_NROWS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_RANK_ASYM,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = false }
	}, {
		.hs_key = SPD_KEY_NRANKS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_NSUBCHAN,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_DRAM_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 8 }
	}, {
		.hs_key = SPD_KEY_DATA_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 32 }
	}, {
		.hs_key = SPD_KEY_ECC_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 8 }
	}, {
		.hs_key = SPD_KEY_DEV_RCD_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Montage Technology Group" }
	}, {
		.hs_key = SPD_KEY_DEV_RCD_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_RCD_T_DDR5RCD01 },
	}, {
		.hs_key = SPD_KEY_DEV_RCD_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "2.2" }
	}, {
		.hs_key = SPD_KEY_DDR5_RCD_QACK_EN,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = true }
	}, {
		.hs_key = SPD_KEY_DDR5_RCD_QBCK_EN,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = false }
	}, {
		.hs_key = SPD_KEY_DDR5_RCD_QCCK_EN,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = false }
	}, {
		.hs_key = SPD_KEY_DDR5_RCD_QDCK_EN,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = false }
	}, {
		.hs_key = SPD_KEY_DDR5_RCD_QACS_EN,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = true }
	}, {
		.hs_key = SPD_KEY_DDR5_RCD_QBCS_EN,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = false }
	}, {
		.hs_key = SPD_KEY_DDR5_RCD_QxCA13_EN,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = true }
	}, {
		.hs_key = SPD_KEY_DDR5_RCD_QACK_DS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DRIVE_LIGHT },
	}, {
		.hs_key = SPD_KEY_DDR5_RCD_QCK_SLEW,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_SLEW_MODERATE },
	}, {
		.hs_key = SPD_KEY_DDR5_RCD_QCA_SLEW,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_SLEW_SLOW },
	}, {
		.hs_key = SPD_KEY_DDR5_RCD_QCS_SLEW,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_SLEW_SLOW },
	}, {
		.hs_key = SPD_KEY_MFG_MOD_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "A-DATA Technology" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_YEAR,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "AF" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_WEEK,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "82" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_SN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "13576428" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_PN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "AQD-D5V16GR48-SB" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "00" }
	}, {
		.hs_key = SPD_KEY_MFG_DRAM_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Samsung" }
	}, {
		.hs_key = SPD_KEY_TCKAVG_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 416 },
	}, {
		.hs_key = SPD_KEY_TCKAVG_MAX,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 1010 },
	}, {
		.hs_key = SPD_KEY_CAS,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 8,
		    .ha_vals = { 22, 26, 28, 30, 32, 36, 40, 42 } } },
	}, {
		.hs_key = SPD_KEY_TAA_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 16000 },
	}, {
		.hs_key = SPD_KEY_TRCD_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 16000 },
	}, {
		.hs_key = SPD_KEY_TRP_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 16000 },
	}, {
		.hs_key = SPD_KEY_TRAS_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 32000 },
	}, {
		.hs_key = SPD_KEY_TRC_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 48000 },
	}, {
		.hs_key = SPD_KEY_TWR_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 30000 },
	}, {
		.hs_key = SPD_KEY_TRFC1_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 295000 }
	}, {
		.hs_key = SPD_KEY_TRFC2_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 160000 }
	}, {
		.hs_key = SPD_KEY_TRFCSB,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 130000 }
	}, {
		.hs_key = NULL
	} }
};
