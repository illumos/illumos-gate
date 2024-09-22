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
 * LPDDR5/X SPD tests
 */

#include <libjedec.h>
#include "libjedec_hex2spd.h"

const hex2spd_test_t micron_lp5 = {
	.ht_file = "lpddr5/MT62F4G32D8DV-023",
	.ht_checks = { {
		.hs_key = SPD_KEY_DRAM_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DT_LPDDR5_SDRAM }
	}, {
		.hs_key = SPD_KEY_MOD_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_MOD_TYPE_SOLDER }
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
		.hs_key = SPD_KEY_MOD_REV_ENC,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_MOD_REV_ADD,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 0 }
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
		.hs_val = { .hs_u32 = 6 }
	}, {
		.hs_key = SPD_KEY_NBGRP_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_NBANK_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_DIE_SIZE,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 16ULL * 1024ULL * 1024ULL * 1024ULL }
	}, {
		.hs_key = SPD_KEY_PKG_NDIE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 8 }
	}, {
		.hs_key = SPD_KEY_RANK_ASYM,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = false }
	}, {
		.hs_key = SPD_KEY_NRANKS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_DRAM_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 8 }
	}, {
		/*
		 * While the datasheet describes itself as having 4 channels, in
		 * the SPD data this is only thought of as sub-channels.
		 */
		.hs_key = SPD_KEY_DRAM_NCHAN,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_NSUBCHAN,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 4 }
	}, {
		.hs_key = SPD_KEY_DATA_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 16 }
	}, {
		.hs_key = SPD_KEY_ECC_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 0 }
	}, {
		.hs_key = SPD_KEY_TCKAVG_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 938 }
	}, {
		.hs_key = SPD_KEY_TCKAVG_MAX,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 0x7c83 }
	}, {
		.hs_key = SPD_KEY_TAA_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 21270 }
	}, {
		.hs_key = SPD_KEY_TRCD_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 18000 }
	}, {
		.hs_key = SPD_KEY_TRPAB_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 21000 }
	}, {
		.hs_key = SPD_KEY_TRPPB_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 18000 }
	}, {
		.hs_key = SPD_KEY_TRFCAB_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 280000 }
	}, {
		.hs_key = SPD_KEY_TRFCPB_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 140000 }
	}, {
		.hs_key = SPD_KEY_MOD_OPER_TEMP,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = JEDEC_TEMP_CASE_IT }
	}, {
		.hs_key = NULL,
	} }
};

const hex2spd_test_t fake_lp5_camm2 = {
	.ht_file = "lpddr5/CAMM2",
	.ht_checks = { {
		.hs_key = SPD_KEY_DRAM_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DT_LPDDR5X_SDRAM }
	}, {
		.hs_key = SPD_KEY_MOD_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_MOD_TYPE_CAMM2 }
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
		.hs_key = SPD_KEY_MOD_REV_ENC,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_MOD_REV_ADD,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 0 }
	}, {
		.hs_key = SPD_KEY_MOD_HYBRID_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_MOD_NOT_HYBRID }
	}, {
		.hs_key = SPD_KEY_NROW_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 16 }
	}, {
		.hs_key = SPD_KEY_NCOL_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 6 }
	}, {
		.hs_key = SPD_KEY_NBGRP_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 0 }
	}, {
		.hs_key = SPD_KEY_NBANK_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 3 }
	}, {
		.hs_key = SPD_KEY_DIE_SIZE,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 16ULL * 1024ULL * 1024ULL * 1024ULL }
	}, {
		.hs_key = SPD_KEY_PKG_NDIE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_PPR,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_PPR_F_HARD_PPR | SPD_PPR_F_SOFT_PPR }
	}, {
		.hs_key = SPD_KEY_RANK_ASYM,
		.hs_type = DATA_TYPE_BOOLEAN,
		.hs_val = { .hs_bool = false }
	}, {
		.hs_key = SPD_KEY_NRANKS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_DRAM_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 16 }
	}, {
		/*
		 * LPDDR5 SPD doesn't provide a way to usefully break this into
		 * channels. Even though CAMM2 is defined as 2 64-bit channels,
		 * it doesn't say so in the SPD.
		 */
		.hs_key = SPD_KEY_DRAM_NCHAN,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_NSUBCHAN,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 8 }
	}, {
		.hs_key = SPD_KEY_DATA_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 16 }
	}, {
		.hs_key = SPD_KEY_ECC_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 0 }
	}, {
		.hs_key = SPD_KEY_TCKAVG_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 777 }
	}, {
		.hs_key = SPD_KEY_TCKAVG_MAX,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 0x7c83 }
	}, {
		.hs_key = SPD_KEY_TAA_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 23230 }
	}, {
		.hs_key = SPD_KEY_TRCD_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 19000 }
	}, {
		.hs_key = SPD_KEY_TRPAB_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 21000 }
	}, {
		.hs_key = SPD_KEY_TRPPB_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 18000 }
	}, {
		.hs_key = SPD_KEY_TRFCAB_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 380000 }
	}, {
		.hs_key = SPD_KEY_TRFCPB_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 90000 }
	}, {
		.hs_key = SPD_KEY_DEVS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DEVICE_TEMP_1 | SPD_DEVICE_PMIC_0 |
		    SPD_DEVICE_SPD | SPD_DEVICE_CD_0 | SPD_DEVICE_CD_1 }
	}, {
		.hs_key = SPD_KEY_DEV_SPD_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "AMD" }
	}, {
		.hs_key = SPD_KEY_DEV_SPD_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_SPD_T_SPD5118 },
	}, {
		.hs_key = SPD_KEY_DEV_SPD_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "A.0" }
	}, {
		.hs_key = SPD_KEY_DEV_PMIC0_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Hitachi" }
	}, {
		.hs_key = SPD_KEY_DEV_PMIC0_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_PMIC_T_PMIC5200 },
	}, {
		.hs_key = SPD_KEY_DEV_PMIC0_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "B.0" }
	}, {
		.hs_key = SPD_KEY_DEV_TEMP_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Fairchild" }
	}, {
		.hs_key = SPD_KEY_DEV_TEMP_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_TEMP_T_TS5210 },
	}, {
		.hs_key = SPD_KEY_DEV_TEMP_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "C.0" }
	}, {
		.hs_key = SPD_KEY_DEV_CD0_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Fujitsu" }
	}, {
		.hs_key = SPD_KEY_DEV_CD0_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_CD_T_DDR5CK01 },
	}, {
		.hs_key = SPD_KEY_DEV_CD0_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "D.0" }
	}, {
		.hs_key = SPD_KEY_DEV_CD1_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Intel" }
	}, {
		.hs_key = SPD_KEY_DEV_CD1_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_CD_T_DDR5CK01 },
	}, {
		.hs_key = SPD_KEY_DEV_CD1_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "E.0" }
	}, {
		.hs_key = SPD_KEY_MOD_HEIGHT,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 34 }
	}, {
		.hs_key = SPD_KEY_MOD_FRONT_THICK,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 5 }
	}, {
		.hs_key = SPD_KEY_MOD_BACK_THICK,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_MOD_REF_DESIGN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "G" }
	}, {
		.hs_key = SPD_KEY_MOD_DESIGN_REV,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 3 }
	}, {
		.hs_key = SPD_KEY_MOD_OPER_TEMP,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = JEDEC_TEMP_CASE_NT }
	}, {
		.hs_key = SPD_KEY_MOD_NROWS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = NULL,
	} }
};
