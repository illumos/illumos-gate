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
 * LPDDR4/X SPD tests
 */

#include <libjedec.h>
#include "libjedec_hex2spd.h"

const hex2spd_test_t micron_lp4 = {
	.ht_file = "lpddr4/MT53D1024M32D4",
	.ht_checks = { {
		.hs_key = SPD_KEY_DRAM_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_DT_LPDDR4_SDRAM }
	}, {
		.hs_key = SPD_KEY_MOD_TYPE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_MOD_TYPE_SOLDER }
	}, {
		.hs_key = SPD_KEY_NBYTES_TOTAL,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 512 }
	}, {
		.hs_key = SPD_KEY_NBYTES_USED,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 384 }
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
		.hs_val = { .hs_u32 = 16 }
	}, {
		.hs_key = SPD_KEY_NCOL_BITS,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 10 }
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
		.hs_val = { .hs_u64 = 32ULL * 1024ULL * 1024ULL * 1024ULL }
	}, {
		.hs_key = SPD_KEY_PKG_NDIE,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 4 }
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
		.hs_val = { .hs_u32 = 16 }
	}, {
		.hs_key = SPD_KEY_DRAM_NCHAN,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 2 }
	}, {
		.hs_key = SPD_KEY_NSUBCHAN,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 1 }
	}, {
		.hs_key = SPD_KEY_DATA_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 16 }
	}, {
		.hs_key = SPD_KEY_ECC_WIDTH,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 0 }
	}, {
		.hs_key = SPD_KEY_MAW,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = 4096 }
	}, {
		.hs_key = SPD_KEY_MAC,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_KEY_MAC_UNLIMITED }
	}, {
		.hs_key = SPD_KEY_TCKAVG_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 468 }
	}, {
		.hs_key = SPD_KEY_TCKAVG_MAX,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 1500 }
	}, {
		.hs_key = SPD_KEY_CAS,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 1, .ha_vals = { 44 } } }
	}, {
		.hs_key = SPD_KEY_TAA_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 4375 }
	}, {
		.hs_key = SPD_KEY_LP_RWLAT,
		.hs_type = DATA_TYPE_UINT32,
		.hs_val = { .hs_u32 = SPD_LP_RWLAT_WRITE_A }
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
		.hs_val = { .hs_u64 = 380000 }
	}, {
		.hs_key = SPD_KEY_TRFCPB_MIN,
		.hs_type = DATA_TYPE_UINT64,
		.hs_val = { .hs_u64 = 190000 }
	}, {
		.hs_key = SPD_KEY_DDR4_MAP_DQ0,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 4,
		    .ha_vals = { 0, 1, 2, 3 } } },
	}, {
		.hs_key = SPD_KEY_DDR4_MAP_DQ4,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 4,
		    .ha_vals = { 4, 5, 6, 7 } } },
	}, {
		.hs_key = SPD_KEY_DDR4_MAP_DQ16,
		.hs_type = DATA_TYPE_UINT32_ARRAY,
		.hs_val = { .hs_u32a = { .ha_nval = 4,
		    .ha_vals = { 0, 1, 3, 2 } } },
	}, {
		.hs_key = SPD_KEY_MFG_MOD_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Micron Technology" }
	}, {
		.hs_key = SPD_KEY_MFG_DRAM_MFG_NAME,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "Micron Technology" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_YEAR,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "AA" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_WEEK,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "BB" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_SN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "10010220" }
	}, {
		.hs_key = SPD_KEY_MFG_MOD_PN,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "MT53D1024M32D4" },
	}, {
		.hs_key = SPD_KEY_MFG_MOD_REV,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "2B" }
	}, {
		.hs_key = SPD_KEY_MFG_DRAM_STEP,
		.hs_type = DATA_TYPE_STRING,
		.hs_val = { .hs_str = "B2" }
	}, {
		.hs_key = NULL,
	} }
};
