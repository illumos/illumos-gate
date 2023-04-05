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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * This tries to make sure that if we had invalid state somehow, we'd properly
 * end up detecting an error. Note, for these we try to do include the most bare
 * minimum style zen_umc_t to minimize the size (at least in this one file for a
 * change). Note, testing hole decoding errors has been performed in
 * zen_umc_test_hole.c.
 */

#include "zen_umc_test.h"

/*
 * This first structure is used to test:
 *   o Being outside TOM2
 *   o Being in the 1 TiB reserved region
 *   o Not being covered by a valid DF rule
 *   o Several invalid interleave combinations
 *   o Unsupported interleave rule
 *   o Bad Remap set counts
 */
static const zen_umc_t zen_umc_bad_df = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 2ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_df_rev = DF_REV_3,
	.umc_decomp = {
		.dfd_sock_mask = 0x01,
		.dfd_die_mask = 0x00,
		.dfd_node_mask = 0x20,
		.dfd_comp_mask = 0x1f,
		.dfd_sock_shift = 0,
		.dfd_die_shift = 0,
		.dfd_node_shift = 5,
		.dfd_comp_shift = 0
	},
	.umc_ndfs = 1,
	.umc_dfs = { {
		.zud_dfno = 0,
		.zud_dram_nrules = 10,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 0,
			.ddr_limit = 1ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 1,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_COD4_2CH
		}, {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 2ULL * 1024ULL * 1024ULL,
			.ddr_limit = 3ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 2,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_COD1_8CH
		}, {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 4ULL * 1024ULL * 1024ULL,
			.ddr_limit = 5ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 2,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_6CH
		}, {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 6ULL * 1024ULL * 1024ULL,
			.ddr_limit = 7ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 2,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_6CH
		}, {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 8ULL * 1024ULL * 1024ULL,
			.ddr_limit = 9ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 2,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = INT32_MAX
		}, {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 10ULL * 1024ULL * 1024ULL,
			.ddr_limit = 11ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 1,
			.ddr_die_ileave_bits = 1,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_5CH
		}, {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 12ULL * 1024ULL * 1024ULL,
			.ddr_limit = 13ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 2,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_2CH
		}, {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_REMAP_EN |
			    DF_DRAM_F_REMAP_SOCK,
			.ddr_base = 14ULL * 1024ULL * 1024ULL,
			.ddr_limit = 15ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH
		}, {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_REMAP_EN,
			.ddr_base = 16ULL * 1024ULL * 1024ULL,
			.ddr_limit = 17ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH
		}, {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_REMAP_EN,
			.ddr_base = 18ULL * 1024ULL * 1024ULL,
			.ddr_limit = 19ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH,
			.ddr_remap_ent = 3
		}  },
	} }
};

/*
 * This UMC contains a weird relationship between its rule, TOM and the actual
 * DRAM hole base. This creates an inconsistency that should underflow. This is
 * honestly a bit odd to actually try to find in the wild. The fact that TOM is
 * much greater than the hole base is key. This requires DFv4 for subtracting
 * the base.
 */
static const zen_umc_t zen_umc_hole_underflow = {
	.umc_tom = 3ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 2ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_df_rev = DF_REV_4,
	.umc_decomp = {
		.dfd_sock_mask = 0x01,
		.dfd_die_mask = 0x00,
		.dfd_node_mask = 0x20,
		.dfd_comp_mask = 0x1f,
		.dfd_sock_shift = 0,
		.dfd_die_shift = 0,
		.dfd_node_shift = 5,
		.dfd_comp_shift = 0
	},
	.umc_ndfs = 1,
	.umc_dfs = { {
		.zud_flags = ZEN_UMC_DF_F_HOLE_VALID,
		.zud_dfno = 0,
		.zud_dram_nrules = 2,
		.zud_hole_base = 0x0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HOLE,
			.ddr_base = 1ULL * 1024ULL * 1024ULL,
			.ddr_limit = 8ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_2CH
		} }
	} },
};

/*
 * This is a variant of the previous one, but it takes place when normalization
 * occurs. The biggest gotcha there is that for DFv3 the base isn't subtracted
 * initially for interleaving, only when normalizing.
 */
static const zen_umc_t zen_umc_norm_underflow = {
	.umc_tom = 3ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 16ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_df_rev = DF_REV_3,
	.umc_decomp = {
		.dfd_sock_mask = 0x01,
		.dfd_die_mask = 0x00,
		.dfd_node_mask = 0x20,
		.dfd_comp_mask = 0x1f,
		.dfd_sock_shift = 0,
		.dfd_die_shift = 0,
		.dfd_node_shift = 5,
		.dfd_comp_shift = 0
	},
	.umc_ndfs = 1,
	.umc_dfs = { {
		.zud_flags = ZEN_UMC_DF_F_HOLE_VALID,
		.zud_dfno = 0,
		.zud_dram_nrules = 2,
		.zud_nchan = 1,
		.zud_hole_base = 0xc0000000,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HOLE,
			.ddr_base = 4ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_limit = 8ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_1CH
		} },
		.zud_chan = { {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0,
			.chan_instid = 0,
			.chan_logid = 0,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HOLE,
				.ddr_base = 4ULL * 1024ULL * 1024ULL * 1024ULL,
				.ddr_limit = 8ULL * 1024ULL * 1024ULL * 1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_1CH
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_base = {
						.udb_base = 0,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0x3ffffffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x11,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x11,
					.ucs_bank_bits = { 0xf, 0x10, 0xd,
					    0xe },
					.ucs_col_bits = { 0x3, 0x4, 0x5, 0x6,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc }
				} }
			} },
		} }
	} }
};

/*
 * This DF is designed to capture bad remap entry pointers and remap entries
 * with bad components.
 */
static const zen_umc_t zen_umc_remap_errs = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 64ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_df_rev = DF_REV_3,
	.umc_decomp = {
		.dfd_sock_mask = 0x01,
		.dfd_die_mask = 0x00,
		.dfd_node_mask = 0x20,
		.dfd_comp_mask = 0x1f,
		.dfd_sock_shift = 0,
		.dfd_die_shift = 0,
		.dfd_node_shift = 5,
		.dfd_comp_shift = 0
	},
	.umc_ndfs = 1,
	.umc_dfs = { {
		.zud_dfno = 0,
		.zud_dram_nrules = 2,
		.zud_nchan = 4,
		.zud_cs_nremap = 2,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_REMAP_EN |
			    DF_DRAM_F_REMAP_SOCK,
			.ddr_base = 0,
			.ddr_limit = 32ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0x1f,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 12,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_1CH,
		}, {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_REMAP_EN,
			.ddr_base = 32ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_limit = 64ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 12,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_1CH,
			.ddr_remap_ent = 1
		} },
		.zud_remap = { {
			.csr_nremaps = ZEN_UMC_MAX_REMAP_ENTS,
			.csr_remaps = { 0x0 }
		}, {
			.csr_nremaps = ZEN_UMC_MAX_REMAP_ENTS,
			.csr_remaps = { 0x21 }
		} }
	} }
};

/*
 * This umc is used to cover the cases where:
 *   o There is no match to the fabric ID
 *   o The UMC in question doesn't have rules for our PA
 *   o Normalization underflow
 *   o Failure to match a chip-select
 */
static const zen_umc_t zen_umc_fab_errs = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 64ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_df_rev = DF_REV_3,
	.umc_decomp = {
		.dfd_sock_mask = 0x01,
		.dfd_die_mask = 0x00,
		.dfd_node_mask = 0x20,
		.dfd_comp_mask = 0x1f,
		.dfd_sock_shift = 0,
		.dfd_die_shift = 0,
		.dfd_node_shift = 5,
		.dfd_comp_shift = 0
	},
	.umc_ndfs = 1,
	.umc_dfs = { {
		.zud_dfno = 0,
		.zud_dram_nrules = 4,
		.zud_nchan = 2,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 0,
			.ddr_limit = 1ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0x22,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_1CH
		}, {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 2ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_limit = 3ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_1CH
		}, {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 4ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_limit = 5ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0x1,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_1CH
		} },
		.zud_chan = { {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0,
			.chan_instid = 0,
			.chan_logid = 0,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID,
				.ddr_base = 32ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_limit = 64ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_1CH
			} }
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 1,
			.chan_instid = 1,
			.chan_logid = 1,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID,
				.ddr_base = 0,
				.ddr_limit = 64ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_1CH
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_base = {
						.udb_base = 0x400000000,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0x3ffffffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x11,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x11,
					.ucs_bank_bits = { 0xf, 0x10, 0xd,
					    0xe },
					.ucs_col_bits = { 0x3, 0x4, 0x5, 0x6,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc }
				} }
			} },
		} }
	} }
};

const umc_decode_test_t zen_umc_test_errors[] = { {
	.udt_desc = "Memory beyond TOM2 doesn't decode (0)",
	.udt_umc = &zen_umc_bad_df,
	.udt_pa = 0x20000000000,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_OUTSIDE_DRAM
}, {
	.udt_desc = "Memory beyond TOM2 doesn't decode (1)",
	.udt_umc = &zen_umc_bad_df,
	.udt_pa = 0x2123456789a,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_OUTSIDE_DRAM
}, {
	.udt_desc = "Memory in 1 TiB-12 GiB hole doesn't decode (0)",
	.udt_umc = &zen_umc_bad_df,
	.udt_pa = 0xfd00000000,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_OUTSIDE_DRAM
}, {
	.udt_desc = "Memory in 1 TiB-12 GiB hole doesn't decode (1)",
	.udt_umc = &zen_umc_bad_df,
	.udt_pa = 0xfd00000001,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_OUTSIDE_DRAM
}, {
	.udt_desc = "Memory in 1 TiB-12 GiB hole doesn't decode (2)",
	.udt_umc = &zen_umc_bad_df,
	.udt_pa = 0xffffffffff,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_OUTSIDE_DRAM
}, {
	.udt_desc = "No valid DF rule (0)",
	.udt_umc = &zen_umc_bad_df,
	.udt_pa = 0x1ffffffffff,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_NO_DF_RULE
}, {
	.udt_desc = "No valid DF rule (1)",
	.udt_umc = &zen_umc_bad_df,
	.udt_pa = 0xfcffffffff,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_NO_DF_RULE
}, {
	.udt_desc = "No valid DF rule (2)",
	.udt_umc = &zen_umc_bad_df,
	.udt_pa = 0x123456,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_NO_DF_RULE
}, {
	.udt_desc = "Bad COD hash interleave - socket",
	.udt_umc = &zen_umc_bad_df,
	.udt_pa = 0x0,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_COD_BAD_ILEAVE
}, {
	.udt_desc = "Bad COD hash interleave - die",
	.udt_umc = &zen_umc_bad_df,
	.udt_pa = 0x200000,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_COD_BAD_ILEAVE
}, {
	.udt_desc = "Bad COD 6ch hash interleave - socket",
	.udt_umc = &zen_umc_bad_df,
	.udt_pa = 0x400000,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_COD_BAD_ILEAVE
}, {
	.udt_desc = "Bad COD 6ch hash interleave - die",
	.udt_umc = &zen_umc_bad_df,
	.udt_pa = 0x600000,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_COD_BAD_ILEAVE
}, {
	.udt_desc = "Unknown interleave",
	.udt_umc = &zen_umc_bad_df,
	.udt_pa = 0x800000,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_CHAN_ILEAVE_NOTSUP,
}, {
	.udt_desc = "Bad NPS hash interleave - die",
	.udt_umc = &zen_umc_bad_df,
	.udt_pa = 0xc00000,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_NPS_BAD_ILEAVE
}, {
	.udt_desc = "Bad NPS NP2 hash interleave - die",
	.udt_umc = &zen_umc_bad_df,
	.udt_pa = 0xa00000,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_NPS_BAD_ILEAVE
}, {
	.udt_desc = "Bad Remap Set - DFv3",
	.udt_umc = &zen_umc_bad_df,
	.udt_pa = 0xe00000,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_BAD_REMAP_SET
}, {
	.udt_desc = "Bad Remap Set - DFv4 (0)",
	.udt_umc = &zen_umc_bad_df,
	.udt_pa = 0x1000000,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_BAD_REMAP_SET
}, {
	.udt_desc = "Bad Remap Set - DFv4 (1)",
	.udt_umc = &zen_umc_bad_df,
	.udt_pa = 0x1200000,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_BAD_REMAP_SET
}, {
	.udt_desc = "Interleave address underflow",
	.udt_umc = &zen_umc_hole_underflow,
	.udt_pa = 0x100000000,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_ILEAVE_UNDERFLOW
}, {
	.udt_desc = "Normal address underflow",
	.udt_umc = &zen_umc_norm_underflow,
	.udt_pa = 0x100000000,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_CALC_NORM_UNDERFLOW
}, {
	.udt_desc = "Non-existent remap entry",
	.udt_umc = &zen_umc_remap_errs,
	.udt_pa = 0x0,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_BAD_REMAP_ENTRY
}, {
	.udt_desc = "Remap entry has bogus ID",
	.udt_umc = &zen_umc_remap_errs,
	.udt_pa = 0x8f0000000,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_REMAP_HAS_BAD_COMP
}, {
	.udt_desc = "Target fabric ID doesn't exist",
	.udt_umc = &zen_umc_fab_errs,
	.udt_pa = 0x12345,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_CANNOT_MAP_FABID
}, {
	.udt_desc = "UMC doesn't have DRAM rule",
	.udt_umc = &zen_umc_fab_errs,
	.udt_pa = 0x87654321,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_UMC_DOESNT_HAVE_PA
}, {
	.udt_desc = "No matching chip-select",
	.udt_umc = &zen_umc_fab_errs,
	.udt_pa = 0x101234567,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_NO_CS_BASE_MATCH
}, {
	.udt_desc = NULL
} };
