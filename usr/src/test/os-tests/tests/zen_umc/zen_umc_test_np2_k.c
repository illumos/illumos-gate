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
 * Test the various forms NPS 1K/2K non-power of 2 variants that we have.
 * Specifically:
 *
 *  o 3 Channels (1K, 1P)
 *  o 6 channels (2K, 1P)
 *  o 5 channels (2K, 1P)
 *  o 10 channels (1K, 1P)
 */

#include "zen_umc_test.h"

/*
 * Our first lovely non-power of 2 configuration. This is a 1K 3 channel config.
 * Back to normal sized DIMMs.
 */
static const zen_umc_t zen_umc_nps_3ch_1k = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 48ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_df_rev = DF_REV_4D2,
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
		.zud_dram_nrules = 1,
		.zud_nchan = 3,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HASH_16_18 |
			    DF_DRAM_F_HASH_21_23 | DF_DRAM_F_HASH_30_32,
			.ddr_base = 0,
			.ddr_limit = 48ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 8,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_3CH_1K
		} },
		.zud_chan = { {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0,
			.chan_instid = 0,
			.chan_logid = 0,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 48ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_3CH_1K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 1,
			.chan_instid = 1,
			.chan_logid = 1,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 48ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_3CH_1K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 2,
			.chan_instid = 2,
			.chan_logid = 2,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 48ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_3CH_1K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		} }
	} }
};

/*
 * Next we have a 6 channel variant that uses a 2K based hash.
 */
static const zen_umc_t zen_umc_nps_6ch_2k = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 96ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_df_rev = DF_REV_4D2,
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
		.zud_dram_nrules = 1,
		.zud_nchan = 6,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HASH_16_18 |
			    DF_DRAM_F_HASH_21_23 | DF_DRAM_F_HASH_30_32,
			.ddr_base = 0,
			.ddr_limit = 96ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 8,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_6CH_2K
		} },
		.zud_chan = { {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0,
			.chan_instid = 0,
			.chan_logid = 0,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_6CH_2K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 1,
			.chan_instid = 1,
			.chan_logid = 1,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_6CH_2K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 2,
			.chan_instid = 2,
			.chan_logid = 2,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_6CH_2K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 3,
			.chan_instid = 3,
			.chan_logid = 3,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_6CH_2K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 4,
			.chan_instid = 4,
			.chan_logid = 4,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_6CH_2K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 5,
			.chan_instid = 5,
			.chan_logid = 5,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_6CH_2K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		} }
	} }
};

/*
 * 5 Channel hash, 2K
 */
static const zen_umc_t zen_umc_nps_5ch_2k = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 80ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_df_rev = DF_REV_4D2,
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
		.zud_dram_nrules = 1,
		.zud_nchan = 5,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HASH_16_18 |
			    DF_DRAM_F_HASH_21_23 | DF_DRAM_F_HASH_30_32,
			.ddr_base = 0,
			.ddr_limit = 80ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 8,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_5CH_2K
		} },
		.zud_chan = { {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0,
			.chan_instid = 0,
			.chan_logid = 0,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 80ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_5CH_2K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 1,
			.chan_instid = 1,
			.chan_logid = 1,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 80ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_5CH_2K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 2,
			.chan_instid = 2,
			.chan_logid = 2,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 80ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_5CH_2K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 3,
			.chan_instid = 3,
			.chan_logid = 3,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 80ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_5CH_2K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 4,
			.chan_instid = 4,
			.chan_logid = 4,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 80ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_5CH_2K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		} }
	} }
};

static const zen_umc_t zen_umc_nps_10ch_1k = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 160ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_df_rev = DF_REV_4D2,
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
		.zud_dram_nrules = 1,
		.zud_nchan = 10,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HASH_16_18 |
			    DF_DRAM_F_HASH_21_23 | DF_DRAM_F_HASH_30_32,
			.ddr_base = 0,
			.ddr_limit = 160ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 8,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_10CH_1K
		} },
		.zud_chan = { {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0,
			.chan_instid = 0,
			.chan_logid = 0,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 160ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_10CH_1K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 1,
			.chan_instid = 1,
			.chan_logid = 1,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 160ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_10CH_1K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 2,
			.chan_instid = 2,
			.chan_logid = 2,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 160ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_10CH_1K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 3,
			.chan_instid = 3,
			.chan_logid = 3,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 160ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_10CH_1K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 4,
			.chan_instid = 4,
			.chan_logid = 4,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 160ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_10CH_1K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 5,
			.chan_instid = 5,
			.chan_logid = 5,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 160ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_10CH_1K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 6,
			.chan_instid = 6,
			.chan_logid = 6,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 160ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_10CH_1K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 7,
			.chan_instid = 7,
			.chan_logid = 7,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 160ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_10CH_1K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 8,
			.chan_instid = 8,
			.chan_logid = 8,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 160ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_10CH_1K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 9,
			.chan_instid = 9,
			.chan_logid = 9,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 160ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_10CH_1K
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} },
		} }
	} }
};

const umc_decode_test_t zen_umc_test_np2_k[] = { {
	.udt_desc = "DF 4D2 NPS 1K 3ch (0)",
	.udt_umc = &zen_umc_nps_3ch_1k,
	.udt_pa = 0x95,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x95,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x15,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0x0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 3ch (1)",
	.udt_umc = &zen_umc_nps_3ch_1k,
	.udt_pa = 0x195,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x95,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x15,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0x0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 3ch (2)",
	.udt_umc = &zen_umc_nps_3ch_1k,
	.udt_pa = 0x295,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x95,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x15,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0x0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 3ch (3)",
	.udt_umc = &zen_umc_nps_3ch_1k,
	.udt_pa = 0xc95,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x395,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x75,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0x0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 3ch (4)",
	.udt_umc = &zen_umc_nps_3ch_1k,
	.udt_pa = 0xd95,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x395,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x75,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0x0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 3ch (5)",
	.udt_umc = &zen_umc_nps_3ch_1k,
	.udt_pa = 0xe95,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x395,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x75,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0x0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 3ch (6)",
	.udt_umc = &zen_umc_nps_3ch_1k,
	.udt_pa = 0xf95,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x795,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xf5,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0x0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 3ch (7)",
	.udt_umc = &zen_umc_nps_3ch_1k,
	.udt_pa = 0x1c95,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x795,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xf5,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0x0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 3ch (8)",
	.udt_umc = &zen_umc_nps_3ch_1k,
	.udt_pa = 0x1d95,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x795,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xf5,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0x0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 3ch (9)",
	.udt_umc = &zen_umc_nps_3ch_1k,
	.udt_pa = 0x2032f0695,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xabba5995,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x335,
	.udt_dimm_row = 0x2aee,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x4,
	.udt_dimm_subchan = 0x0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 3ch (10)",
	.udt_umc = &zen_umc_nps_3ch_1k,
	.udt_pa = 0x2032f0795,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xabba5995,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x335,
	.udt_dimm_row = 0x2aee,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x4,
	.udt_dimm_subchan = 0x0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 3ch (11)",
	.udt_umc = &zen_umc_nps_3ch_1k,
	.udt_pa = 0x2032f1495,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xabba5995,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x335,
	.udt_dimm_row = 0x2aee,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x4,
	.udt_dimm_subchan = 0x0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (0)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x2b,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2b,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xa,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (1)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x12b,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2b,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xa,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (2)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x102b,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2b,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xa,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (3)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x112b,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2b,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xa,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (4)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x202b,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2b,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xa,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (5)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x212b,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2b,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 5,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xa,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (0)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x2b,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2b,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xa,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	/*
	 * This next set shows that we honor the hash of bit 8, but don't hash
	 * other bits.
	 */
	.udt_desc = "DF 4D2 NPS 2K 6ch (6)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x68002b,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x11502b,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0x5,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x20a,
	.udt_dimm_row = 0x4,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (7)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x68012b,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x11502b,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0x4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x20a,
	.udt_dimm_row = 0x4,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (8)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x67f02b,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x11502b,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0x3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x20a,
	.udt_dimm_row = 0x4,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (9)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x67f12b,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x11502b,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0x2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x20a,
	.udt_dimm_row = 0x4,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (10)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x67e02b,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x11502b,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0x1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x20a,
	.udt_dimm_row = 0x4,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (11)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x67e12b,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x11502b,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0x0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x20a,
	.udt_dimm_row = 0x4,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	/*
	 * Next, confirm that we preserve bits 9-11 properly as we walk across
	 * things. Use both bit 21 and bit 30 hashes. This also deals with the
	 * bit 14 addition to bit 8.
	 */
	.udt_desc = "DF 4D2 NPS 2K 6ch (12)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x1cff23e2b,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x4d530f2b,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1ea,
	.udt_dimm_row = 0x1354,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x6,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (13)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x1cff23f2b,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x4d530f2b,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1ea,
	.udt_dimm_row = 0x1354,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x6,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (14)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x1cff24f2b,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x4d530f2b,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1ea,
	.udt_dimm_row = 0x1354,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x6,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (15)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x1cff24e2b,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x4d530f2b,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1ea,
	.udt_dimm_row = 0x1354,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x6,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (16)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x1cff25f2b,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x4d530f2b,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1ea,
	.udt_dimm_row = 0x1354,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x6,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (17)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x1cff25e2b,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x4d530f2b,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 5,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1ea,
	.udt_dimm_row = 0x1354,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x6,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (18)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0x23456789a,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x5e0e6c9a,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x196,
	.udt_dimm_row = 0x1783,
	.udt_dimm_bank = 0x3,
	.udt_dimm_bank_group = 0x4,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (19)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0xa98765432,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1c413ba32,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x34c,
	.udt_dimm_row = 0x7104,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 0x7,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 6ch (20)",
	.udt_umc = &zen_umc_nps_6ch_2k,
	.udt_pa = 0xbeeffeeb,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1fd2afeb,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1fa,
	.udt_dimm_row = 0x7f4,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 5ch (0)",
	.udt_umc = &zen_umc_nps_5ch_2k,
	.udt_pa = 0x95,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x95,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x15,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 5ch (1)",
	.udt_umc = &zen_umc_nps_5ch_2k,
	.udt_pa = 0x1195,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x95,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x15,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 5ch (2)",
	.udt_umc = &zen_umc_nps_5ch_2k,
	.udt_pa = 0x195,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x95,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x15,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 5ch (3)",
	.udt_umc = &zen_umc_nps_5ch_2k,
	.udt_pa = 0x2095,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x95,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x15,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 5ch (4)",
	.udt_umc = &zen_umc_nps_5ch_2k,
	.udt_pa = 0x1095,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x95,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x15,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	/*
	 * The 5 channel variant doesn't use any hash bits. We use addresses
	 * that would normally impact hashing for this next set. In addition,
	 * exercise the preserved bits 9-11.
	 */
	.udt_desc = "DF 4D2 NPS 2K 5ch (5)",
	.udt_umc = &zen_umc_nps_5ch_2k,
	.udt_pa = 0xffffff95,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x33333795,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x2f5,
	.udt_dimm_row = 0xccc,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 0x6,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 5ch (6)",
	.udt_umc = &zen_umc_nps_5ch_2k,
	.udt_pa = 0x100001e95,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x33333795,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x2f5,
	.udt_dimm_row = 0xccc,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 0x6,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 5ch (7)",
	.udt_umc = &zen_umc_nps_5ch_2k,
	.udt_pa = 0x100000f95,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x33333795,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x2f5,
	.udt_dimm_row = 0xccc,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 0x6,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 5ch (8)",
	.udt_umc = &zen_umc_nps_5ch_2k,
	.udt_pa = 0x100000e95,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x33333795,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x2f5,
	.udt_dimm_row = 0xccc,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 0x6,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 5ch (9)",
	.udt_umc = &zen_umc_nps_5ch_2k,
	.udt_pa = 0xfffffe95,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x33333795,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x2f5,
	.udt_dimm_row = 0xccc,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 0x6,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (0)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xf7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xf7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1d,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (1)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0x1f7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xf7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1d,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (2)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0x12f7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xf7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1d,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (3)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0x13f7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xf7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1d,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (4)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0x2f7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xf7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1d,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (5)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0x3f7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xf7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 5,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1d,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (6)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0x20f7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xf7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 6,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1d,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (7)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0x21f7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xf7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 7,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1d,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (8)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0x10f7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xf7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 8,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1d,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (9)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0x11f7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xf7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 9,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1d,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	/*
	 * Exercise hashing bit 8, but ensure no hashing of bit 9 comes into
	 * play. Note, we don't touch bit 14 as part of this.
	 */
	.udt_desc = "DF 4D2 NPS 1K 10ch (10)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xc06300f7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x133d18f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 9,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x31d,
	.udt_dimm_row = 0x4cf,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (11)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xc06301f7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x133d18f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 8,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x31d,
	.udt_dimm_row = 0x4cf,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (12)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xc06310f7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x133d18f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 7,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x31d,
	.udt_dimm_row = 0x4cf,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (13)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xc06311f7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x133d18f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 6,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x31d,
	.udt_dimm_row = 0x4cf,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (14)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xc062f2f7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x133d18f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 5,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x31d,
	.udt_dimm_row = 0x4cf,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (15)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xc062f3f7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x133d18f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x31d,
	.udt_dimm_row = 0x4cf,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (16)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xc06302f7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x133d18f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x31d,
	.udt_dimm_row = 0x4cf,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (17)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xc06303f7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x133d18f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x31d,
	.udt_dimm_row = 0x4cf,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (18)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xc062f0f7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x133d18f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x31d,
	.udt_dimm_row = 0x4cf,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (19)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xc062f1f7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x133d18f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x31d,
	.udt_dimm_row = 0x4cf,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	/*
	 * One last set of 10 channel tests with bit 14 on the scene and
	 * ensuring that bits 10-11 are preserved.
	 */
	.udt_desc = "DF 4D2 NPS 1K 10ch (20)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xfdcbbcdf7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x19612c7f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xfd,
	.udt_dimm_row = 0x6584,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (21)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xfdcbbccf7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x19612c7f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xfd,
	.udt_dimm_row = 0x6584,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (22)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xfdcbbaef7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x19612c7f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xfd,
	.udt_dimm_row = 0x6584,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (23)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xfdcbbaff7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x19612c7f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xfd,
	.udt_dimm_row = 0x6584,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (24)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xfdcbbbef7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x19612c7f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 9,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xfd,
	.udt_dimm_row = 0x6584,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (25)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xfdcbbbff7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x19612c7f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 8,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xfd,
	.udt_dimm_row = 0x6584,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (26)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xfdcbbcff7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x19612c7f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 7,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xfd,
	.udt_dimm_row = 0x6584,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (27)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xfdcbbcef7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x19612c7f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 6,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xfd,
	.udt_dimm_row = 0x6584,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (28)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xfdcbbbcf7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x19612c7f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 5,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xfd,
	.udt_dimm_row = 0x6584,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 10ch (29)",
	.udt_umc = &zen_umc_nps_10ch_1k,
	.udt_pa = 0xfdcbbbdf7,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x19612c7f7,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xfd,
	.udt_dimm_row = 0x6584,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = NULL
} };
