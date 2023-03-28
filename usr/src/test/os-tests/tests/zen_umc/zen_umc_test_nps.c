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
 * Go through and test the different versions of NPS hashing. Unlike with the
 * COD hash, we also need to take into account socket interleaving. In addition
 * to the basic ones, we also do a 5-channel and 6-channel variant to get
 * various parts of the non-power of 2 forms tested.
 */

#include "zen_umc_test.h"

/*
 * Start with the heavy hitter, the 2 socket, 8 channel (8/socket) configuration
 * that does both socket interleaving and the hashing. Because this is a DFv4
 * variant, we opt to set up the channels for DDR5.
 */
static const zen_umc_t zen_umc_nps8_2p = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 256ULL * 1024ULL * 1024ULL * 1024ULL,
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
	.umc_ndfs = 2,
	.umc_dfs = { {
		.zud_dfno = 0,
		.zud_dram_nrules = 1,
		.zud_nchan = 8,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HASH_16_18 |
			    DF_DRAM_F_HASH_21_23 | DF_DRAM_F_HASH_30_32,
			.ddr_base = 0,
			.ddr_limit = 256ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 1,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH
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
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH
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
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH
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
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH
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
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH
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
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH
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
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH
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
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH
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
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH
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
		}    }
	}, {
		.zud_dfno = 1,
		.zud_dram_nrules = 2,
		.zud_nchan = 8,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HASH_16_18 |
			    DF_DRAM_F_HASH_21_23 | DF_DRAM_F_HASH_30_32,
			.ddr_base = 0,
			.ddr_limit = 256ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 1,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH
		} },
		.zud_chan = { {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0x20,
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
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH
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
			.chan_fabid = 0x21,
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
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH
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
			.chan_fabid = 0x22,
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
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH
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
			.chan_fabid = 0x23,
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
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH
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
			.chan_fabid = 0x24,
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
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH
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
			.chan_fabid = 0x25,
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
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH
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
			.chan_fabid = 0x26,
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
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH
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
			.chan_fabid = 0x27,
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
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH
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
		}  }
	} }
};

/*
 * Here we switch back to a 1P 2-channel configuration so we can test how things
 * change with the extra bit that is now included since we're not hashing the
 * socket.
 */
static const zen_umc_t zen_umc_nps2_1p = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 32ULL * 1024ULL * 1024ULL * 1024ULL,
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
		.zud_dfno = 0,
		.zud_dram_nrules = 1,
		.zud_nchan = 2,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HASH_16_18 |
			    DF_DRAM_F_HASH_21_23 | DF_DRAM_F_HASH_30_32,
			.ddr_base = 0,
			.ddr_limit = 32ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_2CH
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
				.ddr_limit = 32ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_2CH
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
				.ddr_limit = 32ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_2CH
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
 * This here is a five-channel version, giving us some of our favorite non-power
 * of 2 cases.
 */
static const zen_umc_t zen_umc_nps5_1p = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 80ULL * 1024ULL * 1024ULL * 1024ULL,
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
			.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_5CH
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
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_5CH
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
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_5CH
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
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_5CH
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
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_5CH
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
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_5CH
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
 * And now in 6-channels so we can get the spiciness of the new normalization
 * scheme. We've also turned off several of the hash bits on this so we can
 * verify that using those middle bits doesn't do anything here.
 */
static const zen_umc_t zen_umc_nps6_1p = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 96ULL * 1024ULL * 1024ULL * 1024ULL,
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
		.zud_dfno = 0,
		.zud_dram_nrules = 1,
		.zud_nchan = 6,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HASH_30_32,
			.ddr_base = 0,
			.ddr_limit = 96ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 8,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_6CH
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
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_6CH
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
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_6CH
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
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_6CH
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
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_6CH
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
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_6CH
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
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_6CH
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
 * Finally our last bit here is a 3-channel 2P system. This is used to test that
 * the variant of the normalization with socket interleaving works correctly.
 */
static const zen_umc_t zen_umc_nps3_2p = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 96ULL * 1024ULL * 1024ULL * 1024ULL,
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
	.umc_ndfs = 2,
	.umc_dfs = { {
		.zud_dfno = 0,
		.zud_dram_nrules = 1,
		.zud_nchan = 3,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HASH_21_23,
			.ddr_base = 0,
			.ddr_limit = 96ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 1,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 8,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_3CH
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
				    DF_DRAM_F_HASH_21_23,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_3CH
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
				    DF_DRAM_F_HASH_21_23,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_3CH
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
				    DF_DRAM_F_HASH_21_23,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_3CH
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
			} }
		} }
	}, {
		.zud_dfno = 1,
		.zud_dram_nrules = 1,
		.zud_nchan = 3,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HASH_21_23,
			.ddr_base = 0,
			.ddr_limit = 96ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 1,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 8,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_3CH
		} },
		.zud_chan = { {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0x20,
			.chan_instid = 0,
			.chan_logid = 0,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_21_23,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_3CH
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
			.chan_fabid = 0x21,
			.chan_instid = 1,
			.chan_logid = 1,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_21_23,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_3CH
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
			.chan_fabid = 0x22,
			.chan_instid = 2,
			.chan_logid = 2,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR5,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_21_23,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_3CH
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
			} }
		} }
	} }
};

const umc_decode_test_t zen_umc_test_nps[] = { {
	.udt_desc = "NPS 8ch, 2P ilv (0)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x123,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x123,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x28,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (1)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x323,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x123,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x28,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (2)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x1123,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x123,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x28,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (3)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x1323,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x123,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x28,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (4)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x2123,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x123,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x28,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (5)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x2323,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x123,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x28,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (6)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x3123,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x123,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x28,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (7)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x3323,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x123,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x28,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (8)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x4123,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x123,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x28,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (9)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x4323,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x123,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x28,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (10)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x5123,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x123,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 5,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x28,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (11)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x5323,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x123,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 5,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x28,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (12)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x6123,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x123,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 6,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x28,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (13)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x6323,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x123,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 6,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x28,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (14)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x7123,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x123,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 7,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x28,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (15)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x7323,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x123,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 7,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x28,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (16)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x17323,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1123,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 7,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x228,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (17)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x217323,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x21123,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 7,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x228,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x4,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (18)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x40217323,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x4021123,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 7,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x228,
	.udt_dimm_row = 0x100,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x4,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (19)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x240217323,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x24021123,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x228,
	.udt_dimm_row = 0x900,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x4,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (20)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x240617323,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x24061123,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x228,
	.udt_dimm_row = 0x901,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x4,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (21)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x240617323,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x24061123,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x228,
	.udt_dimm_row = 0x901,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x4,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (22)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x240687323,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x24068123,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 6,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x28,
	.udt_dimm_row = 0x901,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 8ch, 2P ilv (23)",
	.udt_umc = &zen_umc_nps8_2p,
	.udt_pa = 0x2c0687323,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2c068123,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 7,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x28,
	.udt_dimm_row = 0xb01,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 2ch, 1P (0)",
	.udt_umc = &zen_umc_nps2_1p,
	.udt_pa = 0x167,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x167,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x29,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 2ch, 1P (1)",
	.udt_umc = &zen_umc_nps2_1p,
	.udt_pa = 0x367,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x167,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x29,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 2ch, 1P (2)",
	.udt_umc = &zen_umc_nps2_1p,
	.udt_pa = 0x4167,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2167,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x29,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 2ch, 1P (3)",
	.udt_umc = &zen_umc_nps2_1p,
	.udt_pa = 0x14167,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xa167,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x29,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0x1,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 2ch, 1P (4)",
	.udt_umc = &zen_umc_nps2_1p,
	.udt_pa = 0x40014167,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2000a167,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x29,
	.udt_dimm_row = 0x800,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0x1,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 2ch, 1P (5)",
	.udt_umc = &zen_umc_nps2_1p,
	.udt_pa = 0x214167,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x10a167,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x29,
	.udt_dimm_row = 0x4,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0x1,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 2ch, 1P (6)",
	.udt_umc = &zen_umc_nps2_1p,
	.udt_pa = 0x40214167,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2010a167,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x29,
	.udt_dimm_row = 0x804,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0x1,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 5ch, 1P (0)",
	.udt_umc = &zen_umc_nps5_1p,
	.udt_pa = 0xcd,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xcd,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x13,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 5ch, 1P (1)",
	.udt_umc = &zen_umc_nps5_1p,
	.udt_pa = 0x1cd,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x20cd,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x13,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 5ch, 1P (2)",
	.udt_umc = &zen_umc_nps5_1p,
	.udt_pa = 0x2cd,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1cd,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x33,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 5ch, 1P (3)",
	.udt_umc = &zen_umc_nps5_1p,
	.udt_pa = 0x3cd,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x21cd,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x33,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 5ch, 1P (4)",
	.udt_umc = &zen_umc_nps5_1p,
	.udt_pa = 0x4cd,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2cd,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x53,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 5ch, 1P (5)",
	.udt_umc = &zen_umc_nps5_1p,
	.udt_pa = 0x5cd,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x22cd,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x53,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 5ch, 1P (6)",
	.udt_umc = &zen_umc_nps5_1p,
	.udt_pa = 0x6cd,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x3cd,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x73,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 5ch, 1P (7)",
	.udt_umc = &zen_umc_nps5_1p,
	.udt_pa = 0x3ecd,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1fcd,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f3,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 5ch, 1P (8)",
	.udt_umc = &zen_umc_nps5_1p,
	.udt_pa = 0x3fcd,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x3fcd,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f3,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 5ch, 1P (9)",
	.udt_umc = &zen_umc_nps5_1p,
	.udt_pa = 0x40cd,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x20cd,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x13,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 5ch, 1P (10)",
	.udt_umc = &zen_umc_nps5_1p,
	.udt_pa = 0x41cd,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xcd,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x13,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 5ch, 1P (11)",
	.udt_umc = &zen_umc_nps5_1p,
	.udt_pa = 0x80cd,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xcd,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x13,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 5ch, 1P (12)",
	.udt_umc = &zen_umc_nps5_1p,
	.udt_pa = 0x81cd,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x20cd,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x13,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 5ch, 1P (13)",
	.udt_umc = &zen_umc_nps5_1p,
	.udt_pa = 0xc0cd,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x20cd,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x13,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 5ch, 1P (14)",
	.udt_umc = &zen_umc_nps5_1p,
	.udt_pa = 0xc1cd,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xcd,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x13,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 5ch, 1P (15)",
	.udt_umc = &zen_umc_nps5_1p,
	.udt_pa = 0x100cd,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x20cd,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x13,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 5ch, 1P (16)",
	.udt_umc = &zen_umc_nps5_1p,
	.udt_pa = 0x101cd,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xcd,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x13,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 5ch, 1P (17)",
	.udt_umc = &zen_umc_nps5_1p,
	.udt_pa = 0x140cd,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x40cd,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x13,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 5ch, 1P (18)",
	.udt_umc = &zen_umc_nps5_1p,
	.udt_pa = 0x141cd,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x60cd,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x13,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (0)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0xbc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xbc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1f,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (1)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x1bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x10bc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x21f,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (2)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x20bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xbc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1f,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (3)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x21bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x10bc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x21f,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (4)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x40bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x10bc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x21f,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (5)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x41bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xbc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1f,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (6)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x60bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x10bc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 5,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x21f,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (7)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x61bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xbc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1f,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (8)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x80bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xbc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1f,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (9)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x81bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x10bc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x21f,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (10)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0xa0bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xbc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 5,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1f,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (11)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0xa1bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x10bc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x21f,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
},
/*
 * We don't use hashing on the 64 KiB range, but walking through it should still
 * change the component IDs because of how the scheme works, but it should be
 * more contiguous.
 */
{
	.udt_desc = "NPS 6ch, 1P (12)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x120bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x20bc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1f,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (13)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x220bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x40bc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 5,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1f,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (14)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x320bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x80bc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1f,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x1,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (15)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x420bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xa0bc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1f,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 0x1,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (16)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x720bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x120bc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1f,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (17)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x1000020bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2aaaa0bc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1f,
	.udt_dimm_row = 0xaaa,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (18)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x1800020bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x400000bc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1f,
	.udt_dimm_row = 0x1000,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (19)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x1c00020bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x4aaab0bc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x21f,
	.udt_dimm_row = 0x12aa,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (20)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x1c00060bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x4aaaa0bc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1f,
	.udt_dimm_row = 0x12aa,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (21)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x1c00040bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x4aaaa0bc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 5,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1f,
	.udt_dimm_row = 0x12aa,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (22)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x1c00041bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x4aaab0bc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x21f,
	.udt_dimm_row = 0x12aa,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 6ch, 1P (23)",
	.udt_umc = &zen_umc_nps6_1p,
	.udt_pa = 0x1c00061bc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x4aaab0bc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x21f,
	.udt_dimm_row = 0x12aa,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 3ch, 2P (0)",
	.udt_umc = &zen_umc_nps3_2p,
	.udt_pa = 0xad,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xad,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1b,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 3ch, 2P (1)",
	.udt_umc = &zen_umc_nps3_2p,
	.udt_pa = 0x1ad,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xad,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1b,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 3ch, 2P (2)",
	.udt_umc = &zen_umc_nps3_2p,
	.udt_pa = 0x40ad,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xad,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1b,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 3ch, 2P (3)",
	.udt_umc = &zen_umc_nps3_2p,
	.udt_pa = 0x41ad,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xad,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1b,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 3ch, 2P (4)",
	.udt_umc = &zen_umc_nps3_2p,
	.udt_pa = 0x80ad,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xad,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1b,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 3ch, 2P (5)",
	.udt_umc = &zen_umc_nps3_2p,
	.udt_pa = 0x81ad,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xad,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1b,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0x0,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 3ch, 2P (6)",
	.udt_umc = &zen_umc_nps3_2p,
	.udt_pa = 0x1fc0ad,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x540ad,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1b,
	.udt_dimm_row = 0x1,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 3ch, 2P (7)",
	.udt_umc = &zen_umc_nps3_2p,
	.udt_pa = 0x1fc1ad,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x540ad,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1b,
	.udt_dimm_row = 0x1,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 3ch, 2P (8)",
	.udt_umc = &zen_umc_nps3_2p,
	.udt_pa = 0x2000ad,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x540ad,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1b,
	.udt_dimm_row = 0x1,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 3ch, 2P (9)",
	.udt_umc = &zen_umc_nps3_2p,
	.udt_pa = 0x2001ad,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x540ad,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1b,
	.udt_dimm_row = 0x1,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 3ch, 2P (10)",
	.udt_umc = &zen_umc_nps3_2p,
	.udt_pa = 0x2040ad,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x560ad,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1b,
	.udt_dimm_row = 0x1,
	.udt_dimm_bank = 0x3,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 3ch, 2P (11)",
	.udt_umc = &zen_umc_nps3_2p,
	.udt_pa = 0x2041ad,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x560ad,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1b,
	.udt_dimm_row = 0x1,
	.udt_dimm_bank = 0x3,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 3ch, 2P (12)",
	.udt_umc = &zen_umc_nps3_2p,
	.udt_pa = 0x2080ad,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x560ad,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1b,
	.udt_dimm_row = 0x1,
	.udt_dimm_bank = 0x3,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 3ch, 2P (13)",
	.udt_umc = &zen_umc_nps3_2p,
	.udt_pa = 0x2081ad,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x560ad,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1b,
	.udt_dimm_row = 0x1,
	.udt_dimm_bank = 0x3,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 3ch, 2P (14)",
	.udt_umc = &zen_umc_nps3_2p,
	.udt_pa = 0x20c0ad,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x560ad,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1b,
	.udt_dimm_row = 0x1,
	.udt_dimm_bank = 0x3,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 3ch, 2P (15)",
	.udt_umc = &zen_umc_nps3_2p,
	.udt_pa = 0x20c1ad,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x560ad,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1b,
	.udt_dimm_row = 0x1,
	.udt_dimm_bank = 0x3,
	.udt_dimm_bank_group = 0x2,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 3ch, 2P (16)",
	.udt_umc = &zen_umc_nps3_2p,
	.udt_pa = 0x10020c0ad,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2ab020ad,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1b,
	.udt_dimm_row = 0xaac,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "NPS 3ch, 2P (17)",
	.udt_umc = &zen_umc_nps3_2p,
	.udt_pa = 0x10020c1ad,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2ab020ad,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1b,
	.udt_dimm_row = 0xaac,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 0x0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = NULL
} };
