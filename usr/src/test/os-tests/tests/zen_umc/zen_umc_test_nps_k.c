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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Test the various forms NPS 1K/2K variants that we have. We explicitly test:
 *
 *  o 2K 2P interleaving with 8 channels
 *  o 1K 1P interleaving with 2 channels
 *  o >1T hashing
 *
 * Non-power of 2 1K/2K channel interleaving is in zen_umc_test_np2_k.c.
 */

#include "zen_umc_test.h"

/*
 * First we have a variant of 'zen_umc_nps8_2p' for the DF 4D2, 2K edition. This
 * forces all bits in the address interleaving to be used.
 */
static const zen_umc_t zen_umc_nps8_2p_2k = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 256ULL * 1024ULL * 1024ULL * 1024ULL,
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
			.ddr_addr_start = 8,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH_2K
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
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH_2K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
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
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH_2K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
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
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH_2K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
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
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH_2K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
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
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH_2K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
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
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH_2K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
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
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH_2K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
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
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH_2K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
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
			.ddr_addr_start = 8,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH_2K
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
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH_2K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
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
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH_2K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
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
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH_2K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
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
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH_2K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
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
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH_2K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
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
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH_2K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
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
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH_2K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
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
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH_2K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
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
 * This is a 1P 2-channel configuration that uses a 1K hash mode. It uses all
 * the interleave bits other than 1T.
 */
static const zen_umc_t zen_umc_nps2_1p_1k = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 32ULL * 1024ULL * 1024ULL * 1024ULL,
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
			.ddr_addr_start = 8,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_2CH_1K
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
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_2CH_1K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
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
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_2CH_1K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
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
 * This test is designed to allow us to create a >1T configuration which means
 * we would like to have 4T of address space. To do this we're going to create a
 * fake 1T DDR5 DIMM that is all in one channel. This is a bit lazy of us as
 * such a thing doesn't exist, but it makes life simpler. We have this in an
 * NPS2 4CH configuration with the 1K variant so we can get more address bits
 * flowing.
 */
static const zen_umc_t zen_umc_nps4_1T_1k = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 4ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL,
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
		.zud_nchan = 4,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HASH_16_18 |
			    DF_DRAM_F_HASH_21_23 | DF_DRAM_F_HASH_30_32 |
			    DF_DRAM_F_HASH_40_42,
			.ddr_base = 0,
			.ddr_limit = 4ULL * 1024ULL * 1024ULL * 1024ULL *
			    1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 8,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_4CH_1K
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
				    DF_DRAM_F_HASH_30_32 |
				    DF_DRAM_F_HASH_40_42,
				.ddr_base = 0,
				.ddr_limit = 4ULL * 1024ULL * 1024ULL *
				    1024ULL * 1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_4CH_1K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
					.ucs_base = {
						.udb_base = 0,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0xffffffffff,
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x16,
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
				    DF_DRAM_F_HASH_30_32 |
				    DF_DRAM_F_HASH_40_42,
				.ddr_base = 0,
				.ddr_limit = 4ULL * 1024ULL * 1024ULL *
				    1024ULL * 1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_4CH_1K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
					.ucs_base = {
						.udb_base = 0,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0xffffffffff,
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x16,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} }
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
				    DF_DRAM_F_HASH_30_32 |
				    DF_DRAM_F_HASH_40_42,
				.ddr_base = 0,
				.ddr_limit = 4ULL * 1024ULL * 1024ULL *
				    1024ULL * 1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_4CH_1K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
					.ucs_base = {
						.udb_base = 0,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0xffffffffff,
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x16,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11, 0xd,
					    0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} }
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
				    DF_DRAM_F_HASH_30_32 |
				    DF_DRAM_F_HASH_40_42,
				.ddr_base = 0,
				.ddr_limit = 4ULL * 1024ULL * 1024ULL *
				    1024ULL * 1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_4CH_1K
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
					.ucs_base = {
						.udb_base = 0,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0xffffffffff,
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x16,
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

/*
 * For the NPS tests we first walk each way of getting to the same normalized
 * address through each hash variant.
 */
const umc_decode_test_t zen_umc_test_nps_k[] = { {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (0)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x023,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x023,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x08,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (1)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x123,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x023,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x08,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (2)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x1023,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x023,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x08,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (3)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x1123,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x023,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x08,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (4)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x2023,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x023,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x08,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (5)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x2123,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x023,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x08,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (6)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x3023,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x023,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x08,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (7)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x3123,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x023,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x08,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (8)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x4023,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x023,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x08,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (9)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x4123,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x023,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x08,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (10)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x5023,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x023,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 5,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x08,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (11)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x5123,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x023,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 5,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x08,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (12)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x6023,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x023,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 6,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x08,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (13)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x6123,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x023,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 6,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x08,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (14)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x7023,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x023,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 7,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x08,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (15)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x7123,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x023,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 7,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x08,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	/*
	 * Now that we've shown that basics work here, let's start using the
	 * hashing pieces and confirming that as we vary that we end up going to
	 * different sockets and channels rather than the base ones that we had.
	 */
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (16)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x10023,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1023,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x208,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (17)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x10123,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1023,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x208,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (18)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x20023,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2023,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x8,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (19)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x27023,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2023,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 7,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x8,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	/*
	 * The 2K variant does not use the 2nd bit for any of the hashes. We'll
	 * walk bits 21-25 and make sure that bit 22 doesn't influence anything
	 * while the others do.
	 */
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (20)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x27023,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2023,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 7,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x8,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (21)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x227023,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x22023,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 7,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x8,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0x4,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (22)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x427023,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x42023,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 7,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x8,
	.udt_dimm_row = 0x1,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (23)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x627023,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x62023,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 7,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x8,
	.udt_dimm_row = 0x1,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0x4,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (24)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0x827023,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x82023,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 6,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x8,
	.udt_dimm_row = 0x2,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (25)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0xa27023,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xa2023,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 6,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x8,
	.udt_dimm_row = 0x2,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0x4,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (26)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0xc27023,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xc2023,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 6,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x8,
	.udt_dimm_row = 0x3,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 2K 8ch, 2P ilv (27)",
	.udt_umc = &zen_umc_nps8_2p_2k,
	.udt_pa = 0xf27023,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xf2023,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x8,
	.udt_dimm_row = 0x3,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 6,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 2ch 1P (0)",
	.udt_umc = &zen_umc_nps2_1p_1k,
	.udt_pa = 0x042,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x042,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x00,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0x1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 2ch 1P (1)",
	.udt_umc = &zen_umc_nps2_1p_1k,
	.udt_pa = 0x142,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x042,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x00,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0x1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0

}, {
	.udt_desc = "DF 4D2 NPS 1K 2ch 1P (2)",
	.udt_umc = &zen_umc_nps2_1p_1k,
	.udt_pa = 0x242,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x142,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x20,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0x1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 2ch 1P (3)",
	.udt_umc = &zen_umc_nps2_1p_1k,
	.udt_pa = 0x342,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x142,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x20,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0x1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 2ch 1P (4)",
	.udt_umc = &zen_umc_nps2_1p_1k,
	.udt_pa = 0x10042,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x8042,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x1,
	.udt_dimm_subchan = 0x1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 2ch 1P (4)",
	.udt_umc = &zen_umc_nps2_1p_1k,
	.udt_pa = 0x10142,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x8042,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x1,
	.udt_dimm_subchan = 0x1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 2ch 1P (5)",
	.udt_umc = &zen_umc_nps2_1p_1k,
	.udt_pa = 0x210042,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x108042,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0x4,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x1,
	.udt_dimm_subchan = 0x1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 2ch 1P (6)",
	.udt_umc = &zen_umc_nps2_1p_1k,
	.udt_pa = 0x210142,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x108042,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0x4,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x1,
	.udt_dimm_subchan = 0x1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 2ch 1P (5)",
	.udt_umc = &zen_umc_nps2_1p_1k,
	.udt_pa = 0x4210042,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2108042,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0x84,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x1,
	.udt_dimm_subchan = 0x1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 2ch 1P (6)",
	.udt_umc = &zen_umc_nps2_1p_1k,
	.udt_pa = 0x4210142,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2108042,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0x84,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x1,
	.udt_dimm_subchan = 0x1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 2ch 1P (6)",
	.udt_umc = &zen_umc_nps2_1p_1k,
	.udt_pa = 0xbbadcafe,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x5dd6e5fe,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xbf,
	.udt_dimm_row = 0x1775,
	.udt_dimm_bank = 0x3,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 0x1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 2ch 1P (7)",
	.udt_umc = &zen_umc_nps2_1p_1k,
	.udt_pa = 0xbbadcbfe,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x5dd6e5fe,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xbf,
	.udt_dimm_row = 0x1775,
	.udt_dimm_bank = 0x3,
	.udt_dimm_bank_group = 0x5,
	.udt_dimm_subchan = 0x1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	/*
	 * For the 1T tests, we first will show baseline channel selection with
	 * the non-interleave bits. Then we will go up to the 1T range and
	 * alternate more bits to show that we're hashing correctly.
	 */
	.udt_desc = "DF 4D2 NPS 1K 4ch 1T (0)",
	.udt_umc = &zen_umc_nps4_1T_1k,
	.udt_pa = 0x99,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x99,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x16,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 4ch 1T (1)",
	.udt_umc = &zen_umc_nps4_1T_1k,
	.udt_pa = 0x199,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x99,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x16,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 4ch 1T (2)",
	.udt_umc = &zen_umc_nps4_1T_1k,
	.udt_pa = 0x299,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x99,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x16,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 4ch 1T (3)",
	.udt_umc = &zen_umc_nps4_1T_1k,
	.udt_pa = 0x399,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x99,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x16,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 4ch 1T (4)",
	.udt_umc = &zen_umc_nps4_1T_1k,
	.udt_pa = 0x10000000099,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x4000000099,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x16,
	.udt_dimm_row = 0x100000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 4ch 1T (5)",
	.udt_umc = &zen_umc_nps4_1T_1k,
	.udt_pa = 0x20000000099,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x8000000099,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x16,
	.udt_dimm_row = 0x200000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 4ch 1T (6)",
	.udt_umc = &zen_umc_nps4_1T_1k,
	.udt_pa = 0x30000000099,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xc000000099,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x16,
	.udt_dimm_row = 0x300000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 4ch 1T (7)",
	.udt_umc = &zen_umc_nps4_1T_1k,
	.udt_pa = 0x10000000199,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x4000000099,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x16,
	.udt_dimm_row = 0x100000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 4ch 1T (8)",
	.udt_umc = &zen_umc_nps4_1T_1k,
	.udt_pa = 0x10000000399,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x4000000099,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x16,
	.udt_dimm_row = 0x100000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 4ch 1T (9)",
	.udt_umc = &zen_umc_nps4_1T_1k,
	.udt_pa = 0x10000000299,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x4000000099,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x16,
	.udt_dimm_row = 0x100000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 4ch 1T (10)",
	.udt_umc = &zen_umc_nps4_1T_1k,
	.udt_pa = 0xdeadbeefad,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x37ab6fbbad,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x37b,
	.udt_dimm_row = 0xdeadb,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 0x7,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 4ch 1T (11)",
	.udt_umc = &zen_umc_nps4_1T_1k,
	.udt_pa = 0xe1be1275cf,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x386f849dcf,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3b3,
	.udt_dimm_row = 0xe1be1,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x1,
	.udt_dimm_subchan = 0x1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DF 4D2 NPS 1K 4ch 1T (11)",
	.udt_umc = &zen_umc_nps4_1T_1k,
	.udt_pa = 0x23456789abc,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x8d159e26bc,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xdf,
	.udt_dimm_row = 0x234567,
	.udt_dimm_bank = 0x1,
	.udt_dimm_bank_group = 0x4,
	.udt_dimm_subchan = 0x0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = NULL
} };
