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
 * Test the basic interleave scenarios that don't involve hashing or non-powers
 * of 2. Every DRAM channel we map to always has a single 16 GiB DIMM to keep
 * things straightforward. For all of these designs, UMC channels are labeled
 * consecutively. Note, there is no remapping going on here, that is saved for
 * elsewhere. In particular we cover:
 *
 * o Channel Interleaving
 * o Channel + Die Interleaving
 * o Channel + Socket Interleaving
 * o Channel + Die + Socket Interleaving
 *
 * Throughout these we end up trying to vary what the starting address here and
 * we adjust the DF decomposition to try and be something close to an existing
 * DF revision.
 */

#include "zen_umc_test.h"

/*
 * Our first version of this, 4-way channel interleaving.
 */
static const zen_umc_t zen_umc_ilv_1p1d4c_4ch = {
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
		.zud_dram_nrules = 1,
		.zud_nchan = 4,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 0,
			.ddr_limit = 64ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH
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
				.ddr_base = 0,
				.ddr_limit = 64ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH
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
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH
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
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 2,
			.chan_instid = 2,
			.chan_logid = 2,
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
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH
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
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 3,
			.chan_instid = 3,
			.chan_logid = 3,
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
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH
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
		}  }
	} }
};

/*
 * 2P configuration with 4 channels each. We interleave across 2 sockets and 4
 * channels. This uses a single rule.
 */
static const zen_umc_t zen_umc_ilv_2p1d4c_2s4ch = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 128ULL * 1024ULL * 1024ULL * 1024ULL,
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
	.umc_ndfs = 2,
	.umc_dfs = { {
		.zud_dfno = 0,
		.zud_dram_nrules = 1,
		.zud_nchan = 4,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 0,
			.ddr_limit = 128ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 1,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 10,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH
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
				.ddr_base = 0,
				.ddr_limit = 128ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 10,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH
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
				.ddr_limit = 128ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 10,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH
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
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 2,
			.chan_instid = 2,
			.chan_logid = 2,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID,
				.ddr_base = 0,
				.ddr_limit = 128ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 10,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH
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
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 3,
			.chan_instid = 3,
			.chan_logid = 3,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID,
				.ddr_base = 0,
				.ddr_limit = 128ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 10,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH
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
		}  }
	}, {
		.zud_dfno = 1,
		.zud_dram_nrules = 2,
		.zud_nchan = 4,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 0,
			.ddr_limit = 128ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 1,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 10,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH
		} },
		.zud_chan = { {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0x20,
			.chan_instid = 0,
			.chan_logid = 0,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID,
				.ddr_base = 0,
				.ddr_limit = 128ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 10,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH
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
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0x21,
			.chan_instid = 1,
			.chan_logid = 1,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID,
				.ddr_base = 0,
				.ddr_limit = 128ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 10,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH
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
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0x22,
			.chan_instid = 2,
			.chan_logid = 2,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID,
				.ddr_base = 0,
				.ddr_limit = 128ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 10,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH
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
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0x23,
			.chan_instid = 3,
			.chan_logid = 3,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID,
				.ddr_base = 0,
				.ddr_limit = 128ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 10,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH
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
		}  }
	} }
};

/*
 * This is a 2 Die, 2 Channel interleave.
 */
static const zen_umc_t zen_umc_ilv_1p2d2c_2d2ch = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 64ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_df_rev = DF_REV_3,
	.umc_decomp = {
		.dfd_sock_mask = 0x00,
		.dfd_die_mask = 0x01,
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
		.zud_nchan = 2,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 0,
			.ddr_limit = 64ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 1,
			.ddr_addr_start = 12,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
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
				.ddr_base = 0,
				.ddr_limit = 64ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 1,
				.ddr_addr_start = 12,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
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
				.ddr_die_ileave_bits = 1,
				.ddr_addr_start = 12,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
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
	}, {
		.zud_dfno = 1,
		.zud_dram_nrules = 2,
		.zud_nchan = 4,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 0,
			.ddr_limit = 64ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 1,
			.ddr_addr_start = 12,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
		} },
		.zud_chan = { {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0x20,
			.chan_instid = 0,
			.chan_logid = 0,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID,
				.ddr_base = 0,
				.ddr_limit = 64ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 1,
				.ddr_addr_start = 12,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
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
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0x21,
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
				.ddr_die_ileave_bits = 1,
				.ddr_addr_start = 12,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
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
 * This is a 2 Socket 2 Die, 2 Channel interleave, aka naples-light, but with a
 * contiguous DFv4 style socket ID.
 */
static const zen_umc_t zen_umc_ilv_naplesish = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 256ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_df_rev = DF_REV_3,
	.umc_decomp = {
		.dfd_sock_mask = 0x1e,
		.dfd_die_mask = 0x01,
		.dfd_node_mask = 0xf80,
		.dfd_comp_mask = 0x7f,
		.dfd_sock_shift = 1,
		.dfd_die_shift = 0,
		.dfd_node_shift = 7,
		.dfd_comp_shift = 0
	},
	.umc_ndfs = 4,
	.umc_dfs = { {
		.zud_dfno = 0,
		.zud_dram_nrules = 1,
		.zud_nchan = 2,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 0,
			.ddr_limit = 256ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 1,
			.ddr_die_ileave_bits = 1,
			.ddr_addr_start = 8,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
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
				.ddr_base = 0,
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 1,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
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
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 1,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
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
	}, {
		.zud_dfno = 0,
		.zud_dram_nrules = 1,
		.zud_nchan = 2,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 0,
			.ddr_limit = 256ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 1,
			.ddr_die_ileave_bits = 1,
			.ddr_addr_start = 8,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
		} },
		.zud_chan = { {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0x80,
			.chan_instid = 0,
			.chan_logid = 0,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID,
				.ddr_base = 0,
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 1,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
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
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0x81,
			.chan_instid = 1,
			.chan_logid = 1,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID,
				.ddr_base = 0,
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 1,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
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
	}, {
		.zud_dfno = 0,
		.zud_dram_nrules = 1,
		.zud_nchan = 2,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 0,
			.ddr_limit = 256ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 1,
			.ddr_die_ileave_bits = 1,
			.ddr_addr_start = 8,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
		} },
		.zud_chan = { {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0x100,
			.chan_instid = 0,
			.chan_logid = 0,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID,
				.ddr_base = 0,
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 1,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
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
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0x101,
			.chan_instid = 1,
			.chan_logid = 1,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID,
				.ddr_base = 0,
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 1,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
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
	}, {
		.zud_dfno = 1,
		.zud_dram_nrules = 2,
		.zud_nchan = 4,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 0,
			.ddr_limit = 256ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 1,
			.ddr_die_ileave_bits = 1,
			.ddr_addr_start = 8,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
		} },
		.zud_chan = { {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0x180,
			.chan_instid = 0,
			.chan_logid = 0,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID,
				.ddr_base = 0,
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 1,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
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
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0x181,
			.chan_instid = 1,
			.chan_logid = 1,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID,
				.ddr_base = 0,
				.ddr_limit = 256ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 1,
				.ddr_die_ileave_bits = 1,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
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

const umc_decode_test_t zen_umc_test_ilv[] = { {
	.udt_desc = "ILV: 1/1/4 4-way Channel (0)",
	.udt_umc = &zen_umc_ilv_1p1d4c_4ch,
	.udt_pa = 0x1ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ILV: 1/1/4 4-way Channel (1)",
	.udt_umc = &zen_umc_ilv_1p1d4c_4ch,
	.udt_pa = 0x3ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ILV: 1/1/4 4-way Channel (2)",
	.udt_umc = &zen_umc_ilv_1p1d4c_4ch,
	.udt_pa = 0x5ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ILV: 1/1/4 4-way Channel (3)",
	.udt_umc = &zen_umc_ilv_1p1d4c_4ch,
	.udt_pa = 0x7ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ILV: 1/1/4 4-way Channel (4)",
	.udt_umc = &zen_umc_ilv_1p1d4c_4ch,
	.udt_pa = 0x42231679,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1088c479,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x8f,
	.udt_dimm_row = 0x844,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ILV: 2/1/4 2P-way, 4-way Channel (0)",
	.udt_umc = &zen_umc_ilv_2p1d4c_2s4ch,
	.udt_pa = 0x21ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x5ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xbf,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ILV: 2/1/4 2P-way, 4-way Channel (1)",
	.udt_umc = &zen_umc_ilv_2p1d4c_2s4ch,
	.udt_pa = 0x23ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x7ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0xff,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ILV: 2/1/4 2P-way, 4-way Channel (2)",
	.udt_umc = &zen_umc_ilv_2p1d4c_2s4ch,
	.udt_pa = 0xbadc201ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x175b841ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0xbadc,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ilv: 2/1/4 2p-way, 4-way channel (3)",
	.udt_umc = &zen_umc_ilv_2p1d4c_2s4ch,
	.udt_pa = 0xbadc205ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x175b841ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0xbadc,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ilv: 2/1/4 2p-way, 4-way channel (4)",
	.udt_umc = &zen_umc_ilv_2p1d4c_2s4ch,
	.udt_pa = 0xbadc209ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x175b841ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0xbadc,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ilv: 2/1/4 2p-way, 4-way channel (5)",
	.udt_umc = &zen_umc_ilv_2p1d4c_2s4ch,
	.udt_pa = 0xbadc20dff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x175b841ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0xbadc,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ILV: 2/1/4 2P-way, 4-way Channel (6)",
	.udt_umc = &zen_umc_ilv_2p1d4c_2s4ch,
	.udt_pa = 0xbadc211ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x175b841ff,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0xbadc,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ilv: 2/1/4 2p-way, 4-way channel (7)",
	.udt_umc = &zen_umc_ilv_2p1d4c_2s4ch,
	.udt_pa = 0xbadc215ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x175b841ff,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0xbadc,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ilv: 2/1/4 2p-way, 4-way channel (8)",
	.udt_umc = &zen_umc_ilv_2p1d4c_2s4ch,
	.udt_pa = 0xbadc219ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x175b841ff,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0xbadc,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ilv: 2/1/4 2p-way, 4-way channel (9)",
	.udt_umc = &zen_umc_ilv_2p1d4c_2s4ch,
	.udt_pa = 0xbadc21dff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x175b841ff,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0xbadc,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ilv: 1/2/2 2-way die, 2-way channel (0)",
	.udt_umc = &zen_umc_ilv_1p2d2c_2d2ch,
	.udt_pa = 0x12233cfbb,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x488cffbb,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f7,
	.udt_dimm_row = 0x2446,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ilv: 1/2/2 2-way die, 2-way channel (1)",
	.udt_umc = &zen_umc_ilv_1p2d2c_2d2ch,
	.udt_pa = 0x12233efbb,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x488cffbb,
	.udt_sock = 0,
	.udt_die = 1,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f7,
	.udt_dimm_row = 0x2446,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ilv: 1/2/2 2-way die, 2-way channel (2)",
	.udt_umc = &zen_umc_ilv_1p2d2c_2d2ch,
	.udt_pa = 0x12233ffbb,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x488cffbb,
	.udt_sock = 0,
	.udt_die = 1,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f7,
	.udt_dimm_row = 0x2446,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ilv: 1/2/2 2-way die, 2-way channel (3)",
	.udt_umc = &zen_umc_ilv_1p2d2c_2d2ch,
	.udt_pa = 0x12233dfbb,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x488cffbb,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f7,
	.udt_dimm_row = 0x2446,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ilv: 2/2/2 2-way sock, 2-way die, 2-way channel (0)",
	.udt_umc = &zen_umc_ilv_naplesish,
	.udt_pa = 0xffed37f42,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1ffda6f42,
	.udt_sock = 1,
	.udt_die = 1,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1e8,
	.udt_dimm_row = 0xffed,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ilv: 2/2/2 2-way sock, 2-way die, 2-way channel (1)",
	.udt_umc = &zen_umc_ilv_naplesish,
	.udt_pa = 0xffed37e42,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1ffda6f42,
	.udt_sock = 1,
	.udt_die = 1,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1e8,
	.udt_dimm_row = 0xffed,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ilv: 2/2/2 2-way sock, 2-way die, 2-way channel (2)",
	.udt_umc = &zen_umc_ilv_naplesish,
	.udt_pa = 0xffed37d42,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1ffda6f42,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1e8,
	.udt_dimm_row = 0xffed,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ilv: 2/2/2 2-way sock, 2-way die, 2-way channel (3)",
	.udt_umc = &zen_umc_ilv_naplesish,
	.udt_pa = 0xffed37c42,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1ffda6f42,
	.udt_sock = 1,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1e8,
	.udt_dimm_row = 0xffed,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ilv: 2/2/2 2-way sock, 2-way die, 2-way channel (4)",
	.udt_umc = &zen_umc_ilv_naplesish,
	.udt_pa = 0xffed37b42,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1ffda6f42,
	.udt_sock = 0,
	.udt_die = 1,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1e8,
	.udt_dimm_row = 0xffed,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ilv: 2/2/2 2-way sock, 2-way die, 2-way channel (5)",
	.udt_umc = &zen_umc_ilv_naplesish,
	.udt_pa = 0xffed37a42,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1ffda6f42,
	.udt_sock = 0,
	.udt_die = 1,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1e8,
	.udt_dimm_row = 0xffed,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ilv: 2/2/2 2-way sock, 2-way die, 2-way channel (6)",
	.udt_umc = &zen_umc_ilv_naplesish,
	.udt_pa = 0xffed37942,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1ffda6f42,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1e8,
	.udt_dimm_row = 0xffed,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "ilv: 2/2/2 2-way sock, 2-way die, 2-way channel (7)",
	.udt_umc = &zen_umc_ilv_naplesish,
	.udt_pa = 0xffed37842,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1ffda6f42,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1e8,
	.udt_dimm_row = 0xffed,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = NULL
} };
