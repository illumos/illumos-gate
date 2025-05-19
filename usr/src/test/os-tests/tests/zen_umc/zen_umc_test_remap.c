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
 * This works at performing remap tests across both the DFv3 and DFv4 variants.
 */

#include "zen_umc_test.h"

static const zen_umc_t zen_umc_remap_v3 = {
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
		.zud_cs_nremap = 2,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_REMAP_EN |
			    DF_DRAM_F_REMAP_SOCK,
			.ddr_base = 0,
			.ddr_limit = 64ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 12,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH
		} },
		.zud_remap = { {
			.csr_nremaps = ZEN_UMC_MILAN_REMAP_ENTS,
			.csr_remaps = { 0x3, 0x2, 0x1, 0x0, 0x4, 0x5, 0x6, 0x7,
			    0x8, 0x9, 0xa, 0xb },
		}, {
			.csr_nremaps = ZEN_UMC_MILAN_REMAP_ENTS,
			.csr_remaps = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
			    0x8, 0x9, 0xa, 0xb },
		} },
		.zud_chan = { {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0,
			.chan_instid = 0,
			.chan_logid = 0,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_REMAP_EN |
				    DF_DRAM_F_REMAP_SOCK,
				.ddr_base = 0,
				.ddr_limit = 64ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 12,
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
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_REMAP_EN |
				    DF_DRAM_F_REMAP_SOCK,
				.ddr_base = 0,
				.ddr_limit = 64ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 12,
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
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_REMAP_EN |
				    DF_DRAM_F_REMAP_SOCK,
				.ddr_base = 0,
				.ddr_limit = 64ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 12,
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
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_REMAP_EN |
				    DF_DRAM_F_REMAP_SOCK,
				.ddr_base = 0,
				.ddr_limit = 64ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 12,
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
		} }
	} }
};

/*
 * This sets up a DFv4 capable remap engine. The important difference we want to
 * test here is that the remap rules can be selected on a per-DRAM rule basis.
 * This leads us to split our rules in half and end up with two totally
 * different remapping schemes. In comparison, DFv3 is target socket based.
 */
static const zen_umc_t zen_umc_remap_v4 = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 64ULL * 1024ULL * 1024ULL * 1024ULL,
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
		.zud_dram_nrules = 2,
		.zud_nchan = 4,
		.zud_cs_nremap = 2,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_REMAP_EN,
			.ddr_base = 0,
			.ddr_limit = 32ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 12,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH,
			.ddr_remap_ent = 0
		}, {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_REMAP_EN,
			.ddr_base = 32ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_limit = 64ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 12,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH,
			.ddr_remap_ent = 1
		} },
		.zud_remap = { {
			.csr_nremaps = ZEN_UMC_MAX_REMAP_ENTS,
			.csr_remaps = { 0x3, 0x2, 0x1, 0x0, 0x4, 0x5, 0x6, 0x7,
			    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf },
		}, {
			.csr_nremaps = ZEN_UMC_MAX_REMAP_ENTS,
			.csr_remaps = { 0x2, 0x1, 0x3, 0x0, 0x4, 0x5, 0x6, 0x7,
			    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf },
		} },
		.zud_chan = { {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0,
			.chan_instid = 0,
			.chan_logid = 0,
			.chan_nrules = 2,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_REMAP_EN,
				.ddr_base = 0,
				.ddr_limit = 32ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 12,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH,
				.ddr_remap_ent = 0
			}, {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_REMAP_EN,
				.ddr_base = 32ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_limit = 64ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 12,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH,
				.ddr_remap_ent = 1
			} },
			.chan_offsets = { {
				.cho_valid = B_TRUE,
				.cho_offset = 0x200000000,
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
			.chan_nrules = 2,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_REMAP_EN,
				.ddr_base = 0,
				.ddr_limit = 32ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 12,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH,
				.ddr_remap_ent = 0
			}, {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_REMAP_EN,
				.ddr_base = 32ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_limit = 64ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 12,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH,
				.ddr_remap_ent = 1
			} },
			.chan_offsets = { {
				.cho_valid = B_TRUE,
				.cho_offset = 0x200000000,
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
			.chan_nrules = 2,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_REMAP_EN,
				.ddr_base = 0,
				.ddr_limit = 32ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 12,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH,
				.ddr_remap_ent = 0
			}, {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_REMAP_EN,
				.ddr_base = 32ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_limit = 64ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 12,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH,
				.ddr_remap_ent = 1
			} },
			.chan_offsets = { {
				.cho_valid = B_TRUE,
				.cho_offset = 0x200000000,
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
			.chan_nrules = 2,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_REMAP_EN,
				.ddr_base = 0,
				.ddr_limit = 32ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 12,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH,
				.ddr_remap_ent = 0
			}, {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_REMAP_EN,
				.ddr_base = 32ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_limit = 64ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 12,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_4CH,
				.ddr_remap_ent = 1
			} },
			.chan_offsets = { {
				.cho_valid = B_TRUE,
				.cho_offset = 0x200000000,
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

const umc_decode_test_t zen_umc_test_remap[] = { {
	.udt_desc = "Milan Remap (0)",
	.udt_umc = &zen_umc_remap_v3,
	.udt_pa = 0x138,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x138,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x27,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "Milan Remap (1)",
	.udt_umc = &zen_umc_remap_v3,
	.udt_pa = 0x1138,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x138,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x27,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "Milan Remap (2)",
	.udt_umc = &zen_umc_remap_v3,
	.udt_pa = 0x2138,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x138,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x27,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "Milan Remap (3)",
	.udt_umc = &zen_umc_remap_v3,
	.udt_pa = 0x3138,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x138,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x27,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DFv4 Remap (0)",
	.udt_umc = &zen_umc_remap_v4,
	.udt_pa = 0x163,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x163,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x2c,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DFv4 Remap (1)",
	.udt_umc = &zen_umc_remap_v4,
	.udt_pa = 0x1163,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x163,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x2c,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DFv4 Remap (2)",
	.udt_umc = &zen_umc_remap_v4,
	.udt_pa = 0x2163,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x163,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x2c,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DFv4 Remap (3)",
	.udt_umc = &zen_umc_remap_v4,
	.udt_pa = 0x3163,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x163,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x2c,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DFv4 Remap (4)",
	.udt_umc = &zen_umc_remap_v4,
	.udt_pa = 0x900000163,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x240000163,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x2c,
	.udt_dimm_row = 0x12000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DFv4 Remap (5)",
	.udt_umc = &zen_umc_remap_v4,
	.udt_pa = 0x900001163,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x240000163,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x2c,
	.udt_dimm_row = 0x12000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DFv4 Remap (6)",
	.udt_umc = &zen_umc_remap_v4,
	.udt_pa = 0x900002163,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x240000163,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x2c,
	.udt_dimm_row = 0x12000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DFv4 Remap (7)",
	.udt_umc = &zen_umc_remap_v4,
	.udt_pa = 0x900003163,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x240000163,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x2c,
	.udt_dimm_row = 0x12000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = NULL
} };
