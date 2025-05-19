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
 * This provides a few different examples of how we take into account the DRAM
 * hole. There are three primary cases to consider:
 *
 *   o Taking it into account when determine if DRAM is valid or not.
 *   o Taking it into account when we do address interleaving (DFv4)
 *   o Taking it into account when performing normalization.
 */

#include "zen_umc_test.h"

/*
 * This is a standard application of the DRAM hole starting at 2 GiB in the
 * space. This follows the DFv3 rules.
 */
static const zen_umc_t zen_umc_hole_dfv3 = {
	.umc_tom = 2ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 68ULL * 1024ULL * 1024ULL * 1024ULL,
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
		.zud_dram_nrules = 1,
		.zud_nchan = 4,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0x80000000,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HOLE,
			.ddr_base = 0,
			.ddr_limit = 68ULL * 1024ULL * 1024ULL * 1024ULL,
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
				.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HOLE,
				.ddr_base = 0,
				.ddr_limit = 68ULL * 1024ULL * 1024ULL *
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
				.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HOLE,
				.ddr_base = 0,
				.ddr_limit = 68ULL * 1024ULL * 1024ULL *
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
				.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HOLE,
				.ddr_base = 0,
				.ddr_limit = 68ULL * 1024ULL * 1024ULL *
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
				.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HOLE,
				.ddr_base = 0,
				.ddr_limit = 68ULL * 1024ULL * 1024ULL *
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
 * This case is a little insidious to be honest. Here we're using a DFv4 style
 * DRAM hole. Technically the hole needs to be taken into account before
 * interleaving here (unlike DFv3). So we shrink the hole's size to 4 KiB and
 * set up interleaving at address 12. This ensures that stuff around the hole
 * will catch this and adjust for interleve. Yes, this is smaller than the hole
 * is allowed to be in hardware, but here we're all just integers. Basically the
 * whole covers the last 4 KiB of low memory. We use hex here to make these
 * easier to deal with.
 */
static const zen_umc_t zen_umc_hole_dfv4 = {
	.umc_tom = 0xfffff000,
	.umc_tom2 = 0x1000001000,
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
		.zud_dram_nrules = 1,
		.zud_nchan = 4,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0xfffff000,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HOLE,
			.ddr_base = 0,
			.ddr_limit = 0x1000001000,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 12,
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
				.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HOLE,
				.ddr_base = 0,
				.ddr_limit = 0x1000001000,
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
				.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HOLE,
				.ddr_base = 0,
				.ddr_limit = 0x1000001000,
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
				.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HOLE,
				.ddr_base = 0,
				.ddr_limit = 0x1000001000,
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
				.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HOLE,
				.ddr_base = 0,
				.ddr_limit = 0x1000001000,
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
		}  }
	} }
};


const umc_decode_test_t zen_umc_test_hole[] = { {
	.udt_desc = "Memory in hole doesn't decode (0)",
	.udt_umc = &zen_umc_hole_dfv3,
	.udt_pa = 0xb0000000,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_OUTSIDE_DRAM
}, {
	.udt_desc = "Memory in hole doesn't decode (1)",
	.udt_umc = &zen_umc_hole_dfv3,
	.udt_pa = 0x80000000,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_OUTSIDE_DRAM
}, {
	.udt_desc = "Memory in hole doesn't decode (2)",
	.udt_umc = &zen_umc_hole_dfv3,
	.udt_pa = 0xffffffff,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_OUTSIDE_DRAM
},  {
	.udt_desc = "Memory in hole doesn't decode (3)",
	.udt_umc = &zen_umc_hole_dfv3,
	.udt_pa = 0xcba89754,
	.udt_pass = B_FALSE,
	.udt_fail = ZEN_UMC_DECODE_F_OUTSIDE_DRAM
}, {
	.udt_desc = "DRAM Hole DFv3 4ch (0)",
	.udt_umc = &zen_umc_hole_dfv3,
	.udt_pa = 0x7fffffff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1fffffff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3ff,
	.udt_dimm_row = 0xfff,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 3,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DRAM Hole DFv3 4ch (1)",
	.udt_umc = &zen_umc_hole_dfv3,
	.udt_pa = 0x7ffffdff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1fffffff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3ff,
	.udt_dimm_row = 0xfff,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 3,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DRAM Hole DFv3 4ch (2)",
	.udt_umc = &zen_umc_hole_dfv3,
	.udt_pa = 0x7ffffbff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1fffffff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3ff,
	.udt_dimm_row = 0xfff,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 3,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DRAM Hole DFv3 4ch (3)",
	.udt_umc = &zen_umc_hole_dfv3,
	.udt_pa = 0x7ffff9ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1fffffff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3ff,
	.udt_dimm_row = 0xfff,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 3,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DRAM Hole DFv3 4ch (4)",
	.udt_umc = &zen_umc_hole_dfv3,
	.udt_pa = 0x100000000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x20000000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x0,
	.udt_dimm_row = 0x1000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DRAM Hole DFv3 4ch (5)",
	.udt_umc = &zen_umc_hole_dfv3,
	.udt_pa = 0x100000200,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x20000000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x0,
	.udt_dimm_row = 0x1000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DRAM Hole DFv3 4ch (6)",
	.udt_umc = &zen_umc_hole_dfv3,
	.udt_pa = 0x100000400,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x20000000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x0,
	.udt_dimm_row = 0x1000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DRAM Hole DFv3 4ch (7)",
	.udt_umc = &zen_umc_hole_dfv3,
	.udt_pa = 0x100000600,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x20000000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x0,
	.udt_dimm_row = 0x1000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DRAM Hole DFv4 4ch Shenanigans (0)",
	.udt_umc = &zen_umc_hole_dfv4,
	.udt_pa = 0x100000000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x3ffff000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x200,
	.udt_dimm_row = 0x1fff,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 3,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DRAM Hole DFv4 4ch Shenanigans (1)",
	.udt_umc = &zen_umc_hole_dfv4,
	.udt_pa = 0x100001000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x40000000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x0,
	.udt_dimm_row = 0x2000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DRAM Hole DFv4 4ch Shenanigans (2)",
	.udt_umc = &zen_umc_hole_dfv4,
	.udt_pa = 0x100002000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x40000000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x0,
	.udt_dimm_row = 0x2000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "DRAM Hole DFv4 4ch Shenanigans (3)",
	.udt_umc = &zen_umc_hole_dfv4,
	.udt_pa = 0x100003000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x40000000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x0,
	.udt_dimm_row = 0x2000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = NULL
} };
