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
 * This provides a simple case with one DIMM, one channel, one socket, and no
 * interleaving, and no DRAM hole. This sends everything to exactly one DIMM. In
 * particular we have configurations with the following DIMM sizes:
 *
 * o 16 GiB RDIMM (1 rank)
 * o 64 GiB RDIMM (2 rank)
 *
 * There is no hashing going on in the channel in any way here (e.g. no CS
 * interleaving). This is basically simple linear mappings.
 */

#include "zen_umc_test.h"

static const zen_umc_t zen_umc_basic_1p1c1d = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 16ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_df_rev = DF_REV_3,
	/* Per milan_decomp */
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
		.zud_ccm_inst = 0,
		.zud_dram_nrules = 1,
		.zud_nchan = 1,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 0,
			.ddr_limit = 16ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 1,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_1CH
		} },
		.zud_chan = { {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 1,
			.chan_instid = 1,
			.chan_logid = 0,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID,
				.ddr_base = 0,
				.ddr_limit = 16ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 1,
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

static const zen_umc_t zen_umc_basic_1p1c1d_64g = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 64ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_df_rev = DF_REV_3,
	/* Per milan_decomp */
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
		.zud_ccm_inst = 0,
		.zud_dram_nrules = 1,
		.zud_nchan = 1,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 0,
			.ddr_limit = 64ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 1,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_1CH
		} },
		.zud_chan = { {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 1,
			.chan_instid = 1,
			.chan_logid = 0,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID,
				.ddr_base = 0,
				.ddr_limit = 64ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 1,
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
					.ucs_flags = UMC_CS_F_DECODE_EN,
					.ucs_base = {
						.udb_base = 0,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0x7ffffffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x12,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x11,
					.ucs_bank_bits = { 0xf, 0x10, 0xd,
					    0xe },
					.ucs_col_bits = { 0x3, 0x4, 0x5, 0x6,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc }
				}, {
					.ucs_flags = UMC_CS_F_DECODE_EN,
					.ucs_base = {
						.udb_base = 0x800000000,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0x7ffffffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x12,
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

const umc_decode_test_t zen_umc_test_basics[] = { {
	.udt_desc = "decode basic single socket/channel/DIMM DDR4 (0)",
	.udt_umc = &zen_umc_basic_1p1c1d,
	.udt_pa = 0,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "decode basic single socket/channel/DIMM DDR4 (1)",
	.udt_umc = &zen_umc_basic_1p1c1d,
	.udt_pa = 0x123,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x123,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x24,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "decode basic single socket/channel/DIMM DDR4 (2)",
	.udt_umc = &zen_umc_basic_1p1c1d,
	.udt_pa = 0x5000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x5000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x200,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0x2,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "decode basic single socket/channel/DIMM DDR4 (3)",
	.udt_umc = &zen_umc_basic_1p1c1d,
	.udt_pa = 0x345678901,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x345678901,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x120,
	.udt_dimm_row = 0x1a2b3,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0x3,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "decode basic single socket/channel/DIMM DDR4 (4)",
	.udt_umc = &zen_umc_basic_1p1c1d,
	.udt_pa = 0x3ffffffff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x3ffffffff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3ff,
	.udt_dimm_row = 0x1ffff,
	.udt_dimm_bank = 0x3,
	.udt_dimm_bank_group = 0x3,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "single socket/channel/DIMM 2R DDR4 (0)",
	.udt_umc = &zen_umc_basic_1p1c1d_64g,
	.udt_pa = 0,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "single socket/channel/DIMM 2R DDR4 (1)",
	.udt_umc = &zen_umc_basic_1p1c1d_64g,
	.udt_pa = 0x800000000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x800000000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 1
}, {
	.udt_desc = "single socket/channel/DIMM 2R DDR4 (2)",
	.udt_umc = &zen_umc_basic_1p1c1d_64g,
	.udt_pa = 0x876543210,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x876543210,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x242,
	.udt_dimm_row = 0x3b2a,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 1
}, {
	.udt_desc = "single socket/channel/DIMM 2R DDR4 (3)",
	.udt_umc = &zen_umc_basic_1p1c1d_64g,
	.udt_pa = 0x076543210,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x076543210,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x242,
	.udt_dimm_row = 0x3b2a,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = NULL
} };
