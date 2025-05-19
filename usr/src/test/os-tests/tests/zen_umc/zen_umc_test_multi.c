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
 * Here we construct a more realistic DF situation where we have multiple rules.
 * In particular, we use a DFv3 style configuration with a single die and
 * socket. To make sense of the channel offset logic, we construct a system with
 * two channels, one with 64 GiB and one one 8 GiB DIMMs. We basically
 * interleave with the 16 GiB channel over the last 16 GiB of the 128 GiB
 * channel. This requires us to therefore use the channel offset for the first
 * channel to get it in a reasonable spot for the second rule. This also allows
 * us to test what happens with multiple rules and ensure that we select the
 * right one and when two rules map to one channel.
 *
 * Here, the hole is sized to 1.75 GiB. This is based on a system we saw that
 * was set up this way.
 */

#include "zen_umc_test.h"

static const zen_umc_t zen_umc_multi = {
	.umc_tom = 0x90000000,
	.umc_tom2 = 0x2470000000,
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
		.zud_nchan = 4,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0x90000000,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HOLE,
			.ddr_base = 0,
			.ddr_limit = 0x1c70000000,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 8,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_1CH
		}, {
			.ddr_flags = DF_DRAM_F_VALID,
			.ddr_base = 0x1c70000000,
			.ddr_limit = 0x2470000000,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 8,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
		} },
		.zud_chan = { {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0,
			.chan_instid = 0,
			.chan_logid = 0,
			.chan_nrules = 2,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HOLE,
				.ddr_base = 0,
				.ddr_limit = 0x1c70000000,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_1CH
			}, {
				.ddr_flags = DF_DRAM_F_VALID,
				.ddr_base = 0x1c70000000,
				.ddr_limit = 0x2470000000,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
			} },
			.chan_offsets = { {
				.cho_valid = B_TRUE,
				.cho_offset = 0x1c00000000,
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
			}, {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 1,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
					.ucs_base = {
						.udb_base = 0x1000000000,
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
						.udb_base = 0x1800000000,
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
				.ddr_base = 0x1c70000000,
				.ddr_limit = 0x2470000000,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 8,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_2CH
			} },
			.chan_dimms = { {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X8,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
					.ucs_base = {
						.udb_base = 0,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0x3fffdffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x11,
					.ucs_bank_bits = { 0xf, 0x10, 0xd,
					    0xe },
					.ucs_col_bits = { 0x3, 0x4, 0x5, 0x6,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc }
				} }
			}, {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X8,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 0,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
					.ucs_base = {
						.udb_base = 0x20000,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0x3fffdffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
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

const umc_decode_test_t zen_umc_test_multi[] = { {
	.udt_desc = "Multi-rule (0)",
	.udt_umc = &zen_umc_multi,
	.udt_pa = 0x12345603,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x12345603,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x2c0,
	.udt_dimm_row = 0x91a,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0

}, {
	.udt_desc = "Multi-rule (1)",
	.udt_umc = &zen_umc_multi,
	.udt_pa = 0x12345703,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x12345703,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x2e0,
	.udt_dimm_row = 0x91a,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0

}, {
	.udt_desc = "Multi-rule (2)",
	.udt_umc = &zen_umc_multi,
	.udt_pa = 0x1ba9876543,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1b39876543,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 1,
	.udt_dimm_col = 0xa8,
	.udt_dimm_row = 0x19cc3,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 2,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 1

}, {
	.udt_desc = "Multi-rule (3)",
	.udt_umc = &zen_umc_multi,
	.udt_pa = 0x1ba9876643,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1b39876643,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 1,
	.udt_dimm_col = 0xc8,
	.udt_dimm_row = 0x19cc3,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 2,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 1
},
/*
 * All of the accesses below should now hit our second rule. When normalizing we
 * subtract the base and add the channel offset. So that is why the normalized
 * address will look totally different depending on which DIMM we go to.
 */
{
	.udt_desc = "Multi-rule (4)",
	.udt_umc = &zen_umc_multi,
	.udt_pa = 0x1c70000000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1c00000000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 1,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0x20000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 1
}, {
	.udt_desc = "Multi-rule (5)",
	.udt_umc = &zen_umc_multi,
	.udt_pa = 0x1c70000100,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x0,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "Multi-rule (6)",
	.udt_umc = &zen_umc_multi,
	.udt_pa = 0x23456789ab,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x36ab3c4ab,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 1,
	.udt_dimm_col = 0x95,
	.udt_dimm_row = 0xb559,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 3,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "Multi-rule (7)",
	.udt_umc = &zen_umc_multi,
	.udt_pa = 0x2345678aab,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1f6ab3c5ab,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 1,
	.udt_dimm_col = 0xb5,
	.udt_dimm_row = 0x3b559,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 3,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 1
}, {
	.udt_desc = NULL
} };
