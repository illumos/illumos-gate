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
 * Here we try to test a few variants of the Zen 3 COD based hashing, including
 * our favorite 6 channel. These all use DFv3 and 1 DPC 16 GiB channels without
 * any internal hashing (that is tested elsewhere).
 */

#include "zen_umc_test.h"

/*
 * This is a basic 4-channel hash, sending us out to one of four locations. This
 * enables hashing in all three regions because 6 channel variant does not seem
 * to use them.
 */
static const zen_umc_t zen_umc_cod_4ch = {
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
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HASH_16_18 |
			    DF_DRAM_F_HASH_21_23 | DF_DRAM_F_HASH_30_32,
			.ddr_base = 0,
			.ddr_limit = 64ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 9,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_COD2_4CH
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
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 64ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_COD2_4CH
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
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 1,
			.chan_instid = 1,
			.chan_logid = 1,
			.chan_nrules = 1,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 64ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_COD2_4CH
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
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 2,
			.chan_instid = 2,
			.chan_logid = 2,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 64ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_COD2_4CH
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
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 3,
			.chan_instid = 3,
			.chan_logid = 3,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_16_18 |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 64ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 9,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_COD2_4CH
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
		}  }
	} }
};

static const zen_umc_t zen_umc_cod_6ch = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 96ULL * 1024ULL * 1024ULL * 1024ULL,
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
		.zud_nchan = 6,
		.zud_cs_nremap = 0,
		.zud_hole_base = 0,
		.zud_rules = { {
			.ddr_flags = DF_DRAM_F_VALID | DF_DRAM_F_HASH_21_23 |
			    DF_DRAM_F_HASH_30_32,
			.ddr_base = 0,
			.ddr_limit = 96ULL * 1024ULL * 1024ULL * 1024ULL,
			.ddr_dest_fabid = 0,
			.ddr_sock_ileave_bits = 0,
			.ddr_die_ileave_bits = 0,
			.ddr_addr_start = 12,
			.ddr_chan_ileave = DF_CHAN_ILEAVE_6CH
		} },
		.zud_chan = { {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 0,
			.chan_instid = 0,
			.chan_logid = 0,
			.chan_nrules = 1,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_np2_space0 = 21,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 12,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_6CH
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
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 1,
			.chan_instid = 1,
			.chan_logid = 1,
			.chan_nrules = 1,
			.chan_np2_space0 = 21,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 12,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_6CH
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
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 2,
			.chan_instid = 2,
			.chan_logid = 2,
			.chan_nrules = 1,
			.chan_np2_space0 = 21,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 12,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_6CH
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
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 3,
			.chan_instid = 3,
			.chan_logid = 3,
			.chan_nrules = 1,
			.chan_np2_space0 = 21,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 12,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_6CH
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
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 4,
			.chan_instid = 4,
			.chan_logid = 4,
			.chan_nrules = 1,
			.chan_np2_space0 = 21,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 12,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_6CH
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
		}, {
			.chan_flags = UMC_CHAN_F_ECC_EN,
			.chan_fabid = 5,
			.chan_instid = 5,
			.chan_logid = 5,
			.chan_nrules = 1,
			.chan_np2_space0 = 21,
			.chan_type = UMC_DIMM_T_DDR4,
			.chan_rules = { {
				.ddr_flags = DF_DRAM_F_VALID |
				    DF_DRAM_F_HASH_21_23 |
				    DF_DRAM_F_HASH_30_32,
				.ddr_base = 0,
				.ddr_limit = 96ULL * 1024ULL * 1024ULL *
				    1024ULL,
				.ddr_dest_fabid = 0,
				.ddr_sock_ileave_bits = 0,
				.ddr_die_ileave_bits = 0,
				.ddr_addr_start = 12,
				.ddr_chan_ileave = DF_CHAN_ILEAVE_6CH
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
		}  }
	} }
};

const umc_decode_test_t zen_umc_test_cod[] = { {
	.udt_desc = "COD 4ch (0)",
	.udt_umc = &zen_umc_cod_4ch,
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
	.udt_desc = "COD 4ch (1)",
	.udt_umc = &zen_umc_cod_4ch,
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
},  {
	.udt_desc = "COD 4ch (2)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0x11ff,
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
	.udt_desc = "COD 4ch (3)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0x13ff,
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
	.udt_desc = "COD 4ch (4)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0x101ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x41ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 4ch (5)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0x103ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x41ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 4ch (6)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0x303ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xc1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 4ch (7)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0x313ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xc1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 4ch (8)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0x311ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xc1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 4ch (9)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0x2311ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x8c1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0x4,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 4ch (10)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0x6311ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x18c1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0xc,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 4ch (11)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0x6313ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x18c1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0xc,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 4ch (12)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0x6303ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x18c1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0xc,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 4ch (13)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0x6301ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x18c1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0xc,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 4ch (14)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0x406301ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1018c1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0x80c,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 4ch (15)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0x406303ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1018c1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0x80c,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 4ch (16)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0x406311ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1018c1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0x80c,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 4ch (17)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0x406313ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1018c1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0x80c,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 4ch (18)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0xc06313ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x3018c1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0x180c,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 4ch (19)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0xc06311ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x3018c1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0x180c,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 4ch (20)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0xc06301ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x3018c1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0x180c,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 4ch (21)",
	.udt_umc = &zen_umc_cod_4ch,
	.udt_pa = 0xc06303ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x3018c1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0x180c,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 6ch (0)",
	.udt_umc = &zen_umc_cod_6ch,
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
	.udt_desc = "COD 6ch (1)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0x11ff,
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
	.udt_desc = "COD 6ch (2)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0x21ff,
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
	.udt_desc = "COD 6ch (3)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0x31ff,
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
	.udt_desc = "COD 6ch (4)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0x41ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 6ch (5)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0x51ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 5,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 6ch (6)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0x61ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x3000001ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0x18000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 6ch (7)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0x71ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x3000001ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0x18000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 6ch (8)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0x81ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x11ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x23f,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 6ch (9)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0x91ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x11ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 0,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x23f,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 6ch (10)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0xa1ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x11ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x23f,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 6ch (11)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0xb1ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x11ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x23f,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 6ch (12)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0xc1ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x11ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 5,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x23f,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 6ch (13)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0xd1ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x11ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x23f,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 6ch (14)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0xe1ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x3000011ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x23f,
	.udt_dimm_row = 0x18000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 6ch (15)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0xf1ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x3000011ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x23f,
	.udt_dimm_row = 0x18000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
},
/*
 * The above went through and showed that we can probably hash things correctly
 * and account for our mod-3 case. The ones below try to find the higher level
 * addresses that would result in the same normalized address that we have, but
 * on different dies to try and complete the set.
 */
{
	.udt_desc = "COD 6ch (16)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0x8000061ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x3000001ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0x18000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 6ch (17)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0x8000071ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x3000001ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0x18000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 6ch (18)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0x10000061ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x3000001ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0x18000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 6ch (19)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0x10000071ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x3000001ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 5,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0x18000,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
},
/*
 * Now with that there, we go back and show that hashing actually impacts things
 * as we expect. Note, the bit 0 hash was already taken into account.
 */
{
	.udt_desc = "COD 6ch (20)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0x8001ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1001ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0x8,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 6ch (21)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0xa001ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1401ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0xa,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 6ch (22)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0xe001ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x3001c01ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 3,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0x1800e,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 6ch (23)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0x180e001ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x301c01ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 2,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0x180e,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "COD 6ch (24)",
	.udt_umc = &zen_umc_cod_6ch,
	.udt_pa = 0x1c0e041ff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x381c01ff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 4,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x3f,
	.udt_dimm_row = 0x1c0e,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = NULL
} };
