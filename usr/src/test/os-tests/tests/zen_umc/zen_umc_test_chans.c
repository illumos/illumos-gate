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
 * Here we test several different channel related test cases. In particular, we
 * want to exercise the following situations:
 *
 *   o Multiple DIMMs per channel (no hashing)
 *   o Multiple DIMMs per channel (chip-select interleaving)
 *   o CS Hashing
 *   o Bank Hashing
 *   o Bank Swaps
 *   o Basic sub-channel
 *
 * For all of these, we don't do anything special from the Data Fabric to
 * strictly allow us to reason about the channel logic here.
 *
 * Currently, we do not have tests for the following because we don't have a
 * great sense of how the AMD SoC will set this up for the decoder:
 *
 *   o Cases where rank-multiplication and hashing are taking place
 *   o Cases where sub-channel hashing is being used
 */

#include "zen_umc_test.h"

/*
 * This has two of our favorite 64 GiB DIMMs. Everything is done out linearly.
 * Because of this, we don't apply any channel offsets.
 */
static const zen_umc_t zen_umc_chan_no_hash = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 128ULL * 1024ULL * 1024ULL * 1024ULL,
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
			.ddr_limit = 128ULL * 1024ULL * 1024ULL * 1024ULL,
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
				.ddr_limit = 128ULL * 1024ULL * 1024ULL *
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
		} }
	} }
};

/*
 * This is a variant on the prior where we begin to interleave across all 4
 * ranks in a channel, which AMD calls chip-select interleaving. This basically
 * uses bits in the middle of the address to select the rank and therefore
 * shifts all the other bits that get used for rank and bank selection. This
 * works by shifting which address bits are used to actually determine the row
 * up, allowing us to interleave in the middle of this.
 */
static const zen_umc_t zen_umc_chan_ilv = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 128ULL * 1024ULL * 1024ULL * 1024ULL,
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
			.ddr_limit = 128ULL * 1024ULL * 1024ULL * 1024ULL,
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
				.ddr_limit = 128ULL * 1024ULL * 1024ULL *
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
					.ucs_base_mask = 0x1ffff9ffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x12,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x13,
					.ucs_bank_bits = { 0xd, 0xe, 0xf,
					    0x10 },
					.ucs_col_bits = { 0x3, 0x4, 0x5, 0x6,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc }
				}, {
					.ucs_flags = UMC_CS_F_DECODE_EN,
					.ucs_base = {
						.udb_base = 0x20000,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0x1ffff9ffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x12,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x13,
					.ucs_bank_bits = { 0xd, 0xe, 0xf,
					    0x10 },
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
						.udb_base = 0x40000,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0x1ffff9ffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x12,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x13,
					.ucs_bank_bits = { 0xd, 0xe, 0xf,
					    0x10 },
					.ucs_col_bits = { 0x3, 0x4, 0x5, 0x6,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc }
				}, {
					.ucs_flags = UMC_CS_F_DECODE_EN,
					.ucs_base = {
						.udb_base = 0x60000,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0x1ffff9ffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x12,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x13,
					.ucs_bank_bits = { 0xd, 0xe, 0xf,
					    0x10 },
					.ucs_col_bits = { 0x3, 0x4, 0x5, 0x6,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc }
				} }
			} }
		} }
	} }
};

/*
 * This sets up a CS hash across all 4 ranks. The actual values here are
 * representative of a set up we've seen on the CPU.
 */
static const zen_umc_t zen_umc_chan_ilv_cs_hash = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 128ULL * 1024ULL * 1024ULL * 1024ULL,
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
			.ddr_limit = 128ULL * 1024ULL * 1024ULL * 1024ULL,
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
				.ddr_limit = 128ULL * 1024ULL * 1024ULL *
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
					.ucs_base_mask = 0x1ffff9ffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x12,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x13,
					.ucs_bank_bits = { 0xd, 0xe, 0xf,
					    0x10 },
					.ucs_col_bits = { 0x3, 0x4, 0x5, 0x6,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc }
				}, {
					.ucs_flags = UMC_CS_F_DECODE_EN,
					.ucs_base = {
						.udb_base = 0x20000,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0x1ffff9ffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x12,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x13,
					.ucs_bank_bits = { 0xd, 0xe, 0xf,
					    0x10 },
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
						.udb_base = 0x40000,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0x1ffff9ffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x12,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x13,
					.ucs_bank_bits = { 0xd, 0xe, 0xf,
					    0x10 },
					.ucs_col_bits = { 0x3, 0x4, 0x5, 0x6,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc }
				}, {
					.ucs_flags = UMC_CS_F_DECODE_EN,
					.ucs_base = {
						.udb_base = 0x60000,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0x1ffff9ffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x12,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x13,
					.ucs_bank_bits = { 0xd, 0xe, 0xf,
					    0x10 },
					.ucs_col_bits = { 0x3, 0x4, 0x5, 0x6,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc }
				} }
			} },
			.chan_hash = {
				.uch_flags = UMC_CHAN_HASH_F_CS,
				.uch_cs_hashes = { {
					.uah_addr_xor = 0xaaaa80000,
					.uah_en = B_TRUE
				}, {
					.uah_addr_xor = 0x1555500000,
					.uah_en = B_TRUE
				} }
			}
		} }
	} }
};

/*
 * This enables bank hashing across both of the DIMMs in this configuration. The
 * use of the row and not the column to select the bank is based on a CPU config
 * seen in the wild.
 */
static const zen_umc_t zen_umc_chan_ilv_bank_hash = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
	.umc_tom2 = 128ULL * 1024ULL * 1024ULL * 1024ULL,
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
			.ddr_limit = 128ULL * 1024ULL * 1024ULL * 1024ULL,
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
				.ddr_limit = 128ULL * 1024ULL * 1024ULL *
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
					.ucs_base_mask = 0x1ffff9ffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x12,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x13,
					.ucs_bank_bits = { 0xd, 0xe, 0xf,
					    0x10 },
					.ucs_col_bits = { 0x3, 0x4, 0x5, 0x6,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc }
				}, {
					.ucs_flags = UMC_CS_F_DECODE_EN,
					.ucs_base = {
						.udb_base = 0x20000,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0x1ffff9ffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x12,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x13,
					.ucs_bank_bits = { 0xd, 0xe, 0xf,
					    0x10 },
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
						.udb_base = 0x40000,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0x1ffff9ffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x12,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x13,
					.ucs_bank_bits = { 0xd, 0xe, 0xf,
					    0x10 },
					.ucs_col_bits = { 0x3, 0x4, 0x5, 0x6,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc }
				}, {
					.ucs_flags = UMC_CS_F_DECODE_EN,
					.ucs_base = {
						.udb_base = 0x60000,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0x1ffff9ffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x12,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x13,
					.ucs_bank_bits = { 0xd, 0xe, 0xf,
					    0x10 },
					.ucs_col_bits = { 0x3, 0x4, 0x5, 0x6,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc }
				} }
			} },
			.chan_hash = {
				.uch_flags = UMC_CHAN_HASH_F_BANK,
				.uch_bank_hashes = { {
					.ubh_row_xor = 0x11111,
					.ubh_col_xor = 0,
					.ubh_en = B_TRUE
				}, {
					.ubh_row_xor = 0x22222,
					.ubh_col_xor = 0,
					.ubh_en = B_TRUE
				}, {
					.ubh_row_xor = 0x4444,
					.ubh_col_xor = 0,
					.ubh_en = B_TRUE
				}, {
					.ubh_row_xor = 0x8888,
					.ubh_col_xor = 0,
					.ubh_en = B_TRUE
				} }
			}
		} }
	} }
};

/*
 * Some configurations allow optional bank swaps where by the bits we use for
 * the column and the bank are swapped around. Do one of these just to make sure
 * we haven't built in any surprise dependencies.
 */
static const zen_umc_t zen_umc_chan_ilv_bank_swap = {
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
			.ddr_limit = 128ULL * 1024ULL * 1024ULL * 1024ULL,
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
				.ddr_limit = 128ULL * 1024ULL * 1024ULL *
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
					.ucs_base_mask = 0x1ffff9ffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x12,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x13,
					.ucs_bank_bits = { 0x9, 0xa, 0x6,
					    0xb },
					.ucs_col_bits = { 0x3, 0x4, 0x5, 0x7,
					    0x8, 0xc, 0xd, 0xe, 0xf, 0x10 }
				}, {
					.ucs_flags = UMC_CS_F_DECODE_EN,
					.ucs_base = {
						.udb_base = 0x20000,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0x1ffff9ffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x12,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x13,
					.ucs_bank_bits = { 0x9, 0xa, 0x6,
					    0xb },
					.ucs_col_bits = { 0x3, 0x4, 0x5, 0x7,
					    0x8, 0xc, 0xd, 0xe, 0xf, 0x10 }
				} }
			}, {
				.ud_flags = UMC_DIMM_F_VALID,
				.ud_width = UMC_DIMM_W_X4,
				.ud_kind = UMC_DIMM_K_RDIMM,
				.ud_dimmno = 1,
				.ud_cs = { {
					.ucs_flags = UMC_CS_F_DECODE_EN,
					.ucs_base = {
						.udb_base = 0x40000,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0x1ffff9ffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x12,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x13,
					.ucs_bank_bits = { 0x9, 0xa, 0x6,
					    0xb },
					.ucs_col_bits = { 0x3, 0x4, 0x5, 0x7,
					    0x8, 0xc, 0xd, 0xe, 0xf, 0x10 }
				}, {
					.ucs_flags = UMC_CS_F_DECODE_EN,
					.ucs_base = {
						.udb_base = 0x60000,
						.udb_valid = B_TRUE
					},
					.ucs_base_mask = 0x1ffff9ffff,
					.ucs_nbanks = 0x4,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x12,
					.ucs_nbank_groups = 0x2,
					.ucs_row_hi_bit = 0x18,
					.ucs_row_low_bit = 0x13,
					.ucs_bank_bits = { 0x9, 0xa, 0x6,
					    0xb },
					.ucs_col_bits = { 0x3, 0x4, 0x5, 0x7,
					    0x8, 0xc, 0xd, 0xe, 0xf, 0x10 }
				} }
			} }
		} }
	} }
};

/*
 * This is a basic DDR5 channel. We only use a single DIMM and set up a
 * sub-channel on it.
 */
static const zen_umc_t zen_umc_chan_subchan_no_hash = {
	.umc_tom = 4ULL * 1024ULL * 1024ULL * 1024ULL,
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
			.chan_type = UMC_DIMM_T_DDR5,
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
					.ucs_nbanks = 0x5,
					.ucs_ncol = 0xa,
					.ucs_nrow_lo = 0x10,
					.ucs_nbank_groups = 0x3,
					.ucs_row_low_bit = 0x12,
					.ucs_bank_bits = { 0xf, 0x10, 0x11,
					    0xd, 0xe },
					.ucs_col_bits = { 0x2, 0x3, 0x4, 0x5,
					    0x7, 0x8, 0x9, 0xa, 0xb, 0xc },
					.ucs_subchan = 0x6
				} }
			} }
		} }
	} }
};

const umc_decode_test_t zen_umc_test_chans[] = { {
	.udt_desc = "2 DPC 2R no ilv/hash (0)",
	.udt_umc = &zen_umc_chan_no_hash,
	.udt_pa = 0x0,
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
	.udt_desc = "2 DPC 2R no ilv/hash (1)",
	.udt_umc = &zen_umc_chan_no_hash,
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
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 1
}, {
	.udt_desc = "2 DPC 2R no ilv/hash (2)",
	.udt_umc = &zen_umc_chan_no_hash,
	.udt_pa = 0x1000000000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1000000000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 1,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R no ilv/hash (3)",
	.udt_umc = &zen_umc_chan_no_hash,
	.udt_pa = 0x1800000000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1800000000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 1,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 1
}, {
	.udt_desc = "2 DPC 2R no ilv/hash (4)",
	.udt_umc = &zen_umc_chan_no_hash,
	.udt_pa = 0x0ff1ff120,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x0ff1ff120,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x224,
	.udt_dimm_row = 0x7f8f,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 3,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R no ilv/hash (5)",
	.udt_umc = &zen_umc_chan_no_hash,
	.udt_pa = 0x8ff4ff500,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x8ff4ff500,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x2a0,
	.udt_dimm_row = 0x7fa7,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 3,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 1
}, {
	.udt_desc = "2 DPC 2R no ilv/hash (6)",
	.udt_umc = &zen_umc_chan_no_hash,
	.udt_pa = 0x10ff6ff700,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x10ff6ff700,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 1,
	.udt_dimm_col = 0x2e0,
	.udt_dimm_row = 0x7fb7,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 3,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R no ilv/hash (7)",
	.udt_umc = &zen_umc_chan_no_hash,
	.udt_pa = 0x18ff8ff102,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x18ff8ff102,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 1,
	.udt_dimm_col = 0x220,
	.udt_dimm_row = 0x7fc7,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 3,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 1
}, {
	.udt_desc = "2 DPC 2R no hash, rank ilv (0)",
	.udt_umc = &zen_umc_chan_ilv,
	.udt_pa = 0x0,
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
	.udt_desc = "2 DPC 2R no hash, rank ilv (1)",
	.udt_umc = &zen_umc_chan_ilv,
	.udt_pa = 0x20000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x20000,
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
	.udt_dimm_cs = 1
}, {
	.udt_desc = "2 DPC 2R no hash, rank ilv (2)",
	.udt_umc = &zen_umc_chan_ilv,
	.udt_pa = 0x40000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x40000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 1,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R no hash, rank ilv (3)",
	.udt_umc = &zen_umc_chan_ilv,
	.udt_pa = 0x60000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x60000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 1,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 1
}, {
	.udt_desc = "2 DPC 2R no hash, rank ilv (4)",
	.udt_umc = &zen_umc_chan_ilv,
	.udt_pa = 0xe1be12e00,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xe1be12e00,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x1c0,
	.udt_dimm_row = 0x1c37c,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R no hash, rank ilv (5)",
	.udt_umc = &zen_umc_chan_ilv,
	.udt_pa = 0x1fffffffff,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1fffffffff,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 1,
	.udt_dimm_col = 0x3ff,
	.udt_dimm_row = 0x3ffff,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 3,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 1
},
/*
 * Test the CS hashing by first going back and using bits that aren't part of
 * the CS hash modification, e.g. the same 4 interleaving case that we hit
 * earlier. Next, we go through and tweak things that would normally go to a
 * given CS originally by tweaking the bits that would be used in a hash and
 * prove that they go elsewhere.
 */
{
	.udt_desc = "2 DPC 2R cs hash, rank ilv (0)",
	.udt_umc = &zen_umc_chan_ilv_cs_hash,
	.udt_pa = 0x0,
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
	.udt_desc = "2 DPC 2R cs hash, rank ilv (1)",
	.udt_umc = &zen_umc_chan_ilv_cs_hash,
	.udt_pa = 0x20000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x20000,
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
	.udt_dimm_cs = 1
}, {
	.udt_desc = "2 DPC 2R cs hash, rank ilv (2)",
	.udt_umc = &zen_umc_chan_ilv_cs_hash,
	.udt_pa = 0x40000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x40000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 1,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R cs hash, rank ilv (3)",
	.udt_umc = &zen_umc_chan_ilv_cs_hash,
	.udt_pa = 0x60000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x60000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 1,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 1
}, {
	.udt_desc = "2 DPC 2R cs hash, rank ilv (4)",
	.udt_umc = &zen_umc_chan_ilv_cs_hash,
	.udt_pa = 0x80000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x80000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 1,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 1
}, {
	.udt_desc = "2 DPC 2R cs hash, rank ilv (5)",
	.udt_umc = &zen_umc_chan_ilv_cs_hash,
	.udt_pa = 0x180000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x180000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 1,
	.udt_dimm_col = 0,
	.udt_dimm_row = 3,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 1
}, {
	.udt_desc = "2 DPC 2R cs hash, rank ilv (6)",
	.udt_umc = &zen_umc_chan_ilv_cs_hash,
	.udt_pa = 0x100000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x100000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 1,
	.udt_dimm_col = 0,
	.udt_dimm_row = 2,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R cs hash, rank ilv (7)",
	.udt_umc = &zen_umc_chan_ilv_cs_hash,
	.udt_pa = 0x18180000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x18180000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0x303,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R cs hash, rank ilv (8)",
	.udt_umc = &zen_umc_chan_ilv_cs_hash,
	.udt_pa = 0x181a0000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x181a0000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0x303,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 1
}, {
	.udt_desc = "2 DPC 2R cs hash, rank ilv (9)",
	.udt_umc = &zen_umc_chan_ilv_cs_hash,
	.udt_pa = 0x181c0000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x181c0000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 1,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0x303,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R cs hash, rank ilv (10)",
	.udt_umc = &zen_umc_chan_ilv_cs_hash,
	.udt_pa = 0x181e0000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x181e0000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 1,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0x303,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 1
},
/*
 * For the bank hash we first prove that we can target a given row/column in
 * each bank and bank group without hashing (this leads to a total of 16
 * combinations). We then later go back and start tweaking the row/column to
 * change which bank and group we end up in.
 */
{
	.udt_desc = "2 DPC 2R bank hash, rank ilv (0)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0x0,
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
	.udt_desc = "2 DPC 2R bank hash, rank ilv (1)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0x8000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x8000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank hash, rank ilv (2)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0x10000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x10000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank hash, rank ilv (3)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0x18000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x18000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank hash, rank ilv (4)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0x2000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x2000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank hash, rank ilv (5)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0xa000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xa000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank hash, rank ilv (6)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0x12000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x12000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank hash, rank ilv (7)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0x1a000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1a000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank hash, rank ilv (8)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0x4000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x4000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 2,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank hash, rank ilv (9)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0xc000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xc000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 2,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank hash, rank ilv (10)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0x14000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x14000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 2,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank hash, rank ilv (11)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0x1c000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1c000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 2,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank hash, rank ilv (12)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0x6000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x6000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 3,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank hash, rank ilv (13)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0xe000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xe000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 3,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank hash, rank ilv (14)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0x16000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x16000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 2,
	.udt_dimm_bank_group = 3,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank hash, rank ilv (15)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0x1e000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x1e000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 3,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank hash, rank ilv (16)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0x79c000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x79c000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0xf,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank hash, rank ilv (17)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0x7f9c000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x7f9c000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0xff,
	.udt_dimm_bank = 3,
	.udt_dimm_bank_group = 2,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank hash, rank ilv (18)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0x7ff9c000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x7ff9c000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0xfff,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank hash, rank ilv (19)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0x71c000,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x71c000,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0,
	.udt_dimm_row = 0xe,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank hash, rank ilv (20)",
	.udt_umc = &zen_umc_chan_ilv_bank_hash,
	.udt_pa = 0x71c118,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x71c118,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x23,
	.udt_dimm_row = 0xe,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
},
/*
 * Bank swapping. We basically do a few sanity tests on this just to make sure
 * the right bits are triggering things here in the first DIMM/rank.
 */
{
	.udt_desc = "2 DPC 2R bank swap, rank ilv (0)",
	.udt_umc = &zen_umc_chan_ilv_bank_swap,
	.udt_pa = 0x4247,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x4247,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x80,
	.udt_dimm_row = 0,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "2 DPC 2R bank swap, rank ilv (1)",
	.udt_umc = &zen_umc_chan_ilv_bank_swap,
	.udt_pa = 0xff6214247,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0xff6214247,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x280,
	.udt_dimm_row = 0x1fec4,
	.udt_dimm_bank = 1,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = UINT8_MAX,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "Basic DDR5 Sub-channel (0)",
	.udt_umc = &zen_umc_chan_subchan_no_hash,
	.udt_pa = 0x0,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x0,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x0,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 0,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "Basic DDR5 Sub-channel (1)",
	.udt_umc = &zen_umc_chan_subchan_no_hash,
	.udt_pa = 0x9999,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x9999,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x336,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = 0,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = "Basic DDR5 Sub-channel (2)",
	.udt_umc = &zen_umc_chan_subchan_no_hash,
	.udt_pa = 0x99d9,
	.udt_pass = B_TRUE,
	.udt_norm_addr = 0x99d9,
	.udt_sock = 0,
	.udt_die = 0,
	.udt_comp = 1,
	.udt_dimm_no = 0,
	.udt_dimm_col = 0x336,
	.udt_dimm_row = 0x0,
	.udt_dimm_bank = 0,
	.udt_dimm_bank_group = 1,
	.udt_dimm_subchan = 1,
	.udt_dimm_rm = 0,
	.udt_dimm_cs = 0
}, {
	.udt_desc = NULL
} };
