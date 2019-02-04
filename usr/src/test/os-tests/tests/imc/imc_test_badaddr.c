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
 * Copyright 2019 Joyent, Inc.
 */

#include "imc_test.h"

/*
 * This file does a bunch of tests to make sure that we correctly handle cases
 * where we're asked to decode the following types of addresses:
 *
 *   - Legacy Reserved Addresses
 *   - Between TOLM, TOHM
 *   - Above TOHM
 */

/*
 * This IMC represents a basic case where we have a single 8 GiB dual rank DIMM.
 * We have system memory in the lower 2 GiB and then the remaining 6 GiB starts
 * at the bottom of high memory (4 GiB).
 */
static const imc_t imc_badaddr = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,	/* 2 GiB */
			.isad_tohm = 0x280000000ULL,	/* 10 GiB */
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 1,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			},
			.itad_rules[1] = {
				.itr_base = 0x80000000,
				.itr_limit = 0x280000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 1,
		.isock_imcs[0] = {
			.icn_nchannels = 1,
			.icn_dimm_type = IMC_DIMM_DDR3,
			.icn_ecc = B_TRUE,
			.icn_lockstep = B_FALSE,
			.icn_closed = B_FALSE,
			.icn_channels[0] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x80000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0x80000000, 0, 0, 0, 0,
				    0, 0, 0, 0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 2,
					.irle_nwaysbits = 1,
					.irle_limit = 0x200000000ULL,
					.irle_nentries = 5,
					.irle_entries[0] = { 0x0, 0x0 },
					.irle_entries[1] = { 0x1, 0x0 }
				}
			}
		}
	}
};

const imc_test_case_t imc_test_badaddr[] = { {
	.itc_desc = "Bad Address, legacy VGA (1)",
	.itc_imc = &imc_badaddr,
	.itc_pa = 0xa0000,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_LEGACY_RANGE
}, {
	.itc_desc = "Bad Address, legacy VGA (2)",
	.itc_imc = &imc_badaddr,
	.itc_pa = 0xbffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_LEGACY_RANGE
}, {
	.itc_desc = "Bad Address, legacy VGA (3)",
	.itc_imc = &imc_badaddr,
	.itc_pa = 0xafc89,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_LEGACY_RANGE
}, {
	.itc_desc = "Bad Address, legacy PAM (1)",
	.itc_imc = &imc_badaddr,
	.itc_pa = 0xc0000,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_LEGACY_RANGE
}, {
	.itc_desc = "Bad Address, legacy PAM (2)",
	.itc_imc = &imc_badaddr,
	.itc_pa = 0xfffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_LEGACY_RANGE
}, {
	.itc_desc = "Bad Address, Reserved (1)",
	.itc_imc = &imc_badaddr,
	.itc_pa = 0xffffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_LEGACY_RANGE
},  {
	.itc_desc = "Bad Address, Reserved (1)",
	.itc_imc = &imc_badaddr,
	.itc_pa = 0xffffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_LEGACY_RANGE
}, {
	.itc_desc = "Bad Address, System (1)",
	.itc_imc = &imc_badaddr,
	.itc_pa = 0x00fe000000,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_LEGACY_RANGE
}, {
	.itc_desc = "Bad Address, System (2)",
	.itc_imc = &imc_badaddr,
	.itc_pa = 0x00fe123446,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_LEGACY_RANGE
}, {
	.itc_desc = "Bad Address, System (3)",
	.itc_imc = &imc_badaddr,
	.itc_pa = 0x00ff000000,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_LEGACY_RANGE
}, {
	.itc_desc = "Bad Address, System (4)",
	.itc_imc = &imc_badaddr,
	.itc_pa = 0x00ffffffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_LEGACY_RANGE
}, {
	.itc_desc = "Bad Address, System (5)",
	.itc_imc = &imc_badaddr,
	.itc_pa = 0x00ff5abc32,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_LEGACY_RANGE
}, {
	.itc_desc = "Outside TOLM (1)",
	.itc_imc = &imc_badaddr,
	.itc_pa = 0x80000000,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_OUTSIDE_DRAM
}, {
	.itc_desc = "Outside TOLM (2)",
	.itc_imc = &imc_badaddr,
	.itc_pa = 0xF0000000,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_OUTSIDE_DRAM
}, {
	.itc_desc = "Outside TOLM (3)",
	.itc_imc = &imc_badaddr,
	.itc_pa = 0xfdffffffULL,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_OUTSIDE_DRAM
}, {
	.itc_desc = "Outside TOHM (1)",
	.itc_imc = &imc_badaddr,
	.itc_pa = 0x280000000ULL,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_OUTSIDE_DRAM
}, {
	.itc_desc = "Outside TOHM (2)",
	.itc_imc = &imc_badaddr,
	.itc_pa = UINT64_MAX,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_OUTSIDE_DRAM
}, {
	.itc_desc = "Outside TOHM (1)",
	.itc_imc = &imc_badaddr,
	.itc_pa = 0x1280000000ULL,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_OUTSIDE_DRAM
}, {
	.itc_desc = NULL
} };
