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
 * This represents a basic configuration with a single socket, channel, and
 * DIMM that is 2 GiB in size. This entirely punts on the fact that the legacy
 * ranges overlap here.
 */
static const imc_t imc_basic_snb = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,
			.isad_tohm = 0,
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
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
			}
		},
		.isock_nimc = 1,
		.isock_imcs[0] = {
			.icn_nchannels = 1,
			.icn_dimm_type = IMC_DIMM_DDR3,
			.icn_ecc = B_TRUE,
			.icn_lockstep = B_FALSE,
			.icn_closed = B_TRUE,
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
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 2,
					.irle_nwaysbits = 1,
					.irle_limit = 0x80000000,
					.irle_nentries = 5,
					.irle_entries[0] = { 0x0, 0x0 },
					.irle_entries[1] = { 0x1, 0x0 }
				}
			}
		}
	}
};

const imc_test_case_t imc_test_basics[] = { {
	.itc_desc = "decode basic single socket/channel/DIMM, dual rank (1)",
	.itc_imc = &imc_basic_snb,
	.itc_pa = 0x0,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0
}, {
	.itc_desc = "decode basic single socket/channel/DIMM, dual rank (2)",
	.itc_imc = &imc_basic_snb,
	.itc_pa = 0x1000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x1000,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x800
}, {
	.itc_desc = "decode basic single socket/channel/DIMM, dual rank (3)",
	.itc_imc = &imc_basic_snb,
	.itc_pa = 0x7fffffff,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x7fffffff,
	.itc_dimmid = 0,
	.itc_rankid = 1,
	.itc_rankaddr = 0x3fffffff,
}, {
	.itc_desc = NULL
} };
