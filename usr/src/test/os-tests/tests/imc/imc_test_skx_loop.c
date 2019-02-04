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
 * Verify that we properly detect loops on Skylake based multi-socket systems.
 * This represents an erroneous condition.
 */

/*
 * This is a multi-socket bare bones Skylake structure (we don't bother with
 * anything past the SAD as we should never need it. This checks to make sure
 * that we detect such a loop.
 */
static const imc_t imc_skx_loop_2s = {
	.imc_gen = IMC_GEN_SKYLAKE,
	.imc_nsockets = 2,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,
			.isad_tohm = 0,
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 1, 1, 1, 1, 1, 1, 1, 1 }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 },
			}
		}
	},
	.imc_sockets[1] = {
		.isock_nodeid = 1,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,
			.isad_tohm = 0,
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 },
			}
		}
	}
};

/*
 * This has a target that causes us to loop back to ourselves.
 */
static const imc_t imc_skx_loop_self = {
	.imc_gen = IMC_GEN_SKYLAKE,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,
			.isad_tohm = 0,
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 },
			}
		}
	}
};

/*
 * This referes to a non-existant socket in the search loop.
 */
static const imc_t imc_skx_loop_badsock = {
	.imc_gen = IMC_GEN_SKYLAKE,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,
			.isad_tohm = 0,
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 5, 5, 5, 5, 5, 5, 5, 5 }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 },
			}
		}
	}
};

const imc_test_case_t imc_test_skx_loop[] = { {
	.itc_desc = "Skylake loop detection, 2s (1)",
	.itc_imc = &imc_skx_loop_2s,
	.itc_pa = 0x0,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_SAD_SEARCH_LOOP
}, {
	.itc_desc = "Skylake loop detection, 2s (2)",
	.itc_imc = &imc_skx_loop_2s,
	.itc_pa = 0x7fffffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_SAD_SEARCH_LOOP
}, {
	.itc_desc = "Skylake loop detection, self (1)",
	.itc_imc = &imc_skx_loop_self,
	.itc_pa = 0x0,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_SAD_SEARCH_LOOP
}, {
	.itc_desc = "Skylake loop detection, self (2)",
	.itc_imc = &imc_skx_loop_self,
	.itc_pa = 0x7fffffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_SAD_SEARCH_LOOP
}, {
	.itc_desc = "Skylake loop detection, bad sock (1)",
	.itc_imc = &imc_skx_loop_badsock,
	.itc_pa = 0x0,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_REMOTE_MC_ROUTE
}, {
	.itc_desc = "Skylake loop detection, bad sock (2)",
	.itc_imc = &imc_skx_loop_badsock,
	.itc_pa = 0x7fffffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_REMOTE_MC_ROUTE
}, {
	.itc_desc = NULL
} };
