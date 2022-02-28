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
 * Copyright 2022 Oxide Computer Company
 */

/*
 * Test basic fabric ID composition and decomposition across a couple of
 * different styles of fabric decomposition schemes.
 */

#include "zen_umc_test.h"

const df_fabric_decomp_t naples_decomp_cpu = {
	.dfd_sock_mask = 0x04,
	.dfd_die_mask = 0x03,
	.dfd_node_mask = 0xe0,
	.dfd_comp_mask = 0x07,
	.dfd_sock_shift = 2,
	.dfd_die_shift = 0,
	.dfd_node_shift = 5,
	.dfd_comp_shift = 0
};

const df_fabric_decomp_t naples_decomp_apu = {
	.dfd_sock_mask = 0x0,
	.dfd_die_mask = 0x0,
	.dfd_node_mask = 0x0,
	.dfd_comp_mask = 0xf,
	.dfd_sock_shift = 0,
	.dfd_die_shift = 0,
	.dfd_node_shift = 0,
	.dfd_comp_shift = 0
};

const df_fabric_decomp_t milan_decomp = {
	.dfd_sock_mask = 0x01,
	.dfd_die_mask = 0x00,
	.dfd_node_mask = 0x20,
	.dfd_comp_mask = 0x1f,
	.dfd_sock_shift = 0,
	.dfd_die_shift = 0,
	.dfd_node_shift = 5,
	.dfd_comp_shift = 0
};

static const df_fabric_decomp_t contig_decomp = {
	.dfd_sock_mask = 0x1c,
	.dfd_die_mask = 0x3,
	.dfd_node_mask = 0xf80,
	.dfd_comp_mask = 0x07f,
	.dfd_sock_shift = 2,
	.dfd_die_shift = 0,
	.dfd_node_shift = 7,
	.dfd_comp_shift = 0
};

const umc_fabric_test_t zen_umc_test_fabric_ids[] = { {
	.uft_desc = "Naples CPU (0)",
	.uft_decomp = &naples_decomp_cpu,
	.uft_compose = B_FALSE,
	.uft_valid = B_TRUE,
	.uft_fabric_id = 0,
	.uft_sock_id = 0,
	.uft_die_id = 0,
	.uft_comp_id = 0
}, {
	.uft_desc = "Naples CPU Socket 1 (0)",
	.uft_decomp = &naples_decomp_cpu,
	.uft_compose = B_TRUE,
	.uft_valid = B_TRUE,
	.uft_fabric_id = 0x81,
	.uft_sock_id = 1,
	.uft_die_id = 0,
	.uft_comp_id = 1
}, {
	.uft_desc = "Naples CPU Socket 1 (1)",
	.uft_decomp = &naples_decomp_cpu,
	.uft_compose = B_FALSE,
	.uft_valid = B_TRUE,
	.uft_fabric_id = 0x87,
	.uft_sock_id = 1,
	.uft_die_id = 0,
	.uft_comp_id = 7
}, {
	.uft_desc = "Naples Die (0)",
	.uft_decomp = &naples_decomp_cpu,
	.uft_compose = B_FALSE,
	.uft_valid = B_TRUE,
	.uft_fabric_id = 0xa7,
	.uft_sock_id = 1,
	.uft_die_id = 1,
	.uft_comp_id = 7
}, {
	.uft_desc = "Naples Die (1)",
	.uft_decomp = &naples_decomp_cpu,
	.uft_compose = B_TRUE,
	.uft_valid = B_TRUE,
	.uft_fabric_id = 0xe4,
	.uft_sock_id = 1,
	.uft_die_id = 3,
	.uft_comp_id = 4
}, {
	.uft_desc = "Naples CPU Invalid Socket (0)",
	.uft_decomp = &naples_decomp_cpu,
	.uft_compose = B_TRUE,
	.uft_valid = B_FALSE,
	.uft_sock_id = 11,
	.uft_die_id = 3,
	.uft_comp_id = 4
}, {
	.uft_desc = "Naples CPU Invalid Socket (1)",
	.uft_decomp = &naples_decomp_cpu,
	.uft_compose = B_TRUE,
	.uft_valid = B_FALSE,
	.uft_sock_id = 2,
	.uft_die_id = 3,
	.uft_comp_id = 4
}, {
	.uft_desc = "Naples CPU Invalid Socket (2)",
	.uft_decomp = &naples_decomp_cpu,
	.uft_compose = B_FALSE,
	.uft_valid = B_FALSE,
	.uft_fabric_id = 0x91,
}, {
	.uft_desc = "Naples CPU Invalid Die",
	.uft_decomp = &naples_decomp_cpu,
	.uft_compose = B_TRUE,
	.uft_valid = B_FALSE,
	.uft_sock_id = 0,
	.uft_die_id = 4,
	.uft_comp_id = 4
}, {
	.uft_desc = "Naples CPU Invalid Component (0)",
	.uft_decomp = &naples_decomp_cpu,
	.uft_compose = B_TRUE,
	.uft_valid = B_FALSE,
	.uft_sock_id = 0,
	.uft_die_id = 0,
	.uft_comp_id = 0x34
}, {
	.uft_desc = "Naples CPU Invalid Component (1)",
	.uft_decomp = &naples_decomp_cpu,
	.uft_compose = B_FALSE,
	.uft_valid = B_FALSE,
	.uft_fabric_id = 0x88,
}, {
	.uft_desc = "Naples APU Invalid Socket (0)",
	.uft_decomp = &naples_decomp_apu,
	.uft_compose = B_TRUE,
	.uft_valid = B_FALSE,
	.uft_sock_id = 1,
	.uft_die_id = 0,
	.uft_comp_id = 4
}, {
	.uft_desc = "Naples APU Invalid Socket (1)",
	.uft_decomp = &naples_decomp_apu,
	.uft_compose = B_TRUE,
	.uft_valid = B_FALSE,
	.uft_sock_id = 0x22,
	.uft_die_id = 0,
	.uft_comp_id = 4
}, {
	.uft_desc = "Naples APU Invalid Die (0)",
	.uft_decomp = &naples_decomp_apu,
	.uft_compose = B_TRUE,
	.uft_valid = B_FALSE,
	.uft_sock_id = 0,
	.uft_die_id = 1,
	.uft_comp_id = 4
}, {
	.uft_desc = "Naples APU Invalid Die (1)",
	.uft_decomp = &naples_decomp_apu,
	.uft_compose = B_TRUE,
	.uft_valid = B_FALSE,
	.uft_sock_id = 0,
	.uft_die_id = 3,
	.uft_comp_id = 4
}, {
	.uft_desc = "Naples APU Invalid Components (0)",
	.uft_decomp = &naples_decomp_apu,
	.uft_compose = B_TRUE,
	.uft_valid = B_FALSE,
	.uft_sock_id = 0,
	.uft_die_id = 0,
	.uft_comp_id = 0x10
}, {
	.uft_desc = "Naples APU Invalid Components (1)",
	.uft_decomp = &naples_decomp_apu,
	.uft_compose = B_TRUE,
	.uft_valid = B_FALSE,
	.uft_sock_id = 0,
	.uft_die_id = 0,
	.uft_comp_id = 0x13
}, {
	.uft_desc = "Naples APU Roundtrip (0)",
	.uft_decomp = &naples_decomp_apu,
	.uft_compose = B_TRUE,
	.uft_valid = B_TRUE,
	.uft_fabric_id = 0x03,
	.uft_sock_id = 0,
	.uft_die_id = 0,
	.uft_comp_id = 3
}, {
	.uft_desc = "Naples APU Roundtrip (1)",
	.uft_decomp = &naples_decomp_apu,
	.uft_compose = B_TRUE,
	.uft_valid = B_TRUE,
	.uft_fabric_id = 0x00,
	.uft_sock_id = 0,
	.uft_die_id = 0,
	.uft_comp_id = 0
}, {
	.uft_desc = "Naples APU Roundtrip (2)",
	.uft_decomp = &naples_decomp_apu,
	.uft_compose = B_FALSE,
	.uft_valid = B_TRUE,
	.uft_fabric_id = 0x0f,
	.uft_sock_id = 0,
	.uft_die_id = 0,
	.uft_comp_id = 0xf
}, {
	.uft_desc = "Milan Roundtrip (0)",
	.uft_decomp = &milan_decomp,
	.uft_compose = B_FALSE,
	.uft_valid = B_TRUE,
	.uft_fabric_id = 0x00,
	.uft_sock_id = 0,
	.uft_die_id = 0,
	.uft_comp_id = 0
}, {
	.uft_desc = "Milan Roundtrip (1)",
	.uft_decomp = &milan_decomp,
	.uft_compose = B_FALSE,
	.uft_valid = B_TRUE,
	.uft_fabric_id = 0x13,
	.uft_sock_id = 0,
	.uft_die_id = 0,
	.uft_comp_id = 0x13
}, {
	.uft_desc = "Milan Roundtrip (2)",
	.uft_decomp = &milan_decomp,
	.uft_compose = B_TRUE,
	.uft_valid = B_TRUE,
	.uft_fabric_id = 0x33,
	.uft_sock_id = 1,
	.uft_die_id = 0,
	.uft_comp_id = 0x13
}, {
	.uft_desc = "Milan Roundtrip (3)",
	.uft_decomp = &milan_decomp,
	.uft_compose = B_TRUE,
	.uft_valid = B_TRUE,
	.uft_fabric_id = 0x20,
	.uft_sock_id = 1,
	.uft_die_id = 0,
	.uft_comp_id = 0
}, {
	.uft_desc = "Milan Invalid Component (0)",
	.uft_decomp = &milan_decomp,
	.uft_compose = B_TRUE,
	.uft_valid = B_FALSE,
	.uft_sock_id = 0,
	.uft_die_id = 0,
	.uft_comp_id = 0x20
}, {
	.uft_desc = "Milan Invalid Component (1)",
	.uft_decomp = &milan_decomp,
	.uft_compose = B_TRUE,
	.uft_valid = B_FALSE,
	.uft_sock_id = 0,
	.uft_die_id = 0,
	.uft_comp_id = 0x2f
}, {
	.uft_desc = "Milan Invalid Die",
	.uft_decomp = &milan_decomp,
	.uft_compose = B_TRUE,
	.uft_valid = B_FALSE,
	.uft_sock_id = 0,
	.uft_die_id = 1,
	.uft_comp_id = 0xf
}, {
	.uft_desc = "Milan Invalid Socket (0)",
	.uft_decomp = &milan_decomp,
	.uft_compose = B_TRUE,
	.uft_valid = B_FALSE,
	.uft_sock_id = 2,
	.uft_die_id = 0,
	.uft_comp_id = 0xf
}, {
	.uft_desc = "Milan Invalid Socket (1)",
	.uft_decomp = &milan_decomp,
	.uft_compose = B_TRUE,
	.uft_valid = B_FALSE,
	.uft_sock_id = 3,
	.uft_die_id = 0,
	.uft_comp_id = 0xf
}, {
	.uft_desc = "Milan Invalid Socket (2)",
	.uft_decomp = &milan_decomp,
	.uft_compose = B_FALSE,
	.uft_valid = B_FALSE,
	.uft_fabric_id = 0x40
}, {
	.uft_desc = "Milan Invalid Socket (3)",
	.uft_decomp = &milan_decomp,
	.uft_compose = B_FALSE,
	.uft_valid = B_FALSE,
	.uft_fabric_id = 0x8f
}, {
	.uft_desc = "Contig Multi-Die Roundtrip (0)",
	.uft_decomp = &contig_decomp,
	.uft_compose = B_FALSE,
	.uft_valid = B_TRUE,
	.uft_fabric_id = 0,
	.uft_sock_id = 0,
	.uft_die_id = 0,
	.uft_comp_id = 0
}, {
	.uft_desc = "Contig Multi-Die Roundtrip (1)",
	.uft_decomp = &contig_decomp,
	.uft_compose = B_TRUE,
	.uft_valid = B_TRUE,
	.uft_fabric_id = 0xfff,
	.uft_sock_id = 0x7,
	.uft_die_id = 0x3,
	.uft_comp_id = 0x7f
}, {
	.uft_desc = "Contig Multi-Die Roundtrip (2)",
	.uft_decomp = &contig_decomp,
	.uft_compose = B_FALSE,
	.uft_valid = B_TRUE,
	.uft_fabric_id = 0x121,
	.uft_sock_id = 0x0,
	.uft_die_id = 0x2,
	.uft_comp_id = 0x21
}, {
	.uft_desc = "Contig Multi-Die Roundtrip (3)",
	.uft_decomp = &contig_decomp,
	.uft_compose = B_TRUE,
	.uft_valid = B_TRUE,
	.uft_fabric_id = 0x7f7,
	.uft_sock_id = 0x3,
	.uft_die_id = 0x3,
	.uft_comp_id = 0x77
}, {
	.uft_desc = "Contig Multi-Die Bad Socket",
	.uft_decomp = &contig_decomp,
	.uft_compose = B_TRUE,
	.uft_valid = B_FALSE,
	.uft_sock_id = 0x8,
	.uft_die_id = 0x1,
	.uft_comp_id = 0x23
}, {
	.uft_desc = "Contig Multi-Die Bad Die",
	.uft_decomp = &contig_decomp,
	.uft_compose = B_TRUE,
	.uft_valid = B_FALSE,
	.uft_sock_id = 0x2,
	.uft_die_id = 0x5,
	.uft_comp_id = 0x23
}, {
	.uft_desc = "Contig Multi-Die Bad Component",
	.uft_decomp = &contig_decomp,
	.uft_compose = B_TRUE,
	.uft_valid = B_FALSE,
	.uft_sock_id = 0x2,
	.uft_die_id = 0x1,
	.uft_comp_id = 0xff
}, {
	.uft_desc = "Contig Multi-Die Bad Fabric",
	.uft_decomp = &contig_decomp,
	.uft_compose = B_FALSE,
	.uft_valid = B_FALSE,
	.uft_fabric_id = 0x1000
}, {
	.uft_desc = NULL
} };
