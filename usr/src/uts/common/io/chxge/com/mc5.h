/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (C) 2003-2005 Chelsio Communications.  All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* mc5.h */

#ifndef CHELSIO_MC5_H
#define CHELSIO_MC5_H

#include "common.h"

struct pemc5;

struct pemc5_intr_counts {
	unsigned int hit_out_active_region_err;
	unsigned int hit_in_active_region_err;
	unsigned int hit_in_routing_region_err;
	unsigned int miss_err;
	unsigned int lip_equal_zero_err;
	unsigned int lip_miss_err;
	unsigned int parity_err;
	unsigned int active_region_full_err;
	unsigned int next_free_addr_srch_err;
	unsigned int syn_cookie;
	unsigned int syn_cookie_bad_message;
	unsigned int syn_cookie_off_message;
	unsigned int receive_unknown_cmd;
	unsigned int parity_in_request_q_err;
	unsigned int parity_in_dispatch_q_err;
	unsigned int del_and_act_is_empty;
};

#define MC5_LIP_NUM_OF_ENTRIES  64

/* These must be non-0 */
#define MC5_MODE_144_BIT     1
#define MC5_MODE_72_BIT      2

struct pemc5 *t1_mc5_create(adapter_t *adapter, int mode);
int t1_mc5_init(struct pemc5 *mc5, unsigned int nservers,
		unsigned int nroutes, int parity, int syn);
void t1_mc5_destroy(struct pemc5 *mc5);

int t1_read_mc5_range(struct pemc5 *mc5, unsigned int start,
		unsigned int n, u32 *buf);
const struct pemc5_intr_counts *t1_mc5_get_intr_counts(struct pemc5 *mc5);

void t1_mc5_intr_enable(struct pemc5 *mc5);
void t1_mc5_intr_disable(struct pemc5 *mc5);
void t1_mc5_intr_clear(struct pemc5 *mc5);
void t1_mc5_intr_handler(struct pemc5 *mc5);

void t1_mc5_lip_write_entries(struct pemc5 *mc5);
int t1_mc5_lip_add_entry(struct pemc5 *mc5, u32 lip);
void t1_mc5_lip_clear_entries(struct pemc5 *mc5);

unsigned int t1_mc5_get_tcam_size(struct pemc5 *mc5);
unsigned int t1_mc5_get_tcam_rtbl_base(struct pemc5 *mc5);
unsigned int t1_mc5_get_tcam_rtbl_size(struct pemc5 *mc5);
unsigned int t1_mc5_get_tcam_server_base(struct pemc5 *mc5);
unsigned int t1_mc5_get_tcam_server_size(struct pemc5 *mc5);

#endif
