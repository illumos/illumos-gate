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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* mc4.h */

#ifndef CHELSIO_MC4_H
#define CHELSIO_MC4_H

#include "common.h"

struct pemc4_intr_counts {
	unsigned int corr_err;
	unsigned int uncorr_err;
	unsigned int addr_err;
};

struct pemc4;

struct pemc4 *t1_mc4_create(adapter_t *adapter);
void t1_mc4_destroy(struct pemc4 *mc4);
int t1_mc4_init(struct pemc4 *mc4, unsigned int clk);

int t1_mc4_intr_handler(struct pemc4 *mc4);
void t1_mc4_intr_enable(struct pemc4 *mc4);
void t1_mc4_intr_disable(struct pemc4 *mc4);
void t1_mc4_intr_clear(struct pemc4 *mc4);

unsigned int t1_mc4_get_size(struct pemc4 *mc4);
int t1_mc4_bd_read(struct pemc4 *mc4, unsigned int start, unsigned int n,
		   u32 *buf);
const struct pemc4_intr_counts *t1_mc4_get_intr_counts(struct pemc4 *mc4);
#endif
