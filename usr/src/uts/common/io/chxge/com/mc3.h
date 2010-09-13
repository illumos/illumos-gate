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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* mc3.h */

#ifndef CHELSIO_MC3_H
#define CHELSIO_MC3_H

#include "common.h"

struct pemc3_intr_counts {
	unsigned int corr_err;
	unsigned int uncorr_err;
	unsigned int parity_err;
	unsigned int addr_err;
};
	
struct pemc3;

struct pemc3 *t1_mc3_create(adapter_t * adapter);
void t1_mc3_destroy(struct pemc3 *mc3);
int t1_mc3_init(struct pemc3 *mc3, unsigned int mc3_clock);

int t1_mc3_intr_handler(struct pemc3 *mc3);
void t1_mc3_intr_enable(struct pemc3 *mc3);
void t1_mc3_intr_disable(struct pemc3 *mc3);
void t1_mc3_intr_clear(struct pemc3 *mc3);

unsigned int t1_mc3_get_size(struct pemc3 *mc3);
const struct pemc3_intr_counts *t1_mc3_get_intr_counts(struct pemc3 *mc3);

#endif
