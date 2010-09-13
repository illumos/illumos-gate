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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* ulp.h */

#ifndef ULP_H
#define ULP_H

#include "common.h"

struct ulp_intr_counts {
	unsigned int region_table_parity_err;
	unsigned int egress_tp2ulp_data_parity_err;
	unsigned int ingress_tp2ulp_data_parity_err;
	unsigned int pm_intr;
	unsigned int pm_e2c_cmd_payload_sync_err;
	unsigned int pm_c2e_cmd_payload_sync_err;
	unsigned int pm_e2c_fifo_read_empty_err;
	unsigned int pm_c2e_fifo_read_empty_err;
	unsigned int pm_parity_err;
	unsigned int pm_e2c_fifo_write_full_err;
	unsigned int pm_c2e_fifo_write_full_err;
};

struct peulp;

struct peulp *t1_ulp_create(adapter_t * adapter);
void t1_ulp_destroy(struct peulp *ulp);
int t1_ulp_init(struct peulp *ulp, unsigned int pm_tx_base);

void t1_ulp_intr_enable(struct peulp *ulp);
void t1_ulp_intr_clear(struct peulp *ulp);
void t1_ulp_intr_disable(struct peulp *ulp);
int t1_ulp_intr_handler(struct peulp *ulp);
const struct ulp_intr_counts *t1_ulp_get_intr_counts(struct peulp *ulp);
#endif
