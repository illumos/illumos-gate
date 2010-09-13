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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* ulp.c */

#include "common.h"
#include "regs.h"
#include "ulp.h"

struct peulp {
	adapter_t *adapter;
	struct ulp_intr_counts intr_counts;
};

#define ULP_INTR_MASK (F_HREG_PAR_ERR | F_EGRS_DATA_PAR_ERR | \
		       F_INGRS_DATA_PAR_ERR | F_PM_INTR | F_PM_E2C_SYNC_ERR | \
		       F_PM_C2E_SYNC_ERR | F_PM_E2C_EMPTY_ERR | \
		       F_PM_C2E_EMPTY_ERR | V_PM_PAR_ERR(M_PM_PAR_ERR) | \
		       F_PM_E2C_WRT_FULL | F_PM_C2E_WRT_FULL)

void t1_ulp_intr_enable(struct peulp *ulp)
{
	/* Only ASIC boards support PL_ULP block. */
	if (t1_is_asic(ulp->adapter)) {
		u32 pl_intr = t1_read_reg_4(ulp->adapter, A_PL_ENABLE);

		t1_write_reg_4(ulp->adapter, A_ULP_INT_ENABLE, ULP_INTR_MASK);
		t1_write_reg_4(ulp->adapter, A_PL_ENABLE,
			       pl_intr | F_PL_INTR_ULP);
	}
}

void t1_ulp_intr_clear(struct peulp *ulp)
{
	if (t1_is_asic(ulp->adapter)) {
		t1_write_reg_4(ulp->adapter, A_PL_CAUSE, F_PL_INTR_ULP);
		t1_write_reg_4(ulp->adapter, A_ULP_INT_CAUSE, 0xffffffff);
	}
}

void t1_ulp_intr_disable(struct peulp *ulp)
{
	if (t1_is_asic(ulp->adapter)) {
		u32 pl_intr = t1_read_reg_4(ulp->adapter, A_PL_ENABLE);

		t1_write_reg_4(ulp->adapter, A_PL_ENABLE,
			       pl_intr & ~F_PL_INTR_ULP);
		t1_write_reg_4(ulp->adapter, A_ULP_INT_ENABLE, 0);
	}
}

int t1_ulp_intr_handler(struct peulp *ulp)
{
	u32 cause = t1_read_reg_4(ulp->adapter, A_ULP_INT_CAUSE);

	if (cause & F_HREG_PAR_ERR)
		ulp->intr_counts.region_table_parity_err++;

	if (cause & F_EGRS_DATA_PAR_ERR)
		ulp->intr_counts.egress_tp2ulp_data_parity_err++;

	if (cause & F_INGRS_DATA_PAR_ERR)
		ulp->intr_counts.ingress_tp2ulp_data_parity_err++;

	if (cause & F_PM_INTR)
		ulp->intr_counts.pm_intr++;

	if (cause & F_PM_E2C_SYNC_ERR)
		ulp->intr_counts.pm_e2c_cmd_payload_sync_err++;

	if (cause & F_PM_C2E_SYNC_ERR)
		ulp->intr_counts.pm_c2e_cmd_payload_sync_err++;

	if (cause & F_PM_E2C_EMPTY_ERR)
		ulp->intr_counts.pm_e2c_fifo_read_empty_err++;

	if (cause & F_PM_C2E_EMPTY_ERR)
		ulp->intr_counts.pm_c2e_fifo_read_empty_err++;

	if (G_PM_PAR_ERR(cause))
		ulp->intr_counts.pm_parity_err++;

	if (cause & F_PM_E2C_WRT_FULL)
		ulp->intr_counts.pm_e2c_fifo_write_full_err++;

	if (cause & F_PM_C2E_WRT_FULL)
		ulp->intr_counts.pm_c2e_fifo_write_full_err++;

	if (cause & ULP_INTR_MASK)
		t1_fatal_err(ulp->adapter);

	/* Clear status */
	t1_write_reg_4(ulp->adapter, A_ULP_INT_CAUSE, cause);
	return 0;
}

int t1_ulp_init(struct peulp *ulp, unsigned int pm_tx_base)
{
	int i;
	adapter_t *adapter = ulp->adapter;

	/*
	 * Initialize ULP Region Table.
	 *
	 * The region table memory has read enable tied to one, so data is
	 * read out every cycle. The address to this memory is not defined
	 * at reset and gets set first time when first ulp pdu is handled.
	 * So after reset an undefined location is accessed, and since it is
	 * read before any meaningful data is written to it there can be a
	 * parity error.
	 */
	for (i = 0; i < 256; i++) {
		t1_write_reg_4(adapter, A_ULP_HREG_INDEX, i);
		t1_write_reg_4(adapter, A_ULP_HREG_DATA, 0);
	}

	t1_write_reg_4(adapter, A_ULP_ULIMIT, pm_tx_base);
        t1_write_reg_4(adapter, A_ULP_TAGMASK, (pm_tx_base << 1) - 1);

        if (!t1_is_T1B(adapter)) {
                /* region table is not used */
                t1_write_reg_4(adapter, A_ULP_HREG_INDEX, 0);
                /* enable page size in pagepod */
                t1_write_reg_4(adapter, A_ULP_PIO_CTRL, 1);
        }
	return 0;
}

struct peulp *t1_ulp_create(adapter_t *adapter)
{
	struct peulp *ulp = t1_os_malloc_wait_zero(sizeof(*ulp));

	if (ulp)
		ulp->adapter = adapter;
	return ulp;
}

void t1_ulp_destroy(struct peulp * ulp)
{
	t1_os_free((void *)ulp, sizeof(*ulp));
}

const struct ulp_intr_counts *t1_ulp_get_intr_counts(struct peulp *ulp)
{
	return &ulp->intr_counts;
}
