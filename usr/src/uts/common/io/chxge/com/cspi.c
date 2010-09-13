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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* cspi.c */

#include "common.h"
#include "regs.h"
#include "cspi.h"

struct pecspi {
	adapter_t *adapter;
};

int t1_cspi_intr_enable(struct pecspi *cspi)
{
	t1_write_reg_4(cspi->adapter, A_CSPI_INTR_ENABLE, 0xffffffff);
	return 0;
}

int t1_cspi_intr_disable(struct pecspi *cspi)
{
	t1_write_reg_4(cspi->adapter, A_CSPI_INTR_ENABLE, 0);
	return 0;
}

int t1_cspi_intr_status_read(struct pecspi *cspi, u32 *status)
{
	*status = t1_read_reg_4(cspi->adapter, A_CSPI_INTR_STATUS);

	/* TBD XXX Need to poll in case of parity/overflow */
	/* t1_write_reg_4( adapter, CSPI_REG_RAMSTATUS, ); */

	return 0;
}

int t1_cspi_init(struct pecspi *cspi)
{
	adapter_t *adapter = cspi->adapter;

	t1_write_reg_4(adapter, A_CSPI_CALENDAR_LEN, 15);
	t1_write_reg_4(adapter, A_CSPI_FIFO_STATUS_ENABLE, 1);
	return 0;
}

struct pecspi *t1_cspi_create(adapter_t *adapter)
{
	struct pecspi *cspi = t1_os_malloc_wait_zero(sizeof(*cspi));

	if (cspi)
		cspi->adapter = adapter;
	return cspi;
}

void t1_cspi_destroy(struct pecspi *cspi)
{
	t1_os_free((void *)cspi, sizeof(*cspi));
}
