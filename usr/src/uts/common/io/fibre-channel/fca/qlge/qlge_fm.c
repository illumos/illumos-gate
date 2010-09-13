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
 * Copyright 2010 QLogic Corporation. All rights reserved.
 */

#include <qlge.h>

#define	QL_FM_BUF_LEN	128

void
ql_fm_ereport(qlge_t *qlge, char *detail)
{
	uint64_t ena;
	char buf[QL_FM_BUF_LEN];

	(void) snprintf(buf, QL_FM_BUF_LEN, "%s.%s", DDI_FM_DEVICE, detail);
	ena = fm_ena_generate(0, FM_ENA_FMT1);
	if (DDI_FM_EREPORT_CAP(qlge->fm_capabilities)) {
		ddi_fm_ereport_post(qlge->dip, buf, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0, NULL);
	}
}

int
ql_fm_check_acc_handle(ddi_acc_handle_t handle)
{
	ddi_fm_error_t err;

	ddi_fm_acc_err_get(handle, &err, DDI_FME_VERSION);
	/* for OpenSolaris */
	ddi_fm_acc_err_clear(handle, DDI_FME_VERSION);
	return (err.fme_status);
}

int
ql_fm_check_dma_handle(ddi_dma_handle_t handle)
{
	ddi_fm_error_t err;

	ddi_fm_dma_err_get(handle, &err, DDI_FME_VERSION);
	return (err.fme_status);
}
