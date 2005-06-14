/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * PX Fault Management Architecture support for px_pci
 * Minimal implementation for now.  Needs to be filled out later
 */
#include <sys/types.h>
#include <sys/sunndi.h>
#include "px_pci.h"
#include "px_pci_fm.h"

static int px_pci_fm_err_callback(dev_info_t *, ddi_fm_error_t *, const void *);

int
px_pci_fm_attach(pxb_devstate_t *pxb_p)
{
	pxb_p->pxb_fm_cap = DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE |
		DDI_FM_ACCCHK_CAPABLE;

	ddi_fm_init(pxb_p->pxb_dip, &pxb_p->pxb_fm_cap, &pxb_p->pxb_fm_ibc);

	ddi_fm_handler_register(pxb_p->pxb_dip, px_pci_fm_err_callback, pxb_p);
	return (DDI_SUCCESS);
}

void
px_pci_fm_detach(pxb_devstate_t *pxb_p)
{
	ddi_fm_fini(pxb_p->pxb_dip);
}

/*
 * Function used to initialize FMA for our children nodes. Called
 * through pci busops when child node calls ddi_fm_init.
 */
/*ARGSUSED*/
int
px_pci_fm_init_child(dev_info_t *dip, dev_info_t *cdip, int cap,
    ddi_iblock_cookie_t *ibc_p)
{
	pxb_devstate_t *pxb_p = (pxb_devstate_t *)
	    ddi_get_soft_state(pxb_state, ddi_get_instance(dip));

	ASSERT(ibc_p != NULL);
	*ibc_p = pxb_p->pxb_fm_ibc;

	return (pxb_p->pxb_fm_cap);
}

/*
 * Error callback handler.
 * Just pass error on to parent handler for now.
 */
/*ARGSUSED*/
static int
px_pci_fm_err_callback(dev_info_t *dip, ddi_fm_error_t *derr,
    const void *impl_data)
{
	return (ndi_fm_handler_dispatch(dip, NULL, derr));
}
