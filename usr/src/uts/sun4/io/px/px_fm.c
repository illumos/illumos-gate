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
 * PX Fault Management Architecture support
 * Minimal implementation for now.  Needs to be filled out later
 */
#include <sys/types.h>
#include <sys/sunndi.h>
#include "px_obj.h"

static int px_fm_err_callback(dev_info_t *, ddi_fm_error_t *, const void *);

int
px_fm_attach(px_t *px_p)
{
	px_p->px_fm_cap = DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE |
	    DDI_FM_ACCCHK_CAPABLE;

	ddi_fm_init(px_p->px_dip, &px_p->px_fm_cap, &px_p->px_fm_ibc);

	ddi_fm_handler_register(px_p->px_dip, px_fm_err_callback, px_p);
	return (DDI_SUCCESS);
}

void
px_fm_detach(px_t *px_p)
{
	ddi_fm_fini(px_p->px_dip);
}

/*
 * Function used to setup access functions depending on level of desired
 * protection.
 */
void
px_fm_acc_setup(ddi_map_req_t *mp, dev_info_t *rdip)
{
	uchar_t fflag;
	ddi_acc_hdl_t *hp;
	ddi_acc_impl_t *ap;

	hp = mp->map_handlep;
	ap = (ddi_acc_impl_t *)hp->ah_platform_private;
	fflag = ap->ahi_common.ah_acc.devacc_attr_access;

	if (mp->map_op == DDI_MO_MAP_LOCKED) {
		ndi_fmc_insert(rdip, ACC_HANDLE, (void *)hp, NULL);
		switch (fflag) {
		case DDI_FLAGERR_ACC:
			ap->ahi_get8 = i_ddi_prot_get8;
			ap->ahi_get16 = i_ddi_prot_get16;
			ap->ahi_get32 = i_ddi_prot_get32;
			ap->ahi_get64 = i_ddi_prot_get64;
			ap->ahi_put8 = i_ddi_prot_put8;
			ap->ahi_put16 = i_ddi_prot_put16;
			ap->ahi_put32 = i_ddi_prot_put32;
			ap->ahi_put64 = i_ddi_prot_put64;
			ap->ahi_rep_get8 = i_ddi_prot_rep_get8;
			ap->ahi_rep_get16 = i_ddi_prot_rep_get16;
			ap->ahi_rep_get32 = i_ddi_prot_rep_get32;
			ap->ahi_rep_get64 = i_ddi_prot_rep_get64;
			ap->ahi_rep_put8 = i_ddi_prot_rep_put8;
			ap->ahi_rep_put16 = i_ddi_prot_rep_put16;
			ap->ahi_rep_put32 = i_ddi_prot_rep_put32;
			ap->ahi_rep_put64 = i_ddi_prot_rep_put64;
			break;
		case DDI_CAUTIOUS_ACC :
			ap->ahi_get8 = i_ddi_caut_get8;
			ap->ahi_get16 = i_ddi_caut_get16;
			ap->ahi_get32 = i_ddi_caut_get32;
			ap->ahi_get64 = i_ddi_caut_get64;
			ap->ahi_put8 = i_ddi_caut_put8;
			ap->ahi_put16 = i_ddi_caut_put16;
			ap->ahi_put32 = i_ddi_caut_put32;
			ap->ahi_put64 = i_ddi_caut_put64;
			ap->ahi_rep_get8 = i_ddi_caut_rep_get8;
			ap->ahi_rep_get16 = i_ddi_caut_rep_get16;
			ap->ahi_rep_get32 = i_ddi_caut_rep_get32;
			ap->ahi_rep_get64 = i_ddi_caut_rep_get64;
			ap->ahi_rep_put8 = i_ddi_caut_rep_put8;
			ap->ahi_rep_put16 = i_ddi_caut_rep_put16;
			ap->ahi_rep_put32 = i_ddi_caut_rep_put32;
			ap->ahi_rep_put64 = i_ddi_caut_rep_put64;
			break;
		default:
			break;
		}
	} else if (mp->map_op == DDI_MO_UNMAP) {
		ndi_fmc_remove(rdip, ACC_HANDLE, (void *)hp);
	}
}

/*
 * Function used to initialize FMA for our children nodes. Called
 * through pci busops when child node calls ddi_fm_init.
 */
/*ARGSUSED*/
int
px_fm_init_child(dev_info_t *dip, dev_info_t *cdip, int cap,
    ddi_iblock_cookie_t *ibc_p)
{
	px_t *px_p = DIP_TO_STATE(dip);

	ASSERT(ibc_p != NULL);
	*ibc_p = px_p->px_fm_ibc;

	return (px_p->px_fm_cap);
}

/*
 * Error callback.
 * Just call error handler for now.
 */
/*ARGSUSED*/
static int
px_fm_err_callback(dev_info_t *dip, ddi_fm_error_t *derr, const void *impl_data)
{
	return (px_fm_err_handler(dip, derr, impl_data));
}

/*
 * Error handler.
 * Just pass error on to parent handler for now.
 */
/*ARGSUSED*/
int
px_fm_err_handler(dev_info_t *rdip, ddi_fm_error_t *derr, const void *impl_data)
{
	px_t *px_p = (px_t *)impl_data;

	/*
	 * status comes in through derr->fme_flag and
	 *  ((ddi_acc_impl_t *)(derr->fme_acc_handle))->ahi_err->err_expected
	 *
	 * XXX Handling to be filled in by FMA putback.
	 *
	 * Can only call ndi_fm_handler_dispatch with a dip of a device
	 * initialized with FMA.
	 */

	return (ndi_fm_handler_dispatch(px_p->px_dip,
	    ((derr->fme_acc_handle != NULL) ? rdip : NULL), derr));
}
