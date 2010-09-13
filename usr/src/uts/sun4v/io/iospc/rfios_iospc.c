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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/disp.h>
#include <sys/stat.h>
#include <sys/pci.h>
#include <sys/hsvc.h>
#include "iospc.h"
#include "rfios_acc.h"
#include "rfios_tables.h"

extern iospc_grp_t *rfios_leaf_grps[];

#define	RF_REQ_MAJOR_VER	1
#define	RF_REQ_MINOR_VER	0

static hsvc_info_t rfios_hsvc = {
	HSVC_REV_1,
	NULL,
	RF_PERF_COUNTER_GROUP_ID,
	RF_REQ_MAJOR_VER,
	RF_REQ_MINOR_VER,
	MODULE_NAME	/* Passed in as a #define from Makefile */
};

static uint64_t rfios_sup_minor;

iospc_grp_t **
rfios_bind_group(void)
{
	int rval;

	if ((rval = hsvc_register(&rfios_hsvc, &rfios_sup_minor)) !=
	    DDI_SUCCESS) {
		IOSPC_DBG1("%s: Could not hsvc_register: %d\n",
		    MODULE_NAME, rval);

		return (NULL);
	}

	return ((iospc_grp_t **)&rfios_leaf_grps);
}

void
rfios_unbind_group(void)
{
	(void) hsvc_unregister(&rfios_hsvc);
}

int
rfios_access_init(iospc_t *iospc_p, iospc_ksinfo_t *ksinfo_p)
{
	uint32_t regprop[4];
	int len;
	cntr_handle_t   iospc_handle;

	IOSPC_DBG2("rfios_access_init: iospc_p=%p\n", (void *)iospc_p);

	len = sizeof (regprop);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, iospc_p->iospc_dip,
	    DDI_PROP_DONTPASS, "reg", (caddr_t)regprop, &len) !=
	    DDI_SUCCESS) {
		return (FAILURE);
	}

	iospc_handle = (regprop[0] & 0xfffffff);
	ksinfo_p->arg = (void *)iospc_handle;

	return (SUCCESS);

}

int
rfios_access_fini(iospc_t *iospc_p, iospc_ksinfo_t *ksinfo_p)
{
	IOSPC_DBG2("rfios_access_fini: iospc_p=%p ksinfo_p=%p\n",
	    (void *)iospc_p, (void *)ksinfo_p);
	return (SUCCESS);
}

int
rfios_access_hv(iospc_t *iospc_p, void *arg, int op, int regid, uint64_t *data)
{
	cntr_handle_t   iospc_handle = (cntr_handle_t)arg;

	if (op == IOSPC_REG_READ) {
		if (rfiospc_get_perfreg(iospc_handle, regid, data) != H_EOK) {
			IOSPC_DBG2("rfios_access_hv: READ handle=%p regid=%x "
			    "- Failed\n", (void *)iospc_p, regid);
			return (FAILURE);
		}

		IOSPC_DBG2("rfios_access_hv: READ handle=%p regid=%x "
		    "data=%lx\n", (void *)iospc_p, regid, *data);

	} else { /* IOSPC_REG_WRITE */
		if (rfiospc_set_perfreg(iospc_handle, regid, *data) != H_EOK) {
			IOSPC_DBG2("rfios_access_hv: READ handle=%p regid=%x "
			    "- Failed\n", (void *)iospc_p, regid);
			return (FAILURE);
		}

		IOSPC_DBG2("rfios_access_hv: WRITE  handle=%p regid=%x "
		    "data=%lx\n", (void *)iospc_p, regid, *data);
	}

	return (SUCCESS);
}
