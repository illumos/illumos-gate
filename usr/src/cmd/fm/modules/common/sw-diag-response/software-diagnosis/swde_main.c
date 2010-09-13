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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include "../common/sw_impl.h"

static const fmd_prop_t swde_props[] = {
	{ "enable", FMD_TYPE_BOOL, "true" },
	{ NULL, 0, NULL }
};

static const fmd_hdl_ops_t swde_ops = {
	sw_recv,	/* fmdo_recv - provided by common code */
	sw_timeout,	/* fmdo_timeout - provided by common code */
	swde_close,	/* fmdo_close */
	NULL,		/* fmdo_stats */
	NULL,		/* fmdo_gc */
	NULL,		/* fmdo_send */
	NULL		/* fmdo_topo */
};

const fmd_hdl_info_t swde_info = {
	"Software Diagnosis engine", "0.1", &swde_ops, swde_props
};

/*
 * Subsidiary diagnosis "modules" that we host.
 */
static const struct sw_subinfo *subde[SW_SUB_MAX] = {
	&smf_diag_info,
	&panic_diag_info
};

void
_fmd_init(fmd_hdl_t *hdl)
{
	if (sw_fmd_init(hdl, &swde_info, &subde))
		swde_case_init(hdl);
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	swde_case_fini(hdl);
	sw_fmd_fini(hdl);
}
