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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>

#include "fmevt.h"

const fmd_prop_t fmevt_props[] = {
	{ "protocol_forward_disable", FMD_TYPE_BOOL, "false" },
	{ "outbound_channel", FMD_TYPE_STRING, FMD_SNOOP_CHANNEL },
	{ "outbound_channel_depth", FMD_TYPE_INT32, "256" },
	{ "user_priv_highval_channel", FMD_TYPE_STRING,
	    FMEV_CHAN_USER_PRIV_HV },
	{ "user_priv_lowval_channel", FMD_TYPE_STRING,
	    FMEV_CHAN_USER_PRIV_LV },
	{ "sidprefix", FMD_TYPE_STRING, "fmd" },
	{ "inbound_postprocess_smf", FMD_TYPE_BOOL, "true" },
	{ NULL, 0, NULL },
};

static const fmd_hdl_ops_t fmd_ops = {
	fmevt_recv,	/* fmdo_recv */
	NULL,		/* fmdo_timeout */
	NULL,		/* fmdo_close */
	NULL,		/* fmdo_stats */
	NULL,		/* fmdo_gc */
	NULL,		/* fmdo_send */
	NULL		/* fmdo_topo */
};

static const fmd_hdl_info_t fmd_info = {
	"External FM event transport", "0.2", &fmd_ops, fmevt_props
};

fmd_hdl_t *fmevt_hdl;

void
_fmd_init(fmd_hdl_t *hdl)
{
	/*
	 * Register the handle, pulling in configuration from our
	 * conf file.  This includes our event class subscriptions
	 * for those events that we will forward out of fmd.
	 */
	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return;

	fmevt_hdl = hdl;

	fmevt_init_outbound(hdl);
	fmevt_init_inbound(hdl);
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	fmevt_fini_outbound(hdl);
	fmevt_fini_inbound(hdl);
}
