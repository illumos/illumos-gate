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

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/types.h>
#include <strings.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/sysevent.h>

#include "fmevt.h"

static evchan_t *fmevt_outbound_chan;

static struct fmevt_outbound_stats {
	fmd_stat_t recv_calls;
	fmd_stat_t recv_list;
	fmd_stat_t recv_ireport;
	fmd_stat_t recv_other;
	fmd_stat_t fwd_success;
	fmd_stat_t fwd_failure;
} outbound_stats = {
	{ "outbound_recv_calls", FMD_TYPE_UINT64,
	    "total events received for forwarding" },
	{ "outbound_cat1class_list", FMD_TYPE_UINT64,
	    "events received matching list.*" },
	{ "outbound_cat1class_ireport", FMD_TYPE_UINT64,
	    "events received matching ireport.*" },
	{ "outbound_cat1class_other", FMD_TYPE_UINT64,
	    "events of other classes" },
	{ "outbound_fwd_success", FMD_TYPE_UINT64,
	    "events forwarded successfully" },
	{ "outbound_fwd_failure", FMD_TYPE_UINT64,
	    "events we failed to forward" }
};

#define	BUMPSTAT(stat)	outbound_stats.stat.fmds_value.ui64++

/*
 * In the .conf file we subscribe to list.* and ireport.* event classes.
 * Any additions to that set could cause some unexpected behaviour.
 * For example adding fault.foo won't work (since we don't publish
 * faults directly but only within a list.suspect) but we will get
 * any list.* including fault.foo as a suspect.
 */
/*ARGSUSED*/
void
fmevt_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	BUMPSTAT(recv_calls);

	if (strncmp(class, "list.", 5) == 0)
		BUMPSTAT(recv_list);
	else if (strncmp(class, "ireport.", 8) == 0)
		BUMPSTAT(recv_ireport);
	else
		BUMPSTAT(recv_other);

	if (sysevent_evc_publish(fmevt_outbound_chan, class, "",
	    SUNW_VENDOR, FM_PUB, nvl, EVCH_SLEEP) == 0) {
		BUMPSTAT(fwd_success);
	} else {
		BUMPSTAT(fwd_failure);
		fmd_hdl_debug(hdl, "sysevent_evc_publish failed:");
	}
}

void
fmevt_init_outbound(fmd_hdl_t *hdl)
{
	int32_t channel_depth;
	char *channel_name;
	nvlist_t *nvl;

	if (fmd_prop_get_int32(hdl, "protocol_forward_disable") == B_TRUE) {
		fmd_hdl_debug(hdl, "protocol forwarding disabled "
		    "through .conf file setting\n");
		return;
	}

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC, sizeof (outbound_stats) /
	    sizeof (fmd_stat_t), (fmd_stat_t *)&outbound_stats);

	/*
	 * Allow simulation environment to change outbound channel name.
	 */
	channel_name = fmd_prop_get_string(hdl, "outbound_channel");

	if (sysevent_evc_bind(channel_name, &fmevt_outbound_chan,
	    EVCH_CREAT | EVCH_HOLD_PEND_INDEF) != 0) {
		fmd_hdl_abort(hdl, "Unable to bind channel %s",
		    channel_name);
	}

	channel_depth = fmd_prop_get_int32(hdl, "outbound_channel_depth");

	if (sysevent_evc_control(fmevt_outbound_chan, EVCH_SET_CHAN_LEN,
	    (uint32_t)channel_depth) != 0) {
		fmd_hdl_abort(hdl, "Unable to set depth of channel %s to %d",
		    channel_name, channel_depth);
	}
	fmd_prop_free_string(hdl, channel_name);

	nvl = fmd_nvl_alloc(hdl, FMD_SLEEP);
	(void) nvlist_add_nvlist(nvl, "fmdauth",
	    (nvlist_t *)fmd_hdl_fmauth(hdl));
	(void) sysevent_evc_setpropnvl(fmevt_outbound_chan, nvl);
	nvlist_free(nvl);

}

/*ARGSUSED*/
void
fmevt_fini_outbound(fmd_hdl_t *hdl)
{
	if (fmevt_outbound_chan != NULL) {
		(void) sysevent_evc_unbind(fmevt_outbound_chan);
		fmevt_outbound_chan = NULL;
	}
}
