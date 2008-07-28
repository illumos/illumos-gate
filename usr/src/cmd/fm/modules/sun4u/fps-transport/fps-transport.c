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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <fm/fmd_api.h>
#include <fmd_module.h>
#include <fmd_scheme.h>
#include <fmd.h>
#include <libnvpair.h>
#include <libsysevent.h>
#include <errno.h>
#include <string.h>
#include <fpst-defines.h>

static evchan_t *h_event; /* handle for event channel */
static fmd_xprt_t *h_xprt; /* transport handle */
static fmd_hdl_t *h_fmd; /* fmd handle */

static const fmd_hdl_ops_t fps_ops = {
	NULL, /* receive */
	NULL, /* timeout */
	NULL, /* close */
	NULL, /* stats */
	NULL /* gc */
};

static const fmd_hdl_info_t fmd_info = 	{
			FPS_MOD_DESC,
			FPS_MOD_VER,
			&fps_ops,
			NULL
};

static struct sysev_stats {
	fmd_stat_t bad_class;
	fmd_stat_t bad_attr;
	fmd_stat_t eagain;
} sysev_stats = {
	{ "bad_class", FMD_TYPE_UINT64,
	    "events dropped due to invalid class" },
	{ "bad_attr", FMD_TYPE_UINT64,
	    "events dropped due to invalid nvlist" },
	{ "eagain", FMD_TYPE_UINT64, "events retried due to low memory" },
};

/*
 * event_transfer(sysevent_t *ev, void *arg)
 * takes a sysevent ev, extracts the nvlist of
 * data for an ereport, and posts it to the fmd.
 */
/* ARGSUSED */
static int
event_transfer(sysevent_t *ev, void *arg)
{
	hrtime_t hrt;
	nvlist_t *retrieved_list;
	uint64_t seq = sysevent_get_seq(ev);

	if (strcasecmp(sysevent_get_class_name(ev), CLASS) != 0) {
		fmd_hdl_error(h_fmd, "Discarding event 0x%llx: unexpected"
		    " transport class %s\n", seq,
		    sysevent_get_class_name(ev));
		sysev_stats.bad_class.fmds_value.ui64++;

		return (0);
	}

	if (sysevent_get_attr_list(ev, &retrieved_list) == 0) {
		sysevent_get_time(ev, &hrt);
		fmd_xprt_post(h_fmd, h_xprt, retrieved_list, hrt);
	} else {
		if (errno == EAGAIN || errno == ENOMEM) {
			sysev_stats.eagain.fmds_value.ui64++;
			return (EAGAIN);
		}

		fmd_hdl_error(h_fmd, "Event: 0x%llx is missing or"
		    " has an invalid payload.", seq);
		sysev_stats.bad_attr.fmds_value.ui64++;

	}

	return (0);
}

/*
 * _fmd_fini(fmd_hdl_t *handle) is the
 * module exit point. It unsubscribes
 * and unbinds to FPS channel as well
 * as closes fmd transport handle
 */
/* ARGSUSED */
void
_fmd_fini(fmd_hdl_t *handle)
{
	if (h_event != NULL) {
		sysevent_evc_unsubscribe(h_event, SUBSCRIBE_ID);
		sysevent_evc_unbind(h_event);
	}

	if (h_fmd != NULL && h_xprt != NULL)
		fmd_xprt_close(h_fmd, h_xprt);
}

/*
 * _fmd_init(fmd_hdl_t *hdl) is the
 * entry point into the module. It
 * registers the handle hdl and
 * subscribes to the fps sysevent channel.
 */
void
_fmd_init(fmd_hdl_t *hdl)
{
	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0) {
		return;
	}

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC, sizeof (sysev_stats) /
	    sizeof (fmd_stat_t), (fmd_stat_t *)&sysev_stats);

	h_xprt = fmd_xprt_open(hdl, FMD_XPRT_RDONLY, NULL, NULL);
	h_fmd = hdl;

	if (sysevent_evc_bind(CHANNEL, &h_event, BIND_FLAGS) != 0) {
		fmd_hdl_error(hdl, "Failed to bind to channel %s", CHANNEL);
		fmd_hdl_unregister(hdl);
	}

	if (sysevent_evc_subscribe(h_event, SUBSCRIBE_ID, SUBSCRIBE_FLAGS,
	    event_transfer, NULL, 0) != 0) {
		fmd_hdl_error(hdl, "Failed to subsrcibe to channel %s",
		    CHANNEL);
		fmd_hdl_unregister(hdl);
	}
}
