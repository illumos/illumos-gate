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

#include <sys/fm/protocol.h>
#include <fm/fmd_api.h>
#include <strings.h>

static int ior_autoclose;

/*ARGSUSED*/
static void
ior_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	char *uuid;

	if (ior_autoclose && strcmp(class, FM_LIST_SUSPECT_CLASS) == 0 &&
	    nvlist_lookup_string(nvl, FM_SUSPECT_UUID, &uuid) == 0 &&
	    !fmd_case_uuclosed(hdl, uuid))
		fmd_case_uuclose(hdl, uuid);
}

static const fmd_hdl_ops_t fmd_ops = {
	ior_recv,	/* fmdo_recv */
	NULL,		/* fmdo_timeout */
	NULL,		/* fmdo_close */
	NULL,		/* fmdo_stats */
	NULL,		/* fmdo_gc */
};

static const fmd_prop_t ior_props[] = {
	{ "autoclose", FMD_TYPE_BOOL, "false" },
	{ NULL, 0, NULL }
};

static const fmd_hdl_info_t fmd_info = {
	"I/O Retire Agent", "1.0", &fmd_ops, ior_props
};

void
_fmd_init(fmd_hdl_t *hdl)
{
	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) == 0)
		ior_autoclose = fmd_prop_get_int32(hdl, "autoclose");
}
