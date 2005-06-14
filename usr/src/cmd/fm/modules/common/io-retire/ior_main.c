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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <strings.h>
#include <errno.h>
#include <time.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>

static int Autoclose;
static char *lastuuid;

/*ARGSUSED*/
static void
ior_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	char *uuid = NULL;
	char *entryname;
	nvlist_t *asru;
	nvlist_t **nva;
	uint_t nvc = 0;

	fmd_hdl_debug(hdl, "recv: %s\n", class);
	if (strcmp(class, FM_LIST_SUSPECT_CLASS) == 0) {
		(void) nvlist_lookup_string(nvl, FM_SUSPECT_UUID, &uuid);
		(void) nvlist_lookup_nvlist_array(nvl,
		    FM_SUSPECT_FAULT_LIST, &nva, &nvc);

		fmd_hdl_debug(hdl, "uuid: %s\n", uuid);
		/* if getting called again with same uuid, return */
		if (lastuuid != NULL && strcmp(lastuuid, uuid) == 0) {
			fmd_hdl_debug(hdl, "repeat uuid\n");
			return;
		} else if (lastuuid)
			fmd_hdl_strfree(hdl, lastuuid);
		lastuuid = fmd_hdl_strdup(hdl, uuid, FMD_SLEEP);
		for (; nvc-- != 0; nva++) {
			(void) nvlist_lookup_string(*nva, FM_CLASS, &entryname);
			if (nvlist_lookup_nvlist(*nva,
			    FM_FAULT_ASRU, &asru) == 0) {
				fmd_hdl_debug(hdl, "convict: %s\n", entryname);
				fmd_case_uuconvict(hdl, uuid, *nva);
			} else {
				fmd_hdl_debug(hdl,
				    "no convict: %s (no asru)\n", entryname);
			}
		}
		if (Autoclose != 0)
			fmd_case_uuclose(hdl, uuid);
	}
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
	(void) fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info);
	Autoclose = fmd_prop_get_int32(hdl, "autoclose");
}

/*ARGSUSED*/
void
_fmd_fini(fmd_hdl_t *hdl)
{
	/* nothing to do here */
}
