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

/*
 * SMF software diagnosis engine components.
 */

#include <fm/libtopo.h>
#include <strings.h>

#include "../../common/sw.h"
#include "smf.h"

/*
 * Given a "svc' scheme FMRI in nvlist form, produce a string form
 * of the FMRI (with no short-hand).
 */
char *
sw_smf_svcfmri2str(fmd_hdl_t *hdl, nvlist_t *fmri)
{
	char *fmristr = NULL;
	topo_hdl_t *thp;
	char *topostr;
	int err;

	thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION);
	if (topo_fmri_nvl2str(thp, fmri, &topostr, &err) == 0) {
		fmristr = fmd_hdl_strdup(hdl, (const char *)topostr, FMD_SLEEP);
		topo_hdl_strfree(thp, topostr);
	}
	fmd_hdl_topo_rele(hdl, thp);

	return (fmristr);	/* caller must fmd_hdl_strfree */
}

/*
 * Given a "svc" scheme FMRI in nvlist form, produce a short-hand form
 * string FMRI "svc:/..." as generally used in SMF cmdline output.
 */
char *
sw_smf_svcfmri2shortstr(fmd_hdl_t *hdl, nvlist_t *fmri)
{
	char *name, *inst, *bufp, *fullname;
	size_t len;

	if (nvlist_lookup_string(fmri, FM_FMRI_SVC_NAME, &name) != 0 ||
	    nvlist_lookup_string(fmri, FM_FMRI_SVC_INSTANCE, &inst) != 0)
		return (NULL);

	len = strlen(name) + strlen(inst) + 8;
	bufp = fmd_hdl_alloc(hdl, len, FMD_SLEEP);
	(void) snprintf(bufp, len, "svc:/%s:%s", name, inst);

	fullname = fmd_hdl_strdup(hdl, bufp, FMD_SLEEP);
	fmd_hdl_free(hdl, bufp, len);

	return (fullname);	/* caller must fmd_hdl_strfree */
}
