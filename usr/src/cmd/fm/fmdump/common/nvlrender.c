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
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

/*
 * Rendering functions for nvlist_prt that are of use to all types
 * of log.
 */

#include <fmdump.h>
#include <stdio.h>
#include <strings.h>

extern topo_hdl_t *fmd_fmri_topo_hold(int);

/*
 * Can be appointed to be called for dumping all nvlist members of
 * an nvlist we ask to print with nvlist_prt.  Return 0 if the
 * nvlist is not recognized as an fmri, and default formatting
 * will be applied; otherwise format as an fmri string and return 1.
 */

/*ARGSUSED*/
int
fmdump_render_nvlist(nvlist_prtctl_t pctl, void *private, nvlist_t *nvl,
    const char *name, nvlist_t *fmri)
{
	topo_hdl_t *thp = fmd_fmri_topo_hold(TOPO_VERSION);
	FILE *fp = nvlist_prtctl_getdest(pctl);
	char *class, *fmristr = NULL;
	uint8_t version;
	int err;

	if (nvlist_lookup_string(fmri, FM_FMRI_SCHEME, &class) != 0 ||
	    nvlist_lookup_uint8(fmri, FM_VERSION, &version) != 0)
		return (0);

	/*
	 * Instead of hardcoding known FMRI classes here we'll try
	 * topo_fmri_nvl2str which should fail gracefully for invalid
	 * schemes (ie an nvlist that just happens to have the expected
	 * class and version members but that isn't an FMRI).
	 */
	if (topo_fmri_nvl2str(thp, fmri, &fmristr, &err) != 0 ||
	    fmristr == NULL)
		return (0);

	nvlist_prtctl_doindent(pctl, 1);
	nvlist_prtctl_dofmt(pctl, NVLIST_FMT_MEMBER_NAME, name);
	(void) fprintf(fp, "%s", fmristr);
	topo_hdl_strfree(thp, fmristr);

	return (1);
}

/*
 * Thin wrapper around libnvpair's inbuilt JSON routine.  Simply dumps the
 * entire log record nvlist without any reformatting.
 */

/*ARGSUSED*/
int
fmdump_print_json(fmd_log_t *lp, const fmd_log_record_t *rp, FILE *fp)
{
	if (nvlist_print_json(fp, rp->rec_nvl) != 0 || fprintf(fp, "\n") < 0 ||
	    fflush(fp) != 0)
		return (-1);

	return (0);
}
