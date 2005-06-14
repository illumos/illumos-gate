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

#include <fmdump.h>
#include <stdio.h>

/*ARGSUSED*/
static int
flt_short(fmd_log_t *lp, const fmd_log_record_t *rp, FILE *fp)
{
	char buf[32], *uuid = "-", *code = "-";

	(void) nvlist_lookup_string(rp->rec_nvl, FM_SUSPECT_UUID, &uuid);
	(void) nvlist_lookup_string(rp->rec_nvl, FM_SUSPECT_DIAG_CODE, &code);

	fmdump_printf(fp, "%-15s.%4.4llu %-32s %s\n",
	    fmdump_date(buf, sizeof (buf), rp),
	    rp->rec_nsec / (NANOSEC / 10000), uuid, code);

	return (0);
}

static int
flt_verb1(fmd_log_t *lp, const fmd_log_record_t *rp, FILE *fp)
{
	uint_t i, size = 0;
	nvlist_t **nva;

	(void) flt_short(lp, rp, fp);
	(void) nvlist_lookup_uint32(rp->rec_nvl, FM_SUSPECT_FAULT_SZ, &size);

	if (size != 0) {
		(void) nvlist_lookup_nvlist_array(rp->rec_nvl,
		    FM_SUSPECT_FAULT_LIST, &nva, &size);
	}

	for (i = 0; i < size; i++) {
		char *class = NULL, *rname = NULL, *fname = NULL;
		nvlist_t *fru, *rsc;
		uint8_t pct = 0;

		(void) nvlist_lookup_uint8(nva[i], FM_FAULT_CERTAINTY, &pct);
		(void) nvlist_lookup_string(nva[i], FM_CLASS, &class);

		if (nvlist_lookup_nvlist(nva[i], FM_FAULT_FRU, &fru) == 0)
			fname = fmdump_nvl2str(fru);

		if (nvlist_lookup_nvlist(nva[i], FM_FAULT_RESOURCE, &rsc) == 0)
			rname = fmdump_nvl2str(rsc);
		else if (nvlist_lookup_nvlist(nva[i], FM_FAULT_ASRU, &rsc) == 0)
			rname = fmdump_nvl2str(rsc);

		fmdump_printf(fp, "  %3u%%  %s\n"
		    "         FRU: %s\n        rsrc: %s\n\n",
		    pct, class ? class : "-",
		    fname ? fname : "-", rname ? rname : "-");

		free(fname);
		free(rname);
	}

	return (0);
}

static int
flt_verb2(fmd_log_t *lp, const fmd_log_record_t *rp, FILE *fp)
{
	const struct fmdump_fmt *efp = &fmdump_err_ops.do_formats[FMDUMP_VERB1];
	const struct fmdump_fmt *ffp = &fmdump_flt_ops.do_formats[FMDUMP_VERB1];
	uint_t i;

	fmdump_printf(fp, "%s\n", ffp->do_hdr);
	(void) flt_short(lp, rp, fp);

	if (rp->rec_nrefs != 0)
		fmdump_printf(fp, "\n  %s\n", efp->do_hdr);

	for (i = 0; i < rp->rec_nrefs; i++) {
		fmdump_printf(fp, "  ");
		efp->do_func(lp, &rp->rec_xrefs[i], fp);
	}

	fmdump_printf(fp, "\n");
	nvlist_print(fp, rp->rec_nvl);
	fmdump_printf(fp, "\n");

	return (0);
}

const fmdump_ops_t fmdump_flt_ops = {
"fault", {
{
"TIME                 UUID                                 SUNW-MSG-ID",
(fmd_log_rec_f *)flt_short
}, {
"TIME                 UUID                                 SUNW-MSG-ID",
(fmd_log_rec_f *)flt_verb1
}, {
NULL,
(fmd_log_rec_f *)flt_verb2
} }
};
