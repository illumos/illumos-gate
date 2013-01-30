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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

#include <fmdump.h>
#include <stdio.h>
#include <strings.h>

/*ARGSUSED*/
static int
flt_short(fmd_log_t *lp, const fmd_log_record_t *rp, FILE *fp)
{
	char buf[32], str[32];
	char *class = NULL, *uuid = "-", *code = "-";

	static const struct {
		const char *class;
		const char *tag;
	} tags[] = {
		{ FM_LIST_SUSPECT_CLASS,	"Diagnosed" },
		{ FM_LIST_REPAIRED_CLASS,	"Repaired" },
		{ FM_LIST_RESOLVED_CLASS,	"Resolved" },
		{ FM_LIST_UPDATED_CLASS,	"Updated" },
		{ FM_LIST_ISOLATED_CLASS,	"Isolated" },
	};

	(void) nvlist_lookup_string(rp->rec_nvl, FM_SUSPECT_UUID, &uuid);
	(void) nvlist_lookup_string(rp->rec_nvl, FM_SUSPECT_DIAG_CODE, &code);

	(void) nvlist_lookup_string(rp->rec_nvl, FM_CLASS, &class);
	if (class != NULL) {
		int i;

		for (i = 0; i < sizeof (tags) / sizeof (tags[0]); i++) {
			if (strcmp(class, tags[i].class) == 0) {
				(void) snprintf(str, sizeof (str), "%s %s",
				    code, tags[i].tag);
				code = str;
				break;
			}
		}
	}

	fmdump_printf(fp, "%-20s %-32s %s\n",
	    fmdump_date(buf, sizeof (buf), rp), uuid, code);

	return (0);
}

static int
flt_verb1(fmd_log_t *lp, const fmd_log_record_t *rp, FILE *fp)
{
	uint_t i, size = 0;
	nvlist_t **nva;
	uint8_t *ba;

	(void) flt_short(lp, rp, fp);
	(void) nvlist_lookup_uint32(rp->rec_nvl, FM_SUSPECT_FAULT_SZ, &size);

	if (size != 0) {
		(void) nvlist_lookup_nvlist_array(rp->rec_nvl,
		    FM_SUSPECT_FAULT_LIST, &nva, &size);
		(void) nvlist_lookup_uint8_array(rp->rec_nvl,
		    FM_SUSPECT_FAULT_STATUS, &ba, &size);
	}

	for (i = 0; i < size; i++) {
		char *class = NULL, *rname = NULL, *aname = NULL, *fname = NULL;
		char *loc = NULL;
		nvlist_t *fru, *asru, *rsrc;
		uint8_t pct = 0;

		(void) nvlist_lookup_uint8(nva[i], FM_FAULT_CERTAINTY, &pct);
		(void) nvlist_lookup_string(nva[i], FM_CLASS, &class);

		if (nvlist_lookup_nvlist(nva[i], FM_FAULT_FRU, &fru) == 0)
			fname = fmdump_nvl2str(fru);

		if (nvlist_lookup_nvlist(nva[i], FM_FAULT_ASRU, &asru) == 0)
			aname = fmdump_nvl2str(asru);

		if (nvlist_lookup_nvlist(nva[i], FM_FAULT_RESOURCE, &rsrc) == 0)
			rname = fmdump_nvl2str(rsrc);

		if (nvlist_lookup_string(nva[i], FM_FAULT_LOCATION, &loc)
		    == 0) {
			if (fname && strncmp(fname, FM_FMRI_LEGACY_HC_PREFIX,
			    sizeof (FM_FMRI_LEGACY_HC_PREFIX)) == 0)
				loc = fname + sizeof (FM_FMRI_LEGACY_HC_PREFIX);
		}


		fmdump_printf(fp, "  %3u%%  %s",
		    pct, class ? class : "-");

		if (ba[i] & FM_SUSPECT_FAULTY)
			fmdump_printf(fp, "\n\n");
		else if (ba[i] & FM_SUSPECT_NOT_PRESENT)
			fmdump_printf(fp, "\tRemoved\n\n");
		else if (ba[i] & FM_SUSPECT_REPLACED)
			fmdump_printf(fp, "\tReplaced\n\n");
		else if (ba[i] & FM_SUSPECT_REPAIRED)
			fmdump_printf(fp, "\tRepair Attempted\n\n");
		else if (ba[i] & FM_SUSPECT_ACQUITTED)
			fmdump_printf(fp, "\tAcquitted\n\n");
		else
			fmdump_printf(fp, "\n\n");

		fmdump_printf(fp, "        Problem in: %s\n",
		    rname ? rname : "-");

		fmdump_printf(fp, "           Affects: %s\n",
		    aname ? aname : "-");

		fmdump_printf(fp, "               FRU: %s\n",
		    fname ? fname : "-");

		fmdump_printf(fp, "          Location: %s\n\n",
		    loc ? loc : "-");

		free(fname);
		free(aname);
		free(rname);
	}

	return (0);
}

static int
flt_verb23_cmn(fmd_log_t *lp, const fmd_log_record_t *rp, FILE *fp,
    nvlist_prtctl_t pctl)
{
	const struct fmdump_fmt *efp = &fmdump_err_ops.do_formats[FMDUMP_VERB1];
	const struct fmdump_fmt *ffp = &fmdump_flt_ops.do_formats[FMDUMP_VERB2];
	uint_t i;
	char buf[32], str[32];
	char *class = NULL, *uuid = "-", *code = "-";

	(void) nvlist_lookup_string(rp->rec_nvl, FM_SUSPECT_UUID, &uuid);
	(void) nvlist_lookup_string(rp->rec_nvl, FM_SUSPECT_DIAG_CODE, &code);

	(void) nvlist_lookup_string(rp->rec_nvl, FM_CLASS, &class);
	if (class != NULL && strcmp(class, FM_LIST_REPAIRED_CLASS) == 0) {
		(void) snprintf(str, sizeof (str), "%s %s", code, "Repaired");
		code = str;
	}
	if (class != NULL && strcmp(class, FM_LIST_RESOLVED_CLASS) == 0) {
		(void) snprintf(str, sizeof (str), "%s %s", code, "Resolved");
		code = str;
	}
	if (class != NULL && strcmp(class, FM_LIST_UPDATED_CLASS) == 0) {
		(void) snprintf(str, sizeof (str), "%s %s", code, "Updated");
		code = str;
	}

	fmdump_printf(fp, "%s\n", ffp->do_hdr);
	fmdump_printf(fp, "%-20s.%9.9llu %-32s %s\n",
	    fmdump_year(buf, sizeof (buf), rp), rp->rec_nsec, uuid, code);

	if (rp->rec_nrefs != 0)
		fmdump_printf(fp, "\n  %s\n", efp->do_hdr);

	for (i = 0; i < rp->rec_nrefs; i++) {
		fmdump_printf(fp, "  ");
		efp->do_func(lp, &rp->rec_xrefs[i], fp);
	}

	fmdump_printf(fp, "\n");
	if (pctl)
		nvlist_prt(rp->rec_nvl, pctl);
	else
		nvlist_print(fp, rp->rec_nvl);
	fmdump_printf(fp, "\n");

	return (0);
}

static int
flt_verb2(fmd_log_t *lp, const fmd_log_record_t *rp, FILE *fp)
{
	return (flt_verb23_cmn(lp, rp, fp, NULL));
}


static int
flt_pretty(fmd_log_t *lp, const fmd_log_record_t *rp, FILE *fp)
{
	nvlist_prtctl_t pctl;
	int rc;

	if ((pctl = nvlist_prtctl_alloc()) != NULL) {
		nvlist_prtctl_setdest(pctl, fp);
		nvlist_prtctlop_nvlist(pctl, fmdump_render_nvlist, NULL);
	}

	rc = flt_verb23_cmn(lp, rp, fp, pctl);

	nvlist_prtctl_free(pctl);
	return (rc);
}

/*
 * There is a lack of uniformity in how the various entries in our diagnosis
 * are terminated.  Some end with one newline, others with two.  This makes the
 * output of fmdump -m look a bit ugly.  Therefore we postprocess the message
 * before printing it, removing consecutive occurences of newlines.
 */
static void
postprocess_msg(char *msg)
{
	int i = 0, j = 0;
	char *buf;

	if ((buf = malloc(strlen(msg) + 1)) == NULL)
		return;

	buf[j++] = msg[i++];
	for (i = 1; i < strlen(msg); i++) {
		if (!(msg[i] == '\n' && msg[i - 1] == '\n'))
			buf[j++] = msg[i];
	}
	buf[j] = '\0';
	(void) strncpy(msg, buf, j+1);
	free(buf);
}

/*ARGSUSED*/
static int
flt_msg(fmd_log_t *lp, const fmd_log_record_t *rp, FILE *fp)
{
	char *msg;

	if ((msg = fmd_msg_gettext_nv(g_msg, NULL, rp->rec_nvl)) == NULL) {
		(void) fprintf(stderr, "%s: failed to format message: %s\n",
		    g_pname, strerror(errno));
		g_errs++;
		return (-1);
	} else {
		postprocess_msg(msg);
		fmdump_printf(fp, "%s\n", msg);
		free(msg);
	}

	return (0);
}

const fmdump_ops_t fmdump_flt_ops = {
"fault", {
{
"TIME                 UUID                                 SUNW-MSG-ID "
								"EVENT",
(fmd_log_rec_f *)flt_short
}, {
"TIME                 UUID                                 SUNW-MSG-ID "
								"EVENT",
(fmd_log_rec_f *)flt_verb1
}, {
"TIME                           UUID"
"                                 SUNW-MSG-ID",
(fmd_log_rec_f *)flt_verb2
}, {
"TIME                           UUID"
"                                 SUNW-MSG-ID",
(fmd_log_rec_f *)flt_pretty
}, {
NULL,
(fmd_log_rec_f *)flt_msg
}, {
NULL,
(fmd_log_rec_f *)fmdump_print_json
} }
};
