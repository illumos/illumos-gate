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
#include <strings.h>
#include <stdio.h>
#include <time.h>

/*ARGSUSED*/
static int
asru_short(fmd_log_t *lp, const fmd_log_record_t *rp, FILE *fp)
{
	char buf[32];

	fmdump_printf(fp, "%-20s %-32s\n",
	    fmdump_date(buf, sizeof (buf), rp), rp->rec_class);

	return (0);
}

/*ARGSUSED*/
static int
asru_verb1(fmd_log_t *lp, const fmd_log_record_t *rp, FILE *fp)
{
	char *uuid = "-";
	boolean_t f = 0, u = 0;
	char buf[32], state[32];

	(void) nvlist_lookup_string(rp->rec_nvl, FM_RSRC_ASRU_UUID, &uuid);
	(void) nvlist_lookup_boolean_value(rp->rec_nvl,
	    FM_RSRC_ASRU_FAULTY, &f);
	(void) nvlist_lookup_boolean_value(rp->rec_nvl,
	    FM_RSRC_ASRU_UNUSABLE, &u);

	state[0] = '\0';

	if (f)
		(void) strcat(state, ",faulty");
	if (u)
		(void) strcat(state, ",unusable");
	if (!f && !u)
		(void) strcat(state, ",ok");

	fmdump_printf(fp, "%-20s %-36s %s\n",
	    fmdump_date(buf, sizeof (buf), rp), uuid, state + 1);

	return (0);
}

/*ARGSUSED*/
static int
asru_verb23_cmn(fmd_log_t *lp, const fmd_log_record_t *rp, FILE *fp,
    nvlist_prtctl_t pctl)
{
	char *uuid = "-";
	boolean_t f = 0, u = 0;
	char buf[32], state[32];

	(void) nvlist_lookup_string(rp->rec_nvl, FM_RSRC_ASRU_UUID, &uuid);
	(void) nvlist_lookup_boolean_value(rp->rec_nvl,
	    FM_RSRC_ASRU_FAULTY, &f);
	(void) nvlist_lookup_boolean_value(rp->rec_nvl,
	    FM_RSRC_ASRU_UNUSABLE, &u);

	state[0] = '\0';

	if (f)
		(void) strcat(state, ",faulty");
	if (u)
		(void) strcat(state, ",unusable");
	if (!f && !u)
		(void) strcat(state, ",ok");

	fmdump_printf(fp, "%-20s.%9.9llu %-36s %s\n",
	    fmdump_year(buf, sizeof (buf), rp), rp->rec_nsec, uuid, state + 1);

	if (pctl)
		nvlist_prt(rp->rec_nvl, pctl);
	else
		nvlist_print(fp, rp->rec_nvl);

	fmdump_printf(fp, "\n");

	return (0);
}

static int
asru_verb2(fmd_log_t *lp, const fmd_log_record_t *rp, FILE *fp)
{
	return (asru_verb23_cmn(lp, rp, fp, NULL));
}

static int
asru_pretty(fmd_log_t *lp, const fmd_log_record_t *rp, FILE *fp)
{
	nvlist_prtctl_t pctl;
	int rc;

	if ((pctl = nvlist_prtctl_alloc()) != NULL) {
		nvlist_prtctl_setdest(pctl, fp);
		nvlist_prtctlop_nvlist(pctl, fmdump_render_nvlist, NULL);
	}

	rc = asru_verb23_cmn(lp, rp, fp, pctl);

	nvlist_prtctl_free(pctl);
	return (rc);
}

const fmdump_ops_t fmdump_asru_ops = {
"asru", {
{
"TIME                 CLASS",
(fmd_log_rec_f *)asru_short
}, {
"TIME                 UUID                                 STATE",
(fmd_log_rec_f *)asru_verb1
}, {
"TIME                           UUID                                 STATE",
(fmd_log_rec_f *)asru_verb2
}, {
"TIME                           UUID                                 STATE",
(fmd_log_rec_f *)asru_pretty
}, {
NULL, NULL
}, {
NULL,
(fmd_log_rec_f *)fmdump_print_json
} }
};
