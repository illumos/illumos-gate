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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

static int
asru_verb2(fmd_log_t *lp, const fmd_log_record_t *rp, FILE *fp)
{
	(void) asru_verb1(lp, rp, fp);

	nvlist_print(fp, rp->rec_nvl);
	fmdump_printf(fp, "\n");

	return (0);
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
"TIME                 UUID                                 STATE",
(fmd_log_rec_f *)asru_verb2
} }
};
