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
 *
 * stats.c -- simple stats tracking table module
 *
 * this version of stats.c links with eft and implements the
 * stats using the fmd's stats API.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <strings.h>
#include "stats.h"
#include "alloc.h"
#include "out.h"
#include "stats_impl.h"
#include <fm/fmd_api.h>

extern fmd_hdl_t *Hdl;		/* handle from eft.c */

static int Ext;			/* true if extended stats are enabled */

/*
 * stats_init -- initialize the stats module
 *
 */

void
stats_init(int ext)
{
	Ext = ext;
}

void
stats_fini(void)
{
}

static struct stats *
stats_new(const char *name, const char *desc, enum stats_type t)
{
	struct stats *ret = MALLOC(sizeof (*ret));

	bzero(ret, sizeof (*ret));
	ret->t = t;

	(void) strlcpy(ret->fmd_stats.fmds_desc, desc,
	    sizeof (ret->fmd_stats.fmds_desc));

	/* NULL name means generate a unique name */
	if (name == NULL) {
		static int uniqstat;

		(void) snprintf(ret->fmd_stats.fmds_name,
		    sizeof (ret->fmd_stats.fmds_name),
		    "stat.rules%d", uniqstat++);
	} else {
		(void) strlcpy(ret->fmd_stats.fmds_name, name,
		    sizeof (ret->fmd_stats.fmds_name));
	}

	switch (t) {
	case STATS_COUNTER:
		ret->fmd_stats.fmds_type = FMD_TYPE_INT32;
		break;

	case STATS_ELAPSE:
		ret->fmd_stats.fmds_type = FMD_TYPE_TIME;
		break;

	case STATS_STRING:
		ret->fmd_stats.fmds_type = FMD_TYPE_STRING;
		break;

	default:
		out(O_DIE, "stats_new: unknown type %d", t);
	}

	(void) fmd_stat_create(Hdl, FMD_STAT_NOALLOC, 1, &(ret->fmd_stats));

	return (ret);
}

void
stats_delete(struct stats *sp)
{
	if (sp == NULL)
		return;

	fmd_stat_destroy(Hdl, 1, &(sp->fmd_stats));
	FREE(sp);
}

struct stats *
stats_new_counter(const char *name, const char *desc, int ext)
{
	if (ext && !Ext)
		return (NULL);		/* extended stats not enabled */

	return (stats_new(name, desc, STATS_COUNTER));
}

void
stats_counter_bump(struct stats *sp)
{
	if (sp == NULL)
		return;

	ASSERT(sp->t == STATS_COUNTER);

	sp->fmd_stats.fmds_value.i32++;
}

void
stats_counter_add(struct stats *sp, int n)
{
	if (sp == NULL)
		return;

	ASSERT(sp->t == STATS_COUNTER);

	sp->fmd_stats.fmds_value.i32 += n;
}

void
stats_counter_reset(struct stats *sp)
{
	if (sp == NULL)
		return;

	ASSERT(sp->t == STATS_COUNTER);

	sp->fmd_stats.fmds_value.i32 = 0;
}

int
stats_counter_value(struct stats *sp)
{
	if (sp == NULL)
		return (0);

	ASSERT(sp->t == STATS_COUNTER);

	return (sp->fmd_stats.fmds_value.i32);
}

struct stats *
stats_new_elapse(const char *name, const char *desc, int ext)
{
	if (ext && !Ext)
		return (NULL);		/* extended stats not enabled */

	return (stats_new(name, desc, STATS_ELAPSE));
}

void
stats_elapse_start(struct stats *sp)
{
	if (sp == NULL)
		return;

	ASSERT(sp->t == STATS_ELAPSE);

	sp->start = gethrtime();
}

void
stats_elapse_stop(struct stats *sp)
{
	if (sp == NULL)
		return;

	ASSERT(sp->t == STATS_ELAPSE);

	sp->stop = gethrtime();
	sp->fmd_stats.fmds_value.ui64 = sp->stop - sp->start;
}

struct stats *
stats_new_string(const char *name, const char *desc, int ext)
{
	struct stats *r;

	if (ext && !Ext)
		return (NULL);		/* extended stats not enabled */

	r = stats_new(name, desc, STATS_STRING);
	return (r);
}

void
stats_string_set(struct stats *sp, const char *s)
{
	if (sp == NULL)
		return;

	ASSERT(sp->t == STATS_STRING);

	if (sp->fmd_stats.fmds_value.str)
		fmd_hdl_strfree(Hdl, sp->fmd_stats.fmds_value.str);
	sp->fmd_stats.fmds_value.str = fmd_hdl_strdup(Hdl, s, FMD_SLEEP);
}

/*
 * stats_publish -- spew all stats
 *
 */

void
stats_publish(void)
{
	/* nothing to do for eft */
}
