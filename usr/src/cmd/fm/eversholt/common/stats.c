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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * stats.c -- simple stats tracking table module
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <strings.h>
#include "stats.h"
#include "alloc.h"
#include "out.h"

struct stats {
	struct stats *next;
	const char *name;
	const char *desc;
	enum stats_type {
		STATS_COUNTER = 3000,
		STATS_ELAPSE,
		STATS_STRING
	} t;
	union {
		int counter;
		struct {
			hrtime_t start;
			hrtime_t stop;
		} elapse;
		const char *string;
	} u;
};

static int Ext;			/* true if extended stats are enabled */
static struct stats *Statslist;
static struct stats *Laststats;


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
	ret->name = STRDUP(name);
	ret->desc = STRDUP(desc);

	if (Laststats == NULL)
		Statslist = ret;
	else
		Laststats->next = ret;
	Laststats = ret;

	return (ret);
}

void
stats_delete(struct stats *sp)
{
	struct stats *p, *s;

	if (sp == NULL)
		return;

	for (p = NULL, s = Statslist; s != NULL; s = s->next)
		if (s == sp)
			break;

	if (s == NULL)
		return;

	if (p == NULL)
		Statslist = s->next;
	else
		p->next = s->next;

	if (s == Laststats)
		Laststats = p;

	FREE((void *)sp->name);
	FREE((void *)sp->desc);
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

	sp->u.counter++;
}

void
stats_counter_add(struct stats *sp, int n)
{
	if (sp == NULL)
		return;

	ASSERT(sp->t == STATS_COUNTER);

	sp->u.counter += n;
}

void
stats_counter_reset(struct stats *sp)
{
	if (sp == NULL)
		return;

	ASSERT(sp->t == STATS_COUNTER);

	sp->u.counter = 0;
}

int
stats_counter_value(struct stats *sp)
{
	if (sp == NULL)
		return (0);

	ASSERT(sp->t == STATS_COUNTER);

	return (sp->u.counter);
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

	sp->u.elapse.start = gethrtime();
}

void
stats_elapse_stop(struct stats *sp)
{
	if (sp == NULL)
		return;

	ASSERT(sp->t == STATS_ELAPSE);

	sp->u.elapse.stop = gethrtime();
}

struct stats *
stats_new_string(const char *name, const char *desc, int ext)
{
	if (ext && !Ext)
		return (NULL);		/* extended stats not enabled */

	return (stats_new(name, desc, STATS_STRING));
}

void
stats_string_set(struct stats *sp, const char *s)
{
	if (sp == NULL)
		return;

	ASSERT(sp->t == STATS_STRING);

	sp->u.string = s;
}

/*
 * stats_publish -- spew all stats
 *
 */

void
stats_publish(void)
{
	struct stats *sp;

	for (sp = Statslist; sp; sp = sp->next)
		switch (sp->t) {
		case STATS_COUNTER:
			out(O_OK, "%32s %13d %s", sp->name,
			    sp->u.counter, sp->desc);
			break;

		case STATS_ELAPSE:
			if (sp->u.elapse.start && sp->u.elapse.stop) {
				hrtime_t delta =
				    sp->u.elapse.stop - sp->u.elapse.start;

				out(O_OK, "%32s %11lldns %s", sp->name,
				    delta, sp->desc);
			}
			break;

		case STATS_STRING:
			out(O_OK, "%32s %13s %s", sp->name, sp->u.string,
			    sp->desc);
			break;

		default:
			out(O_DIE, "stats_publish: unknown type %d", sp->t);
		}
}
