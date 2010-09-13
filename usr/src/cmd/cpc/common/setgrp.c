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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <libintl.h>
#include <sys/types.h>


#include <libcpc.h>
#include "cpucmds.h"

#define	CHARS_PER_REQ 11	/* space required for printing column headers */

/*
 * These routines are solely used to manage a list of request sets.
 */

struct __cpc_setgrp {
	struct setgrp_elem {
		cpc_set_t	*set;
		uint8_t		sysonly;	/* All reqs sys-mode only ? */
		int		nreqs;
		int		*picnums;	/* picnum used per req */
		cpc_buf_t	*data1;
		cpc_buf_t	*data2;
		cpc_buf_t	*scratch;
		char *name;
		char *hdr;
	} *sets;		/* array of events and names */
	int nelem;		/* size of array */
	int current;		/* currently bound event in eventset */
	int smt;		/* Measures physical events on SMT CPU */
	int has_sysonly_set;	/* Does this group have a system-only set? */
	cpc_t *cpc;		/* library handle */
};

static void *emalloc(size_t n);

cpc_setgrp_t *
cpc_setgrp_new(cpc_t *cpc, int smt)
{
	cpc_setgrp_t *sgrp;

	sgrp = emalloc(sizeof (*sgrp));
	sgrp->current = -1;
	sgrp->cpc = cpc;
	sgrp->smt = smt;
	sgrp->has_sysonly_set = 0;
	return (sgrp);
}

/*
 * Walker to count the number of requests in a set, and check if any requests
 * count user-mode events.
 */
/*ARGSUSED*/
static void
cpc_setgrp_walker(void *arg, int index, const char *event, uint64_t preset,
    uint_t flags, int nattrs, const cpc_attr_t *attrs)
{
	struct setgrp_elem *se = arg;

	se->nreqs++;
	if (flags & CPC_COUNT_USER)
		se->sysonly = 0;
}

/*
 * Walker to discover the picnums used by the requests in a set.
 */
/*ARGSUSED*/
static void
cpc_setgrp_picwalker(void *arg, int index, const char *event, uint64_t preset,
    uint_t flags, int nattrs, const cpc_attr_t *attrs)
{
	int *picnums = arg;
	int i;

	for (i = 0; i < nattrs; i++) {
		if (strncmp(attrs[i].ca_name, "picnum", 7) == 0)
			break;
	}
	if (i == nattrs)
		picnums[index] = -1;

	picnums[index] = (int)attrs[i].ca_val;
}

cpc_setgrp_t *
cpc_setgrp_newset(cpc_setgrp_t *sgrp, const char *spec, int *errcnt)
{
	cpc_set_t		*set;
	struct setgrp_elem	*new;
	char			hdr[CHARS_PER_REQ+1];
	int			i;

	if ((set = cpc_strtoset(sgrp->cpc, spec, sgrp->smt)) == NULL) {
		*errcnt += 1;
		return (NULL);
	}

	if ((new = realloc(sgrp->sets, (1 + sgrp->nelem) * sizeof (*new)))
	    == NULL) {
		(void) fprintf(stderr,
		    gettext("cpc_setgrp: no re memory available\n"));
		exit(0);
	}

	sgrp->sets = new;
	sgrp->sets[sgrp->nelem].set = set;
	/*
	 * Count the number of requests in the set we just made. If any requests
	 * in the set have CPC_COUNT_USER in the flags, the sysonly flag will
	 * be cleared.
	 */
	sgrp->sets[sgrp->nelem].nreqs = 0;
	sgrp->sets[sgrp->nelem].sysonly = 1;
	cpc_walk_requests(sgrp->cpc, set, &(sgrp->sets[sgrp->nelem]),
	    cpc_setgrp_walker);

	if (sgrp->sets[sgrp->nelem].sysonly == 1)
		sgrp->has_sysonly_set = 1;

	sgrp->sets[sgrp->nelem].picnums = emalloc(sgrp->sets[sgrp->nelem].nreqs
	    * sizeof (int));

	sgrp->sets[sgrp->nelem].hdr = emalloc((sgrp->sets[sgrp->nelem].nreqs *
	    CHARS_PER_REQ) + 1);

	/*
	 * Find out which picnums the requests are using.
	 */
	cpc_walk_requests(sgrp->cpc, set, sgrp->sets[sgrp->nelem].picnums,
	    cpc_setgrp_picwalker);
	/*
	 * Use the picnums we discovered to build a printable header for this
	 * set.
	 */
	sgrp->sets[sgrp->nelem].hdr[0] = '\0';
	for (i = 0; i < sgrp->sets[sgrp->nelem].nreqs; i++) {
		(void) snprintf(hdr, CHARS_PER_REQ, "%8s%-2d ", "pic",
		    sgrp->sets[sgrp->nelem].picnums[i]);
		(void) strncat(sgrp->sets[sgrp->nelem].hdr, hdr,
		    sgrp->sets[sgrp->nelem].nreqs * CHARS_PER_REQ);
	}
	sgrp->sets[sgrp->nelem].hdr[strlen(sgrp->sets[sgrp->nelem].hdr)] = '\0';

	if ((sgrp->sets[sgrp->nelem].name = strdup(spec)) == NULL) {
		(void) fprintf(stderr,
		    gettext("cpc_setgrp: no memory available\n"));
		exit(0);
	}

	if ((sgrp->sets[sgrp->nelem].data1 = cpc_buf_create(sgrp->cpc, set))
	    == NULL ||
	    (sgrp->sets[sgrp->nelem].data2 = cpc_buf_create(sgrp->cpc, set))
	    == NULL ||
	    (sgrp->sets[sgrp->nelem].scratch = cpc_buf_create(sgrp->cpc, set))
	    == NULL) {
		(void) fprintf(stderr,
		    gettext("cpc_setgrp: no memory available\n"));
		exit(0);
	}

	if (sgrp->current < 0)
		sgrp->current = 0;
	sgrp->nelem++;
	return (sgrp);
}

int
cpc_setgrp_getbufs(cpc_setgrp_t *sgrp, cpc_buf_t ***data1, cpc_buf_t ***data2,
    cpc_buf_t ***scratch)
{
	if ((uint_t)sgrp->current >= sgrp->nelem)
		return (-1);

	*data1   = &(sgrp->sets[sgrp->current].data1);
	*data2   = &(sgrp->sets[sgrp->current].data2);
	*scratch = &(sgrp->sets[sgrp->current].scratch);

	return (sgrp->sets[sgrp->current].nreqs);
}

cpc_setgrp_t *
cpc_setgrp_clone(cpc_setgrp_t *old)
{
	int			i;
	cpc_setgrp_t		*new;
	struct setgrp_elem	*newa;

	new = emalloc(sizeof (*new));
	newa = emalloc(old->nelem * sizeof (*newa));

	new->nelem = old->nelem;
	new->current = old->current;
	new->cpc = old->cpc;
	new->sets = newa;
	new->smt = old->smt;
	new->has_sysonly_set = old->has_sysonly_set;
	for (i = 0; i < old->nelem; i++) {
		if ((newa[i].set = cpc_strtoset(old->cpc, old->sets[i].name,
		    old->smt)) == NULL) {
			(void) fprintf(stderr,
			    gettext("cpc_setgrp: cpc_strtoset() failed\n"));
			exit(0);
		}
		if ((newa[i].name = strdup(old->sets[i].name)) == NULL) {
			(void) fprintf(stderr,
			    gettext("cpc_setgrp: no memory available\n"));
			exit(0);
		}
		newa[i].sysonly = old->sets[i].sysonly;
		newa[i].nreqs = old->sets[i].nreqs;
		newa[i].data1 = cpc_buf_create(old->cpc, newa[i].set);
		newa[i].data2 = cpc_buf_create(old->cpc, newa[i].set);
		newa[i].scratch = cpc_buf_create(old->cpc, newa[i].set);
		if (newa[i].data1 == NULL || newa[i].data2 == NULL ||
		    newa[i].scratch == NULL) {
			(void) fprintf(stderr,
			    gettext("cpc_setgrp: no memory available\n"));
			exit(0);
		}
		cpc_buf_copy(old->cpc, newa[i].data1, old->sets[i].data1);
		cpc_buf_copy(old->cpc, newa[i].data2, old->sets[i].data2);
		cpc_buf_copy(old->cpc, newa[i].scratch, old->sets[i].scratch);
	}
	return (new);
}

static void
cpc_setgrp_delset(cpc_setgrp_t *sgrp)
{
	int l;

	if ((uint_t)sgrp->current >= sgrp->nelem)
		sgrp->current = sgrp->nelem - 1;
	if (sgrp->current < 0)
		return;
	free(sgrp->sets[sgrp->current].name);
	free(sgrp->sets[sgrp->current].hdr);
	free(sgrp->sets[sgrp->current].picnums);
	(void) cpc_buf_destroy(sgrp->cpc, sgrp->sets[sgrp->current].data1);
	(void) cpc_buf_destroy(sgrp->cpc, sgrp->sets[sgrp->current].data2);
	(void) cpc_buf_destroy(sgrp->cpc, sgrp->sets[sgrp->current].scratch);
	for (l = sgrp->current; l < sgrp->nelem - 1; l++)
		sgrp->sets[l] = sgrp->sets[l + 1];
	sgrp->nelem--;
}

void
cpc_setgrp_free(cpc_setgrp_t *sgrp)
{
	if (sgrp->sets) {
		while (sgrp->nelem)
			cpc_setgrp_delset(sgrp);
		free(sgrp->sets);
	}
	free(sgrp);
}

cpc_set_t *
cpc_setgrp_getset(cpc_setgrp_t *sgrp)
{
	if ((uint_t)sgrp->current >= sgrp->nelem)
		return (NULL);
	return (sgrp->sets[sgrp->current].set);
}

const char *
cpc_setgrp_getname(cpc_setgrp_t *sgrp)
{
	if ((uint_t)sgrp->current >= sgrp->nelem)
		return (NULL);
	return (sgrp->sets[sgrp->current].name);
}

const char *
cpc_setgrp_gethdr(cpc_setgrp_t *sgrp)
{
	if ((uint_t)sgrp->current >= sgrp->nelem)
		return (NULL);
	return (sgrp->sets[sgrp->current].hdr);
}

int
cpc_setgrp_numsets(cpc_setgrp_t *sgrp)
{
	return (sgrp->nelem);
}

cpc_set_t *
cpc_setgrp_nextset(cpc_setgrp_t *sgrp)
{
	if (sgrp->current < 0)
		return (NULL);

	if (++sgrp->current >= sgrp->nelem)
		sgrp->current = 0;

	return (cpc_setgrp_getset(sgrp));
}

/*
 * Put the setgrp pointer back to the beginning of the set
 */
void
cpc_setgrp_reset(cpc_setgrp_t *sgrp)
{
	if (sgrp->current > 0)
		sgrp->current = 0;
}

/*
 * Adds the data from the 'data1' buf into the accum setgrp.
 */
void
cpc_setgrp_accum(cpc_setgrp_t *accum, cpc_setgrp_t *sgrp)
{
	int i;

	cpc_setgrp_reset(accum);
	cpc_setgrp_reset(sgrp);
	if (accum->nelem != sgrp->nelem)
		return;

	for (i = 0; i < sgrp->nelem; i++) {
		if (accum->sets[i].nreqs != sgrp->sets[i].nreqs)
			return;
		cpc_buf_add(sgrp->cpc, accum->sets[i].data1,
		    accum->sets[i].data1, sgrp->sets[i].data1);
	}
}

/*
 * Returns 1 if all requests in the current set count only system-mode events.
 */
int
cpc_setgrp_sysonly(cpc_setgrp_t *sgrp)
{
	return ((int)sgrp->sets[sgrp->current].sysonly);
}

/*
 * Returns 1 if any set in the group is a system-mode-only set.
 */
int
cpc_setgrp_has_sysonly(cpc_setgrp_t *sgrp)
{
	return (sgrp->has_sysonly_set);
}

/*
 * If we ever fail to get memory, we print an error message and exit.
 */
static void *
emalloc(size_t n)
{
	/*
	 * Several callers of this routine need zero-filled buffers.
	 */
	void *p = calloc(1, n);

	if (p == NULL) {
		(void) fprintf(stderr,
		    gettext("cpc_setgrp: no memory available\n"));
		exit(0);
	}

	return (p);
}
