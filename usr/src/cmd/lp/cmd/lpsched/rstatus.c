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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lpsched.h"


/**
 ** insertr()
 **/

void
insertr(RSTATUS *r)
{
	RSTATUS			*prs;


	if (!Request_List) {
		Request_List = r;
		return;
	}
	
	for (prs = Request_List; prs; prs = prs->next) {
		if (rsort(&r, &prs) < 0) {
			r->prev = prs->prev;
			if (r->prev)
				r->prev->next = r;
			r->next = prs;
			prs->prev = r;
			if (prs == Request_List)
				Request_List = r;
			return;
		}

		if (prs->next)
			continue;

		r->prev = prs;
		prs->next = r;
		return;
	}
}

/**
 ** remover()
 **/

void
remover(RSTATUS *r)
{
	if (r == Request_List)		/* on the request chain */
		Request_List = r->next;
	
	if (r->next)
		r->next->prev = r->prev;
	
	if (r->prev)
		r->prev->next = r->next;
	
	r->next = 0;
	r->prev = 0;
	return;
}

/**
 ** request_by_id()
 **/

RSTATUS *
request_by_id(char *id)
{
	register RSTATUS	*prs;
	
	for (prs = Request_List; prs; prs = prs->next)
		if (STREQU(id, prs->secure->req_id))
			return (prs);
	return (0);
}

RSTATUS *
request_by_id_num( long num )
{
	register RSTATUS        *prs;

	for (prs = Request_List; prs; prs = prs->next) {
		char *tmp = strrchr(prs->secure->req_id, '-');

		if (tmp && (num == atol(++tmp)))
			return (prs);
	}
	return(0);
}


/**
 ** rsort()
 **/

static int		later ( RSTATUS * , RSTATUS * );

int
rsort (RSTATUS **p1, RSTATUS **p2)
{
	/*
	 * Of two requests needing immediate handling, the first
	 * will be the request with the LATER date. In case of a tie,
	 * the first is the one with the larger request ID (i.e. the
	 * one that came in last).
	 */
	if ((*p1)->request->outcome & RS_IMMEDIATE)
		if ((*p2)->request->outcome & RS_IMMEDIATE)
			if (later(*p1, *p2))
				return (-1);
			else
				return (1);
		else
			return (-1);

	else if ((*p2)->request->outcome & RS_IMMEDIATE)
		return (1);

	/*
	 * Of two requests not needing immediate handling, the first
	 * will be the request with the highest priority. If both have
	 * the same priority, the first is the one with the EARLIER date.
	 * In case of a tie, the first is the one with the smaller ID
	 * (i.e. the one that came in first).
	 */
	else if ((*p1)->request->priority == (*p2)->request->priority)
		if (!later(*p1, *p2))
			return (-1);
		else
			return (1);

	else
		return ((*p1)->request->priority - (*p2)->request->priority);
	/*NOTREACHED*/
}

static int
later(RSTATUS *prs1, RSTATUS *prs2)
{
	if (prs1->secure->date > prs2->secure->date)
		return (1);

	else if (prs1->secure->date < prs2->secure->date)
		return (0);

	/*
	 * The dates are the same, so compare the request IDs.
	 * One problem with comparing request IDs is that the order
	 * of two IDs may be reversed if the IDs wrapped around. This
	 * is a very unlikely problem, because the cycle should take
	 * more than one second to wrap!
	 */
	else {
		register int		len1 = strlen(prs1->req_file),
					len2 = strlen(prs2->req_file);

		/*
		 * Use the request file name (ID-0) for comparison,
		 * because the real request ID (DEST-ID) won't compare
		 * properly because of the destination prefix.
		 * The strlen() comparison is necessary, otherwise
		 * IDs like "99-0" and "100-0" will compare wrong.
		 */
		if (len1 > len2)
			return (1);
		else if (len1 < len2)
			return (0);
		else
			return (strcmp(prs1->req_file, prs2->req_file) > 0);
	}
	/*NOTREACHED*/
}
