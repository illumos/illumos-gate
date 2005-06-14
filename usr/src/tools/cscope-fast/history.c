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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	cscope - interactive C symbol or text cross-reference
 *
 *	command history
 */

#include <stdio.h>
#include "global.h"

HISTORY *head, *tail, *current;

/* add a cmd to the history list */
void
addcmd(int f, char *s)
{
	HISTORY *h;

	h = (HISTORY *)mymalloc(sizeof (HISTORY));
	if (tail) {
		tail->next = h;
		h->next = 0;
		h->previous = tail;
		tail = h;
	} else {
		head = tail = h;
		h->next = h->previous = 0;
	}
	h->field = f;
	h->text = stralloc(s);
	current = 0;
}

/* return previous history item */

HISTORY *
prevcmd(void)
{
	if (current) {
		if (current->previous)	/* stay on first item */
			return (current = current->previous);
		else
			return (current);
	} else if (tail)
		return (current = tail);
	else
		return (NULL);
}

/* return next history item */

HISTORY *
nextcmd(void)
{
	if (current) {
		if (current->next)	/* stay on first item */
			return (current = current->next);
		else
			return (current);
	} else
		return (NULL);
}

/* reset current to tail */

void
resetcmd(void)
{
	current = 0;
}

HISTORY *
currentcmd(void)
{
	return (current);
}
