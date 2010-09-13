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
#pragma ident	"%Z%%M%	%I%	%E% SMI" 

#include <sys/types.h>

/*
 * Copyright (c) 1987 by Sun Microsystems, Inc.
 */

char	*malloc();

struct handlers {
	void	(*handler)();
	caddr_t	arg;
	struct	handlers *next;
};

extern	struct handlers *_exit_handlers;

int
on_exit(handler, arg)
	void (*handler)();
	caddr_t arg;
{
	register struct handlers *h =
	    (struct handlers *)malloc(sizeof (*h));
	
	if (h == 0)
		return (-1);
	h->handler = handler;
	h->arg = arg;
	h->next = _exit_handlers;
	_exit_handlers = h;
	return (0);
}
