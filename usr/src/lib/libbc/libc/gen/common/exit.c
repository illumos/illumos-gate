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

struct handlers {
	void	(*handler)();
	caddr_t	arg;
	struct	handlers *next;
};

extern	void _cleanup();

/* the list of handlers and their arguments */
struct	handlers *_exit_handlers;

/*
 * exit -- do termination processing, then evaporate process
 */
void
exit(code)
	int code;
{
	register struct handlers *h;

	while (h = _exit_handlers) {
		_exit_handlers = h->next;
		(*h->handler)(code, h->arg);
	}
	_cleanup();
	_exit(code);
}
