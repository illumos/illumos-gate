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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma weak __fex_get_handling = fex_get_handling
#pragma weak __fex_set_handling = fex_set_handling
#pragma weak __fex_getexcepthandler = fex_getexcepthandler
#pragma weak __fex_setexcepthandler = fex_setexcepthandler

#include <fenv.h>
#include <ucontext.h>
#include <thread.h>
#include "fex_handler.h"

int fex_get_handling(int e)
{
	struct fex_handler_data	*thr_handlers;
	int						i;

	thr_handlers = __fex_get_thr_handlers();
	for (i = 0; i < FEX_NUM_EXC; i++)
		if (e & (1 << i))
			return thr_handlers[i].__mode;
	return FEX_NOHANDLER;
}

int fex_set_handling(int e, int mode, void (*handler)())
{
	struct fex_handler_data	*thr_handlers;
	int						i;

	if (e & ~((1 << FEX_NUM_EXC) - 1))
		return 0;
	thr_handlers = __fex_get_thr_handlers();
	for (i = 0; i < FEX_NUM_EXC; i++) {
		if (e & (1 << i)) {
			thr_handlers[i].__mode = mode;
			thr_handlers[i].__handler = handler;
		}
	}
	__fex_update_te();
	return 1;
}

void fex_getexcepthandler(fex_handler_t *buf, int e)
{
	struct fex_handler_data	*thr_handlers;
	int						i;

	thr_handlers = __fex_get_thr_handlers();
	for (i = 0; i < FEX_NUM_EXC; i++)
		if (e & (1 << i))
			(*buf)[i] = thr_handlers[i];
}

void fex_setexcepthandler(const fex_handler_t *buf, int e)
{
	struct fex_handler_data	*thr_handlers;
	int						i;

	thr_handlers = __fex_get_thr_handlers();
	for (i = 0; i < FEX_NUM_EXC; i++)
		if (e & (1 << i))
			thr_handlers[i] = (*buf)[i];
	__fex_update_te();
}
