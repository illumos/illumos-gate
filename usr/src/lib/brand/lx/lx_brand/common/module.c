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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * We don't support Linux modules, but we have to emulate enough of the system
 * calls to show that we don't have any modules installed.
 */

#include <errno.h>
#include <sys/types.h>
#include <sys/lx_misc.h>
#include <sys/lx_syscall.h>

/*
 * For query_module(), we provide an empty list of modules, and return ENOENT
 * on any request for a specific module.
 */
#define	LX_QM_MODULES	1
#define	LX_QM_DEPS	2
#define	LX_QM_REFS	3
#define	LX_QM_SYMBOLS	4
#define	LX_QM_INFO	5

/*ARGSUSED*/
long
lx_query_module(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4,
    uintptr_t p5)
{
	/*
	 * parameter p1 is the 'name' argument.
	 */
	int which = (int)p2;
	char *buf = (char *)p3;
	size_t bufsize = (size_t)p4;
	size_t *ret = (size_t *)p5;

	switch (which) {
	case 0:
		/*
		 * Special case: always return 0
		 */
		return (0);

	case LX_QM_MODULES:
		/*
		 * Generate an empty list of modules.
		 */
		if (bufsize && buf)
			buf[0] = '\0';
		if (ret)
			*ret = 0;
		return (0);

	case LX_QM_DEPS:
	case LX_QM_REFS:
	case LX_QM_SYMBOLS:
	case LX_QM_INFO:
		/*
		 * Any requests for specific module information return ENOENT.
		 */
		return (-ENOENT);

	default:
		return (-EINVAL);
	}
}
