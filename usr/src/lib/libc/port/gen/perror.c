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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2025 Oxide Computer Company
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#include "lint.h"
#include "_libc_gettext.h"
#include "syserr.h"

#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * Print the error indicated
 * in the cerror cell.
 */
void
perror(const char *s)
{
	const char *c;
	int err = errno;

	if (err < _sys_num_nerr && err >= 0)
		c = _libc_gettext(&_sys_nerrs[_sys_nindex[err]]);
	else
		c = _libc_gettext("Unknown error");

	if (s && *s) {
		(void) write(2, s, strlen(s));
		(void) write(2, ": ", 2);
	}
	(void) write(2, c, strlen(c));
	(void) write(2, "\n", 1);
}
