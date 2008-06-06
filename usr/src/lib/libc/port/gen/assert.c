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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak __assert = _assert
#pragma weak __assert_c99 = _assert_c99

#include "lint.h"
#include "_libc_gettext.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include "libc.h"

/*
 * Called from "assert" macro; prints without printf or stdio.
 */
void
_assert(const char *assertion, const char *filename, int line_num)
{
	char buf[512];

	(void) snprintf(buf, sizeof (buf),
	    _libc_gettext("Assertion failed: %s, file %s, line %d\n"),
	    assertion, filename, line_num);
	(void) write(2, buf, strlen(buf));
	__set_panicstr(buf);
	abort();
}

/*
 * Called from "assert" macro in 1999 C based compiles; prints
 * function name in addition to the filename and line number
 * printed for earlier version C compiles.
 */
void
_assert_c99(const char *assertion, const char *filename, int line_num,
		const char *funcname)
{
	char buf[512];

	(void) snprintf(buf, sizeof (buf),
	    _libc_gettext("Assertion failed: %s, file %s, line %d, \
function %s\n"),
	    assertion, filename, line_num, funcname);
	(void) write(2, buf, strlen(buf));
	__set_panicstr(buf);
	abort();
}
