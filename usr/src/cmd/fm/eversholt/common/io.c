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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * io.c -- io wrapper functions, replacable in more constrained
 * environments, such as within a DE.
 */

#include <stdio.h>
#include <stdlib.h>

void
io_abort(const char *buf)
{
	(void) fprintf(stderr, "%s\n", buf);
	abort();
}

void
io_die(const char *buf)
{
	(void) fprintf(stderr, "%s\n", buf);
	exit(1);
}

void
io_err(const char *buf)
{
	(void) fprintf(stderr, "%s\n", buf);
}

void
io_out(const char *buf)
{
	(void) printf("%s\n", buf);
}

void
io_exit(int code)
{
	exit(code);
}
