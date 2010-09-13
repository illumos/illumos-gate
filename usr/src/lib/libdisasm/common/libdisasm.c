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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libdisasm.h>
#include <stdlib.h>
#ifdef DIS_STANDALONE
#include <mdb/mdb_modapi.h>
#endif

static int _dis_errno;

/*
 * For the standalone library, we need to link against mdb's malloc/free.
 * Otherwise, use the standard malloc/free.
 */
#ifdef DIS_STANDALONE
void *
dis_zalloc(size_t bytes)
{
	return (mdb_zalloc(bytes, UM_SLEEP));
}

void
dis_free(void *ptr, size_t bytes)
{
	mdb_free(ptr, bytes);
}
#else
void *
dis_zalloc(size_t bytes)
{
	return (calloc(1, bytes));
}

/*ARGSUSED*/
void
dis_free(void *ptr, size_t bytes)
{
	free(ptr);
}
#endif

int
dis_seterrno(int error)
{
	_dis_errno = error;
	return (-1);
}

int
dis_errno(void)
{
	return (_dis_errno);
}

const char *
dis_strerror(int error)
{
	switch (error) {
	case E_DIS_NOMEM:
		return ("out of memory");
	case E_DIS_INVALFLAG:
		return ("invalid flags for this architecture");
	default:
		return ("unknown error");
	}
}
