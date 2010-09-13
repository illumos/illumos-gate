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

#include "lint.h"
#include <sys/types.h>
#include <shadow.h>
#include <nss_dbdefs.h>
#include <stdio.h>
#include "tsd.h"

#ifdef	NSS_INCLUDE_UNSAFE

/*
 * Ye olde non-reentrant interface (MT-unsafe, caveat utor)
 */

static void
free_spbuf(void *arg)
{
	nss_XbyY_buf_t **buffer = arg;

	NSS_XbyY_FREE(buffer);
}

static nss_XbyY_buf_t *
get_spbuf()
{
	nss_XbyY_buf_t **buffer =
	    tsdalloc(_T_SPBUF, sizeof (nss_XbyY_buf_t *), free_spbuf);
	nss_XbyY_buf_t *b;

	if (buffer == NULL)
		return (NULL);
	b = NSS_XbyY_ALLOC(buffer, sizeof (struct spwd), NSS_BUFLEN_SHADOW);
	return (b);
}

struct spwd *
getspnam(const char *nam)
{
	nss_XbyY_buf_t	*b = get_spbuf();

	return (b == NULL ? NULL :
	    getspnam_r(nam, b->result, b->buffer, b->buflen));
}

struct spwd *
getspent(void)
{
	nss_XbyY_buf_t	*b = get_spbuf();

	return (b == NULL ? NULL :
	    getspent_r(b->result, b->buffer, b->buflen));
}

struct spwd *
fgetspent(FILE *f)
{
	nss_XbyY_buf_t	*b = get_spbuf();

	return (b == NULL ? NULL :
	    fgetspent_r(f, b->result, b->buffer, b->buflen));
}

#endif	/* NSS_INCLUDE_UNSAFE */
