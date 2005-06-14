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
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*	3.0 SID #	1.2	*/

#pragma weak getgrnam	= _getgrnam
#pragma weak getgrgid	= _getgrgid
#pragma weak getgrent	= _getgrent
#pragma weak fgetgrent	= _fgetgrent

#include "synonyms.h"
#include <sys/types.h>
#include <grp.h>
#include <nss_dbdefs.h>
#include <stdio.h>
#include "tsd.h"

#ifdef	NSS_INCLUDE_UNSAFE

/*
 * Ye olde non-reentrant interface (MT-unsafe, caveat utor)
 */

static void
free_grbuf(void *arg)
{
	nss_XbyY_buf_t **buffer = arg;

	NSS_XbyY_FREE(buffer);
}

static nss_XbyY_buf_t *
get_grbuf()
{
	nss_XbyY_buf_t **buffer =
	    tsdalloc(_T_GRBUF, sizeof (nss_XbyY_buf_t *), free_grbuf);
	nss_XbyY_buf_t *b;

	if (buffer == NULL)
		return (NULL);
	b = NSS_XbyY_ALLOC(buffer, sizeof (struct group), NSS_BUFLEN_GROUP);
	return (b);
}

struct group *
getgrgid(gid_t gid)
{
	nss_XbyY_buf_t	*b = get_grbuf();

	return (b == NULL ? NULL :
	    getgrgid_r(gid, b->result, b->buffer, b->buflen));
}

struct group *
getgrnam(const char *nam)
{
	nss_XbyY_buf_t	*b = get_grbuf();

	return (b == NULL ? NULL :
	    getgrnam_r(nam, b->result, b->buffer, b->buflen));
}

struct group *
getgrent(void)
{
	nss_XbyY_buf_t	*b = get_grbuf();

	return (b == NULL ? NULL :
	    getgrent_r(b->result, b->buffer, b->buflen));
}

struct group *
fgetgrent(FILE *f)
{
	nss_XbyY_buf_t	*b = get_grbuf();

	return (b == NULL ? NULL :
	    fgetgrent_r(f, b->result, b->buffer, b->buflen));
}

#endif	/* NSS_INCLUDE_UNSAFE */
