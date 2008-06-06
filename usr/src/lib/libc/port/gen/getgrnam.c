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

#pragma weak _getgrnam	= getgrnam
#pragma weak _getgrgid	= getgrgid

#include "lint.h"
#include <sys/types.h>
#include <grp.h>
#include <nss_dbdefs.h>
#include <stdio.h>
#include "tsd.h"

#ifdef	NSS_INCLUDE_UNSAFE

extern size_t _nss_get_bufsizes(int arg);

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
get_grbuf(int max_buf)
{
	nss_XbyY_buf_t **buffer =
	    tsdalloc(_T_GRBUF, sizeof (nss_XbyY_buf_t *), free_grbuf);
	nss_XbyY_buf_t *b;
	size_t	blen;

	if (buffer == NULL)
		return (NULL);
	if (max_buf == 0)
		blen = _nss_get_bufsizes(0);		/* default size */
	else
		blen = sysconf(_SC_GETGR_R_SIZE_MAX);	/* max size */
	if (*buffer) {
		if ((*buffer)->buflen >= blen)	/* existing size fits */
			return (*buffer);
		NSS_XbyY_FREE(buffer);		/* existing is too small */
	}
	b = NSS_XbyY_ALLOC(buffer, sizeof (struct group), blen);
	return (b);
}

struct group *
getgrgid(gid_t gid)
{
	nss_XbyY_buf_t	*b = get_grbuf(0);
	struct group *ret;

	if (b == NULL)
		return (NULL);

	ret = getgrgid_r(gid, b->result, b->buffer, b->buflen);
	if (ret == NULL && errno == ERANGE) {
		b = get_grbuf(1);
		if (b == NULL)
			return (NULL);
		ret = getgrgid_r(gid, b->result, b->buffer, b->buflen);
	}
	return (ret);
}

struct group *
getgrnam(const char *nam)
{
	nss_XbyY_buf_t	*b = get_grbuf(0);
	struct group *ret;

	if (b == NULL)
		return (NULL);

	ret = getgrnam_r(nam, b->result, b->buffer, b->buflen);
	if (ret == NULL && errno == ERANGE && nam != NULL) {
		b = get_grbuf(1);
		if (b == NULL)
			return (NULL);
		ret = getgrnam_r(nam, b->result, b->buffer, b->buflen);
	}
	return (ret);
}

struct group *
getgrent(void)
{
	nss_XbyY_buf_t	*b = get_grbuf(1);

	return (b == NULL ? NULL :
	    getgrent_r(b->result, b->buffer, b->buflen));
}

struct group *
fgetgrent(FILE *f)
{
	nss_XbyY_buf_t	*b = get_grbuf(1);

	return (b == NULL ? NULL :
	    fgetgrent_r(f, b->result, b->buffer, b->buflen));
}

#endif	/* NSS_INCLUDE_UNSAFE */
