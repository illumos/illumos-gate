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
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <st_pathname.h>
#include <sys/promif.h>
#include <sys/salib.h>
#include <sys/bootdebug.h>

/*
 * Pathname utilities.
 *
 * In translating file names we copy each argument file
 * name into a pathname structure where we operate on it.
 * Each pathname structure can hold MAXPATHLEN characters
 * including a terminating null, and operations here support
 * fetching strings from user space, getting the next character from
 * a pathname, combining two pathnames (used in symbolic
 * link processing), and peeling off the first component
 * of a pathname.
 */

#define	dprintf	if (boothowto & RB_DEBUG) printf

/*
 * Setup contents of pathname structure. Warn about missing allocations.
 * Structure itself is typically automatic
 * variable in calling routine for convenience.
 *
 * NOTE: if buf is NULL, failure occurs.
 */
int
stpn_alloc(struct st_pathname *pnp)
{
	if (pnp->pn_buf == NULL)
		return (-1);
	pnp->pn_path = (char *)pnp->pn_buf;
	pnp->pn_pathlen = 0;
	return (0);
}

/*
 * Pull a pathname from user user or kernel space
 */
int
stpn_get(char *str, struct st_pathname *pnp)
{
	if (stpn_alloc(pnp) != 0)
		return (-1);
	bcopy(str, pnp->pn_path, strlen(str));
	pnp->pn_pathlen = strlen(str);		/* don't count null byte */
	return (0);
}

/*
 * Set pathname to argument string.
 */
int
stpn_set(struct st_pathname *pnp, char *path)
{
	pnp->pn_path = pnp->pn_buf;
	pnp->pn_pathlen = strlen(pnp->pn_path); /* don't count null byte */
	bcopy(pnp->pn_path, path, pnp->pn_pathlen);
	return (0);
}

/*
 * Combine two argument pathnames by putting
 * second argument before first in first's buffer,
 * and freeing second argument.
 * This isn't very general: it is designed specifically
 * for symbolic link processing.
 */
int
stpn_combine(struct st_pathname *pnp, struct st_pathname *sympnp)
{

	if (pnp->pn_pathlen + sympnp->pn_pathlen >= MAXPATHLEN)
		return (ENAMETOOLONG);
	bcopy(pnp->pn_path, pnp->pn_buf + sympnp->pn_pathlen,
	    (uint_t)pnp->pn_pathlen);
	bcopy(sympnp->pn_path, pnp->pn_buf, (uint_t)sympnp->pn_pathlen);
	pnp->pn_pathlen += sympnp->pn_pathlen;
	pnp->pn_buf[pnp->pn_pathlen] = '\0';
	pnp->pn_path = pnp->pn_buf;
	return (0);
}

/*
 * Get next component off a pathname and leave in
 * buffer comoponent which should have room for
 * NFS_MAXNAMLEN (1024) bytes and a null terminator character.
 * If PEEK is set in flags, just peek at the component,
 * i.e., don't strip it out of pnp.
 */
int
stpn_getcomponent(struct st_pathname *pnp, char *component, int flags)
{
	char *cp;
	int l;
	int n;

	cp = pnp->pn_path;
	l = pnp->pn_pathlen;
	n = 1024;
	while ((l > 0) && (*cp != '/')) {
		if (--n < 0)
			return (ENAMETOOLONG);
		*component++ = *cp++;
		--l;
	}
	if (!(flags & PN_PEEK)) {
		pnp->pn_path = cp;
		pnp->pn_pathlen = l;
	}
	*component = 0;
	return (0);
}

/*
 * skip over consecutive slashes in the pathname
 */
void
stpn_skipslash(struct st_pathname *pnp)
{
	while ((pnp->pn_pathlen != 0) && (*pnp->pn_path == '/')) {
		pnp->pn_path++;
		pnp->pn_pathlen--;
	}
}

/*
 * free pathname resources. This is a nop - the user of these
 * routines is responsible for allocating and freeing their memory.
 */
/*ARGSUSED*/
void
stpn_free(struct st_pathname *pnp)
{
	/* nop */
	dprintf("pn_free(): you shouldn't be calling pn_free()!\n");
}
