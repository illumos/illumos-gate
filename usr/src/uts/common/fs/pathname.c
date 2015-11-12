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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */


#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/errno.h>
#include <sys/pathname.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/debug.h>

/*
 * Pathname utilities.
 *
 * In translating file names we copy each argument file
 * name into a pathname structure where we operate on it.
 * Each pathname structure can hold "pn_bufsize" characters
 * including a terminating null, and operations here support
 * allocating and freeing pathname structures, fetching
 * strings from user space, getting the next character from
 * a pathname, combining two pathnames (used in symbolic
 * link processing), and peeling off the first component
 * of a pathname.
 */

/*
 * Allocate contents of pathname structure.  Structure is typically
 * an automatic variable in calling routine for convenience.
 *
 * May sleep in the call to kmem_alloc() and so must not be called
 * from interrupt level.
 */
void
pn_alloc(struct pathname *pnp)
{
	pn_alloc_sz(pnp, MAXPATHLEN);
}
void
pn_alloc_sz(struct pathname *pnp, size_t sz)
{
	pnp->pn_path = pnp->pn_buf = kmem_alloc(sz, KM_SLEEP);
	pnp->pn_pathlen = 0;
	pnp->pn_bufsize = sz;
}

/*
 * Free pathname resources.
 */
void
pn_free(struct pathname *pnp)
{
	/* pn_bufsize is usually MAXPATHLEN, but may not be */
	kmem_free(pnp->pn_buf, pnp->pn_bufsize);
	pnp->pn_path = pnp->pn_buf = NULL;
	pnp->pn_pathlen = pnp->pn_bufsize = 0;
}

/*
 * Pull a path name from user or kernel space.
 * Called from pn_get() after allocation of a MAXPATHLEN buffer.
 * Also called directly with a TYPICALMAXPATHLEN-size buffer
 * on the stack as a local optimization.
 */
int
pn_get_buf(char *str, enum uio_seg seg, struct pathname *pnp,
	void *buf, size_t bufsize)
{
	int error;

	pnp->pn_path = pnp->pn_buf = buf;
	pnp->pn_bufsize = bufsize;
	if (seg == UIO_USERSPACE)
		error = copyinstr(str, pnp->pn_path, bufsize, &pnp->pn_pathlen);
	else
		error = copystr(str, pnp->pn_path, bufsize, &pnp->pn_pathlen);
	if (error)
		return (error);
	pnp->pn_pathlen--;		/* don't count null byte */
	return (0);
}

/*
 * Pull a path name from user or kernel space.
 */
int
pn_get(char *str, enum uio_seg seg, struct pathname *pnp)
{
	int error;
	void *buf;

	buf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	if ((error = pn_get_buf(str, seg, pnp, buf, MAXPATHLEN)) != 0)
		pn_free(pnp);
	return (error);
}

/*
 * Set path name to argument string.  Storage has already been allocated
 * and pn_buf points to it.
 *
 * On error, all fields except pn_buf will be undefined.
 */
int
pn_set(struct pathname *pnp, char *path)
{
	int error;

	pnp->pn_path = pnp->pn_buf;
	error = copystr(path, pnp->pn_path, pnp->pn_bufsize, &pnp->pn_pathlen);
	pnp->pn_pathlen--;		/* don't count null byte */
	return (error);
}

/*
 * Combine two argument path names by putting the second argument
 * before the first in the first's buffer.  This isn't very general;
 * it is designed specifically for symbolic link processing.
 * This function copies the symlink in-place in the pathname.  This is to
 * ensure that vnode path caching remains correct.  At the point where this is
 * called (from lookuppnvp), we have called pn_getcomponent(), found it is a
 * symlink, and are now replacing the contents.  The complen parameter indicates
 * how much of the pathname to replace.  If the symlink is an absolute path,
 * then we overwrite the entire contents of the pathname.
 */
int
pn_insert(struct pathname *pnp, struct pathname *sympnp, size_t complen)
{

	if (*sympnp->pn_path == '/') {
		/*
		 * Full path, replace everything
		 */
		if (pnp->pn_pathlen + sympnp->pn_pathlen >= pnp->pn_bufsize)
			return (ENAMETOOLONG);
		if (pnp->pn_pathlen != 0)
			ovbcopy(pnp->pn_path, pnp->pn_buf + sympnp->pn_pathlen,
			    pnp->pn_pathlen);
		bcopy(sympnp->pn_path, pnp->pn_buf, sympnp->pn_pathlen);
		pnp->pn_pathlen += sympnp->pn_pathlen;
		pnp->pn_buf[pnp->pn_pathlen] = '\0';
		pnp->pn_path = pnp->pn_buf;
	} else {
		/*
		 * Partial path, replace only last component
		 */
		if ((pnp->pn_path - pnp->pn_buf) - complen +
		    pnp->pn_pathlen + sympnp->pn_pathlen >= pnp->pn_bufsize)
			return (ENAMETOOLONG);

		if (pnp->pn_pathlen != 0)
			ovbcopy(pnp->pn_path, pnp->pn_path - complen +
			    sympnp->pn_pathlen, pnp->pn_pathlen + 1);
		pnp->pn_path -= complen;
		bcopy(sympnp->pn_path, pnp->pn_path, sympnp->pn_pathlen);
		pnp->pn_pathlen += sympnp->pn_pathlen;
	}

	return (0);
}

int
pn_getsymlink(vnode_t *vp, struct pathname *pnp, cred_t *crp)
{
	struct iovec aiov;
	struct uio auio;
	int error;

	aiov.iov_base = pnp->pn_path = pnp->pn_buf;
	aiov.iov_len = pnp->pn_bufsize;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = 0;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_extflg = UIO_COPY_CACHED;
	auio.uio_resid = pnp->pn_bufsize;
	if ((error = VOP_READLINK(vp, &auio, crp, NULL)) == 0) {
		pnp->pn_pathlen = pnp->pn_bufsize - auio.uio_resid;
		if (pnp->pn_pathlen == pnp->pn_bufsize)
			error = ENAMETOOLONG;
		else
			pnp->pn_path[pnp->pn_pathlen] = '\0';
	}
	return (error);
}

/*
 * Get next component from a path name and leave in
 * buffer "component" which should have room for
 * MAXNAMELEN bytes (including a null terminator character).
 */
int
pn_getcomponent(struct pathname *pnp, char *component)
{
	char c, *cp, *path, saved;
	size_t pathlen;

	path = pnp->pn_path;
	pathlen = pnp->pn_pathlen;
	if (pathlen >= MAXNAMELEN) {
		saved = path[MAXNAMELEN];
		path[MAXNAMELEN] = '/';	/* guarantees loop termination */
		for (cp = path; (c = *cp) != '/'; cp++)
			*component++ = c;
		path[MAXNAMELEN] = saved;
		if (cp - path == MAXNAMELEN)
			return (ENAMETOOLONG);
	} else {
		path[pathlen] = '/';	/* guarantees loop termination */
		for (cp = path; (c = *cp) != '/'; cp++)
			*component++ = c;
		path[pathlen] = '\0';
	}

	pnp->pn_path = cp;
	pnp->pn_pathlen = pathlen - (cp - path);
	*component = '\0';
	return (0);
}

/*
 * Skip over consecutive slashes in the path name.
 */
void
pn_skipslash(struct pathname *pnp)
{
	while (pnp->pn_pathlen > 0 && *pnp->pn_path == '/') {
		pnp->pn_path++;
		pnp->pn_pathlen--;
	}
}

/*
 * Sets pn_path to the last component in the pathname, updating
 * pn_pathlen.  If pathname is empty, or degenerate, leaves pn_path
 * pointing at NULL char.  The pathname is explicitly null-terminated
 * so that any trailing slashes are effectively removed.
 */
void
pn_setlast(struct pathname *pnp)
{
	char *buf = pnp->pn_buf;
	char *path = pnp->pn_path + pnp->pn_pathlen - 1;
	char *endpath;

	while (path > buf && *path == '/')
		--path;
	endpath = path + 1;
	while (path > buf && *path != '/')
		--path;
	if (*path == '/')
		path++;
	*endpath = '\0';
	pnp->pn_path = path;
	pnp->pn_pathlen = endpath - path;
}

/*
 * Eliminate any trailing slashes in the pathname.
 * Return non-zero iff there were any trailing slashes.
 */
int
pn_fixslash(struct pathname *pnp)
{
	char *start = pnp->pn_path;
	char *end = start + pnp->pn_pathlen;

	while (end > start && *(end - 1) == '/')
		end--;
	if (pnp->pn_pathlen == end - start)
		return (0);
	*end = '\0';
	pnp->pn_pathlen = end - start;
	return (1);
}

/*
 * Add a slash to the end of the pathname, if it will fit.
 * Return ENAMETOOLONG if it won't.
 */
int
pn_addslash(struct pathname *pnp)
{
	if (pnp->pn_path + pnp->pn_pathlen + 1 >=
	    pnp->pn_buf + pnp->pn_bufsize) {
		if (pnp->pn_pathlen + 1 >= pnp->pn_bufsize)	/* no room */
			return (ENAMETOOLONG);
		/*
		 * Move the component to the start of the buffer
		 * so we have room to add the trailing slash.
		 */
		ovbcopy(pnp->pn_path, pnp->pn_buf, pnp->pn_pathlen);
		pnp->pn_path = pnp->pn_buf;
	}
	pnp->pn_path[pnp->pn_pathlen++] = '/';
	pnp->pn_path[pnp->pn_pathlen] = '\0';
	return (0);
}
