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

/*
 * This file contains the file lookup code for NFS.
 */

#include <rpc/rpc.h>
#include "brpc.h"
#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/xdr.h>
#include <rpc/rpc_msg.h>
#include <sys/t_lock.h>
#include "clnt.h"
#include <rpcsvc/mount.h>
#include <st_pathname.h>
#include <sys/errno.h>
#include <sys/promif.h>
#include "nfs_inet.h"
#include "socket_inet.h"
#include <rpcsvc/nfs_prot.h>
#include <rpcsvc/nfs4_prot.h>
#include <sys/types.h>
#include <sys/salib.h>
#include <sys/sacache.h>
#include <sys/stat.h>
#include <sys/bootvfs.h>
#include <sys/bootdebug.h>
#include "mac.h"

static int root_inum = 1;	/* Dummy i-node number for root */
static int next_inum = 1;	/* Next dummy i-node number	*/

#define	dprintf	if (boothowto & RB_DEBUG) printf

/*
 * starting at current directory (root for us), lookup the pathname.
 * return the file handle of said file.
 */

static int stlookuppn(struct st_pathname *pnp, struct nfs_file *cfile,
			bool_t needroothandle);

/*
 * For NFSv4 we may be calling lookup in the context of evaluating the
 * root path.  In this case we set needroothandle to TRUE.
 */
int
lookup(char *pathname, struct nfs_file *cur_file, bool_t needroothandle)
{
	struct st_pathname pnp;
	int error;

	static char lkup_path[NFS_MAXPATHLEN];	/* pn_alloc doesn't */

	pnp.pn_buf = &lkup_path[0];
	bzero(pnp.pn_buf, NFS_MAXPATHLEN);
	error = stpn_get(pathname, &pnp);
	if (error)
		return (error);
	error = stlookuppn(&pnp, cur_file, needroothandle);
	return (error);
}

static int
stlookuppn(struct st_pathname *pnp, struct nfs_file *cfile,
bool_t needroothandle)
{
	char component[NFS_MAXNAMLEN+1];	/* buffer for component */
	int nlink = 0;
	int error = 0;
	int dino, cino;
	struct nfs_file *cdp = NULL;

	*cfile = roothandle;	/* structure copy - start at the root. */
	dino = root_inum;
begin:
	/*
	 * Each time we begin a new name interpretation (e.g.
	 * when first called and after each symbolic link is
	 * substituted), we allow the search to start at the
	 * root directory if the name starts with a '/', otherwise
	 * continuing from the current directory.
	 */
	component[0] = '\0';
	if (stpn_peekchar(pnp) == '/') {
		if (!needroothandle)
			*cfile = roothandle;
		dino = root_inum;
		stpn_skipslash(pnp);
	}

next:
	/*
	 * Make sure we have a directory.
	 */
	if (!cfile_is_dir(cfile)) {
		error = ENOTDIR;
		goto bad;
	}
	/*
	 * Process the next component of the pathname.
	 */
	error = stpn_stripcomponent(pnp, component);
	if (error)
		goto bad;

	/*
	 * Check for degenerate name (e.g. / or "")
	 * which is a way of talking about a directory,
	 * e.g. "/." or ".".
	 */
	if (component[0] == '\0')
		return (0);

	/*
	 * Handle "..": two special cases.
	 * 1. If at root directory (e.g. after chroot)
	 *    then ignore it so can't get out.
	 * 2. If this vnode is the root of a mounted
	 *    file system, then replace it with the
	 *    vnode which was mounted on so we take the
	 *    .. in the other file system.
	 */
	if (strcmp(component, "..") == 0) {
		if (cfile == &roothandle)
			goto skip;
	}

	/*
	 * Perform a lookup in the current directory.
	 * We create a simple negative lookup cache by storing
	 * inode -1 to indicate file not found.
	 */
	cino = get_dcache(mac_get_dev(), component, dino);
	if (cino == -1)
		return (ENOENT);
#ifdef DEBUG
	dprintf("lookup: component %s pathleft %s\n", component, pnp->pn_path);
#endif
	if ((cino == 0) ||
	    ((cdp = (struct nfs_file *)get_icache(mac_get_dev(), cino)) == 0)) {
		struct nfs_file *lkp;

		/*
		 * If an RPC error occurs, error is not changed,
		 * else it is the NFS error if NULL is returned.
		 */
		error = -1;
		switch (cfile->version) {
		case NFS_VERSION:
			lkp = nfslookup(cfile, component, &error);
			break;
		case NFS_V3:
			lkp = nfs3lookup(cfile, component, &error);
			break;
		case NFS_V4:
			lkp = nfs4lookup(cfile, component, &error);
			break;
		default:
			printf("lookup: NFS Version %d not supported\n",
			    cfile->version);
			lkp = NULL;
			break;
		}

		/*
		 * Check for RPC error
		 */
		if (error == -1) {
			printf("lookup: lookup RPC error\n");
			return (error);
		}

		/*
		 * Check for NFS error
		 */
		if (lkp == NULL) {
			if ((error != NFSERR_NOENT) &&
			    (error != NFS3ERR_NOENT) &&
			    (error != NFS4ERR_NOENT)) {
#ifdef DEBUG
			dprintf("lookup: lkp is NULL with error %d\n", error);
#endif
				return (error);
			}
#ifdef DEBUG
			dprintf("lookup: lkp is NULL with error %d\n", error);
#endif
			/*
			 * File not found so set cached inode to -1
			 */
			set_dcache(mac_get_dev(), component, dino, -1);
			return (error);
		}

		if (cdp = (struct nfs_file *)
		    bkmem_alloc(sizeof (struct nfs_file))) {
			/*
			 *  Save this entry in cache for next time ...
			 */
			if (!cino)
				cino = ++next_inum;
			*cdp = *lkp;

			set_dcache(mac_get_dev(), component, dino, cino);
			set_icache(mac_get_dev(), cino, cdp,
						sizeof (struct nfs_file));
		} else {
			/*
			 *  Out of memory, clear cache keys so we don't get
			 *  confused later.
			 */
			cino = 0;
			cdp = lkp;
		}
	}
	dino = cino;

	/*
	 * If we hit a symbolic link and there is more path to be
	 * translated or this operation does not wish to apply
	 * to a link, then place the contents of the link at the
	 * front of the remaining pathname.
	 */
	if (cfile_is_lnk(cdp)) {
		struct st_pathname linkpath;
		static char path_tmp[NFS_MAXPATHLEN];	/* used for symlinks */
		char *pathp;

		linkpath.pn_buf = &path_tmp[0];

		nlink++;
		if (nlink > MAXSYMLINKS) {
			error = ELOOP;
			goto bad;
		}
		switch (cdp->version) {
		case NFS_VERSION:
			error = nfsgetsymlink(cdp, &pathp);
			break;
		case NFS_V3:
			error = nfs3getsymlink(cdp, &pathp);
			break;
		case NFS_V4:
			error = nfs4getsymlink(cdp, &pathp);
			break;
		default:
			printf("getsymlink: NFS Version %d not supported\n",
			    cdp->version);
			error = ENOTSUP;
			break;
		}

		if (error)
			goto bad;

		(void) stpn_get(pathp, &linkpath);

		if (stpn_pathleft(&linkpath) == 0)
			(void) stpn_set(&linkpath, ".");
		error = stpn_combine(pnp, &linkpath); /* linkpath before pn */
		if (error)
			goto bad;
		goto begin;
	}

	if (needroothandle) {
		roothandle = *cdp;
		needroothandle = FALSE;
	}
	*cfile = *cdp;

skip:
	/*
	 * Skip to next component of the pathname.
	 * If no more components, return last directory (if wanted)  and
	 * last component (if wanted).
	 */
	if (stpn_pathleft(pnp) == 0) {
		(void) stpn_set(pnp, component);
		return (0);
	}
	/*
	 * skip over slashes from end of last component
	 */
	stpn_skipslash(pnp);
	goto next;
bad:
	/*
	 * Error.
	 */
	return (error);
}
