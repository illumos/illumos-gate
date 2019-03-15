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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2016 Joyent, Inc.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

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
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/proc.h>
#include <sys/vtrace.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/dirent.h>
#include <sys/zone.h>
#include <sys/fs/snode.h>

#include <libfksmbfs.h>

extern vnode_t *rootdir;

/*
 * Simplified variation on lookuppnvp()
 */
int
fake_lookup(vnode_t *dvp, char *path, vnode_t **vpp)
{
	char component[MAXNAMELEN];	/* buffer for component */
	pathname_t pn;
	cred_t *cr;
	vnode_t *cvp;	/* current component vp */
	vnode_t *nvp;	/* next component vp */
	char *p;
	int flags = 0;
	int error, len;

	bzero(&pn, sizeof (pn));
	pn.pn_buf = path;
	pn.pn_path = path;
	pn.pn_pathlen = strlen(path);
	pn.pn_bufsize = pn.pn_pathlen + 1;
	p = path;

	cr = CRED();
	cvp = (dvp != NULL) ? dvp : rootdir;
	VN_HOLD(cvp);
	nvp = NULL;

	while (*p != '\0') {
		if (*p == '/') {
			p++;
			continue;
		}

		len = strcspn(p, "/");
		ASSERT(len > 0);
		if (len >= MAXNAMELEN)
			return (EINVAL);
		(void) strncpy(component, p, len);
		component[len] = '\0';
		pn.pn_path = p;
		pn.pn_pathlen = strlen(p);

		error = VOP_LOOKUP(cvp, component, &nvp, &pn, flags,
		    rootdir, cr, NULL, NULL, NULL);
		VN_RELE(cvp);
		if (error != 0)
			return (error);

		/* Lookup gave us a hold on nvp */
		cvp = nvp;
		nvp = NULL;
		p += len;
	}

	*vpp = cvp;
	return (0);
}

/*
 * Lookup the directory and find the start of the
 * last component of the given path.
 */
int
fake_lookup_dir(char *path, vnode_t **vpp, char **lastcomp)
{
	vnode_t *dvp;
	char *last;
	char *tpn = NULL;
	int tpn_sz;
	int lc_off;
	int error;

	*vpp = NULL;
	*lastcomp = NULL;

	tpn_sz = strlen(path) + 1;
	tpn = kmem_alloc(tpn_sz, KM_SLEEP);

	/*
	 * Get a copy of the path, and zap the last /
	 */
	bcopy(path, tpn, tpn_sz);
	last = strrchr(tpn, '/');
	if (last == NULL) {
		lc_off = 0;
		dvp = rootdir;
		VN_HOLD(dvp);
		error = 0;
	} else {
		*last++ = '\0';
		if (*last == '\0') {
			error = EINVAL;
			goto out;
		}
		error = fake_lookup(rootdir, tpn, &dvp);
		if (error != 0) {
			/* dir not found */
			goto out;
		}
		lc_off = last - tpn;
		ASSERT(lc_off >= 0 && lc_off < tpn_sz);
	}
	*vpp = dvp;
	*lastcomp = path + lc_off;

out:
	if (tpn != NULL)
		kmem_free(tpn, tpn_sz);

	return (error);
}
