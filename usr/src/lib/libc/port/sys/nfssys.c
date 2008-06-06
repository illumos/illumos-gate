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

/*	Copyright (c) 1983,1984,1985,1986,1987,1988,1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include <sys/types.h>
#include <sys/types32.h>
#include <rpc/types.h>
#include <sys/vfs.h>
#include <nfs/nfs.h>
#include <nfs/export.h>
#include <nfs/nfssys.h>
#include "libc.h"

int
exportfs(char *dir, struct exportdata *ep)
{
	struct exportfs_args ea;

	ea.dname = dir;
	ea.uex = ep;
	return (_nfssys(EXPORTFS, &ea));
}

int
nfs_getfh(char *path, int vers, int *lenp, char *fhp)
{
	struct nfs_getfh_args nga;

	nga.fname = path;
	nga.vers = vers;
	nga.lenp = lenp;
	nga.fhp = fhp;
	return (_nfssys(NFS_GETFH, &nga));
}

int
nfssvc(int fd)
{
	struct nfs_svc_args nsa;

	nsa.fd = fd;
	return (_nfssys(NFS_SVC, &nsa));
}
