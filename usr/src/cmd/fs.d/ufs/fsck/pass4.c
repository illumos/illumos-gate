/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980, 1986, 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that: (1) source distributions retain this entire copyright
 * notice and comment, and (2) distributions including binaries display
 * the following acknowledgement:  ``This product includes software
 * developed by the University of California, Berkeley and its contributors''
 * in the documentation or other materials provided with the distribution
 * and in all advertising materials mentioning features or use of this
 * software. Neither the name of the University nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/mntent.h>

#define	bcopy(f, t, n)    memcpy(t, f, n)
#define	bzero(s, n)	memset(s, 0, n)
#define	bcmp(s, d, n)	memcmp(s, d, n)

#define	index(s, r)	strchr(s, r)
#define	rindex(s, r)	strrchr(s, r)

#include <sys/fs/ufs_fs.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#include "fsck.h"

int	pass4check();

pass4()
{
	ino_t inumber;
	struct zlncnt *zlnp;
	struct dinode *dp;
	struct inodesc idesc;
	int n;

	bzero((char *)&idesc, sizeof (struct inodesc));
	idesc.id_type = ADDR;
	idesc.id_func = pass4check;
	for (inumber = UFSROOTINO; inumber <= lastino; inumber++) {
		idesc.id_number = inumber;
		idesc.id_fix = DONTKNOW;
		switch (statemap[inumber]) {

		case FSTATE:
		case SSTATE:
		case DFOUND:
			n = lncntp[inumber];
			if (n)
				adjust(&idesc, (short)n);
			else {
				for (zlnp = zlnhead; zlnp; zlnp = zlnp->next)
					if (zlnp->zlncnt == inumber) {
						zlnp->zlncnt = zlnhead->zlncnt;
						zlnp = zlnhead;
						zlnhead = zlnhead->next;
						free((char *)zlnp);
						if (!willreclaim)
						    clri(&idesc, "UNREF", 1);
						break;
					}
			}
			break;

		case DSTATE:
			if (!willreclaim)
				clri(&idesc, "UNREF", 1);
			break;

		case DCLEAR:
			dp = ginode(inumber);
			if (dp->di_size == 0) {
				if (!willreclaim)
					clri(&idesc, "ZERO LENGTH", 1);
				break;
			}
			/* fall through */
		case FCLEAR:
			clri(&idesc, "BAD/DUP", 1);
			break;

		case SCLEAR:
			clri(&idesc, "BAD", 1);
			break;

		case USTATE:
			break;

		default:
			errexit("BAD STATE %d FOR INODE I=%d",
			    statemap[inumber], inumber);
		}
	}
}

pass4check(idesc)
	struct inodesc *idesc;
{
	struct dups *dlp;
	int	nfrags;
	int res = KEEPON;
	daddr32_t blkno = idesc->id_blkno;

	for (nfrags = idesc->id_numfrags; nfrags > 0; blkno++, nfrags--) {
		if (chkrange(blkno, 1)) {
			res = SKIP;
		} else if (testbmap(blkno)) {
			for (dlp = duplist; dlp; dlp = dlp->next) {
				if (dlp->dup != blkno)
					continue;
				dlp->dup = duplist->dup;
				dlp = duplist;
				duplist = duplist->next;
				free((char *)dlp);
				break;
			}
			if (dlp == 0) {
				clrbmap(blkno);
				n_blks--;
			}
		}
	}
	return (res);
}
