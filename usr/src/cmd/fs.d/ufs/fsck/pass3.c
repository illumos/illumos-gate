/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
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
#define	_KERNEL
#include <sys/fs/ufs_fsdir.h>
#undef _KERNEL
#include "fsck.h"

int pass3check();
static void setcurino(struct inodesc *, struct dinode *, struct inoinfo *);

pass3()
{
	struct inoinfo **inpp, *inp;
	ino_t orphan;
	int loopcnt;
	ino_t inumber;
	struct shadowclientinfo *sci;
	struct inodesc curino;
	struct dinode *dp;


	for (inpp = &inpsort[inplast - 1]; inpp >= inpsort; inpp--) {
		inp = *inpp;
		if (inp->i_number == UFSROOTINO ||
		    !(inp->i_parent == 0 || statemap[inp->i_number] == DSTATE))
			continue;
		if (statemap[inp->i_number] == DCLEAR ||
		    statemap[inp->i_number] == USTATE)
			continue;
		for (loopcnt = 0; ; loopcnt++) {
			orphan = inp->i_number;
			if (inp->i_parent == 0 ||
			    statemap[inp->i_parent] != DSTATE ||
			    loopcnt > numdirs)
				break;
			inp = getinoinfo(inp->i_parent);
		}
		dp = ginode(orphan);
		/*
		 * A link count of 0 with parent and .. inodes of 0
		 * indicates a partly deleted directory.
		 * Clear it.
		 */
		if (dp->di_nlink == 0 && inp->i_dotdot == 0 &&
		    inp->i_parent == 0) {
			setcurino(&curino, dp, inp);
			clri(&curino, "UNREF", 1);
			continue;
		}

		if (linkup(orphan, inp->i_dotdot) == 1) {
			if ((dp->di_mode & IFMT) == IFATTRDIR) {
				dp->di_mode &= ~IFATTRDIR;
				dp->di_mode |= IFDIR;
				dp->di_cflags &= ~IXATTR;
				dp->di_size = (u_offset_t)inp->i_isize;
				setcurino(&curino, dp, inp);
				(void) ckinode(dp, &curino);
				inodirty();
			}
			inp->i_parent = inp->i_dotdot = lfdir;
			lncntp[lfdir]--;
			statemap[orphan] = DFOUND;
			propagate();
		}
	}

	for (sci = shadowclientinfo; sci; sci = sci->next) {
		lncntp[sci->shadow] -= sci->totalClients;
	}

	for (sci = attrclientinfo; sci; sci = sci->next) {
		lncntp[sci->shadow] -= sci->totalClients;
	}
}


/*
 * This is used to verify the cflags of files
 * under a directory that used to be a attrdir.
 */

pass3check(idesc)
	struct inodesc *idesc;
{
	struct direct *dirp = idesc->id_dirp;
	struct inoinfo *inp;
	int n, entrysize, ret = 0;
	struct dinode *dp, *pdirp;
	int	isattr = 0;
	int	dirtype = 0;

	if (dirp->d_ino == 0)
		return (KEEPON);

	idesc->id_entryno++;
	if ((strcmp(dirp->d_name, ".") == 0) ||
	    (strcmp(dirp->d_name, "..") == 0)) {
		return (KEEPON);
	}


	switch (statemap[dirp->d_ino]) {
	case DSTATE:
	case DFOUND:
	case FSTATE:
		/*
		 * For extended attribute directories .. may point
		 * to a file.  In this situation we don't want
		 * to decrement link count as it was already
		 * decremented when entry was seen and decremented
		 * in the directory it actually lives in.
		 */
		dp = ginode(dirp->d_ino);
		isattr = (dp->di_cflags & IXATTR);
		pdirp = ginode(idesc->id_number);
		dirtype = (pdirp->di_mode & IFMT);
		n = 0;
		if ((dirtype == IFDIR) && isattr) {
			fileerror(idesc->id_number, dirp->d_ino,
			    "File should NOT be marked as extended attribute");
			dp = ginode(dirp->d_ino);
			dp->di_cflags &= ~IXATTR;
			if ((n = reply("FIX")) == 1) {
				inodirty();
			}
			if (n != 0)
				return (KEEPON | ALTERED);
		}
		break;
	default:
		errexit("PASS3: BAD STATE %d FOR INODE I=%d",
		    statemap[dirp->d_ino], dirp->d_ino);
	}
	if (n == 0)
		return (ret|KEEPON);
	return (ret|KEEPON|ALTERED);
}

static void
setcurino(struct inodesc *ino, struct dinode *dp, struct inoinfo *inp)
{
	bzero((char *)ino, sizeof (struct inodesc));
	bcopy((char *)&inp->i_blks[0],
	    (char *)&dp->di_db[0],
	    (size_t)inp->i_numblks);
	ino->id_number = inp->i_number;
	ino->id_parent = inp->i_parent;
	ino->id_fix = DONTKNOW;
	ino->id_type = DATA;
	ino->id_func = pass3check;
}
