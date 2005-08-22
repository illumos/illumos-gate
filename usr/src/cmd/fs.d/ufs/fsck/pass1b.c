/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mntent.h>
#include <sys/fs/ufs_fs.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#include "fsck.h"

static int pass1bcheck(struct inodesc *);

void
pass1b(void)
{
	struct dinode *dp;
	struct inodesc idesc;
	fsck_ino_t inumber;

	/*
	 * We can get STOP failures from ckinode() that
	 * are completely independent of our dup checks.
	 * If that were not the case, then we could track
	 * when we've seen all of the dups and short-
	 * circuit our search.  As it is, we need to
	 * keep going, so there's no point in looking
	 * at what ckinode() returns to us.
	 */

	for (inumber = UFSROOTINO; inumber < maxino; inumber++) {
		init_inodesc(&idesc);
		idesc.id_type = ADDR;
		idesc.id_func = pass1bcheck;
		idesc.id_number = inumber;
		idesc.id_fix = DONTKNOW;
		dp = ginode(inumber);
		if (statemap[inumber] != USTATE)
			(void) ckinode(dp, &idesc, CKI_TRAVERSE);
	}
}

static int
pass1bcheck(struct inodesc *idesc)
{
	int res = KEEPON;
	int nfrags;
	daddr32_t lbn;
	daddr32_t blkno = idesc->id_blkno;

	for (nfrags = 0; nfrags < idesc->id_numfrags; blkno++, nfrags++) {
		if (chkrange(blkno, 1)) {
			res = SKIP;
		} else {
			/*
			 * Note that we only report additional dup claimants
			 * in this pass, as the first claimant found was
			 * listed during pass 1.
			 */
			lbn = idesc->id_lbn * sblock.fs_frag + nfrags;
			if (find_dup_ref(blkno, idesc->id_number, lbn, DB_INCR))
				blkerror(idesc->id_number, "DUP", blkno, lbn);
		}
	}
	return (res);
}
