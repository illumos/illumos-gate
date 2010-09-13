/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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

void
pass4(void)
{
	fsck_ino_t inumber;
	struct dinode *dp;
	struct inodesc idesc;
	int n, was_dir;
	int need_rescan;
	int scan_pass = 0;

	/*
	 * If we clear a directory, it may have produced orphans which
	 * we need to go pick up.  So, do this until done.  It can be
	 * proven that the loop terminates because at most there can
	 * be lastino directories, and we only rescan if we clear a
	 * directory.
	 */
	do {
		if (debug)
			(void) printf("pass4 scan %d\n", scan_pass++);

		need_rescan = 0;
		for (inumber = UFSROOTINO; inumber <= lastino; inumber++) {
			init_inodesc(&idesc);
			idesc.id_type = ADDR;
			idesc.id_func = pass4check;
			idesc.id_number = inumber;

			was_dir = (statemap[inumber] & DSTATE) == DSTATE;

			switch (statemap[inumber] & ~(INORPHAN | INDELAYD
			    | INZLINK)) {

			case FZLINK:
			case DZLINK:
				/*
				 * INZLINK gets set if the inode claimed zero
				 * links when we first looked at it in pass 1.
				 * If lncntp[] also claims it has zero links,
				 * it really is unreferenced.  However, we
				 * could have found a link to it during one of
				 * the other passes, so we have to check the
				 * final count in lncntp[].
				 */
				if (lncntp[inumber] == 0) {
					clri(&idesc, "UNREF", CLRI_VERBOSE,
					    CLRI_NOP_OK);
					if (was_dir &&
					    (statemap[inumber] == USTATE))
						need_rescan = 1;
					break;
				}
				/* FALLTHROUGH */

			case FSTATE:
			case DFOUND:
			case SSTATE:
				n = lncntp[inumber];
				if (n || (statemap[inumber] &
				    (INDELAYD | INZLINK))) {
					/*
					 * adjust() will clear the inode if
					 * the link count goes to zero.  If
					 * it isn't cleared, we need to note
					 * that we've adjusted the count
					 * already, so we don't do it again
					 * on a rescan.
					 */
					adjust(&idesc, n);
					if (was_dir &&
					    (statemap[inumber] == USTATE)) {
						need_rescan = 1;
					} else {
						TRACK_LNCNTP(inumber,
						    lncntp[inumber] = 0);
					}
				}
				break;

			case DSTATE:
				clri(&idesc, "UNREF", CLRI_VERBOSE,
				    CLRI_NOP_OK);
				if (was_dir && (statemap[inumber] == USTATE))
					need_rescan = 1;
				break;

			case DCLEAR:
				dp = ginode(inumber);
				if (dp->di_size == 0) {
					clri(&idesc, "ZERO LENGTH",
					    CLRI_VERBOSE, CLRI_NOP_CORRUPT);
					break;
				}
				/* FALLTHROUGH */

			case FCLEAR:
				clri(&idesc, "BAD/DUP", CLRI_VERBOSE,
				    CLRI_NOP_CORRUPT);
				break;

			case SCLEAR:
				clri(&idesc, "BAD", CLRI_VERBOSE,
				    CLRI_NOP_CORRUPT);
				break;

			case USTATE:
				break;

			default:
				errexit("BAD STATE 0x%x FOR INODE I=%d",
					(int)statemap[inumber], inumber);
			}
		}
	} while (need_rescan);
}

int
pass4check(struct inodesc *idesc)
{
	int fragnum, cg_frag;
	int res = KEEPON;
	daddr32_t blkno = idesc->id_blkno;
	int cylno;
	struct cg *cgp = &cgrp;
	caddr_t err;

	if ((idesc->id_truncto >= 0) && (idesc->id_lbn < idesc->id_truncto)) {
		if (debug)
			(void) printf(
		    "pass4check: skipping inode %d lbn %d with truncto %d\n",
			    idesc->id_number, idesc->id_lbn,
			    idesc->id_truncto);
		return (KEEPON);
	}

	for (fragnum = 0; fragnum < idesc->id_numfrags; fragnum++) {
		if (chkrange(blkno + fragnum, 1)) {
			res = SKIP;
		} else if (testbmap(blkno + fragnum)) {
			/*
			 * The block's in use.  Remove our reference
			 * from it.
			 *
			 * If it wasn't a dup, or everybody's done with
			 * it, then this is the last reference and it's
			 * safe to actually deallocate the on-disk block.
			 *
			 * We depend on pass 5 resolving the on-disk bitmap
			 * effects.
			 */
			cg_frag = blkno + fragnum;
			if (!find_dup_ref(cg_frag, idesc->id_number,
			    idesc->id_lbn * sblock.fs_frag + fragnum,
			    DB_DECR)) {

				if (debug)
					(void) printf("p4c marking %d avail\n",
					    cg_frag);
				clrbmap(cg_frag);
				n_blks--;

				/*
				 * Do the same for the on-disk bitmap, so
				 * that we don't need another pass to figure
				 * out what's really being used.  We'll let
				 * pass5() work out the fragment/block
				 * accounting.
				 */
				cylno = dtog(&sblock, cg_frag);
				(void) getblk(&cgblk, cgtod(&sblock, cylno),
				    (size_t)sblock.fs_cgsize);
				err = cg_sanity(cgp, cylno);
				if (err != NULL) {
					pfatal("CG %d: %s\n", cylno, err);
					free((void *)err);
					if (reply("REPAIR") == 0)
						errexit("Program terminated.");
					fix_cg(cgp, cylno);
				}
				clrbit(cg_blksfree(cgp),
				    dtogd(&sblock, cg_frag));
				cgdirty();

				res |= ALTERED;
			}
		}
	}
	return (res);
}
