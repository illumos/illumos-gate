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
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mntent.h>
#include <sys/fs/ufs_fs.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#define	_KERNEL
#include <sys/fs/ufs_fsdir.h>
#undef _KERNEL
#include "fsck.h"

static int pass3acheck(struct inodesc *);
static void setcurino(struct inodesc *, struct dinode *, struct inoinfo *);

void
pass3a(void)
{
	caddr_t flow;
	struct inoinfo **inpp, *inp;
	fsck_ino_t orphan;
	int loopcnt;
	int state;
	struct shadowclientinfo *sci, *sci_victim, *sci_prev, **sci_rootp;
	struct inodesc curino;
	struct dinode *dp;
	struct inodesc idesc;
	char namebuf[MAXNAMLEN + 1];

	for (inpp = &inpsort[inplast - 1]; inpp >= inpsort; inpp--) {
		inp = *inpp;
		state = statemap[inp->i_number];
		if (inp->i_number == UFSROOTINO ||
		    (inp->i_parent != 0 && !S_IS_DUNFOUND(state)))
			continue;
		if (state == DCLEAR || state == USTATE || (state & INORPHAN))
			continue;
		/*
		 * If we are running with logging and we come
		 * across unreferenced directories, we just leave
		 * them in DSTATE which will cause them to be pitched
		 * in pass 4.
		 */
		if (preen && !iscorrupt && islog && S_IS_DUNFOUND(state)) {
			if (inp->i_dotdot >= UFSROOTINO) {
				LINK_RANGE(flow, lncntp[inp->i_dotdot], 1);
				if (flow != NULL) {
					dp = ginode(inp->i_dotdot);
					LINK_CLEAR(flow, inp->i_dotdot,
					    dp->di_mode, &idesc);
					if (statemap[inp->i_dotdot] == USTATE)
						continue;
				}
				TRACK_LNCNTP(inp->i_dotdot,
				    lncntp[inp->i_dotdot]++);
			}
			continue;
		}

		for (loopcnt = 0; ; loopcnt++) {
			orphan = inp->i_number;
			/*
			 * Skip out if we aren't connected to the name
			 * space, or our parent is connected, or we've
			 * looked at too many directories.  Our parent
			 * being connected means that orphan is the
			 * first ancestor of *inpp with questionable
			 * antecedents.
			 */
			if (inp->i_parent == 0 ||
			    !INO_IS_DUNFOUND(inp->i_parent) ||
			    loopcnt > numdirs)
				break;
			inp = getinoinfo(inp->i_parent);
			/*
			 * Can't happen, because a non-zero parent's already
			 * been seen and therefore cached.
			 */
			if (inp == NULL)
				errexit("pass3 could not find cached "
					"inode I=%d\n",
					inp->i_parent);
		}

		/*
		 * Already did this one.  Don't bother the user
		 * with redundant questions.
		 */
		if (statemap[orphan] & INORPHAN)
			continue;

		/*
		 * A link count of 0 with parent and .. inodes of 0
		 * indicates a partly deleted directory.
		 * Clear it.
		 */
		dp = ginode(orphan);
		if (dp->di_nlink == 0 && inp->i_dotdot == 0 &&
		    inp->i_parent == 0) {
			/*
			 * clri() just uses curino.id_number; in other
			 * words, it won't use the callback that setcurino()
			 * puts in.
			 */
			setcurino(&curino, dp, inp);
			clri(&curino, "UNREF", CLRI_VERBOSE, CLRI_NOP_OK);

			/*
			 * If we didn't clear it, at least mark it so
			 * we don't waste time on it again.
			 */
			if (statemap[orphan] != USTATE) {
				statemap[orphan] |= INORPHAN;
			}
			continue;
		}

		/*
		 * We can call linkup() multiple times on the same directory
		 * inode, if we were told not to reconnect it the first time.
		 * This is because we find it as a disconnected parent of
		 * of its children (and mark it found), and then finally get
		 * to it in the inpsort array.  This is better than in the
		 * past, where we'd call it every time we found it as a
		 * child's parent.  Ideally, we'd suppress even the second
		 * query, but that confuses pass 4's interpretation of
		 * the state flags.
		 */
		if (loopcnt <= countdirs) {
			if (linkup(orphan, inp->i_dotdot, NULL)) {
				/*
				 * Bookkeeping for any sort of relinked
				 * directory.
				 */
				inp->i_dotdot = lfdir;
				inp->i_parent = inp->i_dotdot;
				statemap[orphan] &= ~(INORPHAN);
			} else {
				statemap[orphan] |= INORPHAN;
			}
			propagate();
			continue;
		}

		/*
		 * We visited more directories than exist in the
		 * filesystem.  The only way to do that is if there's
		 * a loop.
		 */
		pfatal("ORPHANED DIRECTORY LOOP DETECTED I=%d\n", orphan);

		/*
		 * Can never get here with inp->i_parent zero, because
		 * of the interactions between the for() and the
		 * if (loopcnt <= countdirs) above.
		 */
		init_inodesc(&idesc);
		idesc.id_type = DATA;
		idesc.id_number = inp->i_parent;
		idesc.id_parent = orphan;
		idesc.id_func = findname;
		idesc.id_name = namebuf;
		namebuf[0] = '\0';

		/*
		 * Theoretically, this lookup via ckinode can't fail
		 * (if orphan doesn't exist in i_parent, then i_parent
		 * would not have been filled in by pass2check()).
		 * However, if we're interactive, we want to at least
		 * attempt to continue.  The worst case is that it
		 * gets reconnected as #nnn into lost+found instead of
		 * to its old parent with its old name.
		 */
		if ((ckinode(ginode(inp->i_parent),
		    &idesc, CKI_TRAVERSE) & FOUND) == 0)
			pfatal("COULD NOT FIND NAME IN PARENT DIRECTORY");

		if (linkup(orphan, inp->i_parent, namebuf)) {
			if (cleardirentry(inp->i_parent, orphan) & FOUND) {
				LFDIR_LINK_RANGE_NORVAL(flow, lncntp[lfdir], 1,
				    &idesc);
				TRACK_LNCNTP(orphan, lncntp[orphan]++);
			}
			inp->i_parent = inp->i_dotdot = lfdir;
			LFDIR_LINK_RANGE_NORVAL(flow, lncntp[lfdir], -1,
			    &idesc);
			TRACK_LNCNTP(lfdir, lncntp[lfdir]--);
			statemap[orphan] = DFOUND;
		} else {
			/*
			 * Represents a on-disk leak, not an inconsistency,
			 * so don't set iscorrupt.  Such leaks are harmless
			 * in the context of discrepancies that the kernel
			 * will panic over.
			 *
			 * We don't care if tsearch() returns non-NULL
			 * != orphan, since there's no dynamic memory
			 * to free here.
			 */
			if (tsearch((void *)orphan, &limbo_dirs,
				    ino_t_cmp) == NULL)
				errexit("out of memory");
			statemap[orphan] |= INORPHAN;
			continue;
		}
		propagate();
	}

	/*
	 * The essence of the inner loop is to update the inode of
	 * every shadow or attribute inode's lncntp[] by the number of
	 * links we've found to them in pass 2 and above.  Logically,
	 * all that is needed is just the one line:
	 *
	 * lncntp[sci->shadow] -= sci->totalclients;
	 *
	 * However, there's the possibility of wrapping the link count
	 * (this is especially true for shadows, which are expected to
	 * be shared amongst many files).  This means that we have to
	 * range-check before changing anything, and if the check
	 * fails, offer to clear the shadow or attribute.  If we do
	 * clear it, then we have to remove it from the linked list of
	 * all of the type of inodes that we're going through.
	 *
	 * Just to make things a little more complicated, these are
	 * singly-linked lists, so we have to do all the extra
	 * bookkeeping that goes along with that as well.
	 *
	 * The only connection between the shadowclientinfo and
	 * attrclientinfo lists is that they use the same underlying
	 * struct.  Both need this scan, so the outer loop is just to
	 * pick which one we're working on at the moment.  There is no
	 * requirement as to which of these lists is scanned first.
	 */
	for (loopcnt = 0; loopcnt < 2; loopcnt++) {
		if (loopcnt == 0)
			sci_rootp = &shadowclientinfo;
		else
			sci_rootp = &attrclientinfo;

		sci = *sci_rootp;
		sci_prev = NULL;
		while (sci != NULL) {
			sci_victim = NULL;
			LINK_RANGE(flow, lncntp[sci->shadow],
			    -(sci->totalClients));
			if (flow != NULL) {
				/*
				 * Overflowed the link count.
				 */
				dp = ginode(sci->shadow);
				LINK_CLEAR(flow, sci->shadow, dp->di_mode,
				    &idesc);
				if (statemap[sci->shadow] == USTATE) {
					/*
					 * It's been cleared, fix the
					 * lists.
					 */
					if (sci_prev == NULL) {
						*sci_rootp = sci->next;
					} else {
						sci_prev->next = sci->next;
					}
					sci_victim = sci;
				}
			}

			/*
			 * If we did not clear the shadow, then we
			 * need to update the count and advance the
			 * previous pointer.  Otherwise, finish the
			 * clean up once we're done with the struct.
			 */
			if (sci_victim == NULL) {
				TRACK_LNCNTP(sci->shadow,
				    lncntp[sci->shadow] -= sci->totalClients);
				sci_prev = sci;
			}
			sci = sci->next;
			if (sci_victim != NULL)
				deshadow(sci_victim, NULL);
		}
	}
}


/*
 * This is used to verify the cflags of files
 * under a directory that used to be an attrdir.
 */

static int
pass3acheck(struct inodesc *idesc)
{
	struct direct *dirp = idesc->id_dirp;
	int n = 0, ret = 0;
	struct dinode *dp, *pdirp;
	int isattr;
	int dirtype;
	int inotype;

	if (dirp->d_ino == 0)
		return (KEEPON);

	idesc->id_entryno++;
	if ((strcmp(dirp->d_name, ".") == 0) ||
	    (strcmp(dirp->d_name, "..") == 0)) {
		return (KEEPON);
	}

	switch (statemap[dirp->d_ino] & ~(INDELAYD)) {
	case DSTATE:
	case DFOUND:
	case FSTATE:
		/*
		 * Accept DSTATE and DFOUND so we can handle normal
		 * directories as well as xattr directories.
		 *
		 * For extended attribute directories .. may point
		 * to a file.  In this situation we don't want
		 * to decrement link count as it was already
		 * decremented when the entry was seen and decremented
		 * in the directory it actually lives in.
		 */
		dp = ginode(dirp->d_ino);
		isattr = (dp->di_cflags & IXATTR);
		inotype = (dp->di_mode & IFMT);
		pdirp = ginode(idesc->id_number);
		dirtype = (pdirp->di_mode & IFMT);
		/*
		 * IXATTR indicates that an object is itself an extended
		 * attribute.  An IFMT of IFATTRDIR means we are looking
		 * at a directory which contains files which should all
		 * have IXATTR set.  The IFATTRDIR case was handled in
		 * pass 2b.
		 *
		 * Note that the following code actually handles
		 * anything that's marked as an extended attribute but
		 * in a regular directory, not just files.
		 */
		if ((dirtype == IFDIR) && isattr) {
			fileerror(idesc->id_number, dirp->d_ino,
		    "%s I=%d should NOT be marked as extended attribute\n",
			    (inotype == IFDIR) ? "Directory" : "File",
			    dirp->d_ino);
			dp = ginode(dirp->d_ino);
			dp->di_cflags &= ~IXATTR;
			if ((n = reply("FIX")) == 1) {
				inodirty();
			} else {
				iscorrupt = 1;
			}
			if (n != 0)
				return (KEEPON | ALTERED);
		}
		break;
	default:
		errexit("PASS3: BAD STATE %d FOR INODE I=%d",
		    statemap[dirp->d_ino], dirp->d_ino);
		/* NOTREACHED */
	}
	if (n == 0)
		return (ret|KEEPON);
	return (ret|KEEPON|ALTERED);
}

static void
setcurino(struct inodesc *idesc, struct dinode *dp, struct inoinfo *inp)
{
	(void) memmove((void *)&dp->di_db[0], (void *)&inp->i_blks[0],
		inp->i_blkssize);

	init_inodesc(idesc);
	idesc->id_number = inp->i_number;
	idesc->id_parent = inp->i_parent;
	idesc->id_fix = DONTKNOW;
	idesc->id_type = DATA;
	idesc->id_func = pass3acheck;
}

void
maybe_convert_attrdir_to_dir(fsck_ino_t orphan)
{
	struct dinode *dp = ginode(orphan);
	struct inoinfo *inp = getinoinfo(orphan);
	struct inodesc idesc;

	if (dp->di_cflags & IXATTR) {
		dp->di_cflags &= ~IXATTR;
		inodirty();
	}

	if ((dp->di_mode & IFMT) == IFATTRDIR) {
		dp->di_mode &= ~IFATTRDIR;
		dp->di_mode |= IFDIR;
		inodirty();

		setcurino(&idesc, dp, inp);
		idesc.id_fix = FIX;
		idesc.id_filesize = dp->di_size;
		(void) ckinode(dp, &idesc, CKI_TRAVERSE);
	}
}
