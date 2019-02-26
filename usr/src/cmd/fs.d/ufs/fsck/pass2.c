/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved	*/

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

#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/mntent.h>
#include <sys/fs/ufs_fs.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#define	_KERNEL
#include <sys/fs/ufs_fsdir.h>
#undef _KERNEL
#include <string.h>
#include "fsck.h"

#define	MINDIRSIZE	(sizeof (struct dirtemplate))

static int blksort(const void *, const void *);
static int pass2check(struct inodesc *);

void
pass2(void)
{
	struct dinode		*dp, *dp2, *dpattr;
	struct inoinfo		**inpp, *inp;
	struct inoinfo		**inpend;
	struct inodesc		curino;
	struct inodesc		ldesc;
	struct dinode		dino;
	char			pathbuf[MAXPATHLEN + 1];
	int			found;
	int			dirtype;
	caddr_t			errmsg;
	struct shadowclientinfo *sci;

	switch (statemap[UFSROOTINO] & ~INDELAYD) {
	case USTATE:
		pfatal("ROOT INODE UNALLOCATED");
		if (reply("ALLOCATE") == 0) {
			errexit("Program terminated.");
		}
		if (allocdir(UFSROOTINO, UFSROOTINO, 0755, 0) != UFSROOTINO)
			errexit("CANNOT ALLOCATE ROOT INODE\n");
		break;

	case DCLEAR:
		pfatal("DUPS/BAD IN ROOT INODE");
		if (reply("REALLOCATE") == 1) {
			freeino(UFSROOTINO, TI_NOPARENT);
			if (allocdir(UFSROOTINO, UFSROOTINO,
			    0755, 0) != UFSROOTINO)
				errexit("CANNOT ALLOCATE ROOT INODE\n");
			break;
		}
		if (reply("CONTINUE") == 0) {
			errexit("Program terminated.");
		}
		break;

	case FSTATE:
	case FCLEAR:
	case FZLINK:
	case SSTATE:
	case SCLEAR:
		pfatal("ROOT INODE NOT DIRECTORY");
		if (reply("REALLOCATE") == 1) {
			freeino(UFSROOTINO, TI_NOPARENT);
			if (allocdir(UFSROOTINO, UFSROOTINO, 0755, 0) !=
			    UFSROOTINO)
				errexit("CANNOT ALLOCATE ROOT INODE\n");
			break;
		}
		if (reply("FIX") == 0) {
			ckfini();
			errexit("Program terminated.");
		}
		dp = ginode(UFSROOTINO);
		dp->di_mode &= ~IFMT;
		dp->di_mode |= IFDIR;
		inodirty();
		break;

	case DSTATE:
	case DZLINK:
		break;

	default:
		errexit("BAD STATE 0x%x FOR ROOT INODE\n",
		    statemap[UFSROOTINO]);
	}
	statemap[UFSROOTINO] = DFOUND;

	/*
	 * Technically, we do know who the parent is.  However,
	 * if this is set, then we'll get confused during the
	 * second-dir-entry-is-dotdot test for the root inode.
	 */
	inp = getinoinfo(UFSROOTINO);
	if (inp != NULL && inp->i_dotdot != 0)
		inp->i_dotdot = 0;

	/*
	 * Sort the directory list into disk block order.  There's no
	 * requirement to do this, but it may help improve our i/o times
	 * somewhat.
	 */
	qsort((void *)inpsort, (size_t)inplast, sizeof (*inpsort), blksort);
	/*
	 * Check the integrity of each directory.  In general, we treat
	 * attribute directories just like normal ones.  Only the handling
	 * of .. is really different.
	 */
	(void) memset(&dino, 0, sizeof (struct dinode));
	dino.di_mode = IFDIR;
	inpend = &inpsort[inplast];
	for (inpp = inpsort; inpp < inpend; inpp++) {
		inp = *inpp;

		if (inp->i_isize == 0)
			continue;

		/* != DSTATE also covers case of == USTATE */
		if (((statemap[inp->i_number] & STMASK) != DSTATE) ||
		    ((statemap[inp->i_number] & INCLEAR) == INCLEAR))
			continue;

		if (inp->i_isize < (offset_t)MINDIRSIZE) {
			direrror(inp->i_number, "DIRECTORY TOO SHORT");
			inp->i_isize = (offset_t)roundup(MINDIRSIZE, DIRBLKSIZ);
			if (reply("FIX") == 1) {
				dp = ginode(inp->i_number);
				dp->di_size = (u_offset_t)inp->i_isize;
				inodirty();
			} else {
				iscorrupt = 1;
			}
		}
		if ((inp->i_isize & (offset_t)(DIRBLKSIZ - 1)) != 0) {
			getpathname(pathbuf, inp->i_number, inp->i_number);
			pwarn("DIRECTORY %s: LENGTH %lld NOT MULTIPLE OF %d",
			    pathbuf, (longlong_t)inp->i_isize, DIRBLKSIZ);
			inp->i_isize = roundup(inp->i_isize,
			    (offset_t)DIRBLKSIZ);
			if (preen || reply("ADJUST") == 1) {
				dp = ginode(inp->i_number);
				dp->di_size =
				    (u_offset_t)roundup(inp->i_isize,
				    (offset_t)DIRBLKSIZ);
				inodirty();
				if (preen)
					(void) printf(" (ADJUSTED)\n");
			} else {
				iscorrupt = 1;
			}
		}
		dp = ginode(inp->i_number);
		if ((dp->di_mode & IFMT) == IFATTRDIR &&
		    (dp->di_cflags & IXATTR) == 0) {
			pwarn("ATTRIBUTE DIRECTORY  I=%d  MISSING IXATTR FLAG",
			    inp->i_number);
			if (preen || reply("CORRECT") == 1) {
				dp->di_cflags |= IXATTR;
				inodirty();
				if (preen)
					(void) printf(" (CORRECTED)\n");
			}
		}
		dp = &dino;
		dp->di_size = (u_offset_t)inp->i_isize;
		(void) memmove((void *)&dp->di_db[0], (void *)&inp->i_blks[0],
		    inp->i_blkssize);
		init_inodesc(&curino);
		curino.id_type = DATA;
		curino.id_func = pass2check;
		curino.id_number = inp->i_number;
		curino.id_parent = inp->i_parent;
		curino.id_fix = DONTKNOW;
		(void) ckinode(dp, &curino, CKI_TRAVERSE);

		/*
		 * Make sure we mark attrdirs as DFOUND, since they won't
		 * be located during normal scan of standard directories.
		 */
		if (curino.id_parent == 0) {
			dpattr = ginode(inp->i_number);
			if ((dpattr->di_mode & IFMT) == IFATTRDIR) {
				for (sci = attrclientinfo; sci != NULL;
				    sci = sci->next) {
					if (sci->shadow == inp->i_number) {
						curino.id_parent =
						    sci->clients->client[0];
						statemap[inp->i_number] =
						    DFOUND;
						inp->i_parent =
						    curino.id_parent;
					}
				}
			}
		}
	}
	/*
	 * Now that the parents of all directories have been found,
	 * make another pass to verify the value of ..
	 */
	for (inpp = inpsort; inpp < inpend; inpp++) {
		inp = *inpp;
		if (inp->i_parent == 0 || inp->i_isize == 0)
			continue;
		/*
		 * There are only directories in inpsort[], so only
		 * directory-related states need to be checked.  There
		 * should never be any flags associated with USTATE.
		 */
		if ((statemap[inp->i_number] & (STMASK | INCLEAR)) == DCLEAR ||
		    statemap[inp->i_number] == USTATE) {
			continue;
		}
		if (statemap[inp->i_parent] == DFOUND &&
		    S_IS_DUNFOUND(statemap[inp->i_number])) {
			statemap[inp->i_number] = DFOUND |
			    (statemap[inp->i_number] & INCLEAR);
		}
		if (inp->i_dotdot == inp->i_parent ||
		    inp->i_dotdot == (fsck_ino_t)-1) {
			continue;
		}
		if (inp->i_dotdot == 0) {
			inp->i_dotdot = inp->i_parent;
			fileerror(inp->i_parent, inp->i_number,
			    "MISSING '..'");
			if (reply("FIX") == 0) {
				iscorrupt = 1;
				continue;
			}
			dp = ginode(inp->i_number);
			found = 0;
			dirtype = (dp->di_mode & IFMT);

			/*
			 * See if this is an attrdir that we located in pass1.
			 * i.e. it was on an i_oeftflag of some other inode.
			 * if it isn't found then we have an orphaned attrdir
			 * that needs to be tossed into lost+found.
			 */
			if (dirtype == IFATTRDIR) {
				for (sci = attrclientinfo;
				    sci != NULL;
				    sci = sci->next) {
					if (sci->shadow == inp->i_number) {
						inp->i_parent =
						    sci->clients->client[0];
						found = 1;
					}
				}
			}

			/*
			 * We've already proven there's no "..", so this
			 * can't create a duplicate.
			 */
			if (makeentry(inp->i_number, inp->i_parent, "..")) {

				/*
				 * is it an orphaned attrdir?
				 */
				if (dirtype == IFATTRDIR && found == 0) {
					/*
					 * Throw it into lost+found
					 */
					if (linkup(inp->i_number, lfdir,
					    NULL) == 0) {
						pwarn(
			    "Unable to move attrdir I=%d to lost+found\n",
						    inp->i_number);
						iscorrupt = 1;
					}
					maybe_convert_attrdir_to_dir(
					    inp->i_number);
				}
				if (dirtype == IFDIR) {
					LINK_RANGE(errmsg,
					    lncntp[inp->i_parent], -1);
					if (errmsg != NULL) {
						LINK_CLEAR(errmsg,
						    inp->i_parent, IFDIR,
						    &ldesc);
						if (statemap[inp->i_parent] !=
						    USTATE) {
							/*
							 * iscorrupt is
							 * already set
							 */
							continue;
						}
					}
					TRACK_LNCNTP(inp->i_parent,
					    lncntp[inp->i_parent]--);
				}

				continue;
			}
			pfatal("CANNOT FIX, INSUFFICIENT SPACE TO ADD '..'\n");
			iscorrupt = 1;
			inp->i_dotdot = (fsck_ino_t)-1;
			continue;
		}

		dp2 = ginode(inp->i_parent);

		if ((dp2->di_mode & IFMT) == IFATTRDIR) {
			continue;
		}
		fileerror(inp->i_parent, inp->i_number,
		    "BAD INODE NUMBER FOR '..'");
		if (reply("FIX") == 0) {
			iscorrupt = 1;
			continue;
		}

		LINK_RANGE(errmsg, lncntp[inp->i_dotdot], 1);
		if (errmsg != NULL) {
			LINK_CLEAR(errmsg, inp->i_dotdot, IFDIR, &ldesc);
			if (statemap[inp->i_dotdot] != USTATE) {
				/* iscorrupt is already set */
				continue;
			}
		}
		TRACK_LNCNTP(inp->i_dotdot, lncntp[inp->i_dotdot]++);

		LINK_RANGE(errmsg, lncntp[inp->i_parent], -1);
		if (errmsg != NULL) {
			LINK_CLEAR(errmsg, inp->i_parent, IFDIR, &ldesc);
			if (statemap[inp->i_parent] != USTATE) {
				/* iscorrupt is already set */
				continue;
			}
		}
		TRACK_LNCNTP(inp->i_parent, lncntp[inp->i_parent]--);

		inp->i_dotdot = inp->i_parent;
		(void) changeino(inp->i_number, "..", inp->i_parent);
	}
	/*
	 * Mark all the directories that can be found from the root.
	 */
	propagate();
}

/*
 * Sanity-check a single directory entry.  Which entry is being
 * examined is tracked via idesc->id_entryno.  There are two
 * special ones, 0 (.) and 1 (..).  Those have to exist in order
 * in the first two locations in the directory, and have the usual
 * properties.  All other entries have to not be for either of
 * the special two, and the inode they reference has to be
 * reasonable.
 *
 * This is only called from dirscan(), which looks for the
 * ALTERED flag after each invocation.  If it finds it, the
 * relevant buffer gets pushed out, so we don't have to worry
 * about it here.
 */
#define	PASS2B_PROMPT	"REMOVE DIRECTORY ENTRY FROM I=%d"

static int
pass2check(struct inodesc *idesc)
{
	struct direct *dirp = idesc->id_dirp;
	struct inodesc ldesc;
	struct inoinfo *inp;
	short reclen, entrysize;
	int ret = 0;
	int act, update_lncntp;
	struct dinode *dp, *pdirp, *attrdirp;
	caddr_t errmsg;
	struct direct proto;
	char namebuf[MAXPATHLEN + 1];
	char pathbuf[MAXPATHLEN + 1];
	int isattr;
	int pdirtype;
	int breakout = 0;
	int dontreconnect;

	if (idesc->id_entryno != 0)
		goto chk1;
	/*
	 * check for "."
	 */
	if (dirp->d_ino != 0 && strcmp(dirp->d_name, ".") == 0) {
		if (dirp->d_ino != idesc->id_number) {
			direrror(idesc->id_number, "BAD INODE NUMBER FOR '.'");
			dirp->d_ino = idesc->id_number;
			if (reply("FIX") == 1) {
				ret |= ALTERED;
			} else {
				iscorrupt = 1;
			}
		}
		goto chk1;
	}
	/*
	 * Build up a new one, and make sure there's room to put
	 * it where it belongs.
	 */
	direrror(idesc->id_number, "MISSING '.'");
	proto.d_ino = idesc->id_number;
	proto.d_namlen = 1;
	(void) strcpy(proto.d_name, ".");
	entrysize = DIRSIZ(&proto);
	if (dirp->d_ino != 0 && strcmp(dirp->d_name, "..") != 0) {
		pfatal("CANNOT FIX, FIRST ENTRY IN DIRECTORY CONTAINS %s\n",
		    dirp->d_name);
		iscorrupt = 1;
	} else if ((int)dirp->d_reclen < entrysize) {
		pfatal("CANNOT FIX, INSUFFICIENT SPACE TO ADD '.'\n");
		iscorrupt = 1;
	} else if ((int)dirp->d_reclen < 2 * entrysize) {
		/*
		 * No room for another entry after us ("." is the
		 * smallest entry you can have), so just put all
		 * of the old entry's space into the new entry.
		 *
		 * Because we don't touch id_entryno, we end up going
		 * through the chk2 tests as well.
		 */
		proto.d_reclen = dirp->d_reclen;
		(void) memmove((void *)dirp, (void *)&proto,
		    (size_t)entrysize);
		if (reply("FIX") == 1) {
			ret |= ALTERED;
		} else {
			iscorrupt = 1;
		}
	} else {
		/*
		 * There's enough room for an entire additional entry
		 * after this, so create the "." entry and follow it
		 * with an empty entry that covers the rest of the
		 * space.
		 *
		 * The increment of id_entryno means we'll skip the
		 * "." case of chk1, doing the ".." tests instead.
		 * Since we know that there's not a ".." where it
		 * should be (because we just created an empty entry
		 * there), that's the best way of getting it recreated
		 * as well.
		 */
		reclen = dirp->d_reclen - entrysize;
		proto.d_reclen = entrysize;
		(void) memmove((void *)dirp, (void *)&proto,
		    (size_t)entrysize);
		idesc->id_entryno++;
		/*
		 * Make sure the link count is in range before updating
		 * it.  This makes the assumption that the link count
		 * for this inode included one for ".", even though
		 * there wasn't a "." entry.  Even if that's not true,
		 * it's a reasonable working hypothesis, and the link
		 * count verification done in pass4 will fix it for
		 * us anyway.
		 */
		LINK_RANGE(errmsg, lncntp[dirp->d_ino], -1);
		if (errmsg != NULL) {
			LINK_CLEAR(errmsg, dirp->d_ino, IFDIR, &ldesc);
			if (statemap[dirp->d_ino] == USTATE) {
				/*
				 * The inode got zapped, so reset the
				 * directory entry.  Extend it to also
				 * cover the space we were going to make
				 * into a new entry.
				 */
				dirp->d_ino = 0;
				dirp->d_reclen += reclen;
				ret |= ALTERED;
				return (ret);
			}
		}

		/*
		 * Create the new empty entry.
		 */
		/* LINTED pointer cast alignment (entrysize is valid) */
		dirp = (struct direct *)((char *)(dirp) + entrysize);
		(void) memset((void *)dirp, 0, (size_t)reclen);
		dirp->d_reclen = reclen;

		/*
		 * Did the user want us to create a new "."?  This
		 * query assumes that the direrror(MISSING) was the
		 * last thing printed, so if the LINK_RANGE() check
		 * fails, it can't pass through here.
		 */
		if (reply("FIX") == 1) {
			TRACK_LNCNTP(idesc->id_number,
			    lncntp[idesc->id_number]--);
			ret |= ALTERED;
		} else {
			iscorrupt = 1;
		}
	}

	/*
	 * XXX The next few lines are needed whether we're processing "."
	 * or "..".  However, there are some extra steps still needed
	 * for the former, hence the big block of code for
	 * id_entryno == 0.  Alternatively, there could be a label just
	 * before this comment, and everything through the end of that
	 * block moved there.  In some ways, that might make the
	 * control flow more logical (factoring out to separate functions
	 * would be even better).
	 */

chk1:
	if (idesc->id_entryno > 1)
		goto chk2;
	inp = getinoinfo(idesc->id_number);
	if (inp == NULL) {
		/*
		 * This is a can't-happen, since inodes get cached before
		 * we get called on them.
		 */
		errexit("pass2check got NULL from getinoinfo at chk1 I=%d\n",
		    idesc->id_number);
	}
	proto.d_ino = inp->i_parent;
	proto.d_namlen = 2;
	(void) strcpy(proto.d_name, "..");
	entrysize = DIRSIZ(&proto);
	if (idesc->id_entryno == 0) {
		/*
		 * We may not actually need to split things up, but if
		 * there's room to do so, we should, as that implies
		 * that the "." entry is larger than it is supposed
		 * to be, and therefore there's something wrong, albeit
		 * possibly harmlessly so.
		 */
		reclen = DIRSIZ(dirp);
		if ((int)dirp->d_reclen < reclen + entrysize) {
			/*
			 * Not enough room for inserting a ".." after
			 * the "." entry.
			 */
			goto chk2;
		}
		/*
		 * There's enough room for an entire additional entry
		 * after "."'s, so split it up.  There's no reason "."
		 * should be bigger than the minimum, so shrink it to
		 * fit, too.  Since by the time we're done with this
		 * part, dirp will be pointing at where ".." should be,
		 * update id_entryno to show that that's the entry
		 * we're on.
		 */
		proto.d_reclen = dirp->d_reclen - reclen;
		dirp->d_reclen = reclen;
		idesc->id_entryno++;
		if (dirp->d_ino > 0 && dirp->d_ino <= maxino) {
			/*
			 * Account for the link to ourselves.
			 */
			LINK_RANGE(errmsg, lncntp[dirp->d_ino], -1);
			if (errmsg != NULL) {
				LINK_CLEAR(errmsg, dirp->d_ino, IFDIR, &ldesc);
				if (statemap[dirp->d_ino] == USTATE) {
					/*
					 * We were going to split the entry
					 * up, but the link count overflowed.
					 * Since we got rid of the inode,
					 * we need to also zap the directory
					 * entry, and restoring the original
					 * state of things is the least-bad
					 * result.
					 */
					dirp->d_ino = 0;
					dirp->d_reclen += proto.d_reclen;
					ret |= ALTERED;
					return (ret);
				}
			}
			TRACK_LNCNTP(dirp->d_ino, lncntp[dirp->d_ino]--);
			/*
			 * Make sure the new entry doesn't get interpreted
			 * as having actual content.
			 */
			/* LINTED pointer cast alignment (reclen is valid) */
			dirp = (struct direct *)((char *)(dirp) + reclen);
			(void) memset((void *)dirp, 0, (size_t)proto.d_reclen);
			dirp->d_reclen = proto.d_reclen;
		} else {
			/*
			 * Everything was fine, up until we realized that
			 * the indicated inode was impossible.  By clearing
			 * d_ino here, we'll trigger the recreation of it
			 * down below, using i_parent.  Unlike the other
			 * half of this if(), we're everything so it shows
			 * that we're still on the "." entry.
			 */
			fileerror(idesc->id_number, dirp->d_ino,
			    "I OUT OF RANGE");
			dirp->d_ino = 0;
			if (reply("FIX") == 1) {
				ret |= ALTERED;
			} else {
				iscorrupt = 1;
			}
		}
	}
	/*
	 * Record this ".." inode, but only if we haven't seen one before.
	 * If this isn't the first, it'll get cleared below, and so we
	 * want to remember the entry that'll still be around later.
	 */
	if (dirp->d_ino != 0 && inp->i_dotdot == 0 &&
	    strcmp(dirp->d_name, "..") == 0) {
		inp->i_dotdot = dirp->d_ino;
		goto chk2;
	}
	if (dirp->d_ino != 0 && strcmp(dirp->d_name, "..") != 0) {
		fileerror(inp->i_parent, idesc->id_number, "MISSING '..'");
		pfatal("CANNOT FIX, SECOND ENTRY IN DIRECTORY CONTAINS %s\n",
		    dirp->d_name);
		iscorrupt = 1;
		inp->i_dotdot = (fsck_ino_t)-1;
	} else if ((int)dirp->d_reclen < entrysize) {
		fileerror(inp->i_parent, idesc->id_number, "MISSING '..'");
		pfatal("CANNOT FIX, INSUFFICIENT SPACE TO ADD '..'\n");
		/* XXX Same consideration as immediately above. */
		iscorrupt = 1;
		inp->i_dotdot = (fsck_ino_t)-1;
	} else if (inp->i_parent != 0) {
		/*
		 * We know the parent, so fix now.
		 */
		proto.d_ino = inp->i_dotdot = inp->i_parent;
		fileerror(inp->i_parent, idesc->id_number, "MISSING '..'");
		/*
		 * Lint won't be quiet about d_reclen being set but not
		 * used.  It apparently doesn't understand the implications
		 * of calling memmove(), and won't believe us that it's ok.
		 */
		proto.d_reclen = dirp->d_reclen;
		(void) memmove((void *)dirp, (void *)&proto,
		    (size_t)entrysize);
		if (reply("FIX") == 1) {
			ret |= ALTERED;
		} else {
			iscorrupt = 1;
		}
	} else if (inp->i_number == UFSROOTINO) {
		/*
		 * Always know parent of root inode, so fix now.
		 */
		proto.d_ino = inp->i_dotdot = inp->i_parent = UFSROOTINO;
		fileerror(inp->i_parent, idesc->id_number, "MISSING '..'");
		/*
		 * Lint won't be quiet about d_reclen being set but not
		 * used.  It apparently doesn't understand the implications
		 * of calling memmove(), and won't believe us that it's ok.
		 */
		proto.d_reclen = dirp->d_reclen;
		(void) memmove((void *)dirp, (void *)&proto, (size_t)entrysize);
		if (reply("FIX") == 1) {
			ret |= ALTERED;
		} else {
			iscorrupt = 1;
		}
	}
	idesc->id_entryno++;
	if (dirp->d_ino != 0) {
		LINK_RANGE(errmsg, lncntp[dirp->d_ino], -1);
		if (errmsg != NULL) {
			LINK_CLEAR(errmsg, dirp->d_ino, IFDIR, &ldesc);
			if (statemap[dirp->d_ino] == USTATE) {
				dirp->d_ino = 0;
				ret |= ALTERED;
			}
		}
		TRACK_LNCNTP(dirp->d_ino, lncntp[dirp->d_ino]--);
	}
	return (ret|KEEPON);
chk2:
	if (dirp->d_ino == 0)
		return (ret|KEEPON);
	if (dirp->d_namlen <= 2 &&
	    dirp->d_name[0] == '.' &&
	    idesc->id_entryno >= 2) {
		if (dirp->d_namlen == 1) {
			direrror(idesc->id_number, "EXTRA '.' ENTRY");
			dirp->d_ino = 0;
			if (reply("FIX") == 1) {
				ret |= ALTERED;
			} else {
				iscorrupt = 1;
			}
			return (KEEPON | ret);
		}
		if (dirp->d_name[1] == '.') {
			direrror(idesc->id_number, "EXTRA '..' ENTRY");
			dirp->d_ino = 0;
			if (reply("FIX") == 1) {
				ret |= ALTERED;
			} else {
				iscorrupt = 1;
			}
			return (KEEPON | ret);
		}
	}
	/*
	 * Because of this increment, all tests for skipping . and ..
	 * below are ``> 2'', not ``> 1'' as would logically be expected.
	 */
	idesc->id_entryno++;
	act = -1;
	/*
	 * The obvious check would be for d_ino < UFSROOTINO.  However,
	 * 1 is a valid inode number.  Although it isn't currently used,
	 * as it was once the bad block list, there's nothing to prevent
	 * it from acquiring a new purpose in the future.  So, don't
	 * arbitrarily disallow it.  We don't test for <= zero, because
	 * d_ino is unsigned.
	 */
	update_lncntp = 0;
	if (dirp->d_ino > maxino || dirp->d_ino == 0) {
		fileerror(idesc->id_number, dirp->d_ino, "I OUT OF RANGE");
		act = (reply(PASS2B_PROMPT, idesc->id_number) == 1);
	} else {
again:
		update_lncntp = 0;
		switch (statemap[dirp->d_ino] & ~(INDELAYD)) {
		case USTATE:
			if (idesc->id_entryno <= 2)
				break;
			fileerror(idesc->id_number, dirp->d_ino, "UNALLOCATED");
			act = (reply(PASS2B_PROMPT, idesc->id_number) == 1);
			break;

		case DCLEAR:
		case FCLEAR:
		case SCLEAR:
			if (idesc->id_entryno <= 2)
				break;
			dp = ginode(dirp->d_ino);
			if (statemap[dirp->d_ino] == DCLEAR) {
				errmsg = ((dp->di_mode & IFMT) == IFATTRDIR) ?
			    "REFERENCE TO ZERO LENGTH ATTRIBUTE DIRECTORY" :
			    "REFERENCE TO ZERO LENGTH DIRECTORY";
				inp = getinoinfo(dirp->d_ino);
				if (inp == NULL) {
					/*
					 * The inode doesn't exist, as all
					 * should be cached by now.  This
					 * gets caught by the range check
					 * above, and so it is a can't-happen
					 * at this point.
					 */
					errexit("pass2check found a zero-len "
					    "reference to bad I=%d\n",
					    dirp->d_ino);
				}
				if (inp->i_parent != 0) {
					(void) printf(
		    "Multiple links to I=%d, link counts wrong, rerun fsck\n",
					    inp->i_number);
					iscorrupt = 1;
				}
			} else if (statemap[dirp->d_ino] == SCLEAR) {
				/*
				 * In theory, this is a can't-happen,
				 * because shadows don't appear in directory
				 * entries.  However, an inode might've
				 * been reused without a stale directory
				 * entry having been cleared, so check
				 * for it just in case.  We'll check for
				 * the no-dir-entry shadows in pass3b().
				 */
				errmsg = "ZERO LENGTH SHADOW";
			} else {
				errmsg = "DUP/BAD";
			}
			fileerror(idesc->id_number, dirp->d_ino, errmsg);
			if ((act = reply(PASS2B_PROMPT, idesc->id_number)) == 1)
				break;
			/*
			 * Not doing anything about it, so just try
			 * again as whatever the base type was.
			 *
			 * fileerror() invalidated dp.  Lint thinks this
			 * is unnecessary, but we know better.
			 */
			dp = ginode(dirp->d_ino);
			statemap[dirp->d_ino] &= STMASK;
			TRACK_LNCNTP(dirp->d_ino, lncntp[dirp->d_ino] = 0);
			goto again;

		case DSTATE:
		case DZLINK:
			if (statemap[idesc->id_number] == DFOUND) {
				statemap[dirp->d_ino] = DFOUND;
			}
			/* FALLTHROUGH */

		case DFOUND:
			/*
			 * This is encouraging the best-practice of not
			 * hard-linking directories.  It's legal (see POSIX),
			 * but not a good idea.  So, don't consider it an
			 * instance of corruption, but offer to nuke it.
			 */
			inp = getinoinfo(dirp->d_ino);
			if (inp == NULL) {
				/*
				 * Same can't-happen argument as in the
				 * zero-len case above.
				 */
				errexit("pass2check found bad reference to "
				    "hard-linked directory I=%d\n",
				    dirp->d_ino);
			}
			dp = ginode(idesc->id_number);
			if (inp->i_parent != 0 && idesc->id_entryno > 2 &&
			    ((dp->di_mode & IFMT) != IFATTRDIR)) {
				/*
				 * XXX For nested dirs, this can report
				 * the same name for both paths.
				 */
				getpathname(pathbuf, idesc->id_number,
				    dirp->d_ino);
				getpathname(namebuf, dirp->d_ino, dirp->d_ino);
				pwarn(
		    "%s IS AN EXTRANEOUS HARD LINK TO DIRECTORY %s\n",
				    pathbuf, namebuf);
				if (preen) {
					(void) printf(" (IGNORED)\n");
				} else {
					act = reply(PASS2B_PROMPT,
					    idesc->id_number);
					if (act == 1) {
						update_lncntp = 1;
						broke_dir_link = 1;
						break;
					}
				}
			}

			if ((idesc->id_entryno > 2) &&
			    (inp->i_extattr != idesc->id_number)) {
				inp->i_parent = idesc->id_number;
			}
			/* FALLTHROUGH */

		case FSTATE:
		case FZLINK:
			/*
			 * There's nothing to do for normal file-like
			 * things.  Extended attributes come through
			 * here as well, though, and for them, .. may point
			 * to a file.  In this situation we don't want
			 * to decrement link count as it was already
			 * decremented when the entry was seen in the
			 * directory it actually lives in.
			 */
			pdirp = ginode(idesc->id_number);
			pdirtype = (pdirp->di_mode & IFMT);
			dp = ginode(dirp->d_ino);
			isattr = (dp->di_cflags & IXATTR);
			act = -1;
			if (pdirtype == IFATTRDIR &&
			    (strcmp(dirp->d_name, "..") == 0)) {
				dontreconnect = 0;
				if (dp->di_oeftflag != 0) {
					attrdirp = ginode(dp->di_oeftflag);

					/*
					 * is it really an attrdir?
					 * if so, then don't do anything.
					 */

					if ((attrdirp->di_mode & IFMT) ==
					    IFATTRDIR)
						dontreconnect = 1;
					dp = ginode(dirp->d_ino);
				}
				/*
				 * Rare corner case - the attrdir's ..
				 * points to the attrdir itself.
				 */
				if (dirp->d_ino == idesc->id_number) {
					dontreconnect = 1;
					TRACK_LNCNTP(idesc->id_number,
					    lncntp[idesc->id_number]--);
				}
				/*
				 * Lets see if we have an orphaned attrdir
				 * that thinks it belongs to this file.
				 * Only re-connect it if the current
				 * attrdir is 0 or not an attrdir.
				 */
				if ((dp->di_oeftflag != idesc->id_number) &&
				    (dontreconnect == 0)) {
					fileerror(idesc->id_number,
					    dirp->d_ino,
					    "Attribute directory I=%d not "
					    "attached to file I=%d\n",
					    idesc->id_number, dirp->d_ino);
					if ((act = reply("FIX")) == 1) {
						dp = ginode(dirp->d_ino);
						if (debug)
							(void) printf(
				    "debug: changing i=%d's oeft from %d ",
							    dirp->d_ino,
							    dp->di_oeftflag);
						dp->di_oeftflag =
						    idesc->id_number;
						if (debug)
							(void) printf("to %d\n",
							    dp->di_oeftflag);
						inodirty();
						registershadowclient(
						    idesc->id_number,
						    dirp->d_ino,
						    &attrclientinfo);
					}
					dp = ginode(dirp->d_ino);
				}

				/*
				 * This can only be true if we've modified
				 * an inode/xattr connection, and we
				 * don't keep track of those in the link
				 * counts.  So, skipping the checks just
				 * after this is not a problem.
				 */
				if (act > 0)
					return (KEEPON | ALTERED);

				/*
				 * Don't screw up link counts for directories.
				 * If we aren't careful we can perform
				 * an extra decrement, since the .. of
				 * an attrdir could be either a file or a
				 * directory.  If it's a file then its link
				 * should be correct after it is seen when the
				 * directory it lives in scanned.
				 */
				if ((pdirtype == IFATTRDIR) &&
				    ((dp->di_mode & IFMT) == IFDIR))
						breakout = 1;
				if ((dp->di_mode & IFMT) != IFDIR)
					breakout = 1;

			} else if ((pdirtype != IFATTRDIR) ||
			    (strcmp(dirp->d_name, ".") != 0)) {
				if ((pdirtype == IFDIR) && isattr) {
					fileerror(idesc->id_number,
					    dirp->d_ino,
					    "File should NOT be marked as "
					    "extended attribute\n");
					if ((act = reply("FIX")) == 1) {
						dp = ginode(dirp->d_ino);
						if (debug)
							(void) printf(
				    "changing i=%d's cflags from 0x%x to ",
							    dirp->d_ino,
							    dp->di_cflags);

						dp->di_cflags &= ~IXATTR;
						if (debug)
							(void) printf("0x%x\n",
							    dp->di_cflags);
						inodirty();
						if ((dp->di_mode & IFMT) ==
						    IFATTRDIR) {
							dp->di_mode &=
							    ~IFATTRDIR;
							dp->di_mode |= IFDIR;
							inodirty();
							pdirp = ginode(
							    idesc->id_number);
							if (pdirp->di_oeftflag
							    != 0) {
							pdirp->di_oeftflag = 0;
								inodirty();
							}
						}
					}
				} else {
					if (pdirtype == IFATTRDIR &&
					    (isattr == 0)) {
						fileerror(idesc->id_number,
						    dirp->d_ino,
						    "File should BE marked as "
						    "extended attribute\n");
						if ((act = reply("FIX")) == 1) {
							dp = ginode(
							    dirp->d_ino);
							dp->di_cflags |= IXATTR;
							/*
							 * Make sure it's a file
							 * while we're at it.
							 */
							dp->di_mode &= ~IFMT;
							dp->di_mode |= IFREG;
							inodirty();
						}
					}
				}

			}
			if (breakout == 0 || dontreconnect == 0) {
				TRACK_LNCNTP(dirp->d_ino,
				    lncntp[dirp->d_ino]--);
				if (act > 0)
					return (KEEPON | ALTERED);
			}
			break;

		case SSTATE:
			errmsg = "ACL IN DIRECTORY";
			fileerror(idesc->id_number, dirp->d_ino, errmsg);
			act = (reply(PASS2B_PROMPT, idesc->id_number) == 1);
			break;

		default:
			errexit("BAD STATE 0x%x FOR INODE I=%d",
			    statemap[dirp->d_ino], dirp->d_ino);
		}
	}

	if (act == 0) {
		iscorrupt = 1;
	}

	if (act <= 0)
		return (ret|KEEPON);

	if (update_lncntp) {
		LINK_RANGE(errmsg, lncntp[idesc->id_number], 1);
		if (errmsg != NULL) {
			LINK_CLEAR(errmsg, idesc->id_number, IFDIR, &ldesc);
			if (statemap[idesc->id_number] == USTATE) {
				idesc->id_number = 0;
				ret |= ALTERED;
			}
		}
		TRACK_LNCNTP(idesc->id_number, lncntp[idesc->id_number]++);
	}

	dirp->d_ino = 0;

	return (ret|KEEPON|ALTERED);
}

#undef	PASS2B_PROMPT

/*
 * Routine to sort disk blocks.
 */
static int
blksort(const void *arg1, const void *arg2)
{
	const struct inoinfo **inpp1 = (const struct inoinfo **)arg1;
	const struct inoinfo **inpp2 = (const struct inoinfo **)arg2;

	return ((*inpp1)->i_blks[0] - (*inpp2)->i_blks[0]);
}
