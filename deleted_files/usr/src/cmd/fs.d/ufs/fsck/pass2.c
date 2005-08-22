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
#include <sys/sysmacros.h>
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
#include <string.h>
#include "fsck.h"

#define	MINDIRSIZE	(sizeof (struct dirtemplate))

int	pass2check(), blksort();

pass2()
{
	struct dinode 		*dp, *dp2, *dpattr;
	struct inoinfo 		**inpp, *inp;
	struct inoinfo 		**inpend;
	struct inodesc 		curino;
	struct dinode 		dino;
	char 			pathbuf[MAXPATHLEN + 1];
	ino_t			parent;
	int			found;
	int			dirtype;
	struct shadowclientinfo *sci;

	switch (statemap[UFSROOTINO]) {

	case USTATE:
		pfatal("ROOT INODE UNALLOCATED");
		if (reply("ALLOCATE") == 0)
			errexit("");
		if (allocdir(UFSROOTINO, UFSROOTINO, 0755) != UFSROOTINO)
			errexit("CANNOT ALLOCATE ROOT INODE\n");
		break;

	case DCLEAR:
		pfatal("DUPS/BAD IN ROOT INODE");
		if (reply("REALLOCATE")) {
			printf("pass2: DCLEAR\n");
			freeino(UFSROOTINO);
			if (allocdir(UFSROOTINO, UFSROOTINO,
							0755) != UFSROOTINO)
				errexit("CANNOT ALLOCATE ROOT INODE\n");
			break;
		}
		if (reply("CONTINUE") == 0)
			errexit("");
		break;

	case FSTATE:
	case FCLEAR:
	case SSTATE:
	case SCLEAR:
		pfatal("ROOT INODE NOT DIRECTORY");
		if (reply("REALLOCATE")) {
			printf("pass2: FSTATE/FCLEAR/SSTATE/SCLEAR\n");
			freeino(UFSROOTINO);
			if (allocdir(UFSROOTINO, UFSROOTINO,
							0755) != UFSROOTINO)
				errexit("CANNOT ALLOCATE ROOT INODE\n");
			break;
		}
		if (reply("FIX") == 0)
			errexit("");
		dp = ginode(UFSROOTINO);
		dp->di_mode &= ~IFMT;
		dp->di_mode |= IFDIR;
		dp->di_smode = dp->di_mode;
		inodirty();
		break;

	case DSTATE:
		break;

	default:
		errexit("BAD STATE %d FOR ROOT INODE", statemap[UFSROOTINO]);
	}
	statemap[UFSROOTINO] = DFOUND;
	/*
	 * Sort the directory list into disk block order.
	 */
	qsort((char *)inpsort, (int)inplast, sizeof (*inpsort), blksort);
	/*
	 * Check the integrity of each directory.
	 */
	bzero((char *)&curino, sizeof (struct inodesc));
	curino.id_type = DATA;
	curino.id_func = pass2check;
	dp = &dino;
	dp->di_mode = IFDIR;
	inpend = &inpsort[inplast];
	for (inpp = inpsort; inpp < inpend; inpp++) {
		inp = *inpp;

		if (inp->i_isize == 0)
			continue;
		if (statemap[inp->i_number] == DCLEAR ||
		    statemap[inp->i_number] == USTATE)
			continue;
		if (inp->i_isize < (offset_t)MINDIRSIZE) {
			direrror(inp->i_number, "DIRECTORY TOO SHORT");
			inp->i_isize = (offset_t)MINDIRSIZE;
			if (reply("FIX") == 1) {
				dp = ginode(inp->i_number);
				dp->di_size = (u_offset_t)MINDIRSIZE;
				inodirty();
				dp = &dino;
			}
		}
		if ((inp->i_isize & (offset_t)(DIRBLKSIZ - 1)) != 0) {
			getpathname(pathbuf, inp->i_number,
					inp->i_number);
			pwarn("DIRECTORY %s: LENGTH %lld NOT MULTIPLE OF %d",
					pathbuf, inp->i_isize, DIRBLKSIZ);
			if (preen)
				printf(" (ADJUSTED)\n");
			inp->i_isize = roundup(inp->i_isize,
					(offset_t)DIRBLKSIZ);
			if (preen || reply("ADJUST") == 1) {
				dp = ginode(inp->i_number);
				dp->di_size =
					(u_offset_t)roundup(
						inp->i_isize,
						(offset_t)DIRBLKSIZ);
				inodirty();
				dp = &dino;
			}
		}
		dp->di_size = (u_offset_t)inp->i_isize;
		bcopy((char *)&inp->i_blks[0], (char *)&dp->di_db[0],
			(size_t)inp->i_numblks);
		curino.id_number = inp->i_number;
		curino.id_parent = inp->i_parent;
		curino.id_fix = DONTKNOW;
		(void) ckinode(dp, &curino);

		/*
		 * Make sure we mark attrdirs as DFOUND, since the won't
		 * be located during normal scan of standard directories.
		 */
		if (curino.id_parent == 0) {
			dpattr = ginode(inp->i_number);
			if (dpattr &&
			    (dpattr->di_mode & IFMT) == IFATTRDIR) {
				for (sci = attrclientinfo; sci;
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
	 * make another pass to verify the value of `..'
	 */
	for (inpp = inpsort; inpp < inpend; inpp++) {
		inp = *inpp;
		if (inp->i_parent == 0 || inp->i_isize == 0)
			continue;
		if (statemap[inp->i_number] == DCLEAR ||
		    statemap[inp->i_number] == USTATE)
			continue;
		if (statemap[inp->i_parent] == DFOUND &&
		    statemap[inp->i_number] == DSTATE)
			statemap[inp->i_number] = DFOUND;
		if (inp->i_dotdot == inp->i_parent ||
		    inp->i_dotdot == (ino_t)-1)
			continue;
		if (inp->i_dotdot == 0) {
			inp->i_dotdot = inp->i_parent;
			fileerror(inp->i_parent, inp->i_number, "MISSING '..'");
			if (reply("FIX") == 0)
				continue;
			dp = ginode(inp->i_number);
			parent = inp->i_parent;
			found = 0;
			dirtype = (dp->di_mode & IFMT);

			/*
			 * See if this is an attrdir that we located in pass1.
			 * i.e. it was on an i_oeftflag of some other inode.
			 * if it isn't found then we have an orphaned attrdir
			 * that needs to be tossed into lost+found.
			 */
			if (dirtype == IFATTRDIR) {
				for (sci = attrclientinfo; sci;
				    sci = sci->next) {
					if (sci->shadow == inp->i_number) {
					    parent = sci->clients->client[0];
						found = 1;
					}
				}
			}

			if (makeentry(inp->i_number, inp->i_parent, "..")) {

				/*
				 * is it an orphaned attrdir?
				 */
				if (dirtype == IFATTRDIR && found == 0) {
					/*
					 * Throw it into lost+found
					 */
					if (linkup(inp->i_number, lfdir) == 0) {
						pwarn("Unable to move attrdir"
						    " I=%d to lost+found\n",
						    inp->i_number);
					}
					dp = ginode(inp->i_number);
					dp->di_mode &= ~IFATTRDIR;
					dp->di_mode |= IFDIR;
					dp->di_cflags &= ~IXATTR;
					dirtype = IFDIR;
					inodirty();
				}
				if (dirtype == IFDIR)
					lncntp[inp->i_parent]--;
				continue;
			}
			pfatal("CANNOT FIX, INSUFFICIENT SPACE TO ADD '..'\n");
			iscorrupt = 1;
			inp->i_dotdot = (ino_t)-1;
			continue;
		}

		dp2 = ginode(inp->i_parent);

		if ((dp2->di_mode & IFMT) == IFATTRDIR)
			continue;

		fileerror(inp->i_parent, inp->i_number,
			"BAD INODE NUMBER FOR '..'");
		if (reply("FIX") == 0)
			continue;
		lncntp[inp->i_dotdot]++;
		lncntp[inp->i_parent]--;
		inp->i_dotdot = inp->i_parent;
		(void) changeino(inp->i_number, "..", inp->i_parent);
	}
	/*
	 * Mark all the directories that can be found from the root.
	 */
	propagate();
}

pass2check(idesc)
	struct inodesc *idesc;
{
	struct direct *dirp = idesc->id_dirp;
	struct inoinfo *inp;
	int n, entrysize, ret = 0;
	struct dinode *dp, *pdirp, *attrdirp;
	char *errmsg;
	struct direct proto;
	char namebuf[MAXPATHLEN + 1];
	char pathbuf[MAXPATHLEN + 1];
	int	isattr = 0;
	int	dirtype = 0;
	int	breakout = 0;
	int	dontreconnect = 0;

	/*
	 * check for "."
	 */
	if (idesc->id_entryno != 0)
		goto chk1;
	if (dirp->d_ino != 0 && strcmp(dirp->d_name, ".") == 0) {
		if (dirp->d_ino != idesc->id_number) {
			direrror(idesc->id_number, "BAD INODE NUMBER FOR '.'");
			dirp->d_ino = idesc->id_number;
			if (reply("FIX") == 1)
				ret |= ALTERED;
		}
		goto chk1;
	}
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
		proto.d_reclen = dirp->d_reclen;
		bcopy((char *)&proto, (char *)dirp, entrysize);
		if (reply("FIX") == 1)
			ret |= ALTERED;
	} else {
		n = dirp->d_reclen - entrysize;
		proto.d_reclen = entrysize;
		bcopy((char *)&proto, (char *)dirp, entrysize);
		idesc->id_entryno++;
		lncntp[dirp->d_ino]--;
		dirp = (struct direct *)((char *)(dirp) + entrysize);
		bzero((char *)dirp, n);
		dirp->d_reclen = n;
		if (reply("FIX") == 1)
			ret |= ALTERED;
	}
chk1:
	if (idesc->id_entryno > 1)
		goto chk2;
	inp = getinoinfo(idesc->id_number);
	proto.d_ino = inp->i_parent;
	proto.d_namlen = 2;
	(void) strcpy(proto.d_name, "..");
	entrysize = DIRSIZ(&proto);
	if (idesc->id_entryno == 0) {
		n = DIRSIZ(dirp);
		if ((int)dirp->d_reclen < n + entrysize)
			goto chk2;
		proto.d_reclen = dirp->d_reclen - n;
		dirp->d_reclen = n;
		idesc->id_entryno++;
		if (dirp->d_ino > 0 && dirp->d_ino <= maxino) {
			lncntp[dirp->d_ino]--;
			dirp = (struct direct *)((char *)(dirp) + n);
			bzero((char *)dirp, (size_t)proto.d_reclen);
			dirp->d_reclen = proto.d_reclen;
		} else {
			fileerror(idesc->id_number, dirp->d_ino,
						"I OUT OF RANGE");
			n = reply("REMOVE");
		}
	}
	if (dirp->d_ino != 0 && strcmp(dirp->d_name, "..") == 0) {
		inp->i_dotdot = dirp->d_ino;
		goto chk2;
	}
	if (dirp->d_ino != 0 && strcmp(dirp->d_name, ".") != 0) {
		fileerror(inp->i_parent, idesc->id_number, "MISSING '..'");
		pfatal("CANNOT FIX, SECOND ENTRY IN DIRECTORY CONTAINS %s\n",
			dirp->d_name);
		iscorrupt = 1;
		inp->i_dotdot = (ino_t)-1;
	} else if ((int)dirp->d_reclen < entrysize) {
		fileerror(inp->i_parent, idesc->id_number, "MISSING '..'");
		pfatal("CANNOT FIX, INSUFFICIENT SPACE TO ADD '..'\n");
		iscorrupt = 1;
		inp->i_dotdot = (ino_t)-1;
	} else if (inp->i_parent != 0) {
		/*
		 * We know the parent, so fix now.
		 */
		proto.d_ino = inp->i_dotdot = inp->i_parent;
		fileerror(inp->i_parent, idesc->id_number, "MISSING '..'");
		proto.d_reclen = dirp->d_reclen;
		bcopy((char *)&proto, (char *)dirp, entrysize);
		if (reply("FIX") == 1)
			ret |= ALTERED;
	} else if (inp->i_number == UFSROOTINO) {
		/*
		 * Always know parent of root inode, so fix now.
		 */
		proto.d_ino = inp->i_dotdot = inp->i_parent = UFSROOTINO;
		fileerror(inp->i_parent, idesc->id_number, "MISSING '..'");
		proto.d_reclen = dirp->d_reclen;
		bcopy((char *)&proto, (char *)dirp, entrysize);
		if (reply("FIX") == 1)
			ret |= ALTERED;
	}
	idesc->id_entryno++;
	if (dirp->d_ino != 0)
		lncntp[dirp->d_ino]--;
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
			if (reply("FIX") == 1)
				ret |= ALTERED;
			return (KEEPON | ret);
		}
		if (dirp->d_name[1] == '.') {
			direrror(idesc->id_number, "EXTRA '..' ENTRY");
			dirp->d_ino = 0;
			if (reply("FIX") == 1)
				ret |= ALTERED;
			return (KEEPON | ret);
		}
	}
	idesc->id_entryno++;
	n = 0;
	if (dirp->d_ino > maxino || dirp->d_ino <= 0) {
		fileerror(idesc->id_number, dirp->d_ino, "I OUT OF RANGE");
		n = reply("REMOVE");
	} else {
again:
		switch (statemap[dirp->d_ino]) {
		case USTATE:
			if (idesc->id_entryno <= 2)
				break;
			fileerror(idesc->id_number, dirp->d_ino, "UNALLOCATED");
			n = reply("REMOVE");
			break;

		case DCLEAR:
		case FCLEAR:
		case SCLEAR:
			if (idesc->id_entryno <= 2)
				break;
			dp = ginode(dirp->d_ino);
			if (statemap[dirp->d_ino] == DCLEAR) {
				errmsg = ((dp->di_mode& IFMT) == IFATTRDIR) ?
				    "ZERO LENGTH ATTRIBUTE DIRECTORY" :
				    "ZERO LENGTH DIRECTORY";
			} else if (statemap[dirp->d_ino] == SCLEAR)
				errmsg = "ZERO LENGTH ACL";
			else
				errmsg = "DUP/BAD";
			fileerror(idesc->id_number, dirp->d_ino, errmsg);
			if ((n = reply("REMOVE")) == 1)
				break;
			statemap[dirp->d_ino] =
			    (dp->di_mode & IFMT) == IFDIR ? DSTATE :
			    (dp->di_mode & IFMT) == IFATTRDIR ? DSTATE :
			    (dp->di_mode & IFMT) == IFSHAD ? SSTATE : FSTATE;
			lncntp[dirp->d_ino] = dp->di_nlink;
			goto again;

		case DSTATE:
			if (statemap[idesc->id_number] == DFOUND)
				statemap[dirp->d_ino] = DFOUND;
			/* fall through */

		case DFOUND:
			inp = getinoinfo(dirp->d_ino);
			dp = ginode(idesc->id_number);
			if (inp->i_parent != 0 && idesc->id_entryno > 2 &&
			    ((dp->di_mode & IFMT) != IFATTRDIR)) {
			    getpathname(pathbuf, idesc->id_number,
			    idesc->id_number);
				getpathname(namebuf, dirp->d_ino, dirp->d_ino);
				pwarn("%s %s %s\n", pathbuf,
				    "IS AN EXTRANEOUS HARD LINK TO DIRECTORY",
				    namebuf);
				if (preen)
					printf(" (IGNORED)\n");
				else if ((n = reply("REMOVE")) == 1)
					break;
			}

			if ((idesc->id_entryno > 2) &&
					(inp->i_extattr != idesc->id_number))
				inp->i_parent = idesc->id_number;

			/* fall through */

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
			if (dirtype == IFATTRDIR &&
			    (strcmp(dirp->d_name, "..") == 0)) {
				dp = ginode(dirp->d_ino);
				if (dp->di_oeftflag != 0) {
					attrdirp = ginode(dp->di_oeftflag);

					/*
					 * is it really an attrdir?
					 * if so then don't do anything.
					 */

					if ((attrdirp->di_mode & IFMT) ==
					    IFATTRDIR)
						dontreconnect = 1;
				} else {
					dontreconnect = 0;
				}

				/*
				 * Lets see if we have an orphaned attrdir
				 * that thinks it belongs to this file?
				 * Only re-connect it, if the current
				 * attrdir is 0 or not an attrdir.
				 */
				if ((dp->di_oeftflag != idesc->id_number) &&
				    (dontreconnect == 0)) {
					fileerror(idesc->id_number,
					    dirp->d_ino,
					    "Attribute directory not attached"
					    " to file");
					if ((n = reply("FIX")) == 1) {
						dp->di_oeftflag =
						    idesc->id_number;
						registershadowclient(
						    idesc->id_number,
						    dirp->d_ino,
						    &attrclientinfo);
						inodirty();
					}
				}

				if (n != 0)
					return (KEEPON | ALTERED);

				/*
				 * don't screw up links counts for directories.
				 * If we aren't careful we can perform
				 * an extra decrement, since the .. of
				 * an attrdir could be either a file or a
				 * directory.  If its a file then its link
				 * should be correct after it is seen when the
				 * directory it lives in scanned.
				 */
				if (((pdirp->di_mode & IFMT) == IFATTRDIR) &&
				    ((dp->di_mode & IFMT) == IFDIR))
						breakout = 1;
				if ((dp->di_mode & IFMT) != IFDIR)
					breakout = 1;

			} else {
				if ((dirtype == IFDIR) && isattr) {
					fileerror(idesc->id_number,
					    dirp->d_ino,
					    "File should NOT be marked as "
					    "extended attribute");
					if ((n = reply("FIX")) == 1) {
						dp = ginode(dirp->d_ino);
						dp->di_cflags &= ~IXATTR;
						if ((dp->di_mode & IFMT) ==
						    IFATTRDIR) {
							dp->di_mode &=
							    ~IFATTRDIR;
							dp->di_mode |= IFDIR;
							inodirty();
							pdirp = ginode(
							    idesc->id_number);
							if (
							    pdirp->di_oeftflag
								!= 0) {
							pdirp->di_oeftflag = 0;
								inodirty();
							}
						} else
							inodirty();
					}
				} else {
					if (dirtype == IFATTRDIR &&
					    (isattr == 0)) {
						fileerror(idesc->id_number,
						    dirp->d_ino,
						    "File should BE marked as "
						    "extended attribute");
						if ((n = reply("FIX")) == 1) {
							dp = ginode(
							    dirp->d_ino);
							dp->di_cflags |= IXATTR;
							inodirty();
						}
					}
				}

			}
			if (breakout == 0 || dontreconnect == 0) {
				lncntp[dirp->d_ino]--;
				if (n != 0)
					return (KEEPON | ALTERED);
			}
			break;

		case SSTATE:
			errmsg = "ACL IN DIRECTORY";
			fileerror(idesc->id_number, dirp->d_ino, errmsg);
			n = reply("REMOVE");
			break;

		default:
			errexit("BAD STATE %d FOR INODE I=%d",
			    statemap[dirp->d_ino], dirp->d_ino);
		}
	}
	if (n == 0)
		return (ret|KEEPON);
	dirp->d_ino = 0;
	return (ret|KEEPON|ALTERED);
}

/*
 * Routine to sort disk blocks.
 */
blksort(inpp1, inpp2)
	struct inoinfo **inpp1, **inpp2;
{

	return ((*inpp1)->i_blks[0] - (*inpp2)->i_blks[0]);
}
