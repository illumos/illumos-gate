/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include "restore.h"
/* undef MAXNAMLEN to prevent compiler warnings about redef in dirent.h */
#undef MAXNAMLEN
#include <dirent.h>

#ifdef __STDC__
static char *keyval(int);
static void removexattrs(struct entry *);
static void movexattrs(char *, char *);
#else
static char *keyval();
static void removexattrs();
static void movexattrs();
#endif

/*
 * This implements the 't' option.
 * List entries on the tape.
 */
long
listfile(name, ino, type)
	char *name;
	ino_t ino;
	int type;
{
	long descend = hflag ? GOOD : FAIL;

	if (BIT(ino, dumpmap) == 0) {
		return (descend);
	}
	vprintf(stdout, "%s", type == LEAF ? gettext("leaf") : gettext("dir "));
	(void) fprintf(stdout, "%10lu\t%s\n", ino, name);
	return (descend);
}

/*
 * This implements the 'x' option.
 * Request that new entries be extracted.
 */
long
addfile(name, ino, type)
	char *name;
	ino_t ino;
	int type;
{
	struct entry *ep;
	long descend = hflag ? GOOD : FAIL;
	char buf[100];

	/* Don't know if ino_t is long or long long, so be safe w/ *printf() */

	if (BIT(ino, dumpmap) == 0) {
		if (mflag) {
			dprintf(stdout, gettext(
			    "%s: not on the volume\n"), name);
		} else {
			dprintf(stdout, gettext(
			    "inode %llu: not on the volume\n"),
			    (u_longlong_t)ino);
		}
		return (descend);
	}
	if (!mflag) {
		(void) snprintf(buf, sizeof (buf), "./%llu", (u_longlong_t)ino);
		buf[sizeof (buf) - 1] = '\0';
		name = buf;
		if (type == NODE) {
			(void) genliteraldir(name, ino);
			return (descend);
		}
	}
	ep = lookupino(ino);
	if (ep != NIL) {
		if (strcmp(name, myname(ep)) == 0) {
			/* LINTED: result fits into a short */
			ep->e_flags |= NEW;
			return (descend);
		}
		type |= LINK;
	}
	ep = addentry(name, ino, type);
	if (type == NODE)
		newnode(ep);
	/* LINTED: result fits into a short */
	ep->e_flags |= NEW;
	return (descend);
}

/*
 * This is used by the 'i' option to undo previous requests made by addfile.
 * Delete entries from the request queue.
 */
/* ARGSUSED */
long
deletefile(name, ino, type)
	char *name;
	ino_t ino;
	int type;
{
	long descend = hflag ? GOOD : FAIL;
	struct entry *ep;

	if (BIT(ino, dumpmap) == 0) {
		return (descend);
	}
	ep = lookupino(ino);
	if (ep != NIL) {
		/* LINTED: result fits into a short */
		ep->e_flags &= ~NEW;
	}
	return (descend);
}

/*
 * The following four routines implement the incremental
 * restore algorithm. The first removes old entries, the second
 * does renames and calculates the extraction list, the third
 * cleans up link names missed by the first two, and the final
 * one deletes old directories.
 *
 * Directories cannot be immediately deleted, as they may have
 * other files in them which need to be moved out first. As
 * directories to be deleted are found, they are put on the
 * following deletion list. After all deletions and renames
 * are done, this list is actually deleted.
 */
static struct entry *removelist;

/*
 *	Remove unneeded leaves from the old tree.
 *	Remove directories from the lookup chains.
 */
void
#ifdef __STDC__
removeoldleaves(void)
#else
removeoldleaves()
#endif
{
	struct entry *ep;
	ino_t i;

	vprintf(stdout, gettext("Mark entries to be removed.\n"));
	for (i = ROOTINO + 1; i < maxino; i++) {
		if (BIT(i, clrimap))
			continue;
		ep = lookupino(i);
		if (ep == NIL)
			continue;
		while (ep != NIL) {
			dprintf(stdout, gettext("%s: REMOVE\n"), myname(ep));
			removexattrs(ep->e_xattrs);
			if (ep->e_type == LEAF) {
				removeleaf(ep);
				freeentry(ep);
			} else {
				mktempname(ep);
				deleteino(ep->e_ino);
				/*
				 * once the inode is deleted from the symbol
				 * table, the e_next field is reusable
				 */
				ep->e_next = removelist;
				removelist = ep;
			}
			ep = ep->e_links;
		}
	}
}

/*
 *	For each directory entry on the incremental tape, determine which
 *	category it falls into as follows:
 *	KEEP - entries that are to be left alone.
 *	NEW - new entries to be added.
 *	EXTRACT - files that must be updated with new contents.
 *	LINK - new links to be added.
 *	Renames are done at the same time.
 */
long
nodeupdates(name, ino, type)
	char *name;
	ino_t ino;
	int type;
{
	struct entry *ep, *np, *ip;
	long descend = GOOD;
	int lookuptype = 0;
	int key = 0;
		/* key values */
#define	ONTAPE	0x1	/* inode is on the tape */
#define	INOFND	0x2	/* inode already exists */
#define	NAMEFND	0x4	/* name already exists */
#define	MODECHG	0x8	/* mode of inode changed */

	/*
	 * This routine is called once for each element in the
	 * directory hierarchy, with a full path name.
	 * The "type" value is incorrectly specified as LEAF for
	 * directories that are not on the dump tape.
	 *
	 * Check to see if the file is on the tape.
	 */
	if (BIT(ino, dumpmap))
		key |= ONTAPE;
	/*
	 * Check to see if the name exists, and if the name is a link.
	 */
	np = lookupname(name);
	if (np != NIL) {
		key |= NAMEFND;
		ip = lookupino(np->e_ino);
		if (ip == NULL) {
			(void) fprintf(stderr,
			    gettext("corrupted symbol table\n"));
			done(1);
		}
		if (ip != np)
			lookuptype = LINK;
	}
	/*
	 * Check to see if the inode exists, and if one of its links
	 * corresponds to the name (if one was found).
	 */
	ip = lookupino(ino);
	if (ip != NIL) {
		key |= INOFND;
		for (ep = ip->e_links; ep != NIL; ep = ep->e_links) {
			if (ep == np) {
				/*
				 * Need to set the NEW flag on the hard link
				 * so it gets created because we extract the
				 * "parent".  If the NAMEFND key is set, remove
				 * the leaf.
				 */
				if (ip->e_flags & EXTRACT) {
					if (key & NAMEFND) {
						removeleaf(np);
						freeentry(np);
						np = NIL;
						key &= ~NAMEFND;
					}
					ep->e_flags |= NEW;
				} else {
					ip = ep;
				}
				break;
			}
		}
	}
	/*
	 * If both a name and an inode are found, but they do not
	 * correspond to the same file, then both the inode that has
	 * been found and the inode corresponding to the name that
	 * has been found need to be renamed. The current pathname
	 * is the new name for the inode that has been found. Since
	 * all files to be deleted have already been removed, the
	 * named file is either a now-unneeded link, or it must live
	 * under a new name in this dump level. If it is a link, it
	 * can be removed. If it is not a link, it is given a
	 * temporary name in anticipation that it will be renamed
	 * when it is later found by inode number.
	 */
	if (((key & (INOFND|NAMEFND)) == (INOFND|NAMEFND)) && ip != np) {
		if (lookuptype == LINK) {
			removeleaf(np);
			freeentry(np);
		} else {
			dprintf(stdout,
			    gettext("name/inode conflict, mktempname %s\n"),
				myname(np));
			mktempname(np);
		}
		np = NIL;
		key &= ~NAMEFND;
	}
	if ((key & ONTAPE) &&
	    (((key & INOFND) && ip->e_type != type) ||
	    ((key & NAMEFND) && np->e_type != type)))
		key |= MODECHG;

	/*
	 * Decide on the disposition of the file based on its flags.
	 * Note that we have already handled the case in which
	 * a name and inode are found that correspond to different files.
	 * Thus if both NAMEFND and INOFND are set then ip == np.
	 */
	switch (key) {

	/*
	 * A previously existing file has been found.
	 * Mark it as KEEP so that other links to the inode can be
	 * detected, and so that it will not be reclaimed by the search
	 * for unreferenced names.
	 */
	case INOFND|NAMEFND:
		/* LINTED: result fits into a short */
		ip->e_flags |= KEEP;
		dprintf(stdout, "[%s] %s: %s\n", keyval(key), name,
		    flagvalues(ip));
		break;

	/*
	 * A file on the tape has a name which is the same as a name
	 * corresponding to a different file in the previous dump.
	 * Since all files to be deleted have already been removed,
	 * this file is either a now-unneeded link, or it must live
	 * under a new name in this dump level. If it is a link, it
	 * can simply be removed. If it is not a link, it is given a
	 * temporary name in anticipation that it will be renamed
	 * when it is later found by inode number (see INOFND case
	 * below). The entry is then treated as a new file.
	 */
	case ONTAPE|NAMEFND:
	case ONTAPE|NAMEFND|MODECHG:
		if (lookuptype == LINK || key == (ONTAPE|NAMEFND)) {
			removeleaf(np);
			freeentry(np);
		} else {
			/*
			 * Create a temporary node only if MODECHG.
			 */
			mktempname(np);
		}
		/*FALLTHROUGH*/

	/*
	 * A previously non-existent file.
	 * Add it to the file system, and request its extraction.
	 * If it is a directory, create it immediately.
	 * (Since the name is unused there can be no conflict)
	 */
	case ONTAPE:
		ep = addentry(name, ino, type);
		if (type == NODE)
			newnode(ep);
		/* LINTED: result fits into a short */
		ep->e_flags |= NEW|KEEP;
		dprintf(stdout, "[%s] %s: %s\n", keyval(key), name,
			flagvalues(ep));
		break;

	/*
	 * A file with the same inode number, but a different
	 * name has been found. If the other name has not already
	 * been found (indicated by the KEEP flag, see above) then
	 * this must be a new name for the file, and it is renamed.
	 * If the other name has been found then this must be a
	 * link to the file. Hard links to directories are not
	 * permitted, and are either deleted or converted to
	 * symbolic links. Finally, if the file is on the tape,
	 * a request is made to extract it.
	 */
	case ONTAPE|INOFND:
		if (type == LEAF && (ip->e_flags & KEEP) == 0) {
			/* LINTED: result fits into a short */
			ip->e_flags |= EXTRACT;
		}
		/*FALLTHROUGH*/
	case INOFND:
		if ((ip->e_flags & KEEP) == 0) {
			renameit(myname(ip), name);
			moveentry(ip, name);
			/* LINTED: result fits into a short */
			ip->e_flags |= KEEP;
			dprintf(stdout, "[%s] %s: %s\n", keyval(key), name,
			    flagvalues(ip));
			break;
		}
		if (ip->e_type == NODE) {
			descend = FAIL;
			(void) fprintf(stderr, gettext(
			    "deleted hard link %s to directory %s\n"),
			    name, myname(ip));
			break;
		}
		ep = addentry(name, ino, type|LINK);
		/* LINTED: result fits into a short */
		ep->e_flags |= NEW;
		dprintf(stdout, "[%s] %s: %s|LINK\n", keyval(key), name,
		    flagvalues(ep));
		break;

	/*
	 * A previously known file which is to be updated.
	 */
	case ONTAPE|INOFND|NAMEFND:
		/*
		 * Extract leaf nodes.
		 */
		if (type == LEAF) {
			/* LINTED: result fits into a short */
			np->e_flags |= EXTRACT;
		}
		/* LINTED: result fits into a short */
		np->e_flags |= KEEP;
		dprintf(stdout, "[%s] %s: %s\n", keyval(key), name,
			flagvalues(np));
		break;

	/*
	 * An inode is being reused in a completely different way.
	 * Normally an extract can simply do an "unlink" followed
	 * by a "creat". Here we must do effectively the same
	 * thing. The complications arise because we cannot really
	 * delete a directory since it may still contain files
	 * that we need to rename, so we delete it from the symbol
	 * table, and put it on the list to be deleted eventually.
	 * Conversely if a directory is to be created, it must be
	 * done immediately, rather than waiting until the
	 * extraction phase.
	 */
	case ONTAPE|INOFND|MODECHG:
	case ONTAPE|INOFND|NAMEFND|MODECHG:
		if (ip->e_flags & KEEP) {
			badentry(ip, gettext("cannot KEEP and change modes"));
			break;
		}
		if (ip->e_type == LEAF) {
			/* changing from leaf to node */
			removeleaf(ip);
			freeentry(ip);
			ip = addentry(name, ino, type);
			newnode(ip);
		} else {
			/* changing from node to leaf */
			if ((ip->e_flags & TMPNAME) == 0)
				mktempname(ip);
			deleteino(ip->e_ino);
			ip->e_next = removelist;
			removelist = ip;
			ip = addentry(name, ino, type);
		}
		/* LINTED: result fits into a short */
		ip->e_flags |= NEW|KEEP;
		dprintf(stdout, "[%s] %s: %s\n", keyval(key), name,
			flagvalues(ip));
		break;

	/*
	 * A hard link to a directory that has been removed.
	 * Ignore it.
	 */
	case NAMEFND:
		dprintf(stdout, gettext("[%s] %s: Extraneous name\n"),
			keyval(key),
			name);
		descend = FAIL;
		break;

	/*
	 * If we find a directory entry for a file that is not on
	 * the tape, then we must have found a file that was created
	 * while the dump was in progress. Since we have no contents
	 * for it, we discard the name knowing that it will be on the
	 * next incremental tape.
	 */
	case 0:
		(void) fprintf(stderr,
		    gettext("%s: (inode %lu) not found on volume\n"),
		    name, ino);
		break;

	/*
	 * If any of these arise, something is grievously wrong with
	 * the current state of the symbol table.
	 */
	case INOFND|NAMEFND|MODECHG:
	case NAMEFND|MODECHG:
	case INOFND|MODECHG:
		(void) fprintf(stderr, "[%s] %s: %s\n",
		    keyval(key), name, gettext("inconsistent state"));
		done(1);
		/* NOTREACHED */

	/*
	 * These states "cannot" arise for any state of the symbol table.
	 */
	case ONTAPE|MODECHG:
	case MODECHG:
	default:
		(void) fprintf(stderr, "[%s] %s: %s\n",
		    keyval(key), name, gettext("impossible state"));
		done(1);
		/* NOTREACHED */
	}
	return (descend);
}

/*
 * Calculate the active flags in a key.
 */
static char *
keyval(key)
	int key;
{
	static char keybuf[32];

	/* Note longest case is everything except |NIL */

	(void) strcpy(keybuf, "|NIL");
	keybuf[0] = '\0';
	if (key & ONTAPE)
		(void) strcat(keybuf, "|ONTAPE");
	if (key & INOFND)
		(void) strcat(keybuf, "|INOFND");
	if (key & NAMEFND)
		(void) strcat(keybuf, "|NAMEFND");
	if (key & MODECHG)
		(void) strcat(keybuf, "|MODECHG");
	return (&keybuf[1]);
}

/*
 * Find unreferenced link names.
 */
void
#ifdef __STDC__
findunreflinks(void)
#else
findunreflinks()
#endif
{
	struct entry *ep, *np;
	ino_t i;

	vprintf(stdout, gettext("Find unreferenced names.\n"));
	for (i = ROOTINO; i < maxino; i++) {
		ep = lookupino(i);
		if (ep == NIL || ep->e_type == LEAF || BIT(i, dumpmap) == 0)
			continue;
		for (np = ep->e_entries; np != NIL; np = np->e_sibling) {
			if (np->e_flags == 0) {
				dprintf(stdout, gettext(
				    "%s: remove unreferenced name\n"),
				    myname(np));
				removeleaf(np);
				freeentry(np);
			}
		}
	}
	/*
	 * Any leaves remaining in removed directories are unreferenced.
	 */
	for (ep = removelist; ep != NIL; ep = ep->e_next) {
		for (np = ep->e_entries; np != NIL; np = np->e_sibling) {
			if (np->e_type == LEAF) {
				if (np->e_flags != 0)
					badentry(np, gettext(
						"unreferenced with flags"));
				dprintf(stdout, gettext(
				    "%s: remove unreferenced name\n"),
				    myname(np));
				removeleaf(np);
				freeentry(np);
			}
		}
	}
}

/*
 * Remove old nodes (directories).
 * Note that this routine runs in O(N*D) where:
 *	N is the number of directory entries to be removed.
 *	D is the maximum depth of the tree.
 * If N == D this can be quite slow. If the list were
 * topologically sorted, the deletion could be done in
 * time O(N).
 */
void
#ifdef __STDC__
removeoldnodes(void)
#else
removeoldnodes()
#endif
{
	struct entry *ep, **prev;
	long change;

	vprintf(stdout, gettext("Remove old nodes (directories).\n"));
	do	{
		change = 0;
		prev = &removelist;
		for (ep = removelist; ep != NIL; ep = *prev) {
			if (ep->e_entries != NIL) {
				prev = &ep->e_next;
				continue;
			}
			*prev = ep->e_next;
			removenode(ep);
			freeentry(ep);
			change++;
		}
	} while (change);
	for (ep = removelist; ep != NIL; ep = ep->e_next)
		badentry(ep, gettext("cannot remove, non-empty"));
}

/*
 * This is the routine used to extract files for the 'r' command.
 * Extract new leaves.
 */
void
createleaves(symtabfile)
	char *symtabfile;
{
	struct entry *ep;
	char name[MAXCOMPLEXLEN];
	ino_t first;
	int curvol;

	if (command == 'R') {
		vprintf(stdout, gettext("Continue extraction of new leaves\n"));
	} else {
		vprintf(stdout, gettext("Extract new leaves.\n"));
		dumpsymtable(symtabfile, volno);
	}
	first = lowerbnd(ROOTINO);
	curvol = volno;
	while (curfile.ino < maxino) {
		first = lowerbnd(first);
		/*
		 * If the next available file is not the one which we
		 * expect then we have missed one or more files. Since
		 * we do not request files that were not on the tape,
		 * the lost files must have been due to a tape read error,
		 * or a file that was removed while the dump was in progress.
		 *
		 * The loop will terminate with first == maxino, if not
		 * sooner.  Due to the e_flags manipulation, lowerbnd()
		 * will never return its argument.
		 */
		while (first < curfile.ino) {
			ep = lookupino(first);
			if (ep == NIL) {
				(void) fprintf(stderr,
				    gettext("%d: bad first\n"), first);
				done(1);
			}
			(void) fprintf(stderr,
			    gettext("%s: not found on volume\n"),
			    myname(ep));
			/* LINTED: result fits into a short */
			ep->e_flags &= ~(NEW|EXTRACT);
			first = lowerbnd(first);
		}
		/*
		 * If we find files on the tape that have no corresponding
		 * directory entries, then we must have found a file that
		 * was created while the dump was in progress. Since we have
		 * no name for it, we discard it knowing that it will be
		 * on the next incremental tape.
		 */
		if (first != curfile.ino) {
			(void) fprintf(stderr,
			    gettext("expected next file %d, got %d\n"),
				first, curfile.ino);
			skipfile();
			goto next;
		}
		ep = lookupino(curfile.ino);
		if (ep == NIL) {
			(void) fprintf(stderr,
			    gettext("unknown file on volume\n"));
			done(1);
		}
		if ((ep->e_flags & (NEW|EXTRACT)) == 0)
			badentry(ep, gettext("unexpected file on volume"));
		/*
		 * If the file is to be extracted, then the old file must
		 * be removed since its type may change from one leaf type
		 * to another (eg "file" to "character special"). But we
		 * also need to preserve any existing extended attributes;
		 * so first rename the file, then move its attributes, then
		 * remove it.
		 */
		if ((ep->e_flags & EXTRACT) != 0) {
			char *sname = savename(ep->e_name);
			complexcpy(name, myname(ep), MAXCOMPLEXLEN);
			mktempname(ep);
			(void) extractfile(name);
			movexattrs(myname(ep), name);
			removeleaf(ep);
			freename(ep->e_name);
			ep->e_name = sname;
			ep->e_namlen = strlen(ep->e_name);
			/* LINTED: result fits into a short */
			ep->e_flags &= ~REMOVED;
		} else {
			(void) extractfile(myname(ep));
		}
		/* LINTED: result fits into a short */
		ep->e_flags &= ~(NEW|EXTRACT);
		/*
		 * We checkpoint the restore after every tape reel, so
		 * as to simplify the amount of work required by the
		 * 'R' command.
		 */
	next:
		if (curvol != volno) {
			dumpsymtable(symtabfile, volno);
			skipmaps();
			curvol = volno;
		}
	}
}

/*
 * This is the routine used to extract files for the 'x' and 'i' commands.
 * Efficiently extract a subset of the files on a tape.
 */
void
#ifdef __STDC__
createfiles(void)
#else
createfiles()
#endif
{
	ino_t first, next, last;
	struct entry *ep;
	int curvol, nextvol;

	vprintf(stdout, gettext("Extract requested files\n"));
	first = lowerbnd(ROOTINO);
	last = upperbnd(maxino - 1);
	nextvol = volnumber(first);
	if (nextvol == 0) {
		curfile.action = SKIP;
		getvol(1);
		skipmaps();
		skipdirs();
	}
	for (;;) {
		first = lowerbnd(first);
		last = upperbnd(last);
		/*
		 * Check to see if any files remain to be extracted
		 */
		if (first > last)
			return;
		/*
		 * If a map of inode numbers to tape volumes is
		 * available, then select the next volume to be read.
		 */
		if (nextvol > 0) {
			nextvol = volnumber(first);
			if (nextvol != volno) {
				curfile.action = UNKNOWN;
				getvol(nextvol);
				skipmaps();
			}
		}
		/*
		 * Reject any volumes with inodes greater than
		 * the last one needed. This will only be true
		 * if the above code has not selected a volume.
		 */
		while (curfile.ino > last) {
			curfile.action = SKIP;
			getvol(0);
			skipmaps();
			skipdirs();
		}
		/*
		 * Decide on the next inode needed.
		 * Skip across the inodes until it is found
		 * or an out of order volume change is encountered
		 */
		next = lowerbnd(curfile.ino);
		do	{
			curvol = volno;
			while (next > curfile.ino && volno == curvol)
				skipfile();
			skipmaps();
			skipdirs();
		} while (volno == curvol + 1);
		/*
		 * If volume change out of order occurred the
		 * current state must be recalculated
		 */
		if (volno != curvol)
			continue;
		/*
		 * If the current inode is greater than the one we were
		 * looking for then we missed the one we were looking for.
		 * Since we only attempt to extract files listed in the
		 * dump map, the lost files must have been due to a tape
		 * read error, or a file that was removed while the dump
		 * was in progress. Thus we report all requested files
		 * between the one we were looking for, and the one we
		 * found as missing, and delete their request flags.
		 */
		while (next < curfile.ino) {
			ep = lookupino(next);
			if (ep == NIL) {
				(void) fprintf(stderr,
				    gettext("corrupted symbol table\n"));
				done(1);
			}
			(void) fprintf(stderr,
			    gettext("%s: not found on volume\n"),
			    myname(ep));
			/* LINTED: result fits into a short */
			ep->e_flags &= ~NEW;
			next = lowerbnd(next);
		}
		/*
		 * The current inode is the one that we are looking for,
		 * so extract it per its requested name.
		 */
		if (next == curfile.ino && next <= last) {
			ep = lookupino(next);
			if (ep == NIL) {
				(void) fprintf(stderr,
				    gettext("corrupted symbol table\n"));
				done(1);
			}
			(void) extractfile(myname(ep));
			/* LINTED: result fits into a short */
			ep->e_flags &= ~NEW;
			if (volno != curvol)
				skipmaps();
		}
	}
}

/*
 * Add links.
 */
void
#ifdef __STDC__
createlinks(void)
#else
createlinks()
#endif
{
	struct entry *np, *ep;
	ino_t i;
	int dfd;
	char *to, *from;
	int saverr;

	vprintf(stdout, gettext("Add links\n"));
	for (i = ROOTINO; i < maxino; i++) {
		ep = lookupino(i);
		if (ep == NIL)
			continue;
		to = savename(myname(ep));
		for (np = ep->e_links; np != NIL; np = np->e_links) {
			if ((np->e_flags & NEW) == 0)
				continue;
			resolve(myname(np), &dfd, &from);
			if (dfd != AT_FDCWD) {
				if (fchdir(dfd) < 0) {
					saverr = errno;
					(void) fprintf(stderr,
					gettext("%s->%s: link failed: %s\n"),
						from, to, strerror(saverr));
					(void) close(dfd);
					continue;
				}
			}
			if (ep->e_type == NODE) {
				(void) lf_linkit(to, from, SYMLINK);
			} else {
				(void) lf_linkit(to, from, HARDLINK);
			}
			/* LINTED: result fits into a short */
			np->e_flags &= ~NEW;
			if (dfd != AT_FDCWD) {
				fchdir(savepwd);
				(void) close(dfd);
			}
		}
		freename(to);
	}
}

/*
 * Check the symbol table.
 * We do this to insure that all the requested work was done, and
 * that no temporary names remain.
 */
void
#ifdef __STDC__
checkrestore(void)
#else
checkrestore()
#endif
{
	struct entry *ep;
	ino_t i;

	vprintf(stdout, gettext("Check the symbol table.\n"));
	for (i = ROOTINO; i < maxino; i++) {
		for (ep = lookupino(i); ep != NIL; ep = ep->e_links) {
			/* LINTED: result fits into a short */
			ep->e_flags &= ~KEEP;
			if (ep->e_type == NODE) {
				/* LINTED: result fits into a short */
				ep->e_flags &= ~(NEW|EXISTED);
			}
			if ((ep->e_flags & ~(XATTR|XATTRROOT)) != 0)
				badentry(ep, gettext("incomplete operations"));
		}
	}
}

/*
 * Compare with the directory structure on the tape
 * A paranoid check that things are as they should be.
 */
long
verifyfile(name, ino, type)
	char *name;
	ino_t ino;
	int type;
{
	struct entry *np, *ep;
	long descend = GOOD;

	ep = lookupname(name);
	if (ep == NIL) {
		(void) fprintf(stderr,
		    gettext("Warning: missing name %s\n"), name);
		return (FAIL);
	}
	np = lookupino(ino);
	if (np != ep)
		descend = FAIL;
	for (; np != NIL; np = np->e_links)
		if (np == ep)
			break;
	if (np == NIL) {
		(void) fprintf(stderr, gettext("missing inumber %d\n"), ino);
		done(1);
	}
	if (ep->e_type == LEAF && type != LEAF)
		badentry(ep, gettext("type should be LEAF"));
	return (descend);
}

/*
 * This routine does not actually remove any attribute files, it
 * just removes entries from the symbol table.  The attribute files
 * themselves are assumed to be removed automatically when the
 * parent file is removed.
 */
static void
removexattrs(ep)
	struct entry *ep;
{
	struct entry *np = ep;

	if (ep == NIL)
		return;
	for (np = ep->e_entries; np != NIL; np = np->e_sibling) {
		if (np->e_type == NODE) {
			removexattrs(np);
		} else {
			np->e_flags |= REMOVED;
			freeentry(np);
		}
	}
	ep->e_flags |= REMOVED;
	freeentry(ep);
}

/*
 * Move all the extended attributes associated with orig to
 * the file named by the second argument (targ).
 */
static void
movexattrs(orig, targ)
	char *orig;
	char *targ;
{
	char *to, *from;
	int fromfd, fromdir, tofd, todir, tfd;
	DIR *dirp = NULL;
	struct dirent *dp = NULL;

	fromfd = tofd = fromdir = todir = tfd = -1;

	resolve(orig, &tfd, &from);
	if (tfd == AT_FDCWD && pathconf(orig, _PC_XATTR_EXISTS) != 1) {
		/* no attributes to move */
		return;
	}
	if ((fromfd = openat64(tfd, from, O_RDONLY|O_NONBLOCK)) == -1) {
		fprintf(stderr, gettext("%s: cannot move attributes: "), from);
		perror("");
		if (tfd != AT_FDCWD) (void) close(tfd);
		goto out;
	}

	if (fpathconf(fromfd, _PC_XATTR_EXISTS) != 1) {
		/* no attributes to move */
		if (tfd != AT_FDCWD) (void) close(tfd);
		goto out;
	}
	if ((fromdir = openat64(fromfd, ".",
				O_RDONLY|O_NONBLOCK|O_XATTR)) == -1) {
		fprintf(stderr, gettext("%s: cannot access attributes: "),
			from);
		perror("");
		if (tfd != AT_FDCWD) (void) close(tfd);
		goto out;
	}
	if (tfd != AT_FDCWD) (void) close(tfd);

	resolve(targ, &tfd, &to);
	if ((tofd = openat64(tfd, to, O_RDONLY|O_NONBLOCK)) == -1 ||
	    (todir = openat64(tofd, ".", O_RDONLY|O_NONBLOCK|O_XATTR)) == -1) {
		fprintf(stderr, gettext("%s: cannot create attributes: "), to);
		perror("");
		goto out;
	}
	if (tfd != AT_FDCWD) (void) close(tfd);
	(void) close(tofd);

	if ((tfd = dup(fromdir)) == -1 ||
	    (dirp = fdopendir(tfd)) == NULL) {
		fprintf(stderr,
	gettext("%s: cannot allocate DIR structure to attribute directory: "),
			from);
		perror("");
		if (tfd != -1) (void) close(tfd);
		goto out;
	}

	while ((dp = readdir(dirp)) != NULL) {
		if ((dp->d_name[0] == '.' && dp->d_name[1] == '\0') ||
			(dp->d_name[0] == '.' && dp->d_name[1] == '.' &&
			dp->d_name[2] == '\0'))
			continue;
		if ((renameat(fromdir, dp->d_name, todir, dp->d_name)) == -1) {
			fprintf(stderr,
				gettext("%s: cannot move attribute %s: "),
				from, dp->d_name);
			goto out;
		}
	}
out:
	if (fromfd != -1)
		(void) close(fromfd);
	if (tofd != -1)
		(void) close(tofd);
	if (dirp != NULL)
		(void) closedir(dirp);
	if (fromdir != -1)
		(void) close(fromdir);
	if (todir != -1)
		(void) close(todir);
}
