/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
#define	_KERNEL
#include <sys/fs/ufs_fsdir.h>
#undef _KERNEL
#include <sys/fs/ufs_inode.h>
#include "fsck.h"

/*
 * for each large file (size > MAXOFF_T), the global largefile_count
 * gets incremented during this pass.
 */

static uint32_t badblk;		/* number seen for the current inode */
static uint32_t dupblk;		/* number seen for the current inode */

static void clear_attr_acl(fsck_ino_t, fsck_ino_t, char *);
static void verify_inode(fsck_ino_t, struct inodesc *, fsck_ino_t);
static void check_dirholes(fsck_ino_t, struct inodesc *);
static void collapse_dirhole(fsck_ino_t, struct inodesc *);
static void note_used(daddr32_t);

void
pass1(void)
{
	uint_t c, i;
	daddr32_t cgd;
	struct inodesc idesc;
	fsck_ino_t inumber;
	fsck_ino_t maxinumber;

	/*
	 * Set file system reserved blocks in used block map.
	 */
	for (c = 0; c < sblock.fs_ncg; c++) {
		cgd = cgdmin(&sblock, c);
		if (c == 0) {
			/*
			 * Doing the first cylinder group, account for
			 * the cg summaries as well.
			 */
			i = cgbase(&sblock, c);
			cgd += howmany(sblock.fs_cssize, sblock.fs_fsize);
		} else {
			i = cgsblock(&sblock, c);
		}
		for (; i < cgd; i++) {
			note_used(i);
		}
	}
	/*
	 * Note blocks being used by the log, so we don't declare
	 * them as available and some time in the future we get a
	 * freeing free block panic.
	 */
	if (islog && islogok && sblock.fs_logbno)
		examinelog(&note_used);

	/*
	 * Find all allocated blocks.  This must be completed before
	 * we read the contents of any directories, as dirscan() et al
	 * don't want to know about block allocation holes.  So, part
	 * of this pass is to truncate any directories with holes to
	 * just before those holes, so dirscan() can remain blissfully
	 * ignorant.
	 */
	inumber = 0;
	n_files = n_blks = 0;
	resetinodebuf();
	maxinumber = sblock.fs_ncg * sblock.fs_ipg;
	for (c = 0; c < sblock.fs_ncg; c++) {
		for (i = 0; i < sblock.fs_ipg; i++, inumber++) {
			if (inumber < UFSROOTINO)
				continue;
			init_inodesc(&idesc);
			idesc.id_type = ADDR;
			idesc.id_func = pass1check;
			verify_inode(inumber, &idesc, maxinumber);
		}
	}
	freeinodebuf();
}

/*
 * Perform checks on an inode and setup/track the state of the inode
 * in maps (statemap[], lncntp[]) for future reference and validation.
 * Initiate the calls to ckinode and in turn pass1check() to handle
 * further validation.
 */
static void
verify_inode(fsck_ino_t inumber, struct inodesc *idesc, fsck_ino_t maxinumber)
{
	int j, clear, flags;
	int isdir;
	char *err;
	fsck_ino_t shadow, attrinode;
	daddr32_t ndb;
	struct dinode *dp;
	struct inoinfo *iip;

	dp = getnextinode(inumber);
	if ((dp->di_mode & IFMT) == 0) {
		/* mode and type of file is not set */
		if ((memcmp((void *)dp->di_db, (void *)zino.di_db,
		    NDADDR * sizeof (daddr32_t)) != 0) ||
		    (memcmp((void *)dp->di_ib, (void *)zino.di_ib,
		    NIADDR * sizeof (daddr32_t)) != 0) ||
		    (dp->di_mode != 0) || (dp->di_size != 0)) {
			pfatal("PARTIALLY ALLOCATED INODE I=%u", inumber);
			if (reply("CLEAR") == 1) {
				dp = ginode(inumber);
				clearinode(dp);
				inodirty();
			} else {
				iscorrupt = 1;
			}
		}
		statemap[inumber] = USTATE;
		return;
	}

	isdir = ((dp->di_mode & IFMT) == IFDIR) ||
	    ((dp->di_mode & IFMT) == IFATTRDIR);

	lastino = inumber;
	if (dp->di_size > (u_offset_t)UFS_MAXOFFSET_T) {
		pfatal("NEGATIVE SIZE %lld I=%d",
		    (longlong_t)dp->di_size, inumber);
		goto bogus;
	}

	/*
	 * A more precise test of the type is done later on.  Just get
	 * rid of the blatantly-wrong ones before we do any
	 * significant work.
	 */
	if ((dp->di_mode & IFMT) == IFMT) {
		pfatal("BAD MODE 0%o I=%d",
		    dp->di_mode & IFMT, inumber);
		if (reply("BAD MODE: MAKE IT A FILE") == 1) {
			statemap[inumber] = FSTATE;
			dp = ginode(inumber);
			dp->di_mode = IFREG | 0600;
			inodirty();
			truncino(inumber, sblock.fs_fsize, TI_NOPARENT);
			dp = getnextrefresh();
		} else {
			iscorrupt = 1;
		}
	}

	ndb = howmany(dp->di_size, (u_offset_t)sblock.fs_bsize);
	if (ndb < 0) {
		/* extra space to distinguish from previous pfatal() */
		pfatal("NEGATIVE SIZE %lld  I=%d",
		    (longlong_t)dp->di_size, inumber);
		goto bogus;
	}

	if ((dp->di_mode & IFMT) == IFBLK ||
	    (dp->di_mode & IFMT) == IFCHR) {
		if (dp->di_size != 0) {
			pfatal("SPECIAL FILE WITH NON-ZERO LENGTH %lld I=%d",
			    (longlong_t)dp->di_size, inumber);
			goto bogus;
		}

		for (j = 0; j < NDADDR; j++) {
			/*
			 * It's a device, so all the block pointers
			 * should be zero except for di_ordev.
			 * di_ordev is overlayed on the block array,
			 * but where varies between big and little
			 * endian, so make sure that the only non-zero
			 * element is the correct one.  There can be
			 * a device whose ordev is zero, so we can't
			 * check for the reverse.
			 */
			if (dp->di_db[j] != 0 &&
			    &dp->di_db[j] != &dp->di_ordev) {
				if (debug) {
					(void) printf(
					    "spec file di_db[%d] has %d\n",
					    j, dp->di_db[j]);
				}
				pfatal(
			    "SPECIAL FILE WITH NON-ZERO FRAGMENT LIST  I=%d",
				    inumber);
				goto bogus;
			}
		}

		for (j = 0; j < NIADDR; j++) {
			if (dp->di_ib[j] != 0) {
				if (debug)
					(void) printf(
					    "special has %d at ib[%d]\n",
					    dp->di_ib[j], j);
				pfatal(
			    "SPECIAL FILE WITH NON-ZERO FRAGMENT LIST  I=%d",
				    inumber);
				goto bogus;
			}
		}
	} else {
		/*
		 * This assignment is mostly here to appease lint, but
		 * doesn't hurt.
		 */
		err = "Internal error: unexpected variant of having "
		    "blocks past end of file  I=%d";

		clear = 0;

		/*
		 * If it's not a device, it has to follow the
		 * rules for files.  In particular, no blocks after
		 * the last one that di_size says is in use.
		 */
		for (j = ndb; j < NDADDR; j++) {
			if (dp->di_db[j] != 0) {
				if (debug) {
					(void) printf("bad file direct "
					    "addr[%d]: block 0x%x "
					    "format: 0%o\n",
					    j, dp->di_db[j],
					    dp->di_mode & IFMT);
				}
				err = "FILE WITH FRAGMENTS PAST END  I=%d";
				clear = 1;
				break;
			}
		}

		/*
		 * Find last indirect pointer that should be in use,
		 * and make sure any after it are clear.
		 */
		if (!clear) {
			for (j = 0, ndb -= NDADDR; ndb > 0; j++) {
				ndb /= NINDIR(&sblock);
			}
			for (; j < NIADDR; j++) {
				if (dp->di_ib[j] != 0) {
					if (debug) {
						(void) printf("bad file "
						    "indirect addr: block %d\n",
						    dp->di_ib[j]);
					}
					err =
					    "FILE WITH FRAGMENTS PAST END I=%d";
					clear = 2;
					break;
				}
			}
		}

		if (clear) {
			/*
			 * The discarded blocks will be garbage-
			 * collected in pass5.  If we're told not to
			 * discard them, it's just lost blocks, which
			 * isn't worth setting iscorrupt for.
			 */
			pwarn(err, inumber);
			if (preen || reply("DISCARD EXCESS FRAGMENTS") == 1) {
				dp = ginode(inumber);
				if (clear == 1) {
					for (; j < NDADDR; j++)
						dp->di_db[j] = 0;
					j = 0;
				}
				for (; j < NIADDR; j++)
					dp->di_ib[j] = 0;
				inodirty();
				dp = getnextrefresh();
				if (preen)
					(void) printf(" (TRUNCATED)");
			}
		}
	}

	if (ftypeok(dp) == 0) {
		pfatal("UNKNOWN FILE TYPE 0%o  I=%d", dp->di_mode, inumber);
		goto bogus;
	}
	n_files++;
	TRACK_LNCNTP(inumber, lncntp[inumber] = dp->di_nlink);

	/*
	 * We can't do anything about it right now, so note that its
	 * processing is being delayed.  Otherwise, we'd be changing
	 * the block allocations out from under ourselves, which causes
	 * no end of confusion.
	 */
	flags = statemap[inumber] & INDELAYD;

	/*
	 * if errorlocked or logging, then open deleted files will
	 * manifest as di_nlink <= 0 and di_mode != 0
	 * so skip them; they're ok.
	 * Also skip anything already marked to be cleared.
	 */
	if (dp->di_nlink <= 0 &&
	    !((errorlocked || islog) && dp->di_mode == 0) &&
	    !(flags & INCLEAR)) {
		flags |= INZLINK;
		if (debug)
			(void) printf(
		    "marking i=%d INZLINK; nlink %d, mode 0%o, islog %d\n",
			    inumber, dp->di_nlink, dp->di_mode, islog);
	}

	switch (dp->di_mode & IFMT) {
	case IFDIR:
	case IFATTRDIR:
		if (dp->di_size == 0) {
			/*
			 * INCLEAR means it will be ignored by passes 2 & 3.
			 */
			if ((dp->di_mode & IFMT) == IFDIR)
				(void) printf("ZERO-LENGTH DIR  I=%d\n",
				    inumber);
			else
				(void) printf("ZERO-LENGTH ATTRDIR  I=%d\n",
				    inumber);
			add_orphan_dir(inumber);
			flags |= INCLEAR;
			flags &= ~INZLINK;	/* It will be cleared anyway */
		}
		statemap[inumber] = DSTATE | flags;
		cacheino(dp, inumber);
		countdirs++;
		break;

	case IFSHAD:
		if (dp->di_size == 0) {
			(void) printf("ZERO-LENGTH SHADOW  I=%d\n", inumber);
			flags |= INCLEAR;
			flags &= ~INZLINK;	/* It will be cleared anyway */
		}
		statemap[inumber] = SSTATE | flags;
		cacheacl(dp, inumber);
		break;

	default:
		statemap[inumber] = FSTATE | flags;
	}

	badblk = 0;
	dupblk = 0;
	idesc->id_number = inumber;
	idesc->id_fix = DONTKNOW;
	if (dp->di_size > (u_offset_t)MAXOFF_T) {
		largefile_count++;
	}

	(void) ckinode(dp, idesc, CKI_TRAVERSE);
	if (isdir && (idesc->id_firsthole >= 0))
		check_dirholes(inumber, idesc);

	if (dp->di_blocks != idesc->id_entryno) {
		/*
		 * The kernel releases any blocks it finds in the lists,
		 * ignoring the block count itself.  So, a bad count is
		 * not grounds for setting iscorrupt.
		 */
		pwarn("INCORRECT DISK BLOCK COUNT I=%u (%d should be %d)",
		    inumber, (uint32_t)dp->di_blocks, idesc->id_entryno);
		if (!preen && (reply("CORRECT") == 0))
			return;
		dp = ginode(inumber);
		dp->di_blocks = idesc->id_entryno;
		iip = getinoinfo(inumber);
		if (iip != NULL)
			iip->i_isize = dp->di_size;
		inodirty();
		if (preen)
			(void) printf(" (CORRECTED)\n");
	}
	if (isdir && (dp->di_blocks == 0)) {
		/*
		 * INCLEAR will cause passes 2 and 3 to skip it.
		 */
		(void) printf("DIR WITH ZERO BLOCKS  I=%d\n", inumber);
		statemap[inumber] = DCLEAR;
		add_orphan_dir(inumber);
	}

	/*
	 * Check that the ACL is on a valid file type
	 */
	shadow = dp->di_shadow;
	if (shadow != 0) {
		if (acltypeok(dp) == 0) {
			clear_attr_acl(inumber, -1,
			    "NON-ZERO ACL REFERENCE, I=%d\n");
		} else if ((shadow <= UFSROOTINO) ||
		    (shadow > maxinumber)) {
			clear_attr_acl(inumber, -1,
			    "BAD ACL REFERENCE I=%d\n");
		} else {
			registershadowclient(shadow,
			    inumber, &shadowclientinfo);
		}
	}

	attrinode = dp->di_oeftflag;
	if (attrinode != 0) {
		if ((attrinode <= UFSROOTINO) ||
		    (attrinode > maxinumber)) {
			clear_attr_acl(attrinode, inumber,
			    "BAD ATTRIBUTE REFERENCE TO I=%d FROM I=%d\n");
		} else {
			dp = ginode(attrinode);
			if ((dp->di_mode & IFMT) != IFATTRDIR) {
				clear_attr_acl(attrinode, inumber,
			    "BAD ATTRIBUTE DIR REF TO I=%d FROM I=%d\n");
			} else if (dp->di_size == 0) {
				clear_attr_acl(attrinode, inumber,
		    "REFERENCE TO ZERO-LENGTH ATTRIBUTE DIR I=%d from I=%d\n");
			} else {
				registershadowclient(attrinode, inumber,
				    &attrclientinfo);
			}
		}
	}
	return;

	/*
	 * If we got here, we've not had the chance to see if a
	 * directory has holes, but we know the directory's bad,
	 * so it's safe to always return false (no holes found).
	 *
	 * Also, a pfatal() is always done before jumping here, so
	 * we know we're not in preen mode.
	 */
bogus:
	if (isdir) {
		/*
		 * INCLEAR makes passes 2 & 3 skip it.
		 */
		statemap[inumber] = DCLEAR;
		add_orphan_dir(inumber);
		cacheino(dp, inumber);
	} else {
		statemap[inumber] = FCLEAR;
	}
	if (reply("CLEAR") == 1) {
		(void) tdelete((void *)inumber, &limbo_dirs, ino_t_cmp);
		freeino(inumber, TI_PARENT);
		inodirty();
	} else {
		iscorrupt = 1;
	}
}

/*
 * Do fixup for bad acl/attr references.  If PARENT is -1, then
 * we assume we're working on a shadow, otherwise an extended attribute.
 * FMT must be a printf format string, with one %d directive for
 * the inode number.
 */
static void
clear_attr_acl(fsck_ino_t inumber, fsck_ino_t parent, char *fmt)
{
	fsck_ino_t victim = inumber;
	struct dinode *dp;

	if (parent != -1)
		victim = parent;

	if (fmt != NULL) {
		if (parent == -1)
			pwarn(fmt, (int)inumber);
		else
			pwarn(fmt, (int)inumber, (int)parent);
	}

	if (debug)
		(void) printf("parent file/dir I=%d\nvictim I=%d",
		    (int)parent, (int)victim);

	if (!preen && (reply("REMOVE REFERENCE") == 0)) {
		iscorrupt = 1;
		return;
	}

	dp = ginode(victim);
	if (parent == -1) {
		/*
		 * The file had a bad shadow/acl, so lock it down
		 * until someone can protect it the way they need it
		 * to be (i.e., be conservatively paranoid).
		 */
		dp->di_shadow = 0;
		dp->di_mode &= IFMT;
	} else {
		dp->di_oeftflag = 0;
	}

	inodirty();
	if (preen)
		(void) printf(" (CORRECTED)\n");
}

/*
 * Check if we have holes in the directory's indirect
 * blocks.  If there are, get rid of everything after
 * the first hole.
 */
static void
check_dirholes(fsck_ino_t inumber, struct inodesc *idesc)
{
	char pathbuf[MAXPATHLEN + 1];

	getpathname(pathbuf, idesc->id_number, idesc->id_number);
	pfatal("I=%d  DIRECTORY %s: CONTAINS EMPTY BLOCKS",
	    idesc->id_number, pathbuf);
	if (reply("TRUNCATE AT FIRST EMPTY BLOCK") == 1) {
		/*
		 * We found a hole, so get rid of it.
		 */
		collapse_dirhole(inumber, idesc);

		if (preen)
			(void) printf(" (TRUNCATED)\n");
	} else {
		iscorrupt = 1;
	}
}

/*
 * Truncate a directory to its first hole.  If there are non-holes
 * in the direct blocks after the problem block, move them down so
 * that there's somewhat less lossage.  Doing this for indirect blocks
 * is left as an exercise for the reader.
 */
static void
collapse_dirhole(fsck_ino_t inumber, struct inodesc *idesc)
{
	offset_t new_size;
	int blocks;

	if (idesc->id_firsthole < 0) {
		return;
	}

	/*
	 * Since truncino() adjusts the size, we don't need to do that here,
	 * but we have to tell it what final size we want.
	 *
	 * We need to count from block zero up through the last block
	 * before the hole.  If the hole is in the indirect blocks, chop at
	 * the start of the nearest level of indirection.  Orphans will
	 * get reconnected, so we're not actually losing anything by doing
	 * it this way, and we're simplifying truncation significantly.
	 */
	new_size = idesc->id_firsthole * (offset_t)sblock.fs_bsize;
	blocks = howmany(new_size, sblock.fs_bsize);
	if (blocks > NDADDR) {
		if (blocks < (NDADDR + NINDIR(&sblock)))
			blocks = NDADDR;
		else if (blocks < (NDADDR + NINDIR(&sblock) +
		    (NINDIR(&sblock) * NINDIR(&sblock))))
			blocks = NDADDR + NINDIR(&sblock);
		else
			blocks = NDADDR + NINDIR(&sblock) +
			    (NINDIR(&sblock) * NINDIR(&sblock));
		new_size = blocks * sblock.fs_bsize;
		if (debug)
			(void) printf("to %lld (blocks %d)\n",
			    (longlong_t)new_size, blocks);
	}
	truncino(inumber, new_size, TI_NOPARENT);

	/*
	 * Technically, there are still the original number of fragments
	 * associated with the object.  However, that number is not used
	 * to control anything, so we can do the in-memory truncation of
	 * it without bad things happening.
	 */
	idesc->id_entryno = btodb(new_size);
}

int
pass1check(struct inodesc *idesc)
{
	int res = KEEPON;
	int anyout;
	int nfrags;
	daddr32_t lbn;
	daddr32_t fragno = idesc->id_blkno;
	struct dinode *dp;

	/*
	 * If this is a fallocate'd file, block numbers may be stored
	 * as negative. In that case negate the negative numbers.
	 */
	dp = ginode(idesc->id_number);
	if (dp->di_cflags & IFALLOCATE && fragno < 0)
		fragno = -fragno;

	if ((anyout = chkrange(fragno, idesc->id_numfrags)) != 0) {
		/*
		 * Note that blkerror() exits when preening.
		 */
		blkerror(idesc->id_number, "OUT OF RANGE",
		    fragno, idesc->id_lbn * sblock.fs_frag);

		dp = ginode(idesc->id_number);
		if ((((dp->di_mode & IFMT) == IFDIR) ||
		    ((dp->di_mode & IFMT) == IFATTRDIR)) &&
		    (idesc->id_firsthole < 0)) {
			idesc->id_firsthole = idesc->id_lbn;
		}

		if (++badblk >= MAXBAD) {
			pwarn("EXCESSIVE BAD FRAGMENTS I=%u",
			    idesc->id_number);
			if (reply("CONTINUE") == 0)
				errexit("Program terminated.");
			/*
			 * See discussion below as to why we don't
			 * want to short-circuit the processing of
			 * this inode.  However, we know that this
			 * particular block is bad, so we don't need
			 * to go through the dup check loop.
			 */
			return (SKIP | STOP);
		}
	}

	/*
	 * For each fragment, verify that it is a legal one (either
	 * by having already found the entire run to be legal, or by
	 * individual inspection), and if it is legal, see if we've
	 * seen it before or not.  If we haven't, note that we've seen
	 * it and continue on.  If we have (our in-core bitmap shows
	 * it as already being busy), then this must be a duplicate
	 * allocation.  Whine and moan accordingly.
	 *
	 * Note that for full-block allocations, this will produce
	 * a complaint for each fragment making up the block (i.e.,
	 * fs_frags' worth).  Among other things, this could be
	 * considered artificially inflating the dup-block count.
	 * However, since it is possible that one file has a full
	 * fs block allocated, but another is only claiming a frag
	 * or two out of the middle, we'll just live it.
	 */
	for (nfrags = 0; nfrags < idesc->id_numfrags; fragno++, nfrags++) {
		if (anyout && chkrange(fragno, 1)) {
			/* bad fragment number */
			res = SKIP;
		} else if (!testbmap(fragno)) {
			/* no other claims seen as yet */
			note_used(fragno);
		} else {
			/*
			 * We have a duplicate claim for the same fragment.
			 *
			 * blkerror() exits when preening.
			 *
			 * We want to report all the dups up until
			 * hitting MAXDUP.  Fortunately, blkerror()'s
			 * side-effects on statemap[] are idempotent,
			 * so the ``extra'' calls are harmless.
			 */
			lbn = idesc->id_lbn * sblock.fs_frag + nfrags;
			if (dupblk < MAXDUP)
				blkerror(idesc->id_number, "DUP", fragno, lbn);

			/*
			 * Use ==, so we only complain once, no matter
			 * how far over the limit we end up going.
			 */
			if (++dupblk == MAXDUP) {
				pwarn("EXCESSIVE DUPLICATE FRAGMENTS I=%u",
				    idesc->id_number);
				if (reply("CONTINUE") == 0)
					errexit("Program terminated.");

				/*
				 * If we stop the traversal here, then
				 * there may be more dups in the
				 * inode's block list that don't get
				 * flagged.  Later, if we're told to
				 * clear one of the files claiming
				 * these blocks, but not the other, we
				 * will release blocks that are
				 * actually still in use.  An additional
				 * fsck run would be necessary to undo
				 * the damage.  So, instead of the
				 * traditional return (STOP) when told
				 * to continue, we really do just continue.
				 */
			}
			(void) find_dup_ref(fragno, idesc->id_number, lbn,
			    DB_CREATE | DB_INCR);
		}
		/*
		 * id_entryno counts the number of disk blocks found.
		 */
		idesc->id_entryno += btodb(sblock.fs_fsize);
	}
	return (res);
}

static void
note_used(daddr32_t frag)
{
	n_blks++;
	setbmap(frag);
}
