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
#include <sys/mntent.h>
#include <sys/fs/ufs_fs.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#include "fsck.h"

static int check_maps(uchar_t *, uchar_t *, int, int, char *, int, int);

void
pass5(void)
{
	caddr_t err;
	int32_t c, blk, frags;
	size_t	basesize, sumsize, mapsize;
	int excessdirs;
	int inomapsize, blkmapsize;
	int update_csums, update_bitmaps;
	int bad_csum_sb, bad_csum_cg, bad_cgblks_cg, bad_cgblktot_cg;
	struct fs *fs = &sblock;
	struct cg *cg = &cgrp;
	diskaddr_t dbase, dmax;
	diskaddr_t d;
	uint64_t i, j;
	struct csum *cs;
	struct csum backup_cs;
	time_t now;
	struct csum cstotal;
	struct inodesc idesc;
	union {				/* keep lint happy about alignment */
		struct cg cg;		/* the rest of buf has the bitmaps */
		char buf[MAXBSIZE];
	} u;
	caddr_t buf = u.buf;
	struct cg *newcg = &u.cg;

	(void) memset((void *)buf, 0, sizeof (u.buf));
	newcg->cg_niblk = fs->fs_ipg;

	if (fs->fs_postblformat != FS_DYNAMICPOSTBLFMT) {
		pfatal("UNSUPPORTED ROTATIONAL TABLE FORMAT %d\n",
		    fs->fs_postblformat);
		errexit("Program terminated.");
		/* NOTREACHED */
	}

	/* LINTED this subtraction can't overflow and is int32-aligned */
	basesize = &newcg->cg_space[0] - (uchar_t *)newcg;

	/*
	 * We reserve the space for the old rotation summary
	 * tables for the benefit of old kernels, but do not
	 * maintain them in modern kernels. In time, they could
	 * theoretically go away, if we wanted to deal with
	 * changing the on-disk format.
	 */

	/*
	 * Note that we don't use any of the cg_*() macros until
	 * after cg_sanity() has approved of what we've got.
	 */
	newcg->cg_btotoff = basesize;
	newcg->cg_boff = newcg->cg_btotoff + fs->fs_cpg * sizeof (daddr32_t);
	newcg->cg_iusedoff = newcg->cg_boff +
	    fs->fs_cpg * fs->fs_nrpos * sizeof (uint16_t);
	(void) memset(&newcg->cg_space[0], 0, newcg->cg_iusedoff - basesize);

	inomapsize = howmany(fs->fs_ipg, NBBY);
	newcg->cg_freeoff = newcg->cg_iusedoff + inomapsize;
	blkmapsize = howmany(fs->fs_fpg, NBBY);
	newcg->cg_nextfreeoff = newcg->cg_freeoff + blkmapsize;
	newcg->cg_magic = CG_MAGIC;

	sumsize = newcg->cg_iusedoff - newcg->cg_btotoff;
	mapsize = newcg->cg_nextfreeoff - newcg->cg_iusedoff;

	init_inodesc(&idesc);
	idesc.id_type = ADDR;
	(void) memset((void *)&cstotal, 0, sizeof (struct csum));
	now = time(NULL);

	/*
	 * If the last fragments in the file system don't make up a
	 * full file system block, mark the bits in the blockmap
	 * that correspond to those missing fragments as "allocated",
	 * so that the last block doesn't get counted as a free block
	 * and those missing fragments don't get counted as free frags.
	 */
	j = blknum(fs, (uint64_t)fs->fs_size + fs->fs_frag - 1);
	for (i = fs->fs_size; i < j; i++)
		setbmap(i);

	/*
	 * The cg summaries are not always updated when using
	 * logging.  Since we're really concerned with getting a
	 * sane filesystem, rather than in trying to debug UFS
	 * corner cases, logically we would just always recompute
	 * them.  However, it is disconcerting to users to be asked
	 * about updating the summaries when, from their point of
	 * view, there's been no indication of a problem up to this
	 * point.  So, only do it if we find a discrepancy.
	 */
	update_csums = -1;
	update_bitmaps = 0;
	for (c = 0; c < fs->fs_ncg; c++) {
		backup_cs = cstotal;

		/*
		 * cg_sanity() will catch i/o errors for us.
		 */
		(void) getblk(&cgblk, (diskaddr_t)cgtod(fs, c),
		    (size_t)fs->fs_cgsize);
		err = cg_sanity(cg, c);
		if (err != NULL) {
			pfatal("CG %d: %s\n", c, err);
			free((void *)err);
			if (reply("REPAIR") == 0)
				errexit("Program terminated.");
			fix_cg(cg, c);
		}
		/*
		 * If the on-disk timestamp is in the future, then it
		 * by definition is wrong.  Otherwise, if it's in
		 * the past, then use that value so that we don't
		 * declare a spurious mismatch.
		 */
		if (now > cg->cg_time)
			newcg->cg_time = cg->cg_time;
		else
			newcg->cg_time = now;
		newcg->cg_cgx = c;
		dbase = cgbase(fs, c);
		dmax = dbase + fs->fs_fpg;
		if (dmax > fs->fs_size)
			dmax = fs->fs_size;
		newcg->cg_ndblk = dmax - dbase;
		if (c == fs->fs_ncg - 1)
			newcg->cg_ncyl = fs->fs_ncyl - (fs->fs_cpg * c);
		else
			newcg->cg_ncyl = fs->fs_cpg;
		newcg->cg_niblk = sblock.fs_ipg;
		newcg->cg_cs.cs_ndir = 0;
		newcg->cg_cs.cs_nffree = 0;
		newcg->cg_cs.cs_nbfree = 0;
		newcg->cg_cs.cs_nifree = fs->fs_ipg;
		if ((cg->cg_rotor >= 0) && (cg->cg_rotor < newcg->cg_ndblk))
			newcg->cg_rotor = cg->cg_rotor;
		else
			newcg->cg_rotor = 0;
		if ((cg->cg_frotor >= 0) && (cg->cg_frotor < newcg->cg_ndblk))
			newcg->cg_frotor = cg->cg_frotor;
		else
			newcg->cg_frotor = 0;
		if ((cg->cg_irotor >= 0) && (cg->cg_irotor < newcg->cg_niblk))
			newcg->cg_irotor = cg->cg_irotor;
		else
			newcg->cg_irotor = 0;
		(void) memset((void *)&newcg->cg_frsum[0], 0,
		    sizeof (newcg->cg_frsum));
		(void) memset((void *)cg_inosused(newcg), 0, (size_t)mapsize);
		/* LINTED macro is int32-aligned per newcg->cg_btotoff above */
		(void) memset((void *)&cg_blktot(newcg)[0], 0,
		    sumsize + mapsize);
		j = fs->fs_ipg * c;
		for (i = 0; i < fs->fs_ipg; j++, i++) {
			switch (statemap[j] & ~(INORPHAN | INDELAYD)) {

			case USTATE:
				break;

			case DSTATE:
			case DCLEAR:
			case DFOUND:
			case DZLINK:
				newcg->cg_cs.cs_ndir++;
				/* FALLTHROUGH */

			case FSTATE:
			case FCLEAR:
			case FZLINK:
			case SSTATE:
			case SCLEAR:
				newcg->cg_cs.cs_nifree--;
				setbit(cg_inosused(newcg), i);
				break;

			default:
				if (j < UFSROOTINO)
					break;
				errexit("BAD STATE 0x%x FOR INODE I=%d",
				    statemap[j], (int)j);
			}
		}
		if (c == 0) {
			for (i = 0; i < UFSROOTINO; i++) {
				setbit(cg_inosused(newcg), i);
				newcg->cg_cs.cs_nifree--;
			}
		}
		/*
		 * Count up what fragments and blocks are free, and
		 * reflect the relevant section of blockmap[] into
		 * newcg's map.
		 */
		for (i = 0, d = dbase;
		    d < dmax;
		    d += fs->fs_frag, i += fs->fs_frag) {
			frags = 0;
			for (j = 0; j < fs->fs_frag; j++) {
				if (testbmap(d + j))
					continue;
				setbit(cg_blksfree(newcg), i + j);
				frags++;
			}
			if (frags == fs->fs_frag) {
				newcg->cg_cs.cs_nbfree++;
				j = cbtocylno(fs, i);
				/* LINTED macro is int32-aligned per above */
				cg_blktot(newcg)[j]++;
				/* LINTED cg_blks(newcg) is aligned */
				cg_blks(fs, newcg, j)[cbtorpos(fs, i)]++;
			} else if (frags > 0) {
				newcg->cg_cs.cs_nffree += frags;
				blk = blkmap(fs, cg_blksfree(newcg), i);
				fragacct(fs, blk, newcg->cg_frsum, 1);
			}
		}
		cstotal.cs_nffree += newcg->cg_cs.cs_nffree;
		cstotal.cs_nbfree += newcg->cg_cs.cs_nbfree;
		cstotal.cs_nifree += newcg->cg_cs.cs_nifree;
		cstotal.cs_ndir += newcg->cg_cs.cs_ndir;

		/*
		 * Note that, just like the kernel, we dynamically
		 * allocated an array to hold the csums and stuffed
		 * the pointer into the in-core superblock's fs_u.fs_csp
		 * field.  This means that the fs_u field contains a
		 * random value when the disk version is examined, but
		 * fs_cs() gives us a valid pointer nonetheless.
		 * We need to compare the recalculated summaries to
		 * both the superblock version and the on disk version.
		 * If either is bad, copy the calculated version over
		 * the corrupt values.
		 */

		cs = &fs->fs_cs(fs, c);
		bad_csum_sb = (memcmp((void *)cs, (void *)&newcg->cg_cs,
		    sizeof (*cs)) != 0);

		bad_csum_cg = (memcmp((void *)&cg->cg_cs, (void *)&newcg->cg_cs,
		    sizeof (struct csum)) != 0);

		/*
		 * Has the user told us what to do yet?  If not, find out.
		 */
		if ((bad_csum_sb || bad_csum_cg) && (update_csums == -1)) {
			if (preen) {
				update_csums = 1;
				(void) printf("CORRECTING BAD CG SUMMARIES"
				    " FOR CG %d\n", c);
			} else if (update_csums == -1) {
				update_csums = (reply(
				    "CORRECT BAD CG SUMMARIES FOR CG %d",
				    c) == 1);
			}
		}

		if (bad_csum_sb && (update_csums == 1)) {
			(void) memmove((void *)cs, (void *)&newcg->cg_cs,
			    sizeof (*cs));
			sbdirty();
			(void) printf("CORRECTED SUPERBLOCK SUMMARIES FOR"
			    " CG %d\n", c);
		}

		if (bad_csum_cg && (update_csums == 1)) {
			(void) memmove((void *)cg, (void *)newcg,
			    (size_t)basesize);
			/* LINTED per cg_sanity() */
			(void) memmove((void *)&cg_blktot(cg)[0],
			    /* LINTED macro aligned as above */
			    (void *)&cg_blktot(newcg)[0], sumsize);
			cgdirty();
			(void) printf("CORRECTED SUMMARIES FOR CG %d\n", c);
		}

		excessdirs = cg->cg_cs.cs_ndir - newcg->cg_cs.cs_ndir;
		if (excessdirs < 0) {
			pfatal("LOST %d DIRECTORIES IN CG %d\n",
			    -excessdirs, c);
			excessdirs = 0;
		}
		if (excessdirs > 0) {
			if (check_maps((uchar_t *)cg_inosused(newcg),
			    (uchar_t *)cg_inosused(cg), inomapsize,
			    cg->cg_cgx * fs->fs_ipg, "DIR", 0, excessdirs)) {
				if (!verbose)
					(void) printf("DIR BITMAP WRONG ");
				if (preen || update_bitmaps ||
				    reply("FIX") == 1) {
					(void) memmove((void *)cg_inosused(cg),
					    (void *)cg_inosused(newcg),
					    inomapsize);
					cgdirty();
					if (preen ||
					    (!verbose && update_bitmaps))
						(void) printf("(CORRECTED)\n");
					update_bitmaps = 1;
				}
			}
		}

		if (check_maps((uchar_t *)cg_inosused(newcg),
		    (uchar_t *)cg_inosused(cg), inomapsize,
		    cg->cg_cgx * fs->fs_ipg, "FILE", excessdirs, fs->fs_ipg)) {
			if (!verbose)
				(void) printf("FILE BITMAP WRONG ");
			if (preen || update_bitmaps || reply("FIX") == 1) {
				(void) memmove((void *)cg_inosused(cg),
				    (void *)cg_inosused(newcg), inomapsize);
				cgdirty();
				if (preen ||
				    (!verbose && update_bitmaps))
					(void) printf("(CORRECTED)\n");
				update_bitmaps = 1;
			}
		}

		if (check_maps((uchar_t *)cg_blksfree(cg),
		    (uchar_t *)cg_blksfree(newcg), blkmapsize,
		    cg->cg_cgx * fs->fs_fpg, "FRAG", 0, fs->fs_fpg)) {
			if (!verbose)
				(void) printf("FRAG BITMAP WRONG ");
			if (preen || update_bitmaps || reply("FIX") == 1) {
				(void) memmove((void *)cg_blksfree(cg),
				    (void *)cg_blksfree(newcg), blkmapsize);
				cgdirty();
				if (preen ||
				    (!verbose && update_bitmaps))
					(void) printf("(CORRECTED)\n");
				update_bitmaps = 1;
			}
		}

		bad_cgblks_cg = (memcmp((void *)&cg_blks(fs, cg, 0)[0],
		    (void *)&cg_blks(fs, newcg, 0)[0],
		    fs->fs_cpg * fs->fs_nrpos * sizeof (int32_t)) != 0);

		if (bad_cgblks_cg) {
			if (!verbose)
				(void) printf("ROTATIONAL POSITIONS "
				    "BLOCK COUNT WRONG ");
			if (preen || update_bitmaps || reply("FIX") == 1) {
				(void) memmove((void *)&cg_blks(fs, cg, 0)[0],
				    (void *)&cg_blks(fs, newcg, 0)[0],
				    fs->fs_cpg * fs->fs_nrpos *
				    sizeof (int32_t));
				cgdirty();
				if (preen ||
				    (!verbose && update_bitmaps))
					(void) printf("(CORRECTED)\n");
				update_bitmaps = 1;
			}
		}

		bad_cgblktot_cg = (memcmp((void *)&cg_blktot(cg)[0],
		    (void *)&cg_blktot(newcg)[0],
		    fs->fs_cpg * sizeof (int32_t)) != 0);

		if (bad_cgblktot_cg) {
			if (!verbose)
				(void) printf("ROTATIONAL POSITIONS "
				    "BLOCK TOTAL WRONG ");
			if (preen || update_bitmaps || reply("FIX") == 1) {
				(void) memmove((void *)&cg_blktot(cg)[0],
				    (void *)&cg_blktot(newcg)[0],
				    fs->fs_cpg * sizeof (int32_t));
				cgdirty();
				if (preen ||
				    (!verbose && update_bitmaps))
					(void) printf("(CORRECTED)\n");
				update_bitmaps = 1;
			}
		}

		/*
		 * Fixing one set of problems often shows up more in the
		 * same cg.  Just to make sure, go back and check it
		 * again if we found something this time through.
		 */
		if (cgisdirty()) {
			cgflush();
			cstotal = backup_cs;
			c--;
		}
	}

	if ((fflag || !(islog && islogok)) &&
	    (memcmp((void *)&cstotal, (void *)&fs->fs_cstotal,
	    sizeof (struct csum)) != 0)) {
		if (dofix(&idesc, "CORRECT GLOBAL SUMMARY")) {
			(void) memmove((void *)&fs->fs_cstotal,
			    (void *)&cstotal, sizeof (struct csum));
			fs->fs_ronly = 0;
			fs->fs_fmod = 0;
			sbdirty();
		} else {
			iscorrupt = 1;
		}
	}
}

/*
 * Compare two allocation bitmaps, reporting any discrepancies.
 *
 * If a mismatch is found, if the bit is set in map1, it's considered
 * to be an indication that the corresponding resource is supposed
 * to be free, but isn't.  Otherwise, it's considered marked as allocated
 * but not found to be so.  In other words, if the two maps being compared
 * use a set bit to indicate something is free, pass the on-disk map
 * first.  Otherwise, pass the calculated map first.
 */
static int
check_maps(
	uchar_t *map1,	/* map of claimed allocations */
	uchar_t *map2,	/* map of determined allocations */
	int mapsize,	/* size of above two maps */
	int startvalue,	/* resource value for first element in map */
	char *name,	/* name of resource found in maps */
	int skip,	/* number of entries to skip before starting to free */
	int limit)	/* limit on number of entries to free */
{
	long i, j, k, l, m, n, size;
	int astart, aend, ustart, uend;
	int mismatch;

	mismatch = 0;
	astart = ustart = aend = uend = -1;
	for (i = 0; i < mapsize; i++) {
		j = *map1++;
		k = *map2++;
		if (j == k)
			continue;
		for (m = 0, l = 1; m < NBBY; m++, l <<= 1) {
			if ((j & l) == (k & l))
				continue;
			n = startvalue + i * NBBY + m;
			if ((j & l) != 0) {
				if (astart == -1) {
					astart = aend = n;
					continue;
				}
				if (aend + 1 == n) {
					aend = n;
					continue;
				}
				if (verbose) {
					if (astart == aend)
						pwarn(
			    "ALLOCATED %s %d WAS MARKED FREE ON DISK\n",
						    name, astart);
					else
						pwarn(
			    "ALLOCATED %sS %d-%d WERE MARKED FREE ON DISK\n",
						    name, astart, aend);
				}
				mismatch = 1;
				astart = aend = n;
			} else {
				if (ustart == -1) {
					ustart = uend = n;
					continue;
				}
				if (uend + 1 == n) {
					uend = n;
					continue;
				}
				size = uend - ustart + 1;
				if (size <= skip) {
					skip -= size;
					ustart = uend = n;
					continue;
				}
				if (skip > 0) {
					ustart += skip;
					size -= skip;
					skip = 0;
				}
				if (size > limit)
					size = limit;
				if (verbose) {
					if (size == 1)
						pwarn(
			    "UNALLOCATED %s %d WAS MARKED USED ON DISK\n",
						    name, ustart);
					else
						pwarn(
			    "UNALLOCATED %sS %d-%ld WERE MARKED USED ON DISK\n",
						    name, ustart,
						    ustart + size - 1);
				}
				mismatch = 1;
				limit -= size;
				if (limit <= 0)
					return (mismatch);
				ustart = uend = n;
			}
		}
	}
	if (astart != -1) {
		if (verbose) {
			if (astart == aend)
				pwarn(
			    "ALLOCATED %s %d WAS MARKED FREE ON DISK\n",
				    name, astart);
			else
				pwarn(
			    "ALLOCATED %sS %d-%d WERE MARKED FREE ON DISK\n",
				    name, astart, aend);
		}
		mismatch = 1;
	}
	if (ustart != -1) {
		size = uend - ustart + 1;
		if (size <= skip)
			return (mismatch);
		if (skip > 0) {
			ustart += skip;
			size -= skip;
		}
		if (size > limit)
			size = limit;
		if (verbose) {
			if (size == 1)
				pwarn(
			    "UNALLOCATED %s %d WAS MARKED USED ON DISK\n",
				    name, ustart);
			else
				pwarn(
		    "UNALLOCATED %sS %d-%ld WERE MARKED USED ON DISK\n",
				    name, ustart, ustart + size - 1);
		}
		mismatch = 1;
	}
	return (mismatch);
}
