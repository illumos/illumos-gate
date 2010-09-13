/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "dump.h"
#include <sys/file.h>
#include <sys/mman.h>

#ifdef __STDC__
static void lf_dmpindir(daddr32_t, int, u_offset_t *);
static void indir(daddr32_t, int, u_offset_t *);
static void lf_blksout(daddr32_t *, u_offset_t);
static void lf_dumpinode(struct dinode *);
static void dsrch(daddr32_t, ulong_t, u_offset_t);
void lf_dump(struct dinode *);
#else
static void lf_dmpindir();
static void indir();
static void lf_blksout();
static void dsrch();
void lf_dump();
#endif

static	char msgbuf[256];

void
pass(fn, map)
	void (*fn)(struct dinode *);
	uchar_t *map;
{
	int bits;
	ino_t maxino;

	maxino = (unsigned)(sblock->fs_ipg * sblock->fs_ncg - 1);
	/*
	 * Handle pass restarts.  We don't check for UFSROOTINO just in
	 * case we need to restart on the root inode.
	 */
	if (ino != 0) {
		bits = ~0;
		if (map != NULL) {
			/* LINTED: lint seems to think map is signed */
			map += (ino / NBBY);
			bits = *map++;
		}
		bits >>= (ino % NBBY);
		resetino(ino);
		goto restart;
	}
	while (ino < maxino) {
		if ((ino % NBBY) == 0) {
			bits = ~0;
			if (map != NULL)
				bits = *map++;
		}
restart:
		ino++;
		/*
		 * Ignore any inode less than UFSROOTINO and inodes that
		 * we have already done on a previous pass.
		 */
		if ((ino >= UFSROOTINO) && (bits & 1)) {
			/*
			 * The following test is merely an optimization
			 * for common case where "add" will just return.
			 */
			if (!(fn == add && BIT(ino, nodmap)))
				(*fn)(getino(ino));
		}
		bits >>= 1;
	}
}

void
mark(ip)
	struct dinode *ip;
{
	int f;

	f = ip->di_mode & IFMT;
	if (f == 0 || ip->di_nlink <= 0) {
		/* LINTED: 32-bit to 8-bit assignment ok */
		BIC(ino, clrmap);
		return;
	}
	/* LINTED: 32-bit to 8-bit assignment ok */
	BIS(ino, clrmap);
	if (f == IFDIR || f == IFATTRDIR) {
		/* LINTED: 32-bit to 8-bit assignment ok */
		BIS(ino, dirmap);
	}
	if (ip->di_ctime >= spcl.c_ddate) {
		if (f == IFSHAD)
			return;
		/* LINTED: 32-bit to 8-bit assignment ok */
		BIS(ino, nodmap);
		/* attribute changes impact the root */
		if (f == IFATTRDIR)
			BIS(UFSROOTINO, nodmap);
		if (f != IFREG && f != IFDIR && f != IFATTRDIR && f != IFLNK) {
			o_esize += 1;
			return;
		}
		est(ip);
	}
}

void
active_mark(ip)
	struct dinode *ip;
{
	int f;

	f = ip->di_mode & IFMT;
	if (f == 0 || ip->di_nlink <= 0) {
		/* LINTED: 32-bit to 8-bit assignment ok */
		BIC(ino, clrmap);
		return;
	}
	/* LINTED: 32-bit to 8-bit assignment ok */
	BIS(ino, clrmap);
	if (f == IFDIR || f == IFATTRDIR) {
		/* LINTED: 32-bit to 8-bit assignment ok */
		BIS(ino, dirmap);
	}
	if (BIT(ino, activemap)) {
		/* LINTED: 32-bit to 8-bit assignment ok */
		BIS(ino, nodmap);
		/* attribute changes impact the root */
		if (f == IFATTRDIR)
			BIS(UFSROOTINO, nodmap);
		if (f != IFREG && f != IFDIR && f != IFATTRDIR && f != IFLNK) {
			o_esize += 1;
			return;
		}
		est(ip);
	}
}

static struct shcount {
	struct shcount *higher, *lower;
	ino_t ino;
	unsigned long count;
} shcounts = {
	NULL, NULL,
	0,
	0
};
static struct shcount *shc = NULL;

void
markshad(ip)
	struct dinode *ip;
{
	ino_t shadow;

	if (ip->di_shadow == 0)
		return;
	if (shc == NULL)
		shc = &shcounts;

	shadow = (ino_t)(unsigned)(ip->di_shadow);
	while ((shadow > shc->ino) && (shc->higher))
		shc = shc->higher;
	while ((shadow < shc->ino) && (shc->lower))
		shc = shc->lower;
	if (shadow != shc->ino) {
		struct shcount *new;

		new = (struct shcount *)xcalloc(1, sizeof (*new));
		new->higher = shc->higher;
		if (shc->higher != NULL)
			shc->higher->lower = new;
		shc->higher = new;
		new->lower = shc;
		shc = new;
		shc->ino = shadow;
	}

	/* LINTED: 32-bit to 8-bit assignment ok */
	BIS(shadow, shamap);
	shc->count++;
}

void
estshad(ip)
	struct dinode *ip;
{
	u_offset_t esizeprime;
	u_offset_t tmpesize;

	if (ip->di_size <= sizeof (union u_shadow))
		return;

	while ((ino > shc->ino) && (shc->higher))
		shc = shc->higher;
	while ((ino < shc->ino) && (shc->lower))
		shc = shc->lower;
	if (ino != shc->ino)
		return; /* xxx panic? complain? */

	tmpesize = (o_esize + f_esize);
	esizeprime = tmpesize;
	est(ip);
	esizeprime = tmpesize - esizeprime;
	esizeprime *= shc->count - 1;
	f_esize += esizeprime;
}

void
freeshad()
{
	if (shc == NULL)
		return;

	while (shc->higher)
		shc = shc->higher;
	while (shc->lower) {
		shc = shc->lower;
		if (shc->higher) /* else panic? */
			(void) free(shc->higher);
	}
	/*
	 * This should be unnecessary, but do it just to be safe.
	 * Note that shc might be malloc'd or static, so can't free().
	 */
	bzero(shc, sizeof (*shc));
}

void
add(ip)
	struct	dinode	*ip;
{
	int i;
	u_offset_t filesize;

	if (BIT(ino, nodmap))
		return;
	if ((ip->di_mode & IFMT) != IFDIR &&
	    (ip->di_mode & IFMT) != IFATTRDIR) {
		(void) snprintf(msgbuf, sizeof (msgbuf), gettext(
		    "Warning - directory at inode `%lu' vanished!\n"), ino);
		msg(msgbuf);
		/* LINTED: 32-bit to 8-bit assignment ok */
		BIC(ino, dirmap);
		return;
	}
	nsubdir = 0;
	dadded = 0;
	filesize = ip->di_size;
	for (i = 0; i < NDADDR; i++) {
		if (ip->di_db[i] != 0)
			/* LINTED dblksize/blkoff does a safe cast here */
			dsrch(ip->di_db[i], (ulong_t)dblksize(sblock, ip, i),
			    filesize);
		filesize -= (unsigned)(sblock->fs_bsize);
	}
	for (i = 0; i < NIADDR; i++) {
		if (ip->di_ib[i] != 0)
			indir(ip->di_ib[i], i, &filesize);
	}
	if (dadded) {
		nadded++;
		if (!BIT(ino, nodmap)) {
			/* LINTED: 32-bit to 8-bit assignment ok */
			BIS(ino, nodmap);
			if ((ip->di_mode & IFMT) == IFATTRDIR) {
				/* attribute changes "auto-percolate" to root */
				BIS(UFSROOTINO, nodmap);
			}
			est(ip);
		}
	}
	if (nsubdir == 0) {
		if (!BIT(ino, nodmap)) {
			/* LINTED: 32-bit to 8-bit assignment ok */
			BIC(ino, dirmap);
		}
	}
}

static void
indir(d, n, filesize)
	daddr32_t d;
	int n;
	u_offset_t *filesize;
{
	int i;
	daddr32_t idblk[MAXNINDIR];

	if ((unsigned)(sblock->fs_bsize) > sizeof (idblk)) {
		msg(gettext(
"Inconsistency detected: filesystem block size larger than valid maximum.\n"));
		dumpabort();
		/*NOTREACHED*/
	}

	if ((unsigned)NINDIR(sblock) > MAXNINDIR) {
		/*CSTYLED*/
		msg(gettext(
"Inconsistency detected: inode has more indirect \
blocks than valid maximum.\n"));
		dumpabort();
		/*NOTREACHED*/
	}

	if (dadded || *filesize == 0)
		return;

#ifdef	lint
	idblk[0] = '\0';
#endif	/* lint */

	/* xxx sanity check sblock contents before trusting them */
	bread(fsbtodb(sblock, d), (uchar_t *)idblk, (size_t)sblock->fs_bsize);
	if (n <= 0) {
		for (i = 0; i < NINDIR(sblock); i++) {
			d = idblk[i];
			if (d != 0)
				dsrch(d, (ulong_t)(uint32_t)sblock->fs_bsize,
				    *filesize);
			*filesize -= (unsigned)(sblock->fs_bsize);
		}
	} else {
		n--;
		for (i = 0; i < NINDIR(sblock); i++) {
			d = idblk[i];
			if (d != 0)
				indir(d, n, filesize);
		}
	}
}

void
dirdump(ip)
	struct dinode *ip;
{
	/* watchout for dir inodes deleted and maybe reallocated */
	if (((ip->di_mode & IFMT) != IFDIR &&
	    (ip->di_mode & IFMT) != IFATTRDIR) || ip->di_nlink < 2) {
		(void) snprintf(msgbuf, sizeof (msgbuf), gettext(
		    "Warning - directory at inode `%lu' vanished!\n"),
			ino);
		msg(msgbuf);
		return;
	}
	lf_dump(ip);
}

static u_offset_t loffset; /* current offset in file (ufsdump) */

static void
lf_dumpmeta(ip)
	struct dinode *ip;
{
	if ((ip->di_shadow == 0) || shortmeta)
	    return;

	lf_dumpinode(getino((ino_t)(unsigned)(ip->di_shadow)));
}

int
hasshortmeta(ip)
	struct dinode **ip;
{
	ino_t savino;
	int rc;

	if ((*ip)->di_shadow == 0)
		return (0);
	savino = ino;
	*ip = getino((ino_t)(unsigned)((*ip)->di_shadow));
	rc = ((*ip)->di_size <= sizeof (union u_shadow));
	*ip = getino(ino = savino);
	return (rc);
}

void
lf_dumpinode(ip)
    struct dinode *ip;
{
	int i;
	u_offset_t size;

	i = ip->di_mode & IFMT;

	if (i == 0 || ip->di_nlink <= 0)
		return;

	spcl.c_dinode = *ip;
	spcl.c_count = 0;

	if ((i != IFDIR && i != IFATTRDIR && i != IFREG && i != IFLNK &&
	    i != IFSHAD) || ip->di_size == 0) {
		toslave(dospcl, ino);
		return;
	}

	size = NDADDR * (unsigned)(sblock->fs_bsize);
	if (size > ip->di_size)
		size = ip->di_size;

	lf_blksout(&ip->di_db[0], size);

	size = ip->di_size - size;
	if (size > 0) {
		for (i = 0; i < NIADDR; i++) {
			lf_dmpindir(ip->di_ib[i], i, &size);
			if (size == 0)
				break;
		}
	}
}

void
lf_dump(ip)
	struct dinode *ip;
{

	if ((!BIT(ino, nodmap)) && (!BIT(ino, shamap)))
		return;

	shortmeta = hasshortmeta(&ip);
	if (shortmeta) {
		ip = getino((ino_t)(unsigned)(ip->di_shadow));
		/* assume spcl.c_shadow is smaller than 1 block */
		bread(fsbtodb(sblock, ip->di_db[0]),
		    (uchar_t *)spcl.c_shadow.c_shadow, sizeof (spcl.c_shadow));
		spcl.c_flags |= DR_HASMETA;
	} else {
		spcl.c_flags &= ~DR_HASMETA;
	}
	ip = getino(ino);

	loffset = 0;

	if (newtape) {
		spcl.c_type = TS_TAPE;
	} else if (pos)
		spcl.c_type = TS_ADDR;
	else
		spcl.c_type = TS_INODE;

	newtape = 0;
	lf_dumpinode(ip);
	lf_dumpmeta(ip);
	pos = 0;
}

static void
lf_dmpindir(blk, lvl, size)
	daddr32_t blk;
	int lvl;
	u_offset_t *size;
{
	int i;
	u_offset_t cnt;
	daddr32_t idblk[MAXNINDIR];

	if ((unsigned)(sblock->fs_bsize) > sizeof (idblk)) {
		msg(gettext(
"Inconsistency detected: filesystem block size larger than valid maximum.\n"));
		dumpabort();
		/*NOTREACHED*/
	}

	if ((unsigned)NINDIR(sblock) > MAXNINDIR) {
		msg(gettext(
"Inconsistency detected: inode has more indirect \
blocks than valid maximum.\n"));
		dumpabort();
		/*NOTREACHED*/
	}

	if (blk != 0)
		bread(fsbtodb(sblock, blk), (uchar_t *)idblk,
		    (size_t)sblock->fs_bsize);
	else
		bzero((char *)idblk, (size_t)sblock->fs_bsize);
	if (lvl <= 0) {
		cnt = (u_offset_t)(unsigned)NINDIR(sblock) *
		    (u_offset_t)(unsigned)(sblock->fs_bsize);
		if (cnt > *size)
			cnt = *size;
		*size -= cnt;
		lf_blksout(&idblk[0], cnt);
		return;
	}
	lvl--;
	for (i = 0; i < NINDIR(sblock); i++) {
		lf_dmpindir(idblk[i], lvl, size);
		if (*size == 0)
			return;
	}
}

static void
lf_blksout(blkp, bytes)
	daddr32_t *blkp;
	u_offset_t bytes;
{
	u_offset_t i;
	u_offset_t tbperfsb = (unsigned)(sblock->fs_bsize / tp_bsize);

	u_offset_t j, k, count;

	u_offset_t bytepos, diff;
	u_offset_t bytecnt = 0;
	off_t byteoff = 0;	/* bytes to skip within first f/s block */
	off_t fragoff = 0;	/* frags to skip within first f/s block */

	u_offset_t tpblkoff = 0; /* tape blocks to skip in first f/s block */
	u_offset_t tpblkskip = 0;	/* total tape blocks to skip  */
	u_offset_t skip;		/* tape blocks to skip this pass */

	if (pos) {
		/*
		 * We get here if a slave throws a signal to the
		 * master indicating a partially dumped file.
		 * Begin by figuring out what was undone.
		 */
		bytepos = (offset_t)pos * tp_bsize;

		if ((loffset + bytes) <= bytepos) {
			/* This stuff was dumped already, forget it. */
			loffset += (u_offset_t)tp_bsize *
			    /* LINTED: spurious complaint on sign-extending */
			    d_howmany(bytes, (u_offset_t)tp_bsize);
			return;
		}

		if (loffset < bytepos) {
			/*
			 * Some of this was dumped, some wasn't.
			 * Figure out what was done and skip it.
			 */
			diff = bytepos - loffset;
			/* LINTED: spurious complaint on sign-extending */
			tpblkskip = d_howmany(diff, (u_offset_t)tp_bsize);
			/* LINTED room after EOT is only a few MB */
			blkp += (int)(diff / sblock->fs_bsize);

			bytecnt = diff % (unsigned)(sblock->fs_bsize);
			/* LINTED: result fits, due to modulus */
			byteoff = bytecnt % (off_t)(sblock->fs_fsize);
			/* LINTED: spurious complaint on sign-extending */
			tpblkoff = d_howmany(bytecnt,
			    (u_offset_t)(unsigned)tp_bsize);
			/* LINTED: result fits, due to modulus */
			fragoff = bytecnt / (off_t)(sblock->fs_fsize);
			bytecnt = (unsigned)(sblock->fs_bsize) - bytecnt;
		}
	}

	loffset += bytes;

	while (bytes > 0) {
		if (bytes < TP_NINDIR*tp_bsize)
			/* LINTED: spurious complaint on sign-extending */
			count = d_howmany(bytes, (u_offset_t)tp_bsize);
		else
			count = TP_NINDIR;
		if (tpblkskip) {
			if (tpblkskip < TP_NINDIR) {
				bytes -= (tpblkskip * (u_offset_t)tp_bsize);
				skip = tpblkskip;
				tpblkskip = 0;
			} else {
				bytes -= (offset_t)TP_NINDIR*tp_bsize;
				tpblkskip -= TP_NINDIR;
				continue;
			}
		} else
			skip = 0;
		assert(tbperfsb >= tpblkoff);
		assert((count - skip) <= TP_NINDIR);
		for (j = 0, k = 0; j < count - skip; j++, k++) {
			spcl.c_addr[j] = (blkp[k] != 0);
			for (i = tbperfsb - tpblkoff; --i > 0; j++)
				spcl.c_addr[j+1] = spcl.c_addr[j];
			tpblkoff = 0;
		}
		/* LINTED (count - skip) will always fit into an int32_t */
		spcl.c_count = count - skip;
		toslave(dospcl, ino);
		bytecnt = MIN(bytes, bytecnt ?
		    bytecnt : (unsigned)(sblock->fs_bsize));
		j = 0;
		while (j < count - skip) {
			if (*blkp != 0) {
				/* LINTED: fragoff fits into 32 bits */
				dmpblk(*blkp+(int32_t)fragoff,
				    /* LINTED: bytecnt fits into 32 bits */
				    (size_t)bytecnt, byteoff);
			}
			blkp++;
			bytes -= bytecnt;
			/* LINTED: spurious complaint on sign-extending */
			j += d_howmany(bytecnt, (u_offset_t)tp_bsize);
			bytecnt = MIN(bytes, (unsigned)(sblock->fs_bsize));
			byteoff = 0;
			fragoff = 0;
		}
		spcl.c_type = TS_ADDR;
		bytecnt = 0;
	}
	pos = 0;
}

void
bitmap(map, typ)
	uchar_t *map;
	int typ;
{
	int i;
	u_offset_t count;
	uchar_t *cp;

	if (!newtape)
		spcl.c_type = typ;
	else
		newtape = 0;
	for (i = 0; i < TP_NINDIR; i++)
		spcl.c_addr[i] = 1;
	/* LINTED: spurious complaint on sign-extending */
	count = d_howmany(msiz * sizeof (map[0]), tp_bsize) - pos;
	for (cp = &map[pos * tp_bsize]; count > 0;
	    count -= (u_offset_t)(unsigned)spcl.c_count) {
		if (leftover) {
			spcl.c_count = leftover;
			leftover = 0;
		} else {
			/* LINTED value always less than INT32_MAX */
			spcl.c_count = count > TP_NINDIR ? TP_NINDIR : count;
		}
		spclrec();
		for (i = 0; i < spcl.c_count; i++, cp += tp_bsize)
			taprec(cp, 0, tp_bsize);
		spcl.c_type = TS_ADDR;
	}
}

static void
dsrch(d, size, filesize)
	daddr32_t d;
	ulong_t size; 	/* block size */
	u_offset_t filesize;
{
	struct direct *dp;
	struct dinode *ip;
	ulong_t loc;
	char dblk[MAXBSIZE];

	if (dadded || filesize == 0)
		return;
	if (filesize > (u_offset_t)size)
		filesize = (u_offset_t)size;
	if (sizeof (dblk) < roundup(filesize, DEV_BSIZE)) {
		msg(gettext(
"Inconsistency detected: filesystem block size larger than valid maximum.\n"));
		dumpabort();
		/*NOTREACHED*/
	}

#ifdef	lint
	dblk[0] = '\0';
#endif	/* lint */

	/* LINTED ufs disk addresses always fit into 32 bits */
	bread(fsbtodb(sblock, d), (uchar_t *)dblk,
	    /* LINTED from sizeof check above, roundup() <= max(size_t) */
	    (size_t)(roundup(filesize, DEV_BSIZE)));
	loc = 0;
	while ((u_offset_t)loc < filesize) {
		/*LINTED [dblk is char[], loc (dp->d_reclen) % 4 == 0]*/
		dp = (struct direct *)(dblk + loc);
		if (dp->d_reclen == 0) {
			(void) snprintf(msgbuf, sizeof (msgbuf), gettext(
		    "Warning - directory at inode `%lu' is corrupted\n"),
				ino);
			msg(msgbuf);
			break;
		}
		loc += dp->d_reclen;
		if (dp->d_ino == 0)
			continue;
		if (dp->d_name[0] == '.') {
			if (dp->d_name[1] == '\0') {
				if ((ino_t)(dp->d_ino) != ino) {
					(void) snprintf(msgbuf, sizeof (msgbuf),
					    gettext(
			"Warning - directory at inode `%lu' is corrupted:\n\
\t\".\" points to inode `%lu' - run fsck\n"),
					    ino, dp->d_ino);
					msg(msgbuf);
				}
				continue;
			}
			if (dp->d_name[1] == '.' && dp->d_name[2] == '\0') {
				if (!BIT(dp->d_ino, dirmap) &&
				    ((ip = getino(ino)) == NULL ||
				    (ip->di_mode & IFMT) != IFATTRDIR)) {
					(void) snprintf(msgbuf, sizeof (msgbuf),
					    gettext(
			"Warning - directory at inode `%lu' is corrupted:\n\
\t\"..\" points to non-directory inode `%lu' - run fsck\n"),
					    ino, dp->d_ino);
					msg(msgbuf);
				}
				continue;
			}
		}
		if (BIT(dp->d_ino, nodmap)) {
			dadded++;
			return;
		}
		if (BIT(dp->d_ino, dirmap))
			nsubdir++;
	}
}

#define	CACHESIZE 32

struct dinode *
getino(ino)
	ino_t ino;
{
	static ino_t minino, maxino;
	static struct dinode itab[MAXINOPB];
	static struct dinode icache[CACHESIZE];
	static ino_t icacheval[CACHESIZE], lasti = 0;
	static int cacheoff = 0;
	int i;

	if (ino >= minino && ino < maxino) {
		lasti = ino;
		return (&itab[ino - minino]);
	}

	/* before we do major i/o, check for a secondary cache hit */
	for (i = 0; i < CACHESIZE; i++)
		if (icacheval[i] == ino)
			return (icache + i);

	/* we need to do major i/o.  throw the last inode retrieved into */
	/* the cache.  note: this copies garbage the first time it is    */
	/* used, but no harm done.					 */
	icacheval[cacheoff] = lasti;
	bcopy(itab + (lasti - minino), icache + cacheoff, sizeof (itab[0]));
	lasti = ino;
	if (++cacheoff >= CACHESIZE)
		cacheoff = 0;

#define	INOPERDB (DEV_BSIZE / sizeof (struct dinode))
	minino = ino &~ (INOPERDB - 1);
	maxino = ((itog(sblock, ino) + 1) * (unsigned)(sblock->fs_ipg));
	if (maxino > minino + MAXINOPB)
		maxino = minino + MAXINOPB;
	bread(
	    /* LINTED: can't make up for broken system macros here */
	    (fsbtodb(sblock, itod(sblock, ino)) + itoo(sblock, ino) / INOPERDB),
	    /* LINTED: (max - min) * size fits into a size_t */
	    (uchar_t *)itab, (size_t)((maxino - minino) * sizeof (*itab)));
	return (&itab[ino - minino]);
}

#define	BREADEMAX 32

#ifdef NO__LONGLONG__
#define	DEV_LSEEK(fd, offset, whence) \
	lseek((fd), (((off_t)(offset))*DEV_BSIZE), (whence))
#else
#define	DEV_LSEEK(fd, offset, whence) \
	llseek((fd), (((offset_t)((offset)))*DEV_BSIZE), (whence))
#endif

#define	BREAD_FAIL(buf, size)	{ \
		breaderrors += 1; \
		bzero(buf, (size_t)size); \
	}



void
bread(da, ba, cnt)
diskaddr_t da;
uchar_t	*ba;
size_t	cnt;
{
	caddr_t maddr;
	uchar_t *dest;
	int saverr;
	int n;
	size_t len;
	off64_t filoff;
	off64_t mapoff;
	off64_t displacement;

	static size_t pagesize = 0;
	static int breaderrors = 0;

	/* mechanics for caching small bread requests.  these are */
	/* often small ACLs that are used over and over.	  */
	static uchar_t bcache[DEV_BSIZE * CACHESIZE];
	static diskaddr_t bcacheval[CACHESIZE];
	static int cacheoff = 0;
	int i;

	if ((cnt >= DEV_BSIZE) && (mapfd != -1)) {
		if (pagesize == 0)
			pagesize = getpagesize();
		/*
		 * We depend on mmap(2)'s guarantee that mapping a
		 * partial page will cause the remainder of the page
		 * to be zero-filled.
		 */
		filoff = ((off64_t)da) * DEV_BSIZE;
		displacement = filoff & (pagesize - 1);
		mapoff = filoff - displacement;
		/* LINTED offset will fit into 32 bits */
		len = (size_t)roundup(cnt + (filoff - mapoff), pagesize);
		maddr = mmap64(NULL, len, PROT_READ, MAP_SHARED, mapfd, mapoff);
		if (maddr != MAP_FAILED) {
			(void) memcpy(ba, maddr + displacement, cnt);
			(void) munmap(maddr, len);
			return;
		}
	}

	if (DEV_LSEEK(fi, da, L_SET) < 0) {
		saverr = errno;
		msg(gettext("bread: dev_seek error: %s\n"), strerror(saverr));
		/* Don't know where we are, return the least-harmful data */
		BREAD_FAIL(ba, cnt);
		return;
	}

	if (read(fi, ba, (size_t)cnt) == (size_t)cnt)
	    return;

	while (cnt != 0) {

		if (da >= fsbtodb(sblock, sblock->fs_size)) {
			msg(gettext(
			    "Warning - block %llu is beyond the end of `%s'\n"),
			    da, disk);
			BREAD_FAIL(ba, cnt);
			break;
		}

		if (DEV_LSEEK(fi, da, L_SET) < 0) {
			msg(gettext("%s: %s error\n"), "bread", "DEV_LSEEK2");
			BREAD_FAIL(ba, cnt);
			break;
		}

		if (cnt < DEV_BSIZE) {
			/* small read.  check for cache hit. */
			for (i = 0; i < CACHESIZE; i++)
				if (bcacheval[i] == da) {
					bcopy(bcache + (i * DEV_BSIZE),
					    ba, cnt);
					return;
				}

			/* no cache hit; throw this one into the cache... */
			len = cnt;
			dest = bcache + (cacheoff * DEV_BSIZE);
			bcacheval[cacheoff] = da;
			if (++cacheoff >= CACHESIZE)
				cacheoff = 0;
		} else {
			len = DEV_BSIZE;
			dest = ba;
		}

		n = read(fi, dest, DEV_BSIZE);
		if (n != DEV_BSIZE) {
			n = MAX(n, 0);
			bzero(dest+n, DEV_BSIZE-n);
			breaderrors += 1;
			msg(gettext(
			    "Warning - cannot read sector %llu of `%s'\n"),
			    da, disk);
		}
		if (dest != ba)
			bcopy(dest, ba, len);

		da++;
		/* LINTED character pointers aren't signed */
		ba += len;
		cnt -= len;
	}

	if (breaderrors > BREADEMAX) {
		msg(gettext(
		    "More than %d block read errors from dump device `%s'\n"),
		    BREADEMAX, disk);
		dumpailing();
		breaderrors = 0;
	}
}
