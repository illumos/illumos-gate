/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1991,1996,1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "dump.h"
#include <math.h>
#include <limits.h>

/*
 * Uncomment if using mmap'ing of files for pre-fetch.
 * #define ENABLE_MMAP 1
 */

struct inodesc {
	ino_t	id_inumber;		/* inode number */
	long	id_gen;			/* generation number */
	struct inodesc *id_next;	/* next on linked list */
};

static struct inodesc	ilist;		/* list of used inodesc structs */
static struct inodesc	*last;		/* last inodesc init'd or matched */
static struct inodesc	*freeinodesc;	/* free list of inodesc structs */
static struct inodesc	**ialloc;	/* allocated chunks, for freeing */
static int		nchunks;	/* number of allocations */

#ifdef ENABLE_MMAP /* XXX part of mmap support */
/*
 * If an mmap'ed file is truncated as it is being dumped or
 * faulted in, we are delivered a SIGBUS.
 */
static jmp_buf	truncate_buf;
static void	(*savebus)();
static int	incopy;

#ifdef __STDC__
static void onsigbus(int);
#else
static void onsigbus();
#endif

#endif	/* ENABLE_MMAP */

#ifdef DEBUG
extern int xflag;
#endif

#ifdef ENABLE_MMAP /* XXX part of mmap support */
static void
onsigbus(sig)
	int	sig;
{
	if (!incopy) {
		dumpabort();
		/*NOTREACHED*/
	}
	incopy = 0;
	longjmp(truncate_buf, 1);
	/*NOTREACHED*/
}
#endif	/* ENABLE_MMAP */

void
#ifdef __STDC__
allocino(void)
#else
allocino()
#endif
{
	ino_t maxino;
	size_t nused;

	maxino = (unsigned)(sblock->fs_ipg * sblock->fs_ncg);
	if (maxino > ULONG_MAX) {
		msg(gettext("allocino: filesystem too large\n"));
		dumpabort();
		/*NOTREACHED*/
	}
	/* LINTED maxino guaranteed to fit into a size_t by above test */
	nused =  maxino - sblock->fs_cstotal.cs_nifree;
	freeinodesc = (struct inodesc *)xcalloc(nused, sizeof (*freeinodesc));
	if (freeinodesc == (struct inodesc *)0) {
		msg(gettext("%s: out of memory\n"), "allocino");
		dumpabort();
		/*NOTREACHED*/
	}
	last = &ilist;
	ialloc =
	    (struct inodesc **)xmalloc(2*sizeof (*ialloc));
	ialloc[0] = freeinodesc;
	ialloc[1] = (struct inodesc *)0;
	nchunks = 1;
}

void
#ifdef __STDC__
freeino(void)
#else
freeino()
#endif
{
	int i;

	if (ialloc == (struct inodesc **)0)
		return;
	for (i = 0; i < nchunks; i++)
		if (ialloc[i] != 0)
			free(ialloc[i]);
	free(ialloc);
	ialloc = (struct inodesc **)0;
}

void
resetino(ino)
	ino_t	ino;
{
	last = ilist.id_next;
	while (last && last->id_inumber < ino)
		last = last->id_next;
}

char *
unrawname(cp)
	char *cp;
{
	char *dp;
	extern char *getfullblkname();

	dp = getfullblkname(cp);
	if (dp == 0)
		return (0);
	if (*dp == '\0') {
		free(dp);
		return (0);
	}
	if (dp == cp)		/* caller wants to always free() dp */
		dp = strdup(cp);

	return (dp);
}

/*
 * Determine if specified device is mounted at
 * specified mount point.  Returns 1 if mounted,
 * 0 if not mounted, -1 on error.
 */
int
lf_ismounted(devname, dirname)
	char	*devname;	/* name of device (raw or block) */
	char	*dirname;	/* name of f/s mount point */
{
	struct stat64 st;
	char	*blockname;	/* name of block device */
	dev_t	dev;
	int	saverr;

	if ((blockname = unrawname(devname)) == NULL) {
		msg(gettext("Cannot obtain block name from `%s'\n"), devname);
		return (-1);
	}
	if (stat64(blockname, &st) < 0) {
		saverr = errno;
		msg(gettext("Cannot obtain status of device `%s': %s\n"),
		    blockname, strerror(saverr));
		free(blockname);
		return (-1);
	}
	free(blockname);
	dev = st.st_rdev;
	if (stat64(dirname, &st) < 0) {
		saverr = errno;
		msg(gettext("Cannot obtain status of device `%s': %s\n"),
		    dirname, strerror(saverr));
		return (-1);
	}
	if (dev == st.st_dev)
		return (1);
	return (0);
}

#ifdef ENABLE_MMAP /* XXX mapped-file support */
#define	MINMAPSIZE	1024*1024
#define	MAXMAPSIZE	1024*1024*32

static caddr_t	mapbase;	/* base of mapped data */
static caddr_t	mapend;		/* last byte of mapped data */
static size_t	mapsize;	/* amount of mapped data */
/*
 * Map a file prior to dumping and start faulting in its
 * pages.  Stop if we catch a signal indicating our turn
 * to dump has arrived.  If the file is truncated out from
 * under us, immediately return.
 * NB:  the base of the mapped data may not coincide
 * exactly to the requested offset, due to alignment
 * constraints.
 */
caddr_t
mapfile(fd, offset, bytes, fetch)
	int	fd;
	off_t	offset;		/* offset within file */
	off_t	bytes;		/* number of bytes to map */
	int	fetch;		/* start faulting in pages */
{
	/*LINTED [c used during pre-fetch faulting]*/
	volatile char c, *p;
	int stride = (int)sysconf(_SC_PAGESIZE);
	extern int caught;		/* pre-fetch until set */
	caddr_t	mapstart;		/* beginning of file's mapped data */
	off_t	mapoffset;		/* page-aligned offset */
	int	saverr;

	mapbase = mapend = (caddr_t)0;

	if (bytes == 0)
		return ((caddr_t)0);
	/*
	 * mmap the file for reading
	 */
	mapoffset = offset & ~(stride - 1);
	/* LINTED: "bytes" will always fit into a size_t */
	mapsize = bytes + (offset - mapoffset);
	if (mapsize > MAXMAPSIZE)
		mapsize = MAXMAPSIZE;
	while ((mapbase = mmap((caddr_t)0, mapsize, PROT_READ,
	    MAP_SHARED, fd, mapoffset)) == (caddr_t)-1 &&
	    errno == ENOMEM && mapsize >= MINMAPSIZE) {
		/*
		 * Due to address space limitations, we
		 * may not be able to map as much as we want.
		 */
		mapsize /= 2;	/* exponential back-off */
	}

	if (mapbase == (caddr_t)-1) {
		saverr = errno;
		msg(gettext("Cannot map file at inode `%lu' into memory: %s\n"),
			ino, strerror(saverr));
		/* XXX why not call dumpailing() here? */
		if (!query(gettext(
	    "Do you want to attempt to continue? (\"yes\" or \"no\") "))) {
			dumpabort();
			/*NOTREACHED*/
		}
		mapbase = (caddr_t)0;
		return ((caddr_t)0);
	}

	(void) madvise(mapbase, mapsize, MADV_SEQUENTIAL);
	mapstart = mapbase + (offset - mapoffset);
	mapend = mapbase + (mapsize - 1);

	if (!fetch)
		return (mapstart);

	if (setjmp(truncate_buf) == 0) {
		savebus = signal(SIGBUS, onsigbus);
		/*
		 * Touch each page to pre-fetch by faulting.  At least
		 * one of c or *p must be declared volatile, lest the
		 * optimizer eliminate the assignment in the loop.
		 */
		incopy = 1;
		for (p = mapbase; !caught && p <= mapend; p += stride) {
			/* LINTED: c is used for its side-effects */
			c = *p;
		}
		incopy = 0;
	}
#ifdef DEBUG
	else
		/* XGETTEXT:  #ifdef DEBUG only */
		msg(gettext(
			"FILE TRUNCATED (fault): Interrupting pre-fetch\n"));
#endif
	(void) signal(SIGBUS, savebus);
	return (mapstart);
}

void
#ifdef __STDC__
unmapfile(void)
#else
unmapfile()
#endif
{
	if (mapbase) {
		/* XXX we're unmapping it, so what does this gain us? */
		(void) msync(mapbase, mapsize, MS_ASYNC|MS_INVALIDATE);
		(void) munmap(mapbase, mapsize);
		mapbase = (caddr_t)0;
	}
}
#endif	/* ENABLE_MMAP */

void
#ifdef __STDC__
activepass(void)
#else
activepass()
#endif
{
	static int passno = 1;			/* active file pass number */
	char *ext, *old;
	char buf[3000];
	static char defext[] = ".retry";

	if (pipeout) {
		msg(gettext("Cannot re-dump active files to `%s'\n"), tape);
		dumpabort();
		/*NOTREACHED*/
	}

	if (active > 1)
		(void) snprintf(buf, sizeof (buf), gettext(
		    "%d files were active and will be re-dumped\n"), active);
	else
		(void) snprintf(buf, sizeof (buf), gettext(
		    "1 file was active and will be re-dumped\n"));
	msg(buf);

	doingactive++;
	active = 0;
	reset();			/* reset tape params */
	spcl.c_ddate = spcl.c_date;	/* chain with last dump/pass */

	/*
	 * If archiving, create a new
	 * archive file.
	 */
	if (archivefile) {
		old = archivefile;

		ext = strstr(old, defext);
		if (ext != (char *)NULL)
			*ext = '\0'; /* just want the base name */

		/* The two is for the trailing \0 and rounding up log10() */
		archivefile = xmalloc(strlen(old) + strlen(defext) +
		    (int)log10((double)passno) + 2);

		/* Always fits */
		(void) sprintf(archivefile, "%s%s%d", old, defext, passno);
		free(old);
	}

	if (tapeout) {
		if (isrewind(to)) {
			/*
			 * A "rewind" tape device.  When we do
			 * the close, we will lose our position.
			 * Be nice and switch volumes.
			 */
			(void) snprintf(buf, sizeof (buf), gettext(
		"Warning - cannot dump active files to rewind device `%s'\n"),
				tape);
			msg(buf);
			close_rewind();
			changevol();
		} else {
			trewind();
			doposition = 0;
			filenum++;
		}
	} else {
		/*
		 * Not a tape.  Do a volume switch.
		 * This will advance to the next file
		 * if using a sequence of files, next
		 * diskette if using diskettes, or
		 * let the user move the old file out
		 * of the way.
		 */
		close_rewind();
		changevol();	/* switch files */
	}
	(void) snprintf(buf, sizeof (buf), gettext(
	    "Dumping active files (retry pass %d) to `%s'\n"), passno, tape);
	msg(buf);
	passno++;
}
