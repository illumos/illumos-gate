/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#include "synonyms.h"
#include "mtlib.h"
#include "file64.h"

#define	_iob	__iob

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <thread.h>
#include <synch.h>
#include <unistd.h>
#include <string.h>
#include "stdiom.h"
#include <wchar.h>
#include <sys/stat.h>
#include <stddef.h>
#include <errno.h>

#undef end

#define	FILE_ARY_SZ	8 /* a nice size for FILE array & end_buffer_ptrs */

#ifdef	_LP64

/*
 * Macros to declare and loop over a fp or fp/xfp combo to
 * avoid some of the _LP64 ifdef hell.
 */

#define	FPDECL(fp)		FILE *fp
#define	FIRSTFP(lp, fp)		fp = lp->iobp
#define	NEXTFP(fp)		fp++

#define	xFILE			FILE

#else

#define	FPDECL(fp)		FILE *fp; xFILE *x##fp
#define	FIRSTFP(lp, fp)		x##fp = lp->iobp; \
				fp = x##fp ? &x##fp->_iob : &_iob[0]
#define	NEXTFP(fp)		(x##fp ? fp = &(++x##fp)->_iob : ++fp)

/* The extended 32-bit file structure for use in link buffers */
typedef struct xFILE {
	FILE			_iob;		/* must be first! */
	struct xFILEdata	_xdat;
} xFILE;

#define	xmagic			_xdat._magic
#define	xend			_xdat._end
#define	xlock			_xdat._lock
#define	xstate			_xdat._state

#define	FILEx(fp)		((struct xFILE *)(uintptr_t)fp)

/*
 * The magic number stored is actually the pointer scrambled with
 * a magic number.  Pointers to data items live everywhere in memory
 * so we scramble the pointer in order to avoid accidental collisions.
 */
#define	XFILEMAGIC		0x63687367
#define	XMAGIC(xfp)		((uintptr_t)(xfp) ^ XFILEMAGIC)

#endif /* _LP64 */

struct _link_	/* manages a list of streams */
{
	xFILE *iobp;		/* the array of (x)FILE's */
				/* NULL for the __first_link in ILP32 */
	int	niob;		/* length of the arrays */
	struct _link_	*next;	/* next in the list */
};

/*
 * With dynamic linking, iob may be in either the library or in the user's
 * a.out, so the run time linker fixes up the first entry in __first_link at
 * process startup time.
 *
 * In 32 bit processes, we don't have xFILE[FILE_ARY_SZ] but FILE[],
 * and _xftab[] instead; this is denoted by having iobp set to NULL in
 * 32 bit mode for the first link entry.
 */
struct _link_ __first_link =	/* first in linked list */
{
#if !defined(_LP64)
	NULL,
#else
	&_iob[0],
#endif
	_NFILE,
	NULL
};

/*
 * Information cached to speed up searches.  We remember where we
 * last found a free FILE* and we remember whether we saw any fcloses
 * in between.  We also count the number of chunks we allocated, see
 * _findiop() for an explanation.
 * These variables are all protected by _first_link_lock.
 */
static struct _link_ *lastlink = NULL;
static int fcloses;
static int nchunks;

static rwlock_t _first_link_lock = DEFAULTRWLOCK;

static int _fflush_u_iops(void);
static FILE *getiop(FILE *, rmutex_t *, mbstate_t *);

#define	GETIOP(fp, lk, mb)	{FILE *ret; \
	if ((ret = getiop((fp), __libc_threaded? (lk): NULL, (mb))) != NULL) { \
		if (__libc_threaded) \
			(void) __rw_unlock(&_first_link_lock); \
		return (ret); \
	}; \
	}

/*
 * All functions that understand the linked list of iob's follow.
 */
#pragma weak _cleanup = __cleanup
void
__cleanup(void)		/* called at process end to flush ouput streams */
{
	(void) fflush(NULL);
}

/*
 * For fork1-safety (see libc_prepare_atfork(), etc).
 */
void
stdio_locks()
{
	(void) __rw_wrlock(&_first_link_lock);
	/*
	 * XXX: We should acquire all of the iob locks here.
	 */
}

void
stdio_unlocks()
{
	/*
	 * XXX: We should release all of the iob locks here.
	 */
	(void) __rw_unlock(&_first_link_lock);
}

void
_flushlbf(void)		/* fflush() all line-buffered streams */
{
	FPDECL(fp);
	int i;
	struct _link_ *lp;

	if (__libc_threaded)
		(void) __rw_rdlock(&_first_link_lock);

	lp = &__first_link;
	do {
		FIRSTFP(lp, fp);
		for (i = lp->niob; --i >= 0; NEXTFP(fp)) {
			if ((fp->_flag & (_IOLBF | _IOWRT)) ==
			    (_IOLBF | _IOWRT))
				(void) _fflush_u(fp);
		}
	} while ((lp = lp->next) != NULL);

	if (__libc_threaded)
		(void) __rw_unlock(&_first_link_lock);
}

/* allocate an unused stream; NULL if cannot */
FILE *
_findiop(void)
{
	struct _link_ *lp, **prev;

	/* used so there only needs to be one malloc() */
#ifdef _LP64
	typedef	struct	{
		struct _link_	hdr;
		FILE	iob[FILE_ARY_SZ];
	} Pkg;
#else
	typedef union {
		struct {				/* Normal */
			struct _link_	hdr;
			xFILE	iob[FILE_ARY_SZ];
		} Pkgn;
		struct {				/* Reversed */
			xFILE	iob[FILE_ARY_SZ];
			struct _link_	hdr;
		} Pkgr;
	} Pkg;
	uintptr_t delta;
#endif
	Pkg *pkgp;
	struct _link_ *hdr;
	FPDECL(fp);
	int i;

	if (__libc_threaded)
		(void) __rw_wrlock(&_first_link_lock);

	if (lastlink == NULL) {
rescan:
		fcloses = 0;
		lastlink = &__first_link;
	}

	lp = lastlink;

	/*
	 * lock to make testing of fp->_flag == 0 and acquiring the fp atomic
	 * and for allocation of new links
	 * low contention expected on _findiop(), hence coarse locking.
	 * for finer granularity, use fp->_lock for allocating an iop
	 * and make the testing of lp->next and allocation of new link atomic
	 * using lp->_lock
	 */

	do {
		prev = &lp->next;
		FIRSTFP(lp, fp);

		for (i = lp->niob; --i >= 0; NEXTFP(fp)) {
#ifdef	_LP64
			GETIOP(fp, &fp->_lock, &fp->_state);
#else
			GETIOP(fp,
			    xfp ? &xfp->xlock : &_xftab[IOPIND(fp)]._lock,
			    xfp ? &xfp->xstate : &_xftab[IOPIND(fp)]._state);
#endif	/*	_LP64	*/
		}
	} while ((lastlink = lp = lp->next) != NULL);

	/*
	 * If there was a sufficient number of  fcloses since we last started
	 * at __first_link, we rescan all fp's again.  We do not rescan for
	 * all fcloses; that would simplify the algorithm but would make
	 * search times near O(n) again.
	 * Worst case behaviour would still be pretty bad (open a full set,
	 * then continously opening and closing one FILE * gets you a full
	 * scan each time).  That's why we over allocate 1 FILE for each
	 * 32 chunks.  More over allocation is better; this is a nice
	 * empirical value which doesn't cost a lot of memory, doesn't
	 * overallocate until we reach 256 FILE *s and keeps the performance
	 * pretty close to the optimum.
	 */
	if (fcloses > nchunks/32)
		goto rescan;

	/*
	 * Need to allocate another and put it in the linked list.
	 */
	if ((pkgp = malloc(sizeof (Pkg))) == NULL) {
		if (__libc_threaded)
			(void) __rw_unlock(&_first_link_lock);
		return (NULL);
	}

	(void) memset(pkgp, 0, sizeof (Pkg));

#ifdef _LP64
	hdr = &pkgp->hdr;
	hdr->iobp = &pkgp->iob[0];
#else
	/*
	 * The problem with referencing a word after a FILE* is the possibility
	 * of a SIGSEGV if a non-stdio issue FILE structure ends on a page
	 * boundary.  We run this check so we never need to run an expensive
	 * check like mincore() in order to know whether it is
	 * safe to dereference ((xFILE*)fp)->xmagic.
	 * We allocate the block with two alternative layouts; if one
	 * layout is not properly aligned for our purposes, the other layout
	 * will be because the size of _link_ is small compared to
	 * sizeof (xFILE).
	 * The check performed is this:
	 *	If the distance from pkgp to the end of the page is
	 *	less than the the offset of the last xmagic field in the
	 *	xFILE structure, (the 0x1000 boundary is inside our just
	 *	allocated structure) and the distance modulo the size of xFILE
	 *	is identical to the offset of the first xmagic in the
	 *	structure (i.e., XXXXXX000 points to an xmagic field),
	 *	we need to use the reverse structure.
	 */
	if ((delta = 0x1000 - ((uintptr_t)pkgp & 0xfff)) <=
				offsetof(Pkg, Pkgn.iob[FILE_ARY_SZ-1].xmagic) &&
	    delta % sizeof (struct xFILE) ==
		    offsetof(Pkg, Pkgn.iob[0].xmagic)) {
		/* Use reversed structure */
		hdr = &pkgp->Pkgr.hdr;
		hdr->iobp = &pkgp->Pkgr.iob[0];
	} else {
		/* Use normal structure */
		hdr = &pkgp->Pkgn.hdr;
		hdr->iobp = &pkgp->Pkgn.iob[0];
	}
#endif /* _LP64 */

	hdr->niob = FILE_ARY_SZ;
	nchunks++;

#ifdef	_LP64
	fp = hdr->iobp;
	for (i = 0; i < FILE_ARY_SZ; i++)
		_private_mutex_init(&fp[i]._lock,
			USYNC_THREAD|LOCK_RECURSIVE, NULL);
#else
	xfp = hdr->iobp;
	fp = &xfp->_iob;

	for (i = 0; i < FILE_ARY_SZ; i++) {
		xfp[i].xmagic = XMAGIC(&xfp[i]);
		_private_mutex_init(&xfp[i].xlock,
			USYNC_THREAD|LOCK_RECURSIVE, NULL);
	}
#endif	/*	_LP64	*/

	lastlink = *prev = hdr;
	fp->_ptr = 0;
	fp->_base = 0;
	fp->_flag = 0377; /* claim the fp by setting low 8 bits */
	if (__libc_threaded)
		(void) __rw_unlock(&_first_link_lock);

	return (fp);
}

static void
isseekable(FILE *iop)
{
	struct stat64 fstatbuf;
	int save_errno;

	save_errno = errno;

	if (fstat64(iop->_file, &fstatbuf) != 0) {
		/*
		 * when we don't know what it is we'll
		 * do the old behaviour and flush
		 * the stream
		 */
		SET_SEEKABLE(iop);
		errno = save_errno;
		return;
	}

	/*
	 * check for what is non-SEEKABLE
	 * otherwise assume it's SEEKABLE so we get the old
	 * behaviour and flush the stream
	 */

	if (S_ISFIFO(fstatbuf.st_mode) || S_ISCHR(fstatbuf.st_mode) ||
	    S_ISSOCK(fstatbuf.st_mode) || S_ISDOOR(fstatbuf.st_mode)) {
		CLEAR_SEEKABLE(iop);
	} else {
		SET_SEEKABLE(iop);
	}

	errno = save_errno;
}

#ifdef	_LP64
void
_setbufend(FILE *iop, Uchar *end)	/* set the end pointer for this iop */
{
	iop->_end = end;

	isseekable(iop);
}

#undef _realbufend

Uchar *
_realbufend(FILE *iop)		/* get the end pointer for this iop */
{
	return (iop->_end);
}

#else /* _LP64 */

/*
 * Awkward functions not needed for the sane 64 bit environment.
 */
/*
 * xmagic must not be aligned on a 4K boundary. We guarantee this in
 * _findiop().
 */
#define	VALIDXFILE(xfp) \
	(((uintptr_t)&(xfp)->xmagic & 0xfff) && \
	    (xfp)->xmagic == XMAGIC(FILEx(xfp)))

static struct xFILEdata *
getxfdat(FILE *iop)
{
	if (STDIOP(iop))
		return (&_xftab[IOPIND(iop)]);
	else if (VALIDXFILE(FILEx(iop)))
		return (&FILEx(iop)->_xdat);
	else
		return (NULL);
}

void
_setbufend(FILE *iop, Uchar *end)	/* set the end pointer for this iop */
{
	struct xFILEdata *dat = getxfdat(iop);

	if (dat != NULL)
		dat->_end = end;

	isseekable(iop);

	/*
	 * For binary compatibility with user programs using the
	 * old _bufend macro.  This is *so* broken, fileno()
	 * is not the proper index.
	 */
	if (iop->_file < _NFILE)
		_bufendtab[iop->_file] = end;

}

Uchar *
_realbufend(FILE *iop)		/* get the end pointer for this iop */
{
	struct xFILEdata *dat = getxfdat(iop);

	if (dat != NULL)
		return (dat->_end);

	return (NULL);
}

/*
 * _reallock() is invoked in each stdio call through the IOB_LCK() macro,
 * it is therefor extremely performance sensitive.  We get better performance
 * by inlining the STDIOP check in IOB_LCK and inlining a custom version
 * of getfxdat() here.
 */
rmutex_t *
_reallock(FILE *iop)
{
	if (VALIDXFILE(FILEx(iop)))
		return (&FILEx(iop)->xlock);

	return (NULL);
}

#endif	/*	_LP64	*/

/* make sure _cnt, _ptr are correct */
void
_bufsync(FILE *iop, Uchar *bufend)
{
	ssize_t spaceleft;

	spaceleft = bufend - iop->_ptr;
	if (bufend < iop->_ptr) {
		iop->_ptr = bufend;
		iop->_cnt = 0;
	} else if (spaceleft < iop->_cnt)
		iop->_cnt = spaceleft;
}

/* really write out current buffer contents */
int
_xflsbuf(FILE *iop)
{
	ssize_t n;
	Uchar *base = iop->_base;
	Uchar *bufend;
	ssize_t num_wrote;

	/*
	 * Hopefully, be stable with respect to interrupts...
	 */
	n = iop->_ptr - base;
	iop->_ptr = base;
	bufend = _bufend(iop);
	if (iop->_flag & (_IOLBF | _IONBF))
		iop->_cnt = 0;		/* always go to a flush */
	else
		iop->_cnt = bufend - base;

	if (_needsync(iop, bufend))	/* recover from interrupts */
		_bufsync(iop, bufend);

	if (n > 0) {
		while ((num_wrote =
			write(iop->_file, base, (size_t)n)) != n) {
			if (num_wrote <= 0) {
				iop->_flag |= _IOERR;
				return (EOF);
			}
			n -= num_wrote;
			base += num_wrote;
		}
	}
	return (0);
}

/* flush (write) buffer */
int
fflush(FILE *iop)
{
	int res;
	rmutex_t *lk;

	if (iop) {
		FLOCKFILE(lk, iop);
		res = _fflush_u(iop);
		FUNLOCKFILE(lk);
	} else {
		res = _fflush_u_iops();		/* flush all iops */
	}
	return (res);
}

static int
_fflush_u_iops(void)		/* flush all buffers */
{
	FPDECL(iop);

	int i;
	struct _link_ *lp;
	int res = 0;

	if (__libc_threaded)
		(void) __rw_rdlock(&_first_link_lock);

	lp = &__first_link;

	do {
		/*
		 * Don't grab the locks for these file pointers
		 * since they are supposed to be flushed anyway
		 * It could also be the case in which the 2nd
		 * portion (base and lock) are not initialized
		 */
		FIRSTFP(lp, iop);
		for (i = lp->niob; --i >= 0; NEXTFP(iop)) {
		    if (!(iop->_flag & _IONBF)) {
			/*
			 * don't need to worry about the _IORW case
			 * since the iop will also marked with _IOREAD
			 * or _IOWRT whichever we are really doing
			 */
			if (iop->_flag & _IOWRT) {    /* flush write buffers */
			    res |= _fflush_u(iop);
			} else if (iop->_flag & _IOREAD) {
				/*
				 * flush seekable read buffers
				 * don't flush non-seekable read buffers
				 */
			    if (GET_SEEKABLE(iop)) {
				res |= _fflush_u(iop);
			    }
			}
		    }
		}
	} while ((lp = lp->next) != NULL);
	if (__libc_threaded)
		(void) __rw_unlock(&_first_link_lock);
	return (res);
}

/* flush buffer */
int
_fflush_u(FILE *iop)
{
	int res = 0;

	/* this portion is always assumed locked */
	if (!(iop->_flag & _IOWRT)) {
		(void) lseek64(iop->_file, -iop->_cnt, SEEK_CUR);
		iop->_cnt = 0;
		/* needed for ungetc & multibyte pushbacks */
		iop->_ptr = iop->_base;
		if (iop->_flag & _IORW) {
			iop->_flag &= ~_IOREAD;
		}
		return (0);
	}
	if (iop->_base != NULL && iop->_ptr > iop->_base) {
		res = _xflsbuf(iop);
	}
	if (iop->_flag & _IORW) {
		iop->_flag &= ~_IOWRT;
		iop->_cnt = 0;
	}
	return (res);
}

/* flush buffer and close stream */
int
fclose(FILE *iop)
{
	int res = 0;
	rmutex_t *lk;

	if (iop == NULL) {
		return (EOF);		/* avoid passing zero to FLOCKFILE */
	}

	FLOCKFILE(lk, iop);
	if (iop->_flag == 0) {
		FUNLOCKFILE(lk);
		return (EOF);
	}
	/* Is not unbuffered and opened for read and/or write ? */
	if (!(iop->_flag & _IONBF) && (iop->_flag & (_IOWRT | _IOREAD | _IORW)))
		res = _fflush_u(iop);
	if (close(iop->_file) < 0)
		res = EOF;
	if (iop->_flag & _IOMYBUF) {
		(void) free((char *)iop->_base - PUSHBACK);
	}
	iop->_base = NULL;
	iop->_ptr = NULL;
	iop->_cnt = 0;
	iop->_flag = 0;			/* marks it as available */
	FUNLOCKFILE(lk);

	if (__libc_threaded)
		(void) __rw_wrlock(&_first_link_lock);
	fcloses++;
	if (__libc_threaded)
		(void) __rw_unlock(&_first_link_lock);

	return (res);
}

/* flush buffer, close fd but keep the stream used by freopen() */
int
close_fd(FILE *iop)
{
	int res = 0;
	mbstate_t *mb;

	if (iop == NULL || iop->_flag == 0)
		return (EOF);
	/* Is not unbuffered and opened for read and/or write ? */
	if (!(iop->_flag & _IONBF) && (iop->_flag & (_IOWRT | _IOREAD | _IORW)))
		res = _fflush_u(iop);
	if (close(iop->_file) < 0)
		res = EOF;
	if (iop->_flag & _IOMYBUF) {
		(void) free((char *)iop->_base - PUSHBACK);
	}
	iop->_base = NULL;
	iop->_ptr = NULL;
	mb = _getmbstate(iop);
	if (mb != NULL)
		(void) memset(mb, 0, sizeof (mbstate_t));
	iop->_cnt = 0;
	_setorientation(iop, _NO_MODE);
	return (res);
}

static FILE *
getiop(FILE *fp, rmutex_t *lk, mbstate_t *mb)
{
	if (lk != NULL && rmutex_trylock(lk))
		return (NULL);	/* locked: fp in use */

	if (fp->_flag == 0) {	/* unused */
#ifndef	_LP64
		fp->__orientation = 0;
#endif /* _LP64 */
		fp->_cnt = 0;
		fp->_ptr = NULL;
		fp->_base = NULL;
		fp->_flag = 0377;	/* claim the fp by setting low 8 bits */
		(void) memset(mb, 0, sizeof (mbstate_t));
		FUNLOCKFILE(lk);
		return (fp);
	}
	FUNLOCKFILE(lk);
	return (NULL);
}

#ifndef	_LP64
/*
 * DESCRIPTION:
 * This function gets the pointer to the mbstate_t structure associated
 * with the specified iop.
 *
 * RETURNS:
 * If the associated mbstate_t found, the pointer to the mbstate_t is
 * returned.  Otherwise, NULL is returned.
 */
mbstate_t *
_getmbstate(FILE *iop)
{
	struct xFILEdata *dat = getxfdat(iop);

	if (dat != NULL)
		return (&dat->_state);

	return (NULL);
}
#endif
