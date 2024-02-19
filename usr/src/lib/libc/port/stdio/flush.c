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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2020 Robert Mustacchi
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#include "lint.h"
#include "mtlib.h"
#include "file64.h"
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
#include <fcntl.h>
#include <sys/debug.h>
#include <limits.h>

#define	_iob	__iob

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
#define	FPLOCK(fp)		&fp->_lock
#define	FPSTATE(fp)		&fp->_state

#define	xFILE			FILE

#else

#define	FPDECL(fp)		FILE *fp; xFILE *x##fp
#define	FIRSTFP(lp, fp)		x##fp = lp->iobp; \
				fp = x##fp ? &x##fp->_iob : &_iob[0]
#define	NEXTFP(fp)		(x##fp ? fp = &(++x##fp)->_iob : ++fp)
#define	FPLOCK(fp)		x##fp ? \
				    &x##fp->xlock : &_xftab[IOPIND(fp)]._lock
#define	FPSTATE(fp)		x##fp ? \
				    &x##fp->xstate : &_xftab[IOPIND(fp)]._state

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

static mutex_t _first_link_lock = DEFAULTMUTEX;

static int _fflush_l_iops(void);
static FILE *getiop(FILE *, rmutex_t *, mbstate_t *);

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
	(void) mutex_lock(&_first_link_lock);
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
	(void) mutex_unlock(&_first_link_lock);
}

void
_flushlbf(void)		/* fflush() all line-buffered streams */
{
	FPDECL(fp);
	int i;
	struct _link_ *lp;
	/* Allow compiler to optimize the loop */
	int threaded = __libc_threaded;

	if (threaded)
		cancel_safe_mutex_lock(&_first_link_lock);

	lp = &__first_link;
	do {
		FIRSTFP(lp, fp);
		for (i = lp->niob; --i >= 0; NEXTFP(fp)) {
			/*
			 * The additional _IONBF check guards againsts
			 * allocated but uninitialized iops (see _findiop).
			 * We also automatically skip non allocated iop's.
			 * Don't block on locks.
			 */
			if ((fp->_flag & (_IOLBF | _IOWRT | _IONBF)) ==
			    (_IOLBF | _IOWRT)) {
				if (threaded) {
					rmutex_t *lk = FPLOCK(fp);
					if (cancel_safe_mutex_trylock(lk) != 0)
						continue;
					/* Recheck after locking */
					if ((fp->_flag & (_IOLBF | _IOWRT)) ==
					    (_IOLBF | _IOWRT)) {
						(void) _fflush_u(fp);
					}
					cancel_safe_mutex_unlock(lk);
				} else {
					(void) _fflush_u(fp);
				}
			}
		}
	} while ((lp = lp->next) != NULL);

	if (threaded)
		cancel_safe_mutex_unlock(&_first_link_lock);
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
	int threaded = __libc_threaded;

	if (threaded)
		cancel_safe_mutex_lock(&_first_link_lock);

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
			FILE *ret;
			if (threaded) {
				ret = getiop(fp, FPLOCK(fp), FPSTATE(fp));
				if (ret != NULL) {
					cancel_safe_mutex_unlock(
					    &_first_link_lock);
					return (ret);
				}
			} else {
				ret = getiop(fp, NULL, FPSTATE(fp));
				if (ret != NULL)
					return (ret);
			}
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
		if (threaded)
			cancel_safe_mutex_unlock(&_first_link_lock);
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
		(void) mutex_init(&fp[i]._lock,
		    USYNC_THREAD | LOCK_RECURSIVE, NULL);
#else
	xfp = hdr->iobp;
	fp = &xfp->_iob;

	for (i = 0; i < FILE_ARY_SZ; i++) {
		xfp[i].xmagic = XMAGIC(&xfp[i]);
		(void) mutex_init(&xfp[i].xlock,
		    USYNC_THREAD | LOCK_RECURSIVE, NULL);
	}
#endif	/*	_LP64	*/

	lastlink = *prev = hdr;
	fp->_ptr = 0;
	fp->_base = 0;
	/* claim the fp by setting low 8 bits */
	fp->_flag = _DEF_FLAG_MASK;
	if (threaded)
		cancel_safe_mutex_unlock(&_first_link_lock);

	return (fp);
}

static void
isseekable(FILE *iop)
{
	struct stat64 fstatbuf;
	int fd, save_errno;

	save_errno = errno;

	/*
	 * non-FILE based STREAMS are required to declare their own seekability
	 * and therefore we should not try and test them below.
	 */
	fd = _get_fd(iop);
	if (fd == -1) {
		return;
	}
	if (fstat64(fd, &fstatbuf) != 0) {
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
	if (iop->_magic < _NFILE)
		_bufendtab[iop->_magic] = end;

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
		while ((num_wrote = _xwrite(iop, base, (size_t)n)) != n) {
			if (num_wrote <= 0) {
				if (!cancel_active())
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
		res = _fflush_l_iops();		/* flush all iops */
	}
	return (res);
}

static int
_fflush_l_iops(void)		/* flush all buffers */
{
	FPDECL(iop);

	int i;
	struct _link_ *lp;
	int res = 0;
	rmutex_t *lk;
	/* Allow the compiler to optimize the load out of the loop */
	int threaded = __libc_threaded;

	if (threaded)
		cancel_safe_mutex_lock(&_first_link_lock);

	lp = &__first_link;

	do {
		/*
		 * We need to grab the file locks or file corruption
		 * will happen.  But we first check the flags field
		 * knowing that when it is 0, it isn't allocated and
		 * cannot be allocated while we're holding the
		 * _first_link_lock.  And when _IONBF is set (also the
		 * case when _flag is 0377 -- _DEF_FLAG_MASK, or alloc in
		 * progress), we also ignore it.
		 *
		 * Ignore locked streams; it will appear as if
		 * concurrent updates happened after fflush(NULL).  Note
		 * that we even attempt to lock if the locking is set to
		 * "by caller".  We don't want to penalize callers of
		 * __fsetlocking() by not flushing their files.  Note: if
		 * __fsetlocking() callers don't employ any locking, they
		 * may still face corruption in fflush(NULL); but that's
		 * no change from earlier releases.
		 */
		FIRSTFP(lp, iop);
		for (i = lp->niob; --i >= 0; NEXTFP(iop)) {
			unsigned int flag = iop->_flag;

			/* flag 0, flag 0377, or _IONBF set */
			if (flag == 0 || (flag & _IONBF) != 0)
				continue;

			if (threaded) {
				lk = FPLOCK(iop);
				if (cancel_safe_mutex_trylock(lk) != 0)
					continue;
			}

			if (!(iop->_flag & _IONBF)) {
				/*
				 * don't need to worry about the _IORW case
				 * since the iop will also marked with _IOREAD
				 * or _IOWRT whichever we are really doing
				 */
				if (iop->_flag & _IOWRT) {
					/* Flush write buffers */
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
			if (threaded)
				cancel_safe_mutex_unlock(lk);
		}
	} while ((lp = lp->next) != NULL);
	if (threaded)
		cancel_safe_mutex_unlock(&_first_link_lock);
	return (res);
}

/* flush buffer */
int
_fflush_u(FILE *iop)
{
	int res = 0;

	/* this portion is always assumed locked */
	if (!(iop->_flag & _IOWRT)) {
		(void) _xseek64(iop, -iop->_cnt, SEEK_CUR);
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
	if (_xclose(iop) < 0)
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
		cancel_safe_mutex_lock(&_first_link_lock);
	fcloses++;
	if (__libc_threaded)
		cancel_safe_mutex_unlock(&_first_link_lock);

	return (res);
}

/* close all open streams */
int
fcloseall(void)
{
	FPDECL(iop);

	struct _link_ *lp;
	rmutex_t *lk;

	if (__libc_threaded)
		cancel_safe_mutex_lock(&_first_link_lock);

	lp = &__first_link;

	do {
		int i;

		FIRSTFP(lp, iop);
		for (i = lp->niob; --i >= 0; NEXTFP(iop)) {
			/* code stolen from fclose(), above */

			FLOCKFILE(lk, iop);
			if (iop->_flag == 0) {
				FUNLOCKFILE(lk);
				continue;
			}

			/* Not unbuffered and opened for read and/or write? */
			if (!(iop->_flag & _IONBF) &&
			    (iop->_flag & (_IOWRT | _IOREAD | _IORW)))
				(void) _fflush_u(iop);
			(void) _xclose(iop);
			if (iop->_flag & _IOMYBUF)
				free((char *)iop->_base - PUSHBACK);
			iop->_base = NULL;
			iop->_ptr = NULL;
			iop->_cnt = 0;
			iop->_flag = 0;		/* marks it as available */
			FUNLOCKFILE(lk);
			fcloses++;
		}
	} while ((lp = lp->next) != NULL);

	if (__libc_threaded)
		cancel_safe_mutex_unlock(&_first_link_lock);

	return (0);
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
	if (_xclose(iop) < 0)
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
	if (lk != NULL && cancel_safe_mutex_trylock(lk) != 0)
		return (NULL);	/* locked: fp in use */

	if (fp->_flag == 0) {	/* unused */
#ifndef	_LP64
		fp->__orientation = 0;
#endif /* _LP64 */
		fp->_cnt = 0;
		fp->_ptr = NULL;
		fp->_base = NULL;
		/* claim the fp by setting low 8 bits */
		fp->_flag = _DEF_FLAG_MASK;
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

/*
 * More 32-bit only functions.
 * They lookup/set large fd's for extended FILE support.
 */

/*
 * The negative value indicates that Extended fd FILE's has not
 * been enabled by the user.
 */
static int bad_fd = -1;

int
_file_get(FILE *iop)
{
	int altfd;

	/*
	 * Failure indicates a FILE * not allocated through stdio;
	 * it means the flag values are probably bogus and that if
	 * a file descriptor is set, it's in _magic.
	 * Inline getxfdat() for performance reasons.
	 */
	if (STDIOP(iop))
		altfd = _xftab[IOPIND(iop)]._altfd;
	else if (VALIDXFILE(FILEx(iop)))
		altfd = FILEx(iop)->_xdat._altfd;
	else
		return (iop->_magic);
	/*
	 * if this is not an internal extended FILE then check
	 * if _file is being changed from underneath us.
	 * It should not be because if
	 * it is then then we lose our ability to guard against
	 * silent data corruption.
	 */
	if (!iop->__xf_nocheck && bad_fd > -1 && iop->_magic != bad_fd) {
		(void) fprintf(stderr,
		    "Application violated extended FILE safety mechanism.\n"
		    "Please read the man page for extendedFILE.\nAborting\n");
		abort();
	}
	return (altfd);
}

int
_file_set(FILE *iop, int fd, const char *type)
{
	struct xFILEdata *dat;
	int Fflag;

	/* Already known to contain at least one byte */
	while (*++type != '\0')
		;

	Fflag = type[-1] == 'F';
	if (!Fflag && bad_fd < 0) {
		errno = EMFILE;
		return (-1);
	}

	dat = getxfdat(iop);
	iop->__extendedfd = 1;
	iop->__xf_nocheck = Fflag;
	dat->_altfd = fd;
	iop->_magic = (unsigned char)bad_fd;
	return (0);
}

/*
 * Activates extended fd's in FILE's
 */

static const int tries[] = {196, 120, 60, 3};
#define	NTRIES	(sizeof (tries)/sizeof (int))

int
enable_extended_FILE_stdio(int fd, int action)
{
	int i;

	if (action < 0)
		action = SIGABRT;	/* default signal */

	if (fd < 0) {
		/*
		 * search for an available fd and make it the badfd
		 */
		for (i = 0; i < NTRIES; i++) {
			fd = fcntl(tries[i], F_BADFD, action);
			if (fd >= 0)
				break;
		}
		if (fd < 0)	/* failed to find an available fd */
			return (-1);
	} else {
		/* caller requests that fd be the chosen badfd */
		int nfd = fcntl(fd, F_BADFD, action);
		if (nfd < 0 || nfd != fd)
			return (-1);
	}
	bad_fd = fd;
	return (0);
}
#endif

/*
 * Wrappers around the various system calls that stdio needs to make on a file
 * descriptor.
 */
static stdio_ops_t *
get_stdops(FILE *iop)
{
#ifdef	_LP64
	return (iop->_ops);
#else
	struct xFILEdata *dat = getxfdat(iop);
	return (dat->_ops);
#endif
}

static void
set_stdops(FILE *iop, stdio_ops_t *ops)
{
#ifdef	_LP64
	ASSERT3P(iop->_ops, ==, NULL);
	iop->_ops = ops;
#else
	struct xFILEdata *dat = getxfdat(iop);
	ASSERT3P(dat->_ops, ==, NULL);
	dat->_ops = ops;
#endif

}

static void
clr_stdops(FILE *iop)
{
#ifdef	_LP64
	iop->_ops = NULL;
#else
	struct xFILEdata *dat = getxfdat(iop);
	dat->_ops = NULL;
#endif

}

ssize_t
_xread(FILE *iop, void *buf, size_t nbytes)
{
	stdio_ops_t *ops = get_stdops(iop);
	if (ops != NULL) {
		return (ops->std_read(iop, buf, nbytes));
	}

	return (read(_get_fd(iop), buf, nbytes));
}

ssize_t
_xwrite(FILE *iop, const void *buf, size_t nbytes)
{
	stdio_ops_t *ops = get_stdops(iop);
	if (ops != NULL) {
		return (ops->std_write(iop, buf, nbytes));
	}
	return (write(_get_fd(iop), buf, nbytes));
}

off_t
_xseek(FILE *iop, off_t off, int whence)
{
	stdio_ops_t *ops = get_stdops(iop);
	if (ops != NULL) {
		return (ops->std_seek(iop, off, whence));
	}

	return (lseek(_get_fd(iop), off, whence));
}

off64_t
_xseek64(FILE *iop, off64_t off, int whence)
{
	stdio_ops_t *ops = get_stdops(iop);
	if (ops != NULL) {
		/*
		 * The internal APIs only operate with an off_t. An off64_t in
		 * an ILP32 environment may represent a value larger than they
		 * can accept. As such, we try and catch such cases and error
		 * about it before we get there.
		 */
		if (off > LONG_MAX || off < LONG_MIN) {
			errno = EOVERFLOW;
			return (-1);
		}
		return (ops->std_seek(iop, off, whence));
	}

	return (lseek64(_get_fd(iop), off, whence));
}

int
_xclose(FILE *iop)
{
	stdio_ops_t *ops = get_stdops(iop);
	if (ops != NULL) {
		return (ops->std_close(iop));
	}

	return (close(_get_fd(iop)));
}

void *
_xdata(FILE *iop)
{
	stdio_ops_t *ops = get_stdops(iop);
	if (ops != NULL) {
		return (ops->std_data);
	}

	return (NULL);
}

int
_xassoc(FILE *iop, fread_t readf, fwrite_t writef, fseek_t seekf,
    fclose_t closef, void *data)
{
	stdio_ops_t *ops = get_stdops(iop);

	if (ops == NULL) {
		ops = malloc(sizeof (*ops));
		if (ops == NULL) {
			return (-1);
		}
		set_stdops(iop, ops);
	}

	ops->std_read = readf;
	ops->std_write = writef;
	ops->std_seek = seekf;
	ops->std_close = closef;
	ops->std_data = data;

	return (0);
}

void
_xunassoc(FILE *iop)
{
	stdio_ops_t *ops = get_stdops(iop);
	if (ops == NULL) {
		return;
	}
	clr_stdops(iop);
	free(ops);
}

int
_get_fd(FILE *iop)
{
	/*
	 * Streams with an ops vector (currently the memory stream family) do
	 * not have an underlying file descriptor that we can give back to the
	 * user. In such cases, return -1 to explicitly make sure that they'll
	 * get an ebadf from things.
	 */
	if (get_stdops(iop) != NULL) {
		return (-1);
	}
#ifdef  _LP64
	return (iop->_file);
#else
	if (iop->__extendedfd) {
		return (_file_get(iop));
	} else {
		return (iop->_magic);
	}
#endif
}
