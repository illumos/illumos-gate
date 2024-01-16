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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MTLIB_H
#define	_MTLIB_H

#include <thread.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* these are private to the library */
extern	int	primary_link_map;
extern	void	lmutex_lock(mutex_t *);
extern	void	lmutex_unlock(mutex_t *);
extern	void	lrw_rdlock(rwlock_t *);
extern	void	lrw_wrlock(rwlock_t *);
extern	void	lrw_unlock(rwlock_t *);
extern	void	sig_mutex_lock(mutex_t *);
extern	void	sig_mutex_unlock(mutex_t *);
extern	int	sig_mutex_trylock(mutex_t *);
extern	int	sig_cond_wait(cond_t *, mutex_t *);
extern	int	sig_cond_reltimedwait(cond_t *, mutex_t *, const timespec_t *);
extern	void	cancel_safe_mutex_lock(mutex_t *);
extern	void	cancel_safe_mutex_unlock(mutex_t *);
extern	int	cancel_safe_mutex_trylock(mutex_t *);
extern	int	cancel_active(void);
extern	int	_thrp_cancelled(void);

/* the private libc thread-safe allocator */
extern	void	*lmalloc(size_t);
extern	void	lfree(void *, size_t);

#if defined(DEBUG)
extern	void	assert_no_libc_locks_held(void);
#else
#define	assert_no_libc_locks_held()
#endif

#define	_FWRITE _fwrite_unlocked
#define	FILENO(s) _fileno(s)
#define	FERROR(s) ferror(s)
#define	GETC(s) _getc_internal(s)
#define	UNGETC(c, s) _ungetc_unlocked(c, s)
#define	PUTC(c, s) _putc_internal(c, s)
#define	GETWC(s) getwc(s)
#define	PUTWC(c, s) putwc(c, s)

/*
 * Cheap check to tell if stdio needs to lock for MT progs.
 * Referenced directly in port/stdio/flush.c and FLOCKFILE and
 * FUNLOCKFILE macros.  __libc_threaded gets set to 1 when the first
 * thread (beyond the main thread) is created in _thrp_create().
 */
extern	int	__libc_threaded;

#define	FILELOCKING(iop)	(GET_IONOLOCK(iop) == 0)

#define	FLOCKFILE(lk, iop) \
	{ \
		if (__libc_threaded && FILELOCKING(iop)) \
			lk = _flockget((iop)); \
		else \
			lk = NULL; \
	}

#define	FUNLOCKFILE(lk) \
	{ \
		if (lk != NULL) \
			_flockrel(lk); \
	}

#define	FLOCKRETURN(iop, ret) \
	{	int r; \
		rmutex_t *lk; \
		FLOCKFILE(lk, iop); \
		r = (ret); \
		FUNLOCKFILE(lk); \
		return (r); \
	}

#ifdef	__cplusplus
}
#endif

#endif	/* _MTLIB_H */
