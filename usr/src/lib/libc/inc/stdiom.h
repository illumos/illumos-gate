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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * stdiom.h - shared guts of stdio
 */

#ifndef	_STDIOM_H
#define	_STDIOM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.9 */

#include <thread.h>
#include <synch.h>
#include <mtlib.h>
#include <stdarg.h>
#include "file64.h"
#include <wchar.h>
#include "mse.h"


/*
 * The following flags, and the macros that manipulate them, operate upon
 * the FILE structure used by stdio. If new flags are required, they should
 * be created in this file. The values of the flags must be differnt from
 * the currently used values. New macros should be created to use the flags
 * so that the compilation mode dependencies can be isolated here.
 */

#ifdef _LP64
#define	_BYTE_MODE_FLAG	0400
#define	_WC_MODE_FLAG	01000
#define	_IONOLOCK	02000
#define	_SEEKABLE	04000	/* is it seekable? */
#define	SET_IONOLOCK(iop)	((iop)->_flag |= _IONOLOCK)
#define	CLEAR_IONOLOCK(iop)	((iop)->_flag &= ~_IONOLOCK)
#define	GET_IONOLOCK(iop)	((iop)->_flag & _IONOLOCK)
#define	SET_BYTE_MODE(iop)	((iop)->_flag |= _BYTE_MODE_FLAG)
#define	CLEAR_BYTE_MODE(iop)	((iop)->_flag &= ~_BYTE_MODE_FLAG)
#define	GET_BYTE_MODE(iop)	((iop)->_flag & _BYTE_MODE_FLAG)
#define	SET_WC_MODE(iop)	((iop)->_flag |= _WC_MODE_FLAG)
#define	CLEAR_WC_MODE(iop)	((iop)->_flag &= ~_WC_MODE_FLAG)
#define	GET_WC_MODE(iop)	((iop)->_flag & _WC_MODE_FLAG)
#define	GET_NO_MODE(iop)	(!((iop)->_flag & \
					(_BYTE_MODE_FLAG | _WC_MODE_FLAG)))
#define	SET_SEEKABLE(iop)	((iop)->_flag |=  _SEEKABLE)
#define	CLEAR_SEEKABLE(iop)	((iop)->_flag &= ~_SEEKABLE)
#define	GET_SEEKABLE(iop)	((iop)->_flag &   _SEEKABLE)
#else
#define	_BYTE_MODE_FLAG	0001
#define	_WC_MODE_FLAG	0002
#define	SET_IONOLOCK(iop)	((iop)->__ionolock = 1)
#define	CLEAR_IONOLOCK(iop)	((iop)->__ionolock = 0)
#define	GET_IONOLOCK(iop)	((iop)->__ionolock)
#define	SET_BYTE_MODE(iop)	((iop)->__orientation |= _BYTE_MODE_FLAG)
#define	CLEAR_BYTE_MODE(iop)	((iop)->__orientation &= ~_BYTE_MODE_FLAG)
#define	GET_BYTE_MODE(iop)	((iop)->__orientation & _BYTE_MODE_FLAG)
#define	SET_WC_MODE(iop)	((iop)->__orientation |= _WC_MODE_FLAG)
#define	CLEAR_WC_MODE(iop)	((iop)->__orientation &= ~_WC_MODE_FLAG)
#define	GET_WC_MODE(iop)	((iop)->__orientation & _WC_MODE_FLAG)
#define	GET_NO_MODE(iop)	(!((iop)->__orientation & \
					(_BYTE_MODE_FLAG | _WC_MODE_FLAG)))
#define	SET_SEEKABLE(iop)	((iop)->__seekable = 1)
#define	CLEAR_SEEKABLE(iop)	((iop)->__seekable = 0)
#define	GET_SEEKABLE(iop)	((iop)->__seekable)

/* Is iop a member of the _iob array? */
#define	STDIOP(iop)		((iop) >= &_iob[0] && (iop) < &_iob[_NFILE])

/* Compute the index of an _iob array member */
#define	IOPIND(iop)		((iop) - &_iob[0])

#endif

typedef unsigned char	Uchar;

#define	_flockrel(rl)		cancel_safe_mutex_unlock(rl)

#define	MAXVAL	(MAXINT - (MAXINT % BUFSIZ))

/*
 * The number of actual pushback characters is the value
 * of PUSHBACK plus the first byte of the buffer. The FILE buffer must,
 * for performance reasons, start on a word aligned boundry so the value
 * of PUSHBACK should be a multiple of word.
 * At least 4 bytes of PUSHBACK are needed. If sizeof (int) = 1 this breaks.
 */
#define	PUSHBACK	(((3 + sizeof (int) - 1) / sizeof (int)) * sizeof (int))

/* minimum buffer size must be at least 8 or shared library will break */
#define	_SMBFSZ	(((PUSHBACK + 4) < 8) ? 8 : (PUSHBACK + 4))

#if BUFSIZ == 1024
#define	MULTIBFSZ(SZ)	((SZ) & ~0x3ff)
#elif BUFSIZ == 512
#define	MULTIBFSZ(SZ)    ((SZ) & ~0x1ff)
#else
#define	MULTIBFSZ(SZ)    ((SZ) - (SZ % BUFSIZ))
#endif

#undef _bufend
#define	_bufend(iop)	_realbufend(iop)

/*
 * Internal data
 */
extern Uchar _smbuf[][_SMBFSZ];


/*
 * Internal routines from flush.c
 */
extern void	__cleanup(void);
extern void	_flushlbf(void);
extern FILE	*_findiop(void);

/*
 * this is to be found in <stdio.h> for 32bit mode
 */
#ifdef	_LP64
extern int	__filbuf(FILE *);
extern int	__flsbuf(int, FILE *);

/*
 * Not needed as a function in 64 bit mode.
 */
#define	_realbufend(iop)	((iop)->_end)
#else
extern Uchar 	*_realbufend(FILE *iop);
extern rmutex_t	*_reallock(FILE *iop);
#endif	/*	_LP64	*/

extern void	_setbufend(FILE *iop, Uchar *end);
extern rmutex_t *_flockget(FILE *iop);
extern int	_xflsbuf(FILE *iop);
extern int	_wrtchk(FILE *iop);
extern void	_bufsync(FILE *iop, Uchar *bufend);
extern int	_fflush_u(FILE *iop);
extern int	close_fd(FILE *iop);
extern int	_doscan(FILE *, const char *, va_list);
#ifdef	_LP64
extern void	close_pid(void);
#endif	/*	_LP64	*/

/*
 * Internal routines from flush.c
 */
extern int _file_get(FILE *);
extern int _file_set(FILE *, int, const char *);

/*
 * Macros to aid the extended fd FILE work.
 * This helps isolate the changes to only the 32-bit code
 * since 64-bit Solaris is not affected by this.
 */
#ifdef  _LP64
#define	GET_FD(iop)		((iop)->_file)
#define	SET_FILE(iop, fd)	((iop)->_file = (fd))
#else
#define	GET_FD(iop)		\
		(((iop)->__extendedfd) ? _file_get(iop) : (iop)->_magic)
#define	SET_FILE(iop, fd)	(iop)->_magic = (fd); (iop)->__extendedfd = 0
#endif

/*
 * Maximum size of the file descriptor stored in the FILE structure.
 */

#ifdef _LP64
#define	_FILE_FD_MAX	INT_MAX
#else
#define	_FILE_FD_MAX	255
#endif

/*
 * Internal routines from fileno.c
 */
extern int _fileno(FILE *iop);

/*
 * Internal routines from _findbuf.c
 */
extern Uchar 	*_findbuf(FILE *iop);

/*
 * Internal routine used by fopen.c
 */
extern	FILE	*_endopen(const char *, const char *, FILE *, int);

/*
 * Internal routine from fwrite.c
 */
extern size_t _fwrite_unlocked(const void *, size_t, size_t, FILE *);

/*
 * Internal routine from getc.c
 */
int _getc_unlocked(FILE *);

/*
 * Internal routine from put.c
 */
int _putc_unlocked(int, FILE *);

/*
 * Internal routine from ungetc.c
 */
int _ungetc_unlocked(int, FILE *);

/*
 * The following macros improve performance of the stdio by reducing the
 * number of calls to _bufsync and _wrtchk.  _needsync checks whether
 * or not _bufsync needs to be called.  _WRTCHK has the same effect as
 * _wrtchk, but often these functions have no effect, and in those cases
 * the macros avoid the expense of calling the functions.
 */

#define	_needsync(p, bufend)	((bufend - (p)->_ptr) < \
				    ((p)->_cnt < 0 ? 0 : (p)->_cnt))

#define	_WRTCHK(iop)	((((iop->_flag & (_IOWRT | _IOEOF)) != _IOWRT) || \
			    (iop->_base == 0) ||  \
			    (iop->_ptr == iop->_base && iop->_cnt == 0 && \
			    !(iop->_flag & (_IONBF | _IOLBF)))) \
			? _wrtchk(iop) : 0)

#ifdef	_LP64
#define	IOB_LCK(iop)	(&((iop)->_lock))
#else
#define	IOB_LCK(iop)	(STDIOP(iop) ? &_xftab[IOPIND(iop)]._lock \
					: _reallock(iop))

extern struct xFILEdata	_xftab[];

#endif	/*	_LP64	*/

#endif	/* _STDIOM_H */
