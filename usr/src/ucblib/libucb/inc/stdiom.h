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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * stdiom.h - shared guts of stdio therefore it doesn't need
 * a surrounding #ifndef
 */

#ifndef _STDIOM_H
#define	_STDIOM_H

typedef unsigned char	Uchar;

#define	MAXVAL (MAXINT - (MAXINT % BUFSIZ))

/*
 * The number of actual pushback characters is the value
 * of PUSHBACK plus the first byte of the buffer. The FILE buffer must,
 * for performance reasons, start on a word aligned boundry so the value
 * of PUSHBACK should be a multiple of word.
 * At least 4 bytes of PUSHBACK are needed. If sizeof(int) = 1 this breaks.
 */

#define	PUSHBACK ((int)(((3 + sizeof (int) - 1) / sizeof (int)) * sizeof (int)))

/* minimum buffer size must be at least 8 or shared library will break */
#define	_SMBFSZ (((PUSHBACK + 4) < 8) ? 8 : (PUSHBACK + 4))

extern Uchar *_bufendtab[];

#if BUFSIZ == 1024
#define	MULTIBFSZ(SZ)	((SZ) & ~0x3ff)
#elif BUFSIZ == 512
#define	MULTIBFSZ(SZ)    ((SZ) & ~0x1ff)
#else
#define	MULTIBFSZ(SZ)    ((SZ) - (SZ % BUFSIZ))
#endif

#define	_bufend(iop)	_realbufend(iop)
#define	setbufend(iop, end)	_setbufend(iop, end)

	/*
	 * Internal routines from _iob.c
	 */
extern void	_cleanup(void);
extern void	_flushlbf(void);
extern FILE	*_findiop(void);
extern Uchar 	*_realbufend(FILE *iop);
extern void	_setbufend(FILE *iop, Uchar *end);
extern int	_wrtchk(FILE *iop);

	/*
	 * Internal routines from flush.c
	 */
extern void	_bufsync(FILE *iop, Uchar *bufend);
extern int	_xflsbuf(FILE *iop);

	/*
	 * Internal routines from _findbuf.c
	 */
extern Uchar 	*_findbuf(FILE *iop);

#ifndef _LP64
extern int _file_set(FILE *, int, const char *);
#define	SET_FILE(iop, fd)	(iop)->_magic = (fd); (iop)->__extendedfd = 0
#define	_FILE_FD_MAX		255
#endif

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
				(iop->_base == 0) || \
				(iop->_ptr == iop->_base && iop->_cnt == 0 && \
				!(iop->_flag & (_IONBF | _IOLBF)))) \
			? _wrtchk(iop) : 0)
#endif /* _STDIOM_H */
