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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SENDFILE_H
#define	_SYS_SENDFILE_H

#include <sys/feature_tests.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/uio.h>

/*
 * Structure used by sendfilev()
 */
typedef struct sendfilevec {
	int		sfv_fd;
	uint_t		sfv_flag;
	off_t		sfv_off;
	size_t		sfv_len;
} sendfilevec_t;

#define	SFV_NOWAIT	1

#if	defined(_LARGEFILE64_SOURCE)
/*
 * For 32-bit apps accessing largefile offsets
 * using sendfilev64.
 */
typedef struct sendfilevec64 {
	int		sfv_fd;
	uint_t		sfv_flag;
	off64_t		sfv_off;
	size_t		sfv_len;
} sendfilevec64_t;
#endif /* _LARGEFILE64_SOURCE */

#if	defined(_SYSCALL32)
/*
 * For 32-bit app on a 64-bit kernel to copyin the data.
 */
typedef struct ksendfilevec32 {
	int		sfv_fd;
	uint_t		sfv_flag;
	off32_t		sfv_off;
	size32_t	sfv_len;
} ksendfilevec32_t;

/*
 * For 32-bit app on a 64-bit kernel in largefile environment
 * (sendfilev64) to copyin data. Use pack(4) on amd64 kernel
 * to make sizeof(ksendfilevec64_t) == sizeof(sendfilevec64_t).
 */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

typedef struct ksendfilevec64 {
	int		sfv_fd;
	uint_t		sfv_flag;
	off64_t		sfv_off;
	size32_t	sfv_len;
} ksendfilevec64_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#endif /* _SYSCALL32 */


/* The sfv_fd can be a file descriptor or self proc */
#define	SFV_FD_SELF	(-2)

/* System call subcodes */
#define	SENDFILEV	0
#define	SENDFILEV64	1

#ifndef	_KERNEL
/* large file compilation environment setup */
#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname	sendfilev	sendfilev64
#pragma	redefine_extname	sendfile	sendfile64
#else	/* __PRAGMA_REDEFINE_EXTNAME */
#define	sendfilev			sendfilev64
#define	sendfile			sendfile64
#endif	/* __PRAGMA_REDEFINE_EXTNAME */
#endif	/* !_LP64 && _FILE_OFFSET_BITS == 64 */

/* In the LP64 compilation environment, the APIs are already large file */
#if defined(_LP64) && defined(_LARGEFILE64_SOURCE)
#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname	sendfilev64	sendfilev
#pragma redefine_extname	sendfile64	sendfile
#else	/* __PRAGMA_REDEFINE_EXTNAME */
#define	sendfilev64			sendfilev
#define	sendfile64			sendfile
#endif	/* __PRAGMA_REDEFINE_EXTNAME */
#endif	/* _LP64 && _LARGEFILE64_SOURCE */

extern ssize_t sendfilev(int, const struct sendfilevec *, int, size_t *);
extern ssize_t sendfile(int, int, off_t *, size_t);
/* Transitional largefile interface */
#if	defined(_LARGEFILE64_SOURCE) && !((_FILE_OFFSET_BITS == 64) && \
	    !defined(__PRAGMA_REDEFINE_EXTNAME))
extern ssize_t sendfilev64(int, const struct sendfilevec64 *, int, size_t *);
extern ssize_t sendfile64(int, int, off64_t *, size_t);
#endif
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SENDFILE_H */
