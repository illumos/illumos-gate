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
 * Copyright 2026 Gordon Ross <gordon.w.ross@gmail.com>
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef	_MEMORY_H
#define	_MEMORY_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern void *memccpy(void *, const void *, int, size_t);

#if __cplusplus >= 199711L
namespace std {
#endif

extern int memcmp(const void *, const void *, size_t);
extern void *memcpy(void *_RESTRICT_KYWD, const void *_RESTRICT_KYWD, size_t);
extern void *memset(void *, int, size_t);

/* See similar in string_iso.h */
#if __cplusplus >= 199711L
extern const void *memchr(const void *, int, size_t);
#ifndef	_MEMCHR_INLINE
#define	_MEMCHR_INLINE
extern "C++" {
	inline void *memchr(void * __s, int __c, size_t __n) {
		return (void *)memchr((const void *)__s, __c, __n);
	}
}
#endif	/* _MEMCHR_INLINE */

#else	/* __cplusplus >= 199711L */

extern void *memchr(const void *, int, size_t);

#endif	/* __cplusplus >= 199711L */

#if __cplusplus >= 199711L
}	/* end of namespace std */
#endif	/* __cplusplus >= 199711L */

#ifdef	__cplusplus
}
#endif

#if __cplusplus >= 199711L
using std::memcmp;
using std::memcpy;
using std::memset;
using std::memchr;
#endif	/* __cplusplus >= 199711L */

#endif	/* _MEMORY_H */
