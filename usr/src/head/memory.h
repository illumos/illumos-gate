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
extern const void *memchr(const void *, int, size_t);
#ifndef _MEMCHR_INLINE
#define	_MEMCHR_INLINE
extern "C++" {
	inline void *memchr(void * __s, int __c, size_t __n) {
		return (void*)memchr((const void *) __s, __c, __n);
	}
}
#endif /* _MEMCHR_INLINE */
} /* end of namespace std */
using std::memchr;
#else
extern void *memchr(const void *, int, size_t);
#endif
extern void *memcpy(void *, const void *, size_t);
extern void *memset(void *, int, size_t);
extern int memcmp(const void *, const void *, size_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _MEMORY_H */
