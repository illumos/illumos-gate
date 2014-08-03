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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * An application should not include this header directly.  Instead it
 * should be included only through the inclusion of other Sun headers.
 *
 * The contents of this header is limited to identifiers specified in the
 * C Standard.  Any new identifiers specified in future amendments to the
 * C Standard must be placed in this header.  If these new identifiers
 * are required to also be in the C++ Standard "std" namespace, then for
 * anything other than macro definitions, corresponding "using" directives
 * must also be added to <string.h>.
 */

#ifndef _ISO_STRING_ISO_H
#define	_ISO_STRING_ISO_H

#include <sys/feature_tests.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if __cplusplus >= 199711L
namespace std {
#endif

#if !defined(_SIZE_T) || __cplusplus >= 199711L
#define	_SIZE_T
#if defined(_LP64) || defined(_I32LPx)
typedef unsigned long	size_t;		/* size of something in bytes */
#else
typedef unsigned int	size_t;		/* (historical version) */
#endif
#endif	/* !_SIZE_T */

#ifndef	NULL
#if defined(_LP64)
#define	NULL	0L
#else
#define	NULL	0
#endif
#endif

extern int memcmp(const void *, const void *, size_t);
extern void *memcpy(void *_RESTRICT_KYWD, const void *_RESTRICT_KYWD, size_t);
extern void *memmove(void *, const void *, size_t);
extern void *memset(void *, int, size_t);
extern char *strcat(char *_RESTRICT_KYWD, const char *_RESTRICT_KYWD);
extern int strcmp(const char *, const char *);
extern char *strcpy(char *_RESTRICT_KYWD, const char *_RESTRICT_KYWD);
extern int strcoll(const char *, const char *);
extern size_t strcspn(const char *, const char *);
extern char *strerror(int);
extern size_t strlen(const char *);
extern char *strncat(char *_RESTRICT_KYWD, const char *_RESTRICT_KYWD, size_t);
extern int strncmp(const char *, const char *, size_t);
extern char *strncpy(char *_RESTRICT_KYWD, const char *_RESTRICT_KYWD, size_t);
extern size_t strspn(const char *, const char *);
extern char *strtok(char *_RESTRICT_KYWD, const char *_RESTRICT_KYWD);
extern size_t strxfrm(char *_RESTRICT_KYWD, const char *_RESTRICT_KYWD, size_t);

/*
 * The C++ Standard (ISO/IEC 14882:1998) specifies that each of the
 * function signatures for the following functions be replaced by
 * two declarations, both of which have the same behavior.
 */
#if __cplusplus >= 199711L
extern const void *memchr(const void *, int, size_t);
#ifndef	_MEMCHR_INLINE
#define	_MEMCHR_INLINE
extern "C++" {
	inline void *memchr(void * __s, int __c, size_t __n) {
		return (void *)memchr((const void *)__s, __c, __n);
	}
}
#endif  /* _MEMCHR_INLINE */
extern const char *strchr(const char *, int);
#ifndef _STRCHR_INLINE
#define	_STRCHR_INLINE
extern "C++" {
	inline char *strchr(char *__s, int __c) {
		return (char *)strchr((const char *)__s, __c);
	}
}
#endif	/* _STRCHR_INLINE */
extern const char *strpbrk(const char *, const char *);
#ifndef _STRPBRK_INLINE
#define	_STRPBRK_INLINE
extern "C++" {
	inline char *strpbrk(char *__s1, const char *__s2) {
		return (char *)strpbrk((const char *)__s1, __s2);
	}
}
#endif	/* _STRPBRK_INLINE */
extern const char *strrchr(const char *, int);
#ifndef _STRRCHR_INLINE
#define	_STRRCHR_INLINE
extern "C++" {
	inline char *strrchr(char *__s, int __c) {
		return (char *)strrchr((const char *)__s, __c);
	}
}
#endif	/* _STRRCHR_INLINE */
extern const char *strstr(const char *, const char *);
#ifndef _STRSTR_INLINE
#define	_STRSTR_INLINE
extern "C++" {
	inline char *strstr(char *__s1, const char *__s2) {
		return (char *)strstr((const char *)__s1, __s2);
	}
}
#endif	/* _STRSTR_INLINE */
#else /* __cplusplus >= 199711L */
extern void *memchr(const void *, int, size_t);
extern char *strchr(const char *, int);
extern char *strpbrk(const char *, const char *);
extern char *strrchr(const char *, int);
extern char *strstr(const char *, const char *);
#endif /* __cplusplus >= 199711L */

#if __cplusplus >= 199711L
}
#endif /* end of namespace std */

#ifdef	__cplusplus
}
#endif

#endif	/* _ISO_STRING_ISO_H */
