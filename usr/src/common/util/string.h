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

/*
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#ifndef	_COMMON_UTIL_STRING_H
#define	_COMMON_UTIL_STRING_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_KMDB) && (!defined(_BOOT) || defined(__sparc))

extern size_t vsnprintf(char *, size_t, const char *, va_list);
/*PRINTFLIKE3*/
extern size_t snprintf(char *, size_t, const char *, ...);

#if defined(_BOOT) && defined(__sparc)

/*PRINTFLIKE2*/
extern int sprintf(char *, const char *, ...);
extern int vsprintf(char *, const char *, va_list);

#endif /* _BOOT && __sparc */
#endif /* !_KMDB && (!_BOOT || __sparc) */

extern char *strcat(char *, const char *);
extern char *strchr(const char *, int);
extern int strcmp(const char *, const char *);
extern int strncmp(const char *, const char *, size_t);
extern int strcasecmp(const char *, const char *);
extern int strncasecmp(const char *, const char *, size_t);
extern char *strcpy(char *, const char *);
extern char *strncpy(char *, const char *, size_t);
extern char *strrchr(const char *, int c);
extern char *strstr(const char *, const char *);
extern char *strpbrk(const char *, const char *);
extern char *strsep(char **, const char *);
extern char *strncat(char *, const char *, size_t);
extern size_t strlcat(char *, const char *, size_t);
extern size_t strlcpy(char *, const char *, size_t);
extern size_t strspn(const char *, const char *);
extern size_t strnlen(const char *, size_t);

#if defined(_BOOT) || defined(_KMDB)

extern char *strtok(char *, const char *);
extern size_t strlen(const char *);

#endif /* _BOOT || _KMDB */

#ifdef _KERNEL

extern int strident_valid(const char *);
extern void strident_canon(char *, size_t);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _COMMON_UTIL_STRING_H */
