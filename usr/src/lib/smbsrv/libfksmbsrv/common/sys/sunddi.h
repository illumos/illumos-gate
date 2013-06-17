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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_SUNDDI_H
#define	_SYS_SUNDDI_H

/*
 * Sun Specific DDI definitions (fakekernel version)
 * The real sunddi.h has become a "kitchen sink" full of
 * includes we don't want, and lots of places include it.
 * Rather than fight that battle now,  provide this one
 * with just the str*, mem*, and kiconv* functions.
 * Some day, re-factor: sunddi.h, systm.h
 */

#include <sys/isa_defs.h>
#include <sys/dditypes.h>
#include <sys/time.h>
#include <sys/cmn_err.h>

#include <sys/kmem.h>
#include <sys/nvpair.h>
#include <sys/thread.h>
#include <sys/stream.h>

#include <sys/u8_textprep.h>
#include <sys/kiconv.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL) || defined(_FAKE_KERNEL)

extern char *ddi_strdup(const char *str, int flag);
extern char *strdup(const char *str);
extern void strfree(char *str);

extern size_t strlen(const char *) __PURE;
extern size_t strnlen(const char *, size_t) __PURE;
extern char *strcpy(char *, const char *);
extern char *strncpy(char *, const char *, size_t);

/* Need to be consistent with <string.h> C++ definition for strchr() */
#if __cplusplus >= 199711L
extern const char *strchr(const char *, int);
#else
extern char *strchr(const char *, int);
#endif	/* __cplusplus >= 199711L */

#define	DDI_STRSAME(s1, s2)	((*(s1) == *(s2)) && (strcmp((s1), (s2)) == 0))
extern int strcmp(const char *, const char *) __PURE;
extern int strncmp(const char *, const char *, size_t) __PURE;
extern char *strncat(char *, const char *, size_t);
extern size_t strlcat(char *, const char *, size_t);
extern size_t strlcpy(char *, const char *, size_t);
extern size_t strspn(const char *, const char *);
extern size_t strcspn(const char *, const char *);
extern int bcmp(const void *, const void *, size_t) __PURE;
extern int stoi(char **);
extern void numtos(ulong_t, char *);
extern void bcopy(const void *, void *, size_t);
extern void bzero(void *, size_t);

extern void *memcpy(void *, const  void  *, size_t);
extern void *memset(void *, int, size_t);
extern void *memmove(void *, const void *, size_t);
extern int memcmp(const void *, const void *, size_t) __PURE;

/* Need to be consistent with <string.h> C++ definition for memchr() */
#if __cplusplus >= 199711L
extern const void *memchr(const void *, int, size_t);
#else
extern void *memchr(const void *, int, size_t);
#endif /* __cplusplus >= 199711L */

extern int ddi_strtol(const char *, char **, int, long *);
extern int ddi_strtoul(const char *, char **, int, unsigned long *);
extern int ddi_strtoll(const char *, char **, int, longlong_t *);
extern int ddi_strtoull(const char *, char **, int, u_longlong_t *);

/*
 * kiconv functions and their macros.
 */
#define	KICONV_IGNORE_NULL	(0x0001)
#define	KICONV_REPLACE_INVALID	(0x0002)

extern kiconv_t kiconv_open(const char *, const char *);
extern size_t kiconv(kiconv_t, char **, size_t *, char **, size_t *, int *);
extern int kiconv_close(kiconv_t);
extern size_t kiconvstr(const char *, const char *, char *, size_t *, char *,
	size_t *, int, int *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SUNDDI_H */
