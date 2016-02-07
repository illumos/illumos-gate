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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SALIB_H
#define	_SYS_SALIB_H

#include <sys/types.h>
#include <sys/null.h>
#include <time.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern char *asctime(const struct tm *);
extern char *ctime(const time_t *);

extern int bcmp(const void *, const void *, size_t);
extern void bcopy(const void *, void *, size_t);
extern void *bsearch(const void *, const void *, size_t, size_t,
    int (*)(const void *, const void *));
extern void bzero(void *, size_t);

extern int getopt(int, char *const [], const char *);
extern void getopt_reset(void);

extern void *memchr(const void *, int, size_t);
extern int memcmp(const void *, const void *, size_t);
extern void *memcpy(void *, const void *, size_t);
extern void *memccpy(void *, const void *, int, size_t);
extern void *memmove(void *, const void *, size_t);
extern void *memset(void *, int, size_t);

extern void qsort(void *, size_t, size_t, int (*)(const void *,
    const void *));

extern long strtol(const char *, char **, int);
extern unsigned long strtoul(const char *, char **, int);
extern char *strcat(char *, const char *);
extern char *strchr(const char *, int);
extern int strcmp(const char *, const char *);
extern char *strcpy(char *, const char *);
extern int strcasecmp(const char *, const char *);
extern int strncasecmp(const char *, const char *, size_t);
extern size_t strlcpy(char *, const char *, size_t);
extern size_t strlen(const char *);
extern char *strncat(char *, const char *, size_t);
extern size_t strlcat(char *, const char *, size_t);
extern int strncmp(const char *, const char *, size_t);
extern char *strncpy(char *, const char *, size_t);
extern char *strrchr(const char *, int);
extern char *strstr(const char *, const char *);
extern size_t strspn(const char *, const char *);
extern char *strpbrk(const char *, const char *);
extern char *strtok(char *, const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SALIB_H */
