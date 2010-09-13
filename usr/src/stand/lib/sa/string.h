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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SA_STRING_H
#define	_SA_STRING_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Exported interfaces for standalone's subset of libc's <string.h>.
 * All standalone code *must* use this header rather than libc's.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef	NULL
#define	NULL    0		/* defined here as per ISO C */
#endif

extern int	memcmp(const void *,  const void *, size_t);
extern void	*memmove(void *, const void *, size_t);
extern void	*memset(void *, int, size_t);
extern void	*memcpy(void *, const void *, size_t);
extern void	*memchr(const void *, int, size_t);

extern int	strcmp(const char *, const char *);
extern int	strncmp(const char *, const char *, size_t);
extern size_t	strlen(const char *);
extern char	*strcat(char *, const char *);
extern char	*strncat(char *, const char *, size_t);
extern size_t	strlcat(char *, const char *, size_t);
extern char	*strcpy(char *, const char *);
extern char	*strncpy(char *, const char *, size_t);
extern size_t	strlcpy(char *, const char *, size_t);
extern char	*strchr(const char *, int);
extern char	*strrchr(const char *, int);
extern char	*strstr(const char *, const char *);
extern char	*strtok(char *, const char *);
extern char	*strerror(int);
extern char	*strdup(const char *);
extern long	strtol(const char *, char **, int);
extern unsigned long strtoul(const char *, char **, int);

#ifdef __cplusplus
}
#endif

#endif /* _SA_STRING_H */
