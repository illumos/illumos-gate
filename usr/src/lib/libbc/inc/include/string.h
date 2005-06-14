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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	__string_h
#define	__string_h

#include <sys/stdtypes.h>	/* for size_t */

#ifndef NULL
#define	NULL		0
#endif

extern char *	strcat(/* char *s1, const char *s2 */);
extern char *	strchr(/* const char *s, int c */);
extern int	strcmp(/* const char *s1, const char *s2 */);
extern char *	strcpy(/* char *s1, const char *s2 */);
extern size_t	strcspn(/* const char *s1, const char *s2 */);
#ifndef	_POSIX_SOURCE
extern char *	strdup(/* char *s1 */);
#endif
extern size_t	strlen(/* const char *s */);
extern char *	strncat(/* char *s1, const char *s2, size_t n */);
extern int	strncmp(/* const char *s1, const char *s2, size_t n */);
extern char *	strncpy(/* char *s1, const char *s2, size_t n */);
extern char *	strpbrk(/* const char *s1, const char *s2 */);
extern char *	strrchr(/* const char *s, int c */);
extern size_t	strspn(/* const char *s1, const char *s2 */);
extern char *	strstr(/* const char *s1, const char *s2 */);
extern char *	strtok(/* char *s1, const char *s2 */);

#endif	/* !__string_h */
