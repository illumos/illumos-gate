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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MISCUTILS_H
#define	_MISCUTILS_H

/*
 * Miscellaneous functions and macros not directly related to the application.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	NELEM(a)	(sizeof (a) / sizeof ((a)[0]))

boolean_t strcaseeq(const char *a, const char *b);
boolean_t streq(const char *a, const char *b);
char *strndup(const char *s, int n);
boolean_t strbw(const char *a, const char *b);
void *memdup(const void *buf, size_t sz);
void dump(FILE *out, const char *prefix, const void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _MISCUTILS_H */
