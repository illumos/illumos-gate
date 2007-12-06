/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 *  You may not use this file except in compliance with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * alloc.h -- public definitions for memory allocation module
 *
 */

#ifndef	_ESC_COMMON_ALLOC_H
#define	_ESC_COMMON_ALLOC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

void alloc_init(void);
void alloc_fini(void);
void *alloc_realloc(void *ptr, size_t nbytes, const char *fname, int line);
void *alloc_malloc(size_t nbytes, const char *fname, int line);
void alloc_free(void *ptr, const char *fname, int line);
char *alloc_strdup(const char *ptr, const char *fname, int line);
void *alloc_xmalloc(size_t size);
void alloc_xfree(void *ptr, size_t size);

#ifdef DEBUG

#define	MALLOC(nbytes) alloc_malloc(nbytes, __FILE__, __LINE__)
#define	REALLOC(ptr, nbytes) alloc_realloc(ptr, nbytes, __FILE__, __LINE__)
#define	FREE(ptr) alloc_free(ptr, __FILE__, __LINE__)
#define	STRDUP(ptr) alloc_strdup(ptr, __FILE__, __LINE__)

#else

#define	MALLOC(nbytes) alloc_malloc(nbytes, "???", __LINE__)
#define	REALLOC(ptr, nbytes) alloc_realloc(ptr, nbytes, "???", __LINE__)
#define	FREE(ptr) alloc_free(ptr, "???", __LINE__)
#define	STRDUP(ptr) alloc_strdup(ptr, "???", __LINE__)

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _ESC_COMMON_ALLOC_H */
