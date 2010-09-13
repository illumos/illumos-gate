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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SEARCH_H
#define	_SEARCH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3.1.11 */

#include <sys/feature_tests.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* HSEARCH(3C) */
typedef enum { FIND, ENTER } ACTION;

#if defined(__EXTENSIONS__) || !defined(_XOPEN_SOURCE)
struct qelem {
	struct qelem	*q_forw;
	struct qelem	*q_back;
};
#endif /* defined(__EXTENSIONS__) || !defined(_XOPEN_SOURCE) */

typedef struct entry { char *key, *data; } ENTRY;

#if defined(__STDC__)

int hcreate(size_t);
void hdestroy(void);
ENTRY *hsearch(ENTRY, ACTION);
#if defined(__EXTENSIONS__) || !defined(_XOPEN_SOURCE) || defined(_XPG4_2)
void insque(void *, void *);
void remque(void *);
#endif

#else /* defined(__STDC__) */

int hcreate();
void hdestroy();
ENTRY *hsearch();
#if defined(__EXTENSIONS__) || !defined(_XOPEN_SOURCE) || defined(_XPG4_2)
void insque();
void remque();
#endif

#endif /* defined(__STDC__) */

/* TSEARCH(3C) */
typedef enum { preorder, postorder, endorder, leaf } VISIT;

#if defined(__STDC__)
void *tdelete(const void *_RESTRICT_KYWD, void **_RESTRICT_KYWD,
	int (*)(const void *, const void *));
void *tfind(const void *, void *const *, int (*)(const void *, const void *));
void *tsearch(const void *, void **, int (*)(const void *, const void *));
void twalk(const void *, void (*)(const void *, VISIT, int));
#else
void *tdelete();
void *tfind();
void *tsearch();
void twalk();
#endif

#if defined(__STDC__)

#if defined(__EXTENSIONS__) || !defined(_XOPEN_SOURCE)
/* BSEARCH(3C) */
void *bsearch(const void *, const void *, size_t, size_t,
	    int (*)(const void *, const void *));
#endif /* defined(__EXTENSIONS__) || !defined(_XOPEN_SOURCE) */

/* LSEARCH(3C) */
void *lfind(const void *, const void *, size_t *, size_t,
	    int (*)(const void *, const void *));
void *lsearch(const void *, void *, size_t *, size_t,
	    int (*)(const void *, const void *));
#else
void *bsearch();
void *lfind();
void *lsearch();
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SEARCH_H */
