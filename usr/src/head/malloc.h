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

#ifndef _MALLOC_H
#define	_MALLOC_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *	Constants defining mallopt operations
 */
#define	M_MXFAST	1	/* set size of blocks to be fast */
#define	M_NLBLKS	2	/* set number of block in a holding block */
#define	M_GRAIN		3	/* set number of sizes mapped to one, for */
				/* small blocks */
#define	M_KEEP		4	/* retain contents of block after a free */
				/* until another allocation */
/*
 *	structure filled by
 */
struct mallinfo  {
	unsigned long arena;	/* total space in arena */
	unsigned long ordblks;	/* number of ordinary blocks */
	unsigned long smblks;	/* number of small blocks */
	unsigned long hblks;	/* number of holding blocks */
	unsigned long hblkhd;	/* space in holding block headers */
	unsigned long usmblks;	/* space in small blocks in use */
	unsigned long fsmblks;	/* space in free small blocks */
	unsigned long uordblks;	/* space in ordinary blocks in use */
	unsigned long fordblks;	/* space in free ordinary blocks */
	unsigned long keepcost;	/* cost of enabling keep option */
};

#if (!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX)) || \
	defined(_XPG3)
#if __cplusplus >= 199711L
namespace std {
#endif

void *malloc(size_t);
void free(void *);
void *realloc(void *, size_t);
void *calloc(size_t, size_t);

#if __cplusplus >= 199711L
} /* end of namespace std */

using std::malloc;
using std::free;
using std::realloc;
using std::calloc;
#endif /* __cplusplus >= 199711L */
#endif /* (!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX)) || ... */

int mallopt(int, int);
struct mallinfo mallinfo(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _MALLOC_H */
