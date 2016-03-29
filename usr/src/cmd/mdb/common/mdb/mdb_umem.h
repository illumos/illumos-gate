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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MDB_UMEM_H
#define	_MDB_UMEM_H

#include <sys/types.h>
#include <limits.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _MDB

#define	UMEM_FREE_PATTERN		0xdefacedd
#define	UMEM_UNINITIALIZED_PATTERN	0xbeefbabe

typedef struct mdb_mblk mdb_mblk_t;

/* Aligned allocation/frees are not available through the module API */
extern void *mdb_alloc_align(size_t, size_t, uint_t);
extern void mdb_free_align(void *, size_t);

extern void mdb_recycle(mdb_mblk_t **);

/*
 * These values represent an attempt to help constrain dmods that have bugs and
 * have accidentally underflowed their size arguments. They represent
 * allocations that are impossible.
 */
#if	defined(_ILP32)
#define	MDB_ALLOC_MAX	INT32_MAX
#elif	defined(_LP64)
#define	MDB_ALLOC_MAX	INT64_MAX
#else
#error	"Unknown data model"
#endif


#endif /* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_UMEM_H */
