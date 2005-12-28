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

#ifndef	_FMD_USTAT_H
#define	_FMD_USTAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <pthread.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <fmd_api.h>
#include <fmd_list.h>

typedef struct fmd_ustat_snap {
	fmd_stat_t *uss_buf;		/* array of statistic data */
	uint_t uss_len;			/* length of uss_buf array */
} fmd_ustat_snap_t;

typedef struct fmd_ustat_chunk {
	fmd_list_t usc_list;		/* linked list next/prev pointers */
	fmd_stat_t *usc_base;		/* base of chunk allocation */
	uint_t usc_len;			/* number of stat structs in chunk */
	uint_t usc_refs;		/* reference count on chunk */
} fmd_ustat_chunk_t;

typedef struct fmd_ustat_elem {
	struct fmd_ustat_elem *use_next; /* pointer to next statistic in hash */
	const fmd_stat_t *use_stat;	/* pointer to statistic data storage */
	fmd_ustat_chunk_t *use_chunk;	/* pointer to alloc chunk (or NULL) */
} fmd_ustat_elem_t;

typedef struct fmd_ustat {
	pthread_rwlock_t us_lock;	/* lock protecting ustat collection */
	fmd_list_t us_chunks;		/* linked list of allocation chunks */
	fmd_ustat_elem_t **us_hash;	/* hash bucket array of stat elements */
	uint_t us_hashlen;		/* length of us_hash bucket array */
	uint_t us_nelems;		/* number of elements in collection */
} fmd_ustat_t;

extern fmd_ustat_t *fmd_ustat_create(void);
extern void fmd_ustat_destroy(fmd_ustat_t *);
extern int fmd_ustat_snapshot(fmd_ustat_t *, fmd_ustat_snap_t *);

#define	FMD_USTAT_NOALLOC	0x0	/* fmd should use caller's memory */
#define	FMD_USTAT_ALLOC		0x1	/* fmd should allocate stats memory */
#define	FMD_USTAT_VALIDATE	0x2	/* fmd should validate stat names */

#if FMD_STAT_NOALLOC != FMD_USTAT_NOALLOC
#error "FMD_STAT_NOALLOC must match FMD_USTAT_NOALLOC"
#endif

#if FMD_STAT_ALLOC != FMD_USTAT_ALLOC
#error "FMD_STAT_ALLOC must match FMD_USTAT_ALLOC"
#endif

extern fmd_stat_t *fmd_ustat_insert(fmd_ustat_t *,
    uint_t, uint_t, fmd_stat_t *, fmd_stat_t **);

extern void fmd_ustat_delete(fmd_ustat_t *, uint_t, fmd_stat_t *);
extern void fmd_ustat_delete_references(fmd_ustat_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_USTAT_H */
