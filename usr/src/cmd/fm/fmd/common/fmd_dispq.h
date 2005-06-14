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

#ifndef	_FMD_DISPQ_H
#define	_FMD_DISPQ_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <pthread.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <fmd_module.h>
#include <fmd_event.h>

typedef struct fmd_dispqlist {
	struct fmd_dispqlist *dq_next;	/* link to next subscription object */
	fmd_module_t *dq_mod;		/* pointer to subscribing module */
} fmd_dispqlist_t;

typedef struct fmd_dispqelem {
	char *dq_name;			/* name associated with this element */
	struct fmd_dispqelem *dq_link;	/* link to next element in hash chain */
	struct fmd_dispqelem **dq_hash;	/* hash bucket array for lower levels */
	uint_t dq_hashlen;		/* length of dq_hash bucket array */
	fmd_dispqlist_t *dq_list;	/* head of list of subscribers */
	uint_t dq_refs;			/* ref count of hash and list elems */
} fmd_dispqelem_t;

typedef struct fmd_dispq {
	pthread_rwlock_t dq_lock;	/* lock for event dispatch queue */
	fmd_dispqelem_t *dq_root;	/* root hash table pointer */
} fmd_dispq_t;

extern fmd_dispq_t *fmd_dispq_create(void);
extern void fmd_dispq_destroy(fmd_dispq_t *);

extern void fmd_dispq_insert(fmd_dispq_t *, fmd_module_t *, const char *);
extern void fmd_dispq_delete(fmd_dispq_t *, fmd_module_t *, const char *);
extern void fmd_dispq_dispatch(fmd_dispq_t *, fmd_event_t *, const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_DISPQ_H */
