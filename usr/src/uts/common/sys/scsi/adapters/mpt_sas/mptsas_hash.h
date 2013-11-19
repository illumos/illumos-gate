/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#ifndef	_SYS_SCSI_ADAPTERS_MPTHASH_H
#define	_SYS_SCSI_ADAPTERS_MPTHASH_H

#include <sys/types.h>
#include <sys/list.h>

#define	RHL_F_DEAD	0x01

typedef struct refhash_link {
	list_node_t rhl_chain_link;
	list_node_t rhl_global_link;
	uint_t rhl_flags;
	uint_t rhl_refcnt;
} refhash_link_t;

typedef uint64_t (*refhash_hash_f)(const void *);
typedef int (*refhash_cmp_f)(const void *, const void *);
typedef void (*refhash_dtor_f)(void *);
typedef int (*refhash_eval_f)(const void *, void *);

typedef struct refhash {
	list_t *rh_buckets;
	uint_t rh_bucket_count;
	list_t rh_objs;
	size_t rh_obj_size;	/* used by mdb */
	size_t rh_link_off;
	size_t rh_tag_off;
	refhash_hash_f rh_hash;
	refhash_cmp_f rh_cmp;
	refhash_dtor_f rh_dtor;
} refhash_t;

extern refhash_t *refhash_create(uint_t, refhash_hash_f, refhash_cmp_f,
    refhash_dtor_f, size_t, size_t, size_t, int);
extern void refhash_destroy(refhash_t *);
extern void refhash_insert(refhash_t *, void *);
extern void refhash_remove(refhash_t *, void *);
extern void *refhash_lookup(refhash_t *, const void *);
extern void *refhash_linear_search(refhash_t *, refhash_eval_f, void *);
extern void refhash_hold(refhash_t *, void *);
extern void refhash_rele(refhash_t *, void *);
extern void *refhash_first(refhash_t *);
extern void *refhash_next(refhash_t *, void *);
extern boolean_t refhash_obj_valid(refhash_t *hp, const void *);

#endif	/* _SYS_SCSI_ADAPTERS_MPTHASH_H */
