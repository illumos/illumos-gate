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

#include <sys/scsi/adapters/mpt_sas/mptsas_hash.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/list.h>
#include <sys/ddi.h>

#ifdef lint
extern refhash_link_t *obj_to_link(refhash_t *, void *);
extern void *link_to_obj(refhash_t *, refhash_link_t *);
extern void *obj_to_tag(refhash_t *, void *);
#else
#define	obj_to_link(_h, _o)	\
	((refhash_link_t *)(((char *)(_o)) + (_h)->rh_link_off))
#define	link_to_obj(_h, _l)	\
	((void *)(((char *)(_l)) - (_h)->rh_link_off))
#define	obj_to_tag(_h, _o)	\
	((void *)(((char *)(_o)) + (_h)->rh_tag_off))
#endif

refhash_t *
refhash_create(uint_t bucket_count, refhash_hash_f hash,
    refhash_cmp_f cmp, refhash_dtor_f dtor, size_t obj_size, size_t link_off,
    size_t tag_off, int km_flags)
{
	refhash_t *hp;
	uint_t i;

	hp = kmem_alloc(sizeof (refhash_t), km_flags);
	if (hp == NULL)
		return (NULL);
	hp->rh_buckets = kmem_zalloc(bucket_count * sizeof (list_t), km_flags);
	if (hp->rh_buckets == NULL) {
		kmem_free(hp, sizeof (refhash_t));
		return (NULL);
	}
	hp->rh_bucket_count = bucket_count;

	for (i = 0; i < bucket_count; i++) {
		list_create(&hp->rh_buckets[i], sizeof (refhash_link_t),
		    offsetof(refhash_link_t, rhl_chain_link));
	}
	list_create(&hp->rh_objs, sizeof (refhash_link_t),
	    offsetof(refhash_link_t, rhl_global_link));

	hp->rh_obj_size = obj_size;
	hp->rh_link_off = link_off;
	hp->rh_tag_off = tag_off;
	hp->rh_hash = hash;
	hp->rh_cmp = cmp;
	hp->rh_dtor = dtor;

	return (hp);
}

void
refhash_destroy(refhash_t *hp)
{
	ASSERT(list_is_empty(&hp->rh_objs));

	kmem_free(hp->rh_buckets, hp->rh_bucket_count * sizeof (list_t));
	kmem_free(hp, sizeof (refhash_t));
}

void
refhash_insert(refhash_t *hp, void *op)
{
	uint_t bucket;
	refhash_link_t *lp = obj_to_link(hp, op);

	bucket = hp->rh_hash(obj_to_tag(hp, op)) % hp->rh_bucket_count;
	list_link_init(&lp->rhl_chain_link);
	list_link_init(&lp->rhl_global_link);
	lp->rhl_flags = 0;
	lp->rhl_refcnt = 0;
	list_insert_tail(&hp->rh_buckets[bucket], lp);
	list_insert_tail(&hp->rh_objs, lp);
}

static void
refhash_delete(refhash_t *hp, void *op)
{
	refhash_link_t *lp = obj_to_link(hp, op);
	uint_t bucket;

	bucket = hp->rh_hash(obj_to_tag(hp, op)) % hp->rh_bucket_count;
	list_remove(&hp->rh_buckets[bucket], lp);
	list_remove(&hp->rh_objs, lp);
	hp->rh_dtor(op);
}

void
refhash_remove(refhash_t *hp, void *op)
{
	refhash_link_t *lp = obj_to_link(hp, op);

	if (lp->rhl_refcnt > 0) {
		lp->rhl_flags |= RHL_F_DEAD;
	} else {
		refhash_delete(hp, op);
	}
}

void *
refhash_lookup(refhash_t *hp, const void *tp)
{
	uint_t bucket;
	refhash_link_t *lp;
	void *op;

	bucket = hp->rh_hash(tp) % hp->rh_bucket_count;
	for (lp = list_head(&hp->rh_buckets[bucket]); lp != NULL;
	    lp = list_next(&hp->rh_buckets[bucket], lp)) {
		op = link_to_obj(hp, lp);
		if (hp->rh_cmp(obj_to_tag(hp, op), tp) == 0 &&
		    !(lp->rhl_flags & RHL_F_DEAD)) {
			return (op);
		}
	}

	return (NULL);
}

void *
refhash_linear_search(refhash_t *hp, refhash_eval_f eval, void *arg)
{
	void *op;
	refhash_link_t *lp;

	for (lp = list_head(&hp->rh_objs); lp != NULL;
	    lp = list_next(&hp->rh_objs, lp)) {
		op = link_to_obj(hp, lp);
		if (eval(op, arg) == 0)
			return (op);
	}

	return (NULL);
}

void
refhash_hold(refhash_t *hp, void *op)
{
	refhash_link_t *lp = obj_to_link(hp, op);

	++lp->rhl_refcnt;
}

void
refhash_rele(refhash_t *hp, void *op)
{
	refhash_link_t *lp = obj_to_link(hp, op);

	ASSERT(lp->rhl_refcnt > 0);

	if (--lp->rhl_refcnt == 0 && (lp->rhl_flags & RHL_F_DEAD))
		refhash_remove(hp, op);
}

void *
refhash_first(refhash_t *hp)
{
	refhash_link_t *lp;

	lp = list_head(&hp->rh_objs);
	if (lp == NULL)
		return (NULL);

	++lp->rhl_refcnt;

	return (link_to_obj(hp, lp));
}

void *
refhash_next(refhash_t *hp, void *op)
{
	refhash_link_t *lp;

	lp = obj_to_link(hp, op);
	while ((lp = list_next(&hp->rh_objs, lp)) != NULL) {
		if (!(lp->rhl_flags & RHL_F_DEAD))
			break;
	}

	refhash_rele(hp, op);
	if (lp == NULL)
		return (NULL);

	++lp->rhl_refcnt;

	return (link_to_obj(hp, lp));
}

boolean_t
refhash_obj_valid(refhash_t *hp, const void *op)
{
	/* LINTED - E_ARG_INCOMPATIBLE_WITH_ARG_L */
	const refhash_link_t *lp = obj_to_link(hp, op);

	return ((lp->rhl_flags & RHL_F_DEAD) != 0);
}
