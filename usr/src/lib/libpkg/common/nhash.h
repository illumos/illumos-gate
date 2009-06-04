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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NHASH_H
#define	_NHASH_H


#ifdef __cplusplus
extern "C" {
#endif

#ifndef NULL
#define	NULL	0
#endif	/* NULL */

typedef struct item_t {
    void *key;
    int	  keyl;
    void *data;
    int	  datal;
} Item;

#define	Null_Item ((Item *) NULL)

typedef struct bucket_t {
	int nent;
	int nalloc;
	Item **itempp;
} Bucket;

typedef struct cache_t {
	int	hsz;
	int	bsz;
	Bucket *bp;
	int (*hfunc)(void *, int, int);
	int (*cfunc)(void *, void *, int);
} Cache;

#ifdef _KERNEL
#define	malloc	bkmem_alloc
#endif	/* _KERNEL */

extern int init_cache(Cache **cp, int hsz, int bsz,
	    int (*hfunc)(void *, int, int), int (*cfunc)(void *, void *, int));
extern int add_cache(Cache *cp, Item *itemp);
extern Item *lookup_cache(Cache *cp, void *datap, int datalen);

#ifdef __cplusplus
}
#endif

#endif /* _NHASH_H */
