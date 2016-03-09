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
 * Copyright (c) 1994, 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_MED_HASH_H
#define	_MED_HASH_H

#ifdef	__cplusplus
extern "C" {
#endif

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
	void (*kffunc)(void *);
	void (*dffunc)(void *);
} Cache;

#ifdef _KERNEL
#define	malloc	bkmem_alloc
#endif	/* _KERNEL */

extern int	init_cache(Cache **cp, int hsz, int bsz,
			    int (*hfunc)(void *, int, int),
			    int (*cfunc)(void *, void *, int),
			    void (*kffunc)(void *), void (*dffunc)(void *));
extern int	add_cache(Cache *cp, Item *itemp);
extern Item	*lookup_cache(Cache *cp, void *datap, int datalen);
extern Item	*first_item(Cache *cp, int *bidx, int *iidx);
extern Item	*next_item(Cache *cp, int *bidx, int *iidx);
extern void	des_cache(Cache **cpp);
extern int	del_cache(Cache *cp, Item *itemp);
extern void	cache_stat(Cache *cp, char *tag);
extern void	pr_cache(Cache *cp, char *tag,
		    void (*pfunc)(void *, int, void *, int));

#ifdef	__cplusplus
}
#endif

#endif	/* _MED_HASH_H */
