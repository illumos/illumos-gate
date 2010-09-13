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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ISNS_HTAB_H
#define	_ISNS_HTAB_H

#ifdef __cplusplus
extern "C" {
#endif

#define	HASH_RATIO	(3)
#define	MAX_LOGSIZE	(sizeof (uint32_t) * 8 - 1)
#define	HVAL_MASK	(((uint32_t)1 << MAX_LOGSIZE) - 1)
#define	BAD_HVAL_MASK	((uint32_t)1 << MAX_LOGSIZE)
#define	VALID_HVAL(H)	((H) & HVAL_MASK)
#define	BAD_HVAL(H)	(((H) & BAD_HVAL_MASK) == BAD_HVAL_MASK)

#define	FLAGS_CTRL_MASK		(0x10000000)
#define	FLAGS_CHUNK_MASK	(0x00001111)

typedef struct htab_item {
	uint32_t hval;
	void *p;
	struct htab_item *next;
} htab_item_t;

typedef struct htab_itemx {
	uint32_t uid;
	uint32_t hval;
	uint32_t t;
	int bf;
	struct htab_itemx *l;
	struct htab_itemx *r;
	struct htab_itemx *n;
} htab_itemx_t;

typedef struct htab {
	int flags;
	struct cache *c;
	htab_item_t **items;
	uint16_t logsize;
	uint16_t chunks;
	uint32_t mask;
	uint32_t count;
	/* AVL tree of the object UIDs */
	htab_itemx_t *avlt;
	/* the biggest UID in the tree */
	uint32_t buid;
	/* fifo list of available UIDs */
	htab_itemx_t *list;
	htab_itemx_t *tail;
} htab_t;

#define	UID_FLAGS_SEQ	(0x1)

#define	FOR_EACH_ITEM(HTAB, UID, STMT)	\
{\
	UID = htab_get_next(HTAB, UID);\
	while (UID != 0) {\
		STMT\
		UID = htab_get_next(HTAB, UID);\
	}\
}

void htab_init(void);
htab_t *htab_create(int, uint16_t, uint16_t);
void htab_destroy(htab_t *);
uint32_t htab_compute_hval(const uchar_t *);
int htab_add(htab_t *, void *, int, uint32_t *, int *);
isns_obj_t *htab_remove(htab_t *, void *, uint32_t, int);
int htab_lookup(htab_t *, void *, uint32_t,
	uint32_t *, int (*)(void *, void *), int);
uint32_t htab_get_next(htab_t *, uint32_t);
#ifdef DEBUG
void htab_dump(htab_t *);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_HTAB_H */
