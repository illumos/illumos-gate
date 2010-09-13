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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_MDB_LIST_H
#define	_MDB_LIST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _MDB

/*
 * Simple doubly-linked list implementation.  This implementation assumes that
 * each element contains an embedded mdb_list_t structure.  An additional
 * mdb_list_t is used to store the head and tail pointers.  The caller can
 * use mdb_list_prev() on the master list_t to obtain the tail element, or
 * mdb_list_next() to obtain the head element.  The head and tail list elements
 * have their previous and next pointers set to NULL, respectively.
 */

typedef struct mdb_list {
	struct mdb_list *ml_prev;	/* Link to previous list element */
	struct mdb_list *ml_next;	/* Link to next list element */
} mdb_list_t;

#define	mdb_list_prev(elem)	((void *)(((mdb_list_t *)(elem))->ml_prev))
#define	mdb_list_next(elem)	((void *)(((mdb_list_t *)(elem))->ml_next))

extern void mdb_list_append(mdb_list_t *, void *);
extern void mdb_list_prepend(mdb_list_t *, void *);
extern void mdb_list_insert(mdb_list_t *, void *, void *);
extern void mdb_list_delete(mdb_list_t *, void *);
extern void mdb_list_move(mdb_list_t *, mdb_list_t *);

#endif	/* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_LIST_H */
