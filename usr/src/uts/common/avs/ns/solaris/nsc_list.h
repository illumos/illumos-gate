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

#ifndef	_NSC_LIST_H
#define	_NSC_LIST_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Generic lists support.
 */


/*
 * Lists are circular and doubly-linked, with headers.
 * When a list is empty, both pointers in the header
 * point to the header itself.
 */

#if defined(_KERNEL) || defined(_KMEMUSER)

/* list element */
typedef struct ls_elt {
	struct ls_elt *ls_next;
	struct ls_elt *ls_prev;
} ls_elt_t;

#endif /* _KERNEL || _KMEMUSER */

#ifdef _KERNEL

/*
 * All take as arguments side effect-free pointers to list structures
 */
#define	LS_ISEMPTY(listp)	\
	(((ls_elt_t *)(listp))->ls_next == (ls_elt_t *)(listp))
#define	LS_INIT(listp) {			\
	((ls_elt_t *)(listp))->ls_next =	\
	((ls_elt_t *)(listp))->ls_prev =	\
	((ls_elt_t *)(listp));		\
}

#define	LS_REMOVE(listp)	ls_remove((ls_elt_t *)(listp))

/*
 * For these five, ptrs are to list elements, but qp and stackp are
 * implicitly headers.
 */
#define	LS_INS_BEFORE(oldp, newp)	\
	ls_ins_before((ls_elt_t *)(oldp), (ls_elt_t *)(newp))

#define	LS_INS_AFTER(oldp, newp)	\
	ls_ins_after((ls_elt_t *)(oldp), (ls_elt_t *)(newp))

#define	LS_INSQUE(qp, eltp)	\
	ls_ins_before((ls_elt_t *)(qp), (ls_elt_t *)(eltp))

/* result needs cast; 0 result if empty queue */
#define	LS_REMQUE(qp)		ls_remque((ls_elt_t *)(qp))

#define	LS_PUSH(stackp, newp) \
	ls_ins_after((ls_elt_t *)(stackp), (ls_elt_t *)(newp))

/* result needs cast; 0 result if empty stack */
#define	LS_POP(stackp)		ls_remque((ls_elt_t *)(stackp))

/* public function declarations */
void	 ls_ins_before(ls_elt_t *, ls_elt_t *);
void	 ls_ins_after(ls_elt_t *, ls_elt_t *);
ls_elt_t *ls_remque(ls_elt_t *);
void	 ls_remove(ls_elt_t *);

#endif /* _KERNEL */

#if defined(_KERNEL) || defined(_KMEMUSER)

typedef struct llist {
	struct llist *volatile flink;		/* forward link */
	struct llist *volatile rlink;		/* reverse link */
} llist_t;

#endif /* _KERNEL || _KMEMUSER */

#ifdef _KERNEL

#define	INITQUE(l)	((l)->flink = (l)->rlink = (l))
#define	EMPTYQUE(l)	((l)->flink == (l))

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _NSC_LIST_H */
