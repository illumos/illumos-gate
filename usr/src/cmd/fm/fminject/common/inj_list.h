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

#ifndef	_INJ_LIST_H
#define	_INJ_LIST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Simple doubly-linked list implementation.  This implementation assumes that
 * each element contains an embedded inj_list_t structure.  An additional
 * inj_list_t is used to store the head and tail pointers.  The caller can
 * use inj_list_prev() on the master list_t to obtain the tail element, or
 * inj_list_next() to obtain the head element.  The head and tail list elements
 * have their previous and next pointers set to NULL, respectively.
 */

typedef struct inj_list {
	struct inj_list *ml_prev;	/* Link to previous list element */
	struct inj_list *ml_next;	/* Link to next list element */
} inj_list_t;

#define	inj_list_prev(elem)	((void *)(((inj_list_t *)(elem))->ml_prev))
#define	inj_list_next(elem)	((void *)(((inj_list_t *)(elem))->ml_next))

extern void inj_list_append(inj_list_t *, void *);
extern void inj_list_prepend(inj_list_t *, void *);

#ifdef	__cplusplus
}
#endif

#endif	/* _INJ_LIST_H */
