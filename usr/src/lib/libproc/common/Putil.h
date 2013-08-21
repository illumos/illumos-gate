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
/*
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#ifndef	_PUTIL_H
#define	_PUTIL_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Circular doubly-linked list:
 */
typedef struct P_list {
	struct P_list	*list_forw;
	struct P_list	*list_back;
} plist_t;

/*
 * Routines to manipulate linked lists:
 */
extern void list_link(void *, void *);
extern void list_unlink(void *);

#define	list_next(elem)	(void *)(((plist_t *)(elem))->list_forw)
#define	list_prev(elem)	(void *)(((plist_t *)(elem))->list_back)

/*
 * Routines to manipulate sigset_t, fltset_t, or sysset_t.
 */
extern void prset_fill(void *, size_t);
extern void prset_empty(void *, size_t);
extern void prset_add(void *, size_t, uint_t);
extern void prset_del(void *, size_t, uint_t);
extern int prset_ismember(void *, size_t, uint_t);

/*
 * Routine to print debug messages:
 */
extern void dprintf(const char *, ...);

extern void Pinit_ops(ps_ops_t *, const ps_ops_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _PUTIL_H */
