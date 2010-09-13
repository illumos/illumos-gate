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

#ifndef	_INET_IP_LISTUTILS_H
#define	_INET_IP_LISTUTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

boolean_t	lists_are_different(const slist_t *, const slist_t *);
boolean_t	list_has_addr(const slist_t *, const in6_addr_t *);
void		l_intersection(const slist_t *, const slist_t *, slist_t *);
void		l_difference(const slist_t *, const slist_t *, slist_t *);
void		l_remove(slist_t *, const in6_addr_t *);
slist_t		*l_alloc_copy(const slist_t *);
void		l_copy(const slist_t *, slist_t *);
void		l_union_in_a(slist_t *, const slist_t *, boolean_t *);
void		l_intersection_in_a(slist_t *, const slist_t *);
void		l_difference_in_a(slist_t *, const slist_t *);
slist_t		*l_alloc();
void		l_free(slist_t *);

#define	SLIST_IS_EMPTY(sl)	(((sl) == NULL) || ((sl)->sl_numsrc == 0))
#define	SLIST_CNT(sl)		(((sl) == NULL) ? 0 : ((sl)->sl_numsrc))
#define	CLEAR_SLIST(sl)		if ((sl) != NULL) (sl)->sl_numsrc = 0
#define	FREE_SLIST(sl)		if ((sl) != NULL) l_free((sl))
#define	COPY_SLIST(sl, newsl)			\
	if ((newsl) == NULL)			\
		(newsl) = l_alloc_copy((sl));	\
	else					\
		l_copy((sl), (newsl))

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IP_LISTUTILS_H */
