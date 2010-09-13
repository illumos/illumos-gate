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
 *
 *			flist.h
 *
 *   Defines a simple fixed size stack oriented list class
 *
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* Copyright (c) 1994 by Sun Microsystems, Inc. */

/*
 * .LIBRARY Base
 * .FILE flist.cxx
 * .FILE flist.h
 * .NAME flist - simple list manager class
 *
 * .DESCRIPTION
 * The flist class is a simple list manager class designed specifically
 * for use by the mdbug package.
 * There is no destuctor for the class, so when an flist object is
 * deleted any objects still on the list are forgotten.
 */

#ifndef FLIST_H
#define	FLIST_H

#define	FLIST_SIZE  10	/* The number of items that will fit on list. */

typedef struct flist_object {
	char	*f_items[FLIST_SIZE];	/* Pointers to the items. */
	int	 f_index;		/* Index of item returned by next(). */
	int	 f_count;		/* Number of items on list. */

} flist_object_t;

flist_object_t *flist_create();
void	 flist_destroy(flist_object_t *flist_object_p);
void	 fl_push(flist_object_t *flist_object_p, void *);
void	 fl_pop(flist_object_t *flist_object_p);
void	*fl_top(flist_object_t *flist_object_p);
void	*fl_next(flist_object_t *flist_object_p);
void	 fl_clear(flist_object_t *flist_object_p);
int	 fl_space(flist_object_t *flist_object_p);
#endif /* FLIST_H */
