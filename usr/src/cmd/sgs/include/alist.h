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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Define an Alist, a list maintained as a reallocable array, and a for() loop
 * macro to generalize its traversal.  Note that the array can be reallocated
 * as it is being traversed, thus the offset of each element is recomputed from
 * the start of the structure.
 */

#ifndef	_ALIST_H
#define	_ALIST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/machelf.h>

#define	ALO_DATA	(sizeof (Alist) - sizeof (void *))

#define	ALIST_TRAVERSE(LIST, OFF, DATA) \
	(((LIST) != 0) && ((OFF) = ALO_DATA) && \
	(((DATA) = (void *)((char *)(LIST) + (OFF))))); \
	(((LIST) != 0) && ((OFF) < (LIST)->al_next)); \
	(((OFF) += ((LIST)->al_size)), \
	((DATA) = (void *)((char *)(LIST) + (OFF))))

typedef	Word	Aliste;

typedef struct {
	Aliste 		al_end;		/* offset after last al_data[] */
	Aliste 		al_next;	/* offset of next available al_data[] */
	Aliste		al_size;	/* size of each al_data[] item */
	void *		al_data[1];	/* data (can grow) */
} Alist;


/*
 * Define alist descriptor addition return values.
 */
#define	ALE_EXISTS	1		/* alist entry already exists */
#define	ALE_CREATE	2		/* alist entry created */


extern void	*alist_append(Alist **, const void *, size_t, int);
extern int	alist_delete(Alist *, const void *, Aliste *);
extern void	*alist_insert(Alist **, const void *, size_t, int, Aliste);
extern int	alist_test(Alist **, void *, size_t, int);

#ifdef	__cplusplus
}
#endif

#endif /* _ALIST_H */
