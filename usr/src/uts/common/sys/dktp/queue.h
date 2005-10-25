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

#ifndef _SYS_DKTP_QUEUE_H
#define	_SYS_DKTP_QUEUE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct	que_obj {
	opaque_t		que_data;
	struct que_objops	*que_ops;
};

struct	que_objops {
	int	(*que_init)(struct que_data *, void *);
	int	(*que_free)(struct que_obj *);
	int	(*que_ins)(struct que_data *, struct buf *);
	struct buf *(*que_del)(struct que_data *);
	void	*que_res[2];
};

struct que_obj *qfifo_create();
struct que_obj *qmerge_create();
struct que_obj *qsort_create();
struct que_obj *qtag_create();

#define	QUE_INIT(X, lkarg) (*((struct que_obj *)(X))->que_ops->que_init) \
	(((struct que_obj *)(X))->que_data, (lkarg))
#define	QUE_FREE(X) (*((struct que_obj *)(X))->que_ops->que_free) ((X))
#define	QUE_ADD(X, bp) (*((struct que_obj *)(X))->que_ops->que_ins) \
	(((struct que_obj *)(X))->que_data, (bp))
#define	QUE_DEL(X) (*((struct que_obj *)(X))->que_ops->que_del) \
	(((struct que_obj *)(X))->que_data)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_QUEUE_H */
