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

#ifndef _SYS_DKTP_TGCOM_H
#define	_SYS_DKTP_TGCOM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct	tgcom_obj {
	opaque_t		com_data;
	struct tgcom_objops	*com_ops;
};

struct	tgcom_objops {
	int	(*com_init)(opaque_t);
	int	(*com_free)(struct tgcom_obj *);
	int	(*com_pkt)(opaque_t, struct buf *, int (*func)(caddr_t),
	    caddr_t);
	void	(*com_transport)(opaque_t, struct buf *);
	void	*com_resv[2];
};

#define	TGCOM_INIT(X) (*((struct tgcom_obj *)(X))->com_ops->com_init)\
	(((struct tgcom_obj *)(X))->com_data)
#define	TGCOM_FREE(X) (*((struct tgcom_obj *)(X))->com_ops->com_free) ((X))
#define	TGCOM_PKT(X, bp, cb, arg) \
	(*((struct tgcom_obj *)(X))->com_ops->com_pkt) \
		(((struct tgcom_obj *)(X))->com_data, (bp), (cb), (arg))
#define	TGCOM_TRANSPORT(X, bp) \
	(*((struct tgcom_obj *)(X))->com_ops->com_transport) \
		(((struct tgcom_obj *)(X))->com_data, (bp))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_TGCOM_H */
