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

#ifndef _SYS_DKTP_DKLB_H
#define	_SYS_DKTP_DKLB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct	dklb_ext {
	ushort_t		lb_numpart;
	ushort_t		lb_flag;
};
#define	DKLB_VALLB		0x0001

struct	dklb_obj {
	opaque_t		lb_data;
	struct dklb_objops	*lb_ops;
	struct dklb_ext		*lb_ext;
	struct dklb_ext		lb_extblk;
};

struct	dklb_objops {
	int	(*lb_init)(opaque_t, opaque_t, void *);
	int	(*lb_free)(struct dklb_obj *);
	int	(*lb_open)(opaque_t, dev_t, dev_info_t *);
	int	(*lb_ioctl)(opaque_t, int, intptr_t, int, cred_t *, int *);
	void	(*lb_partinfo)(opaque_t, daddr_t *, long *, int);
	void	*lb_resv[2];
};

struct dklb_obj *snlb_create();

#define	DKLB_NUMPART(X) (((struct dklb_obj *)(X))->lb_ext->lb_numpart)
#define	DKLB_VALIDLB(X) (((struct dklb_obj *)(X))->lb_ext->lb_flag & DKLB_VALLB)

#define	DKLB_INIT(X, dkobjp, lkarg) \
	(*((struct dklb_obj *)(X))->lb_ops->lb_init) \
	(((struct dklb_obj *)(X))->lb_data, (dkobjp), (lkarg))
#define	DKLB_FREE(X) (*((struct dklb_obj *)(X))->lb_ops->lb_free) ((X))
#define	DKLB_OPEN(X, dev, dip) (*((struct dklb_obj *)(X))->lb_ops->lb_open) \
	(((struct dklb_obj *)(X))->lb_data, dev, dip)
#define	DKLB_IOCTL(X, cmd, arg, flag, cred_p, rval_p) \
	(*((struct dklb_obj *)(X))->lb_ops->lb_ioctl) \
	(((struct dklb_obj *)(X))->lb_data, (cmd), (arg), (flag), \
		(cred_p), (rval_p))
#define	DKLB_PARTINFO(X, nblk, srtsec, part) \
	(*((struct dklb_obj *)(X))->lb_ops->lb_partinfo)\
	(((struct dklb_obj *)(X))->lb_data, (nblk), (srtsec), (part))

#define	PCFDISK		0

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_DKLB_H */
