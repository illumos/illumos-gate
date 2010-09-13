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

#ifndef _SYS_DKTP_CONTROLLER_H
#define	_SYS_DKTP_CONTROLLER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct	ctl_ext {
	opaque_t	c_type_cookie;	/* controller info 		*/
	dev_info_t	*c_ctldip;	/* dip to controller driver	*/
	dev_info_t	*c_devdip;	/* dip to target device driver	*/
	int		c_targ;		/* device target number		*/
	int		c_blksz;	/* device unit size (secsz)	*/
};

struct	ctl_obj {
	opaque_t		c_data;
	struct ctl_objops	*c_ops;
	struct ctl_ext		*c_ext;
	struct ctl_ext		c_extblk;	/* extended blk defined	*/
						/* for easy of alloc	*/
};

struct	ctl_objops {
	struct 	cmpkt *(*c_pktalloc)(opaque_t, int (*)(caddr_t), caddr_t);
	void	(*c_pktfree)(opaque_t, struct cmpkt *);
	struct 	cmpkt *(*c_memsetup)(opaque_t, struct cmpkt *, struct buf *,
	    int (*)(caddr_t), caddr_t);
	void	(*c_memfree)(opaque_t, struct cmpkt *);
	struct 	cmpkt *(*c_iosetup)(opaque_t, struct cmpkt *);
	int	(*c_transport)(opaque_t, struct cmpkt *);
	int	(*c_reset)(opaque_t, int);
	int	(*c_abort)(opaque_t, struct cmpkt *);
	int	(*c_getcap)(opaque_t, char *, int);
	int	(*c_setcap)(opaque_t, char *, int);
	int	(*c_ioctl)(opaque_t, int, intptr_t, int);
	void 	*c_resv[2];
};

#define	CTL_DIP_CTL(X) (((struct ctl_obj *)(X))->c_ext->c_ctldip)
#define	CTL_DIP_DEV(X) (((struct ctl_obj *)(X))->c_ext->c_devdip)
#define	CTL_GET_TYPE(X) (((struct ctl_obj *)(X))->c_ext->c_type_cookie)
#define	CTL_GET_LKARG(X) (((struct ctl_obj *)(X))->c_ext->c_lkarg)
#define	CTL_GET_TARG(X) (((struct ctl_obj *)(X))->c_ext->c_targ)
#define	CTL_GET_BLKSZ(X) (((struct ctl_obj *)(X))->c_ext->c_blksz)

#define	CTL_PKTALLOC(X, callback, arg) \
	(*((struct ctl_obj *)(X))->c_ops->c_pktalloc) \
	(((struct ctl_obj *)(X))->c_data, (callback), (arg))
#define	CTL_PKTFREE(X, pktp) \
	(*((struct ctl_obj *)(X))->c_ops->c_pktfree) \
	(((struct ctl_obj *)(X))->c_data, (pktp))
#define	CTL_MEMSETUP(X, pktp, bp, callback, arg) \
	(*((struct ctl_obj *)(X))->c_ops->c_memsetup) \
	(((struct ctl_obj *)(X))->c_data, (pktp), (bp), (callback), (arg))
#define	CTL_MEMFREE(X, pktp) (*((struct ctl_obj *)(X))->c_ops->c_memfree) \
	(((struct ctl_obj *)(X))->c_data, (pktp))
#define	CTL_IOSETUP(X, pktp) (*((struct ctl_obj *)(X))->c_ops->c_iosetup) \
	(((struct ctl_obj *)(X))->c_data, (pktp))
#define	CTL_TRANSPORT(X, pktp) (*((struct ctl_obj *)(X))->c_ops->c_transport) \
	(((struct ctl_obj *)(X))->c_data, (pktp))
#define	CTL_ABORT(X, pktp) (*((struct ctl_obj *)(X))->c_ops->c_abort) \
	(((struct ctl_obj *)(X))->c_data, (pktp))
#define	CTL_RESET(X, level) (*((struct ctl_obj *)(X))->c_ops->c_reset) \
	(((struct ctl_obj *)(X))->c_data, (level))
#define	CTL_IOCTL(X, cmd, arg, flag) \
	(*((struct ctl_obj *)(X))->c_ops->c_ioctl) \
	(((struct ctl_obj *)(X))->c_data, (cmd), (arg), (flag))

/*	transport return code						*/
#define	CTL_SEND_SUCCESS	0
#define	CTL_SEND_FAILURE	1
#define	CTL_SEND_BUSY		2

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_CONTROLLER_H */
