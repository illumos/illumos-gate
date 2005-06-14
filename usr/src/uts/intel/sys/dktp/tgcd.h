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

#ifndef _SYS_DKTP_TGCD_H
#define	_SYS_DKTP_TGCD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_LP64)

struct	tgcd_obj {
	opaque_t		cd_data;
	struct tgcd_objops	*cd_ops;
};

struct	tgcd_objops {
	int	(*cd_init)();
	int	(*cd_free)();
	int	(*cd_identify)();
	int	(*cd_ioctl)();
	int	cd_resv[2];
};

#define	TGCD_INIT(X, tgpassthruobjp) \
	(*((struct tgcd_obj *)(X))->cd_ops->cd_init)\
	(((struct tgcd_obj *)(X))->cd_data, (tgpassthruobjp))
#define	TGCD_FREE(X) (*((struct tgcd_obj *)(X))->cd_ops->cd_free) ((X))
#define	TGCD_IDENTIFY(X, inqp, dip) \
	(*((struct tgcd_obj *)(X))->cd_ops->cd_identify)\
		(((struct tgcd_obj *)(X))->cd_data, (inqp), (dip))
#define	TGCD_IOCTL(X, cmdp, dev, cmd, arg, flag) \
	(*((struct tgcd_obj *)(X))->cd_ops->cd_ioctl) \
	(((struct tgcd_obj *)(X))->cd_data, (cmdp), (dev), (cmd), (arg), (flag))

#endif /* !defined(_LP64) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_TGCD_H */
