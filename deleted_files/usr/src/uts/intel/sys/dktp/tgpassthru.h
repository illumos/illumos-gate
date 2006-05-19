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

#ifndef _SYS_DKTP_TGPASSTHRU_H
#define	_SYS_DKTP_TGPASSTHRU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_LP64)

struct	tgpassthru_obj {
	opaque_t			pt_data;
	struct tgpassthru_objops	*pt_ops;
};

struct	tgpassthru_objops {
	int	(*pt_init)();
	int	(*pt_free)();
	int	(*pt_transport)();
	void	*pt_resv[2];
};

#define	TGPASSTHRU_INIT(X) (*((struct tgpassthru_obj *)(X))->pt_ops->pt_init)\
	(((struct tgpassthru_obj *)(X))->pt_data)
#define	TGPASSTHRU_FREE(X) (*((struct tgpassthru_obj *)(X))->pt_ops->pt_free)\
	((X))
#define	TGPASSTHRU_TRANSPORT(X, cmdp, dev, flag) \
	(*((struct tgpassthru_obj *)(X))->pt_ops->pt_transport) \
	(((struct tgpassthru_obj *)(X))->pt_data, (cmdp), (dev), (flag))

#endif	/* !defined(_LP64) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_TGPASSTHRU_H */
