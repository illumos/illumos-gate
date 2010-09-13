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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_INET_NCACONF_H
#define	_INET_NCACONF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Private interface to NCA.
 */
#define	NCA_IOCTL_BASE		('C' << 8)
#define	NCA_SET_IF		(NCA_IOCTL_BASE|1)

#ifndef	ETHERADDRL
#define	ETHERADDRL 6
#endif

#define	ADD_DEF_ROUTE	1
#define	DEL_DEF_ROUTE	2

struct nca_set_ioctl {
	ipaddr_t	local_addr;
	uchar_t		router_ether_addr[ETHERADDRL];
	uchar_t		action;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_NCACONF_H */
