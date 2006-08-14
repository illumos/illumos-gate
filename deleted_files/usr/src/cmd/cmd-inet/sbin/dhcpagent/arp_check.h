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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	ARP_CHECK_H
#define	ARP_CHECK_H

#pragma ident	"%W%	%E% SMI"

#include <sys/types.h>
#include <netinet/in.h>

#include "interface.h"

/*
 * arp_check.[ch] provide an interface for checking whether a given IP
 * address is currently in use.  see arp_check.c for documentation on
 * how to use the exported function.
 */

#ifdef	__cplusplus
extern "C" {
#endif

int		arp_check(struct ifslist *, in_addr_t, in_addr_t, uchar_t *,
		    uint32_t, uint32_t);

#ifdef	__cplusplus
}
#endif

#endif	/* ARP_CHECK_H */
