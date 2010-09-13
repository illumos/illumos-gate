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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_ETHERADDR_H
#define	_ETHERADDR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Module:	etheraddr
 * Description:	This is the solaris-specific interface for retrieving
 *		the MAC (IEEE 802.3) node identifier, a.k.a. the ethernet
 *		address of the system.  Note that this can only get the
 *		ethernet address if the process running the code can open
 *		/dev/[whatever] read/write, e.g. you must be root.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/socket.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <sys/uuid.h>

typedef struct walker_arg {
	uchar_t	wa_etheraddr[DLPI_PHYSADDR_MAX];
	size_t	wa_etheraddrlen;
	boolean_t	wa_addrvalid;
} walker_arg_t;

/* global function */
int	arp_get(uuid_node_t *);
int	get_ethernet_address(uuid_node_t *);

#ifdef __cplusplus
}
#endif

#endif /* _ETHERADDR_H */
