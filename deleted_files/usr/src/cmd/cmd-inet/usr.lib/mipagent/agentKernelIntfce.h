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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_AGENTKERNELINTERFACE_H
#define	_AGENTKERNELINTERFACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Prototypes for routines that interface with routing
 * engine and tunnel driver.
 */

#include <sys/sockio.h>
#include <net/if_arp.h>
#include <net/if_dl.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	ETHER_STR_LEN	18

#define	ADDRT	1
#define	DELRT	0


#define	routeadd(dst, gw, insrc, in_if, out_if) \
    routemodify(dst, gw, insrc, in_if, out_if, ADDRT)
#define	routedel(dst, gw, insrc, in_if, out_if) \
    routemodify(dst, gw, insrc, in_if, out_if, DELRT)

int encapadd(ipaddr_t, ipaddr_t, uint32_t, uint8_t);
int encaprem(ipaddr_t);
int decapadd(ipaddr_t, ipaddr_t);
int decaprem(ipaddr_t, ipaddr_t);
int arpadd(ipaddr_t, unsigned char *, unsigned int);
int arpdel(ipaddr_t);
int arprefresh(HaMobileNodeEntry *, ipaddr_t);
int routemodify(ipaddr_t, ipaddr_t, ipaddr_t, int, int, unsigned int);
int getEthernetAddr(char *, unsigned char *);
int getIfaceInfo(char *, ipaddr_t *, ipaddr_t *, uint64_t *, uint32_t *);
boolean_t MipTunlEntryLookup(void *, uint32_t, uint32_t, uint32_t);
boolean_t existingStaticInterface(const char *);

#ifdef __cplusplus
}
#endif

#endif /* _AGENTKERNELINTERFACE_H */
