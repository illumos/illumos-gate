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
 * Copyright 1990-1999, 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Ethernet implementation-specific definitions
 */

#ifndef _ETHERNET_INET_H
#define	_ETHERNET_INET_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	ETHERSIZE	(ETHERMTU + 50)	/* Usually a little bigger than 1500 */
#define	ETHER_ARP_TIMEOUT	(300000)	/* in milliseconds */
#define	ETHER_IN_TIMEOUT	(5)	/* msecond wait for IP frames */
#define	ETHER_MAX_FRAMES	(200)	/* Maximum of consecutive frames */
#define	ETHER_INPUT_ATTEMPTS	(8)	/* Number of consecutive attempts */
#define	ETHER_WAITCNT		(2)	/* Activity interval */

extern int ether_header_len(struct inetgram *);
extern int ether_arp(struct in_addr *, void *, uint32_t);
extern void ether_revarp(void);
extern int ether_input(int);
extern int ether_output(int, struct inetgram *);

#ifdef	__cplusplus
}
#endif

#endif /* _ETHERNET_INET_H */
