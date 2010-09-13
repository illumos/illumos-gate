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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DHCPV4_H
#define	_DHCPV4_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	DHCP_NO_DATA	1			/* no data */
#define	DHCP_ARP_TIMEOUT	1000		/* Wait one sec for response */
#define	DHCP_RETRIES	0xffffffff	/* Forever */
#define	DHCP_WAIT	4		/* first wait - 4 seconds */

enum DHCPSTATE { INIT, SELECTING, REQUESTING, BOUND, CONFIGURED };

extern PKT_LIST *state_pl;

extern int dhcp(void);
extern boolean_t dhcp_getinfo(uchar_t, uint16_t, uint16_t, void *, size_t *);
extern void dhcp_set_client_id(uint8_t *, uint8_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _DHCPV4_H */
