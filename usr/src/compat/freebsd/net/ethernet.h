/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Pluribus Networks Inc.
 * Copyright 2017 Joyent, Inc.
 */

#ifndef _COMPAT_FREEBSD_SYS_NET_ETHERNET_H_
#define	_COMPAT_FREEBSD_SYS_NET_ETHERNET_H_

#define	ether_addr_octet	octet

#include <sys/ethernet.h>

/*
 * Some basic Ethernet constants.
 */
#define	ETHER_ADDR_LEN		6	/* length of an Ethernet address */
#define	ETHER_CRC_LEN		4	/* length of the Ethernet CRC */
#define	ETHER_MIN_LEN		64	/* minimum frame len, including CRC */

#define	ETHER_VLAN_ENCAP_LEN	4	/* len of 802.1Q VLAN encapsulation */

#define	ETHER_IS_MULTICAST(addr) (*(addr) & 0x01) /* is address mcast/bcast? */

#endif	/* _COMPAT_FREEBSD_SYS_NET_ETHERNET_H_ */
