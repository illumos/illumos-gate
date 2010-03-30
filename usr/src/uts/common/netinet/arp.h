/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef	_NETINET_ARP_H
#define	_NETINET_ARP_H

#include <sys/types.h>
#include <sys/ethernet.h>
#include <sys/socket.h>
#include <net/if_arp.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Ethernet Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  Structure below is adapted
 * to resolving internet addresses.  Field names used correspond to
 * RFC 826.
 */
struct	ether_arp {
	struct	arphdr ea_hdr;		/* fixed-size header */
	struct ether_addr arp_sha;	/* sender hardware address */
	uchar_t	arp_spa[4];		/* sender protocol address */
	struct ether_addr arp_tha;	/* target hardware address */
	uchar_t	arp_tpa[4];		/* target protocol address */
};
#define	arp_hrd	ea_hdr.ar_hrd
#define	arp_pro	ea_hdr.ar_pro
#define	arp_hln	ea_hdr.ar_hln
#define	arp_pln	ea_hdr.ar_pln
#define	arp_op	ea_hdr.ar_op

#ifdef	__cplusplus
}
#endif

#endif	/* _NETINET_ARP_H */
