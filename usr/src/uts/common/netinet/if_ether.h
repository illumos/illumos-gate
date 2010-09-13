/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of California at Berkeley. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#ifndef	_NETINET_IF_ETHER_H
#define	_NETINET_IF_ETHER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* if_ether.h 1.28 89/08/04 SMI; from UCB 7.2 12/7/87 */

#include <sys/ethernet.h>

/*
 * The following include is for compatibility with SunOS 3.x and
 * 4.3bsd.  Newly written programs should include it separately.
 */
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
	ether_addr_t arp_sha;		/* sender hardware address */
	uchar_t	arp_spa[4];		/* sender protocol address */
	ether_addr_t arp_tha;		/* target hardware address */
	uchar_t	arp_tpa[4];		/* target protocol address */
};
#define	arp_hrd	ea_hdr.ar_hrd
#define	arp_pro	ea_hdr.ar_pro
#define	arp_hln	ea_hdr.ar_hln
#define	arp_pln	ea_hdr.ar_pln
#define	arp_op	ea_hdr.ar_op

/*
 *	multicast address structure
 *
 *	Keep a reference count for each multicast address so
 *	addresses loaded into chip are unique.
 */
struct	mcaddr {
	struct	ether_addr	mc_enaddr;	/* multicast address */
	ushort_t mc_count;			/* reference count */
};
#define	MCADDRMAX	64		/* multicast addr table length */
#define	MCCOUNTMAX	4096		/* multicast addr max reference count */

/*
 * Structure shared between the ethernet driver modules and
 * the address resolution code.  For example, each ec_softc or il_softc
 * begins with this structure.
 *
 * The structure contains a pointer to an array of multicast addresses.
 * This pointer is NULL until the first successful SIOCADDMULTI ioctl
 * is issued for the interface.
 */
struct	arpcom {
	struct	ifnet ac_if;		/* network-visible interface */
	struct	ether_addr ac_enaddr;	/* ethernet hardware address */
	struct	in_addr ac_ipaddr;	/* copy of ip address- XXX */
	struct	mcaddr *ac_mcaddr;	/* table of multicast addrs */
	ushort_t ac_nmcaddr;		/* count of M/C addrs in use */
	struct  in_addr ac_lastip;	/* cache of last ARP lookup */
	struct	ether_addr ac_lastarp;	/* result of the last ARP */
};

/*
 * Internet to ethernet address resolution table.
 */
struct	arptab {
	struct	in_addr at_iaddr;	/* internet address */
	union {
	    struct ether_addr atu_enaddr;	/* ethernet address */
	    long   atu_tvsec;			/* timestamp if incomplete */
	} 	at_union;
	uchar_t	at_timer;		/* minutes since last reference */
	uchar_t	at_flags;		/* flags */
	struct	mbuf *at_hold;		/* last packet until resolved/timeout */
};

#define	at_enaddr	at_union.atu_enaddr
#define	at_tvsec	at_union.atu_tvsec

/*
 * Copy IP addresses from a to b - assumes that the two given
 * pointers can be referenced as shorts.  On architectures
 * where this is not the case, use bcopy instead.
 */
#if defined(__sparc) || defined(__i386) || defined(__amd64)
#define	ip_copy(a, b) { ((short *)b)[0] = ((short *)a)[0]; \
	((short *)b)[1] = ((short *)a)[1]; }
#else
#define	ip_copy(a, b) (bcopy((caddr_t)a, (caddr_t)b, 4))
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _NETINET_IF_ETHER_H */
