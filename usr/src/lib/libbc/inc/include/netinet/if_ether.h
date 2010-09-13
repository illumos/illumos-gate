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

#ifndef _netinet_if_ether_h
#define	_netinet_if_ether_h

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The following include is for compatibility with SunOS 3.x and
 * 4.3bsd.  Newly written programs should include it separately.
 */
#include <net/if_arp.h>

/*
 * Ethernet address - 6 octets
 */
struct ether_addr {
	u_char	ether_addr_octet[6];
};

/*
 * Structure of a 10Mb/s Ethernet header.
 */
struct	ether_header {
	struct	ether_addr ether_dhost;
	struct	ether_addr ether_shost;
	u_short	ether_type;
};

#define	ETHERTYPE_PUP		0x0200		/* PUP protocol */
#define	ETHERTYPE_IP		0x0800		/* IP protocol */
#define	ETHERTYPE_ARP		0x0806		/* Addr. resolution protocol */
#define	ETHERTYPE_REVARP	0x8035		/* Reverse ARP */

/*
 * The ETHERTYPE_NTRAILER packet types starting at ETHERTYPE_TRAIL have
 * (type-ETHERTYPE_TRAIL)*512 bytes of data followed
 * by an ETHER type (as given above) and then the (variable-length) header.
 */
#define	ETHERTYPE_TRAIL		0x1000		/* Trailer packet */
#define	ETHERTYPE_NTRAILER	16

#define	ETHERMTU	1500
#define	ETHERMIN	(60-14)

/*
 * Ethernet Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  Structure below is adapted
 * to resolving internet addresses.  Field names used correspond to
 * RFC 826.
 */
struct	ether_arp {
	struct	arphdr ea_hdr;		/* fixed-size header */
	struct	ether_addr arp_sha;	/* sender hardware address */
	u_char	arp_spa[4];		/* sender protocol address */
	struct	ether_addr arp_tha;	/* target hardware address */
	u_char	arp_tpa[4];		/* target protocol address */
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
	u_short	mc_count;			/* reference count */
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
	u_short	ac_nmcaddr;		/* count of M/C addrs in use */
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
	u_char	at_timer;		/* minutes since last reference */
	u_char	at_flags;		/* flags */
	struct	mbuf *at_hold;		/* last packet until resolved/timeout */
};

# define at_enaddr at_union.atu_enaddr
# define at_tvsec at_union.atu_tvsec

/*
 * Compare two Ethernet addresses - assumes that the two given
 * pointers can be referenced as shorts.  On architectures
 * where this is not the case, use bcmp instead.  Note that like
 * bcmp, we return zero if they are the SAME.
 */
#define ether_cmp(a,b) ( ((short *)b)[2] != ((short *)a)[2] || \
 ((short *)b)[1] != ((short *)a)[1] || ((short *)b)[0] != ((short *)a)[0] )

/*
 * Copy Ethernet addresses from a to b - assumes that the two given
 * pointers can be referenced as shorts.  On architectures
 * where this is not the case, use bcopy instead.
 */
#define ether_copy(a,b) { ((short *)b)[0]=((short *)a)[0]; \
 ((short *)b)[1]=((short *)a)[1]; ((short *)b)[2]=((short *)a)[2]; }

/*
 * Copy IP addresses from a to b - assumes that the two given
 * pointers can be referenced as shorts.  On architectures
 * where this is not the case, use bcopy instead.
 */
#define ip_copy(a,b) { ((short *)b)[0]=((short *)a)[0]; \
 ((short *)b)[1]=((short *)a)[1]; }

#endif /* !_netinet_if_ether_h */
