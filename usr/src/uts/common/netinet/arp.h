/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef	_NETINET_ARP_H
#define	_NETINET_ARP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/ethernet.h>
#include <sys/socket.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  ARP packets are variable
 * in size; the arphdr structure defines the fixed-length portion.
 * Protocol type values are the same as those for 10 Mb/s Ethernet.
 * It is followed by the variable-sized fields ar_sha, arp_spa,
 * arp_tha and arp_tpa in that order, according to the lengths
 * specified.  Field names used correspond to RFC 826.
 */
struct	arphdr {
	ushort_t ar_hrd;	/* format of hardware address */
#define	ARPHRD_ETHER 	1	/* ethernet hardware address */
#define	ARPHRD_IEEE802 	6	/* IEEE 802 hardware address */
#define	ARPHRD_FRAME	15	/* Frame relay */
#define	ARPHRD_ATM	16	/* ATM */
#define	ARPHRD_HDLC	17	/* HDLC */
#define	ARPHRD_FC	18	/* Fibre Channel RFC 4338 */
#define	ARPHRD_IPATM	19	/* ATM RFC 2225 */
#define	ARPHRD_TUNNEL	31	/* IPsec Tunnel RFC 3456 */
#define	ARPHRD_IB	32	/* IPoIB hardware address */
	ushort_t ar_pro;	/* format of protocol address */
	uchar_t	ar_hln;		/* length of hardware address */
	uchar_t	ar_pln;		/* length of protocol address */
	ushort_t ar_op;		/* one of: */
#define	ARPOP_REQUEST	1	/* request to resolve address */
#define	ARPOP_REPLY	2	/* response to previous request */
#define	REVARP_REQUEST	3	/* Reverse ARP request */
#define	REVARP_REPLY	4	/* Reverse ARP reply */
	/*
	 * The remaining fields are variable in size,
	 * according to the sizes above, and are defined
	 * as appropriate for specific hardware/protocol
	 * combinations.  (E.g., see <netinet/if_ether.h>.)
	 */
#ifdef	notdef
	uchar_t	ar_sha[];	/* sender hardware address */
	uchar_t	ar_spa[];	/* sender protocol address */
	uchar_t	ar_tha[];	/* target hardware address */
	uchar_t	ar_tpa[];	/* target protocol address */
#endif	/* notdef */
};

/* Maximum hardware and protocol address length */
#define	ARP_MAX_ADDR_LEN	255

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

/*
 * ARP ioctl request
 */
struct arpreq {
	struct	sockaddr arp_pa;		/* protocol address */
	struct	sockaddr arp_ha;		/* hardware address */
	int	arp_flags;			/* flags */
};
/*  arp_flags field values */
#define	ATF_INUSE	0x01	/* entry in use */
#define	ATF_COM		0x02	/* completed entry (enaddr valid) */
#define	ATF_PERM	0x04	/* permanent entry */
#define	ATF_PUBL	0x08	/* publish entry (respond for other host) */
#define	ATF_USETRAILERS	0x10	/* has requested trailers */
#define	ATF_AUTHORITY	0x20	/* hardware address is authoritative */

#ifdef	__cplusplus
}
#endif

#endif	/* _NETINET_ARP_H */
