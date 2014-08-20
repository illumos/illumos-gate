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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * ethernet.h header for common Ethernet declarations.
 */

#ifndef	_SYS_ETHERNET_H
#define	_SYS_ETHERNET_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	ETHERADDRL	(6)		/* ethernet address length in octets */
#define	ETHERFCSL	(4)		/* ethernet FCS length in octets */

/*
 * Ethernet address - 6 octets
 */
typedef uchar_t ether_addr_t[ETHERADDRL];

/*
 * Ethernet address - 6 octets
 */
struct	ether_addr {
	ether_addr_t	ether_addr_octet;
};

/*
 * Structure of a 10Mb/s Ethernet header.
 */
struct	ether_header {
	struct	ether_addr	ether_dhost;
	struct	ether_addr	ether_shost;
	ushort_t		ether_type;
};

#define	ETHER_CFI	0

struct	ether_vlan_header {
	struct	ether_addr	ether_dhost;
	struct	ether_addr	ether_shost;
	ushort_t		ether_tpid;
	ushort_t		ether_tci;
	ushort_t		ether_type;
};

/*
 * The VLAN tag.  Available for applications that cannot make use of struct
 * ether_vlan_header because they assume Ethernet encapsulation.
 */
struct ether_vlan_extinfo {
	ushort_t		ether_tci;
	ushort_t		ether_type;
};

#define	ETHERTYPE_PUP		(0x0200)	/* PUP protocol */
#define	ETHERTYPE_802_MIN	(0x0600)	/* Min valid ethernet type */
						/* under IEEE 802.3 rules */
#define	ETHERTYPE_IP		(0x0800)	/* IP protocol */
#define	ETHERTYPE_ARP		(0x0806)	/* Addr. resolution protocol */
#define	ETHERTYPE_REVARP	(0x8035)	/* Reverse ARP */
#define	ETHERTYPE_AT		(0x809b)	/* AppleTalk protocol */
#define	ETHERTYPE_AARP		(0x80f3)	/* AppleTalk ARP */
#define	ETHERTYPE_VLAN		(0x8100)	/* 802.1Q VLAN */
#define	ETHERTYPE_IPV6		(0x86dd)	/* IPv6 */
#define	ETHERTYPE_SLOW		(0x8809)	/* Slow Protocol */
#define	ETHERTYPE_PPPOED	(0x8863)	/* PPPoE Discovery Stage */
#define	ETHERTYPE_PPPOES	(0x8864)	/* PPPoE Session Stage */
#define	ETHERTYPE_EAPOL		(0x888e)	/* EAPOL protocol */
#define	ETHERTYPE_RSN_PREAUTH	(0x88c7)	/* RSN PRE-Authentication */
#define	ETHERTYPE_TRILL		(0x88c8)	/* TBD. TRILL frame */
#define	ETHERTYPE_FCOE		(0x8906)	/* FCoE */
#define	ETHERTYPE_MAX		(0xffff)	/* Max valid ethernet type */

/*
 * The ETHERTYPE_NTRAILER packet types starting at ETHERTYPE_TRAIL have
 * (type-ETHERTYPE_TRAIL)*512 bytes of data followed
 * by an ETHER type (as given above) and then the (variable-length) header.
 */
#define	ETHERTYPE_TRAIL		(0x1000)	/* Trailer packet */
#define	ETHERTYPE_NTRAILER	(16)

#define	ETHERMTU		(1500)	/* max frame w/o header or fcs */
#define	ETHERMIN		(60)	/* min frame w/header w/o fcs */
#define	ETHERMAX		(1514)	/* max frame w/header w/o fcs */

/*
 * Compare two Ethernet addresses - assumes that the two given
 * pointers can be referenced as shorts.  On architectures
 * where this is not the case, use bcmp instead.  Note that like
 * bcmp, we return zero if they are the SAME.
 */

#if defined(__sparc) || defined(__i386) || defined(__amd64)
#define	ether_cmp(a, b) (((short *)b)[2] != ((short *)a)[2] || \
	((short *)b)[1] != ((short *)a)[1] || \
	((short *)b)[0] != ((short *)a)[0])
#else
#define	ether_cmp(a, b) (bcmp((caddr_t)a, (caddr_t)b, 6))
#endif

/*
 * Copy Ethernet addresses from a to b - assumes that the two given
 * pointers can be referenced as shorts.  On architectures
 * where this is not the case, use bcopy instead.
 */

#if defined(__sparc) || defined(__i386) || defined(__amd64)
#define	ether_copy(a, b) { ((short *)b)[0] = ((short *)a)[0]; \
	((short *)b)[1] = ((short *)a)[1]; ((short *)b)[2] = ((short *)a)[2]; }
#else
#define	ether_copy(a, b) (bcopy((caddr_t)a, (caddr_t)b, 6))
#endif

#ifdef	_KERNEL
extern int localetheraddr(struct ether_addr *, struct ether_addr *);
extern char *ether_sprintf(struct ether_addr *);
extern int ether_aton(char *, uchar_t *);
#else	/* _KERNEL */
extern char *ether_ntoa(const struct ether_addr *);
extern struct ether_addr *ether_aton(const char *);
extern int ether_ntohost(char *, const struct ether_addr *);
extern int ether_hostton(const char *, struct ether_addr *);
extern int ether_line(const char *, struct ether_addr *, char *);
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ETHERNET_H */
