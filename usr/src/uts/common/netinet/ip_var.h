/*
 * Copyright (c) 1997-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Overlay for ip header used by other protocols (tcp, udp).
 */

#ifndef	_NETINET_IP_VAR_H
#define	_NETINET_IP_VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* ip_var.h 1.11 88/08/19 SMI; from UCB 7.1 6/5/86	*/

#include <sys/isa_defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct ipovly {
#ifdef _LP64
	uint32_t	ih_next, ih_prev;
#else
	caddr_t	ih_next, ih_prev;	/* for protocol sequence q's */
#endif
	uchar_t	ih_x1;			/* (unused) */
	uchar_t	ih_pr;			/* protocol */
	short	ih_len;			/* protocol length */
	struct	in_addr ih_src;		/* source internet address */
	struct	in_addr ih_dst;		/* destination internet address */
};

/*
 * Ip reassembly queue structure.  Each fragment
 * being reassembled is attached to one of these structures.
 * They are timed out after ipq_ttl drops to 0, and may also
 * be reclaimed if memory becomes tight.
 */
struct ipq {
	struct	ipq *next, *prev;	/* to other reass headers */
	uchar_t	ipq_ttl;		/* time for reass q to live */
	uchar_t	ipq_p;			/* protocol of this fragment */
	ushort_t ipq_id;		/* sequence id for reassembly */
	struct	ipasfrag *ipq_next, *ipq_prev;
					/* to ip headers of fragments */
	struct	in_addr ipq_src, ipq_dst;
};

/*
 * Ip header, when holding a fragment.
 *
 * Note: ipf_next must be at same offset as ipq_next above
 */
struct	ipasfrag {
#ifdef _BIT_FIELDS_LTOH
	uchar_t	ip_hl:4,
		ip_v:4;
#else
	uchar_t	ip_v:4,
		ip_hl:4;
#endif
	uchar_t	ipf_mff;		/* copied from (ip_off&IP_MF) */
	short	ip_len;
	ushort_t ip_id;
	short	ip_off;
	uchar_t	ip_ttl;
	uchar_t	ip_p;
	ushort_t ip_sum;
	struct	ipasfrag *ipf_next;	/* next fragment */
	struct	ipasfrag *ipf_prev;	/* previous fragment */
};

/*
 * Structure stored in mbuf in inpcb.ip_options
 * and passed to ip_output when ip options are in use.
 * The actual length of the options (including ipopt_dst)
 * is in m_len.
 */
#define	MAX_IPOPTLEN	40

struct ipoption {
	struct	in_addr ipopt_dst;	/* first-hop dst if source routed */
	char	ipopt_list[MAX_IPOPTLEN];	/* options proper */
};

struct	ipstat {
	long	ips_total;		/* total packets received */
	long	ips_badsum;		/* checksum bad */
	long	ips_tooshort;		/* packet too short */
	long	ips_toosmall;		/* not enough data */
	long	ips_badhlen;		/* ip header length < data size */
	long	ips_badlen;		/* ip length < ip header length */
	long	ips_fragments;		/* fragments received */
	long	ips_fragdropped;	/* frags dropped (dups, out of space) */
	long	ips_fragtimeout;	/* fragments timed out */
	long	ips_forward;		/* packets forwarded */
	long	ips_cantforward;	/* packets rcvd for unreachable dest */
	long	ips_redirectsent;	/* packets forwarded on same net */
};

#ifdef _KERNEL
/* flags passed to ip_output as last parameter */
#define	IP_FORWARDING		0x1		/* most of ip header exists */
#define	IP_ROUTETOIF		SO_DONTROUTE	/* bypass routing tables */
#define	IP_ALLOWBROADCAST	SO_BROADCAST	/* can send broadcast packets */
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _NETINET_IP_VAR_H */
