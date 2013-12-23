/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
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

/*
 * Constants and structures defined by the internet system,
 * according to following documents
 *
 * Internet ASSIGNED NUMBERS (RFC1700) and its successors:
 *	http://www.iana.org/assignments/protocol-numbers
 *	http://www.iana.org/assignments/port-numbers
 * Basic Socket Interface Extensions for IPv6 (RFC2133 and its successors)
 *
 */

#ifndef _NETINET_IN_H
#define	_NETINET_IN_H

#include <sys/feature_tests.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#include <sys/socket_impl.h>
#endif	/* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

#ifndef _SOCKLEN_T
#define	_SOCKLEN_T

/*
 * The socklen definitions are reproduced here from sys/socket.h so as to
 * not introduce that namespace into existing users of netinet/in.h.
 */
#if defined(_XPG4_2) && !defined(_XPG5) && !defined(_LP64)
typedef	size_t		socklen_t;
#else
typedef	uint32_t	socklen_t;
#endif	/* defined(_XPG4_2) && !defined(_XPG5) && !defined(_LP64) */

#if defined(_XPG4_2) || defined(_BOOT)
typedef	socklen_t	*Psocklen_t;
#else
typedef	void		*Psocklen_t;
#endif	/* defined(_XPG4_2) || defined(_BOOT) */

#endif /* _SOCKLEN_T */

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#include <sys/stream.h>
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */
/*
 * Symbols such as htonl() are required to be exposed through this file,
 * per XNS Issue 5. This is achieved by inclusion of <sys/byteorder.h>
 */
#if !defined(_XPG4_2) || defined(__EXTENSIONS__) || defined(_XPG5)
#include <sys/byteorder.h>
#endif

#ifndef _IN_PORT_T
#define	_IN_PORT_T
typedef	uint16_t	in_port_t;
#endif

/*
 * Note: IPv4 address data structures usage conventions.
 * The "in_addr_t" type below (required by Unix standards)
 * is NOT a typedef of "struct in_addr" and violates the usual
 * conventions where "struct <name>" and <name>_t are corresponding
 * typedefs.
 * To minimize confusion, kernel data structures/usage prefers use
 * of "ipaddr_t" as atomic uint32_t type and avoid using "in_addr_t"
 * The user level APIs continue to follow the historic popular
 * practice of using "struct in_addr".
 */
#ifndef _IN_ADDR_T
#define	_IN_ADDR_T
typedef	uint32_t	in_addr_t;
#endif

#ifndef _IPADDR_T
#define	_IPADDR_T
typedef uint32_t ipaddr_t;
#endif

#if !defined(_XPG4_2) || defined(_XPG6) || defined(__EXTENSIONS__)

struct in6_addr {
	union {
		/*
		 * Note: Static initalizers of "union" type assume
		 * the constant on the RHS is the type of the first member
		 * of union.
		 * To make static initializers (and efficient usage) work,
		 * the order of members exposed to user and kernel view of
		 * this data structure is different.
		 * User environment sees specified uint8_t type as first
		 * member whereas kernel sees most efficient type as
		 * first member.
		 */
#ifdef _KERNEL
		uint32_t	_S6_u32[4];	/* IPv6 address */
		uint8_t		_S6_u8[16];	/* IPv6 address */
#else
		uint8_t		_S6_u8[16];	/* IPv6 address */
		uint32_t	_S6_u32[4];	/* IPv6 address */
#endif
		uint32_t	__S6_align;	/* Align on 32 bit boundary */
	} _S6_un;
};
#define	s6_addr		_S6_un._S6_u8

#ifdef _KERNEL
#define	s6_addr8	_S6_un._S6_u8
#define	s6_addr32	_S6_un._S6_u32
#endif

typedef struct in6_addr in6_addr_t;

#endif /* !defined(_XPG4_2) || defined(_XPG6) || defined(__EXTENSIONS__) */

#ifndef _SA_FAMILY_T
#define	_SA_FAMILY_T
typedef	uint16_t	sa_family_t;
#endif

/*
 * Protocols
 *
 * Some of these constant names are copied for the DTrace IP provider in
 * usr/src/lib/libdtrace/common/{ip.d.in, ip.sed.in}, which should be kept
 * in sync.
 */
#define	IPPROTO_IP		0		/* dummy for IP */
#define	IPPROTO_HOPOPTS		0		/* Hop by hop header for IPv6 */
#define	IPPROTO_ICMP		1		/* control message protocol */
#define	IPPROTO_IGMP		2		/* group control protocol */
#define	IPPROTO_GGP		3		/* gateway^2 (deprecated) */
#define	IPPROTO_ENCAP		4		/* IP in IP encapsulation */
#define	IPPROTO_TCP		6		/* tcp */
#define	IPPROTO_EGP		8		/* exterior gateway protocol */
#define	IPPROTO_PUP		12		/* pup */
#define	IPPROTO_UDP		17		/* user datagram protocol */
#define	IPPROTO_IDP		22		/* xns idp */
#define	IPPROTO_IPV6		41		/* IPv6 encapsulated in IP */
#define	IPPROTO_ROUTING		43		/* Routing header for IPv6 */
#define	IPPROTO_FRAGMENT	44		/* Fragment header for IPv6 */
#define	IPPROTO_RSVP		46		/* rsvp */
#define	IPPROTO_ESP		50		/* IPsec Encap. Sec. Payload */
#define	IPPROTO_AH		51		/* IPsec Authentication Hdr. */
#define	IPPROTO_ICMPV6		58		/* ICMP for IPv6 */
#define	IPPROTO_NONE		59		/* No next header for IPv6 */
#define	IPPROTO_DSTOPTS		60		/* Destination options */
#define	IPPROTO_HELLO		63		/* "hello" routing protocol */
#define	IPPROTO_ND		77		/* UNOFFICIAL net disk proto */
#define	IPPROTO_EON		80		/* ISO clnp */
#define	IPPROTO_OSPF		89		/* OSPF */
#define	IPPROTO_PIM		103		/* PIM routing protocol */
#define	IPPROTO_SCTP		132		/* Stream Control */
						/* Transmission Protocol */

#define	IPPROTO_RAW		255		/* raw IP packet */
#define	IPPROTO_MAX		256

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	PROTO_SDP		257		/* Sockets Direct Protocol */
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

/*
 * Port/socket numbers: network standard functions
 *
 * Entries should exist here for each port number compiled into an ON
 * component, such as snoop.
 */
#define	IPPORT_ECHO		7
#define	IPPORT_DISCARD		9
#define	IPPORT_SYSTAT		11
#define	IPPORT_DAYTIME		13
#define	IPPORT_NETSTAT		15
#define	IPPORT_CHARGEN		19
#define	IPPORT_FTP		21
#define	IPPORT_TELNET		23
#define	IPPORT_SMTP		25
#define	IPPORT_TIMESERVER	37
#define	IPPORT_NAMESERVER	42
#define	IPPORT_WHOIS		43
#define	IPPORT_DOMAIN		53
#define	IPPORT_MDNS		5353
#define	IPPORT_MTP		57

/*
 * Port/socket numbers: host specific functions
 */
#define	IPPORT_BOOTPS		67
#define	IPPORT_BOOTPC		68
#define	IPPORT_TFTP		69
#define	IPPORT_RJE		77
#define	IPPORT_FINGER		79
#define	IPPORT_HTTP		80
#define	IPPORT_HTTP_ALT		8080
#define	IPPORT_TTYLINK		87
#define	IPPORT_SUPDUP		95
#define	IPPORT_NTP		123
#define	IPPORT_NETBIOS_NS	137
#define	IPPORT_NETBIOS_DGM	138
#define	IPPORT_NETBIOS_SSN	139
#define	IPPORT_LDAP		389
#define	IPPORT_SLP		427
#define	IPPORT_MIP		434
#define	IPPORT_SMB		445		/* a.k.a. microsoft-ds */

/*
 * Internet Key Exchange (IKE) ports
 */
#define	IPPORT_IKE		500
#define	IPPORT_IKE_NATT		4500

/*
 * UNIX TCP sockets
 */
#define	IPPORT_EXECSERVER	512
#define	IPPORT_LOGINSERVER	513
#define	IPPORT_CMDSERVER	514
#define	IPPORT_PRINTER		515
#define	IPPORT_EFSSERVER	520

/*
 * UNIX UDP sockets
 */
#define	IPPORT_BIFFUDP		512
#define	IPPORT_WHOSERVER	513
#define	IPPORT_SYSLOG		514
#define	IPPORT_TALK		517
#define	IPPORT_ROUTESERVER	520
#define	IPPORT_RIPNG		521

/*
 * DHCPv6 UDP ports
 */
#define	IPPORT_DHCPV6C		546
#define	IPPORT_DHCPV6S		547

#define	IPPORT_SOCKS		1080

/*
 * Ports < IPPORT_RESERVED are reserved for
 * privileged processes (e.g. root).
 * Ports > IPPORT_USERRESERVED are reserved
 * for servers, not necessarily privileged.
 */
#define	IPPORT_RESERVED		1024
#define	IPPORT_USERRESERVED	5000

/*
 * Link numbers
 */
#define	IMPLINK_IP		155
#define	IMPLINK_LOWEXPER	156
#define	IMPLINK_HIGHEXPER	158

/*
 * IPv4 Internet address
 *	This definition contains obsolete fields for compatibility
 *	with SunOS 3.x and 4.2bsd.  The presence of subnets renders
 *	divisions into fixed fields misleading at best.  New code
 *	should use only the s_addr field.
 */

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	_S_un_b	S_un_b
#define	_S_un_w	S_un_w
#define	_S_addr	S_addr
#define	_S_un	S_un
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

struct in_addr {
	union {
		struct { uint8_t s_b1, s_b2, s_b3, s_b4; } _S_un_b;
		struct { uint16_t s_w1, s_w2; } _S_un_w;
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
		uint32_t _S_addr;
#else
		in_addr_t _S_addr;
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */
	} _S_un;
#define	s_addr	_S_un._S_addr		/* should be used for all code */
#define	s_host	_S_un._S_un_b.s_b2	/* OBSOLETE: host on imp */
#define	s_net	_S_un._S_un_b.s_b1	/* OBSOLETE: network */
#define	s_imp	_S_un._S_un_w.s_w2	/* OBSOLETE: imp */
#define	s_impno	_S_un._S_un_b.s_b4	/* OBSOLETE: imp # */
#define	s_lh	_S_un._S_un_b.s_b3	/* OBSOLETE: logical host */
};

/*
 * Definitions of bits in internet address integers.
 * On subnets, the decomposition of addresses to host and net parts
 * is done according to subnet mask, not the masks here.
 *
 * Note that with the introduction of CIDR, IN_CLASSA, IN_CLASSB,
 * IN_CLASSC, IN_CLASSD and IN_CLASSE macros have become "de-facto
 * obsolete". IN_MULTICAST macro should be used to test if a address
 * is a multicast address.
 */
#define	IN_CLASSA(i)		(((i) & 0x80000000U) == 0)
#define	IN_CLASSA_NET		0xff000000U
#define	IN_CLASSA_NSHIFT	24
#define	IN_CLASSA_HOST		0x00ffffffU
#define	IN_CLASSA_MAX		128

#define	IN_CLASSB(i)		(((i) & 0xc0000000U) == 0x80000000U)
#define	IN_CLASSB_NET		0xffff0000U
#define	IN_CLASSB_NSHIFT	16
#define	IN_CLASSB_HOST		0x0000ffffU
#define	IN_CLASSB_MAX		65536

#define	IN_CLASSC(i)		(((i) & 0xe0000000U) == 0xc0000000U)
#define	IN_CLASSC_NET		0xffffff00U
#define	IN_CLASSC_NSHIFT	8
#define	IN_CLASSC_HOST		0x000000ffU

#define	IN_CLASSD(i)		(((i) & 0xf0000000U) == 0xe0000000U)
#define	IN_CLASSD_NET		0xf0000000U	/* These aren't really  */
#define	IN_CLASSD_NSHIFT	28		/* net and host fields, but */
#define	IN_CLASSD_HOST		0x0fffffffU	/* routing needn't know */

#define	IN_CLASSE(i)		(((i) & 0xf0000000U) == 0xf0000000U)
#define	IN_CLASSE_NET		0xffffffffU

#define	IN_MULTICAST(i)		IN_CLASSD(i)

/*
 * We have removed CLASS E checks from the kernel
 * But we preserve these defines for userland in order
 * to avoid compile  breakage of some 3rd party piece of software
 */
#ifndef _KERNEL
#define	IN_EXPERIMENTAL(i)	(((i) & 0xe0000000U) == 0xe0000000U)
#define	IN_BADCLASS(i)		(((i) & 0xf0000000U) == 0xf0000000U)
#endif

#define	INADDR_ANY		0x00000000U
#define	INADDR_LOOPBACK		0x7F000001U
#define	INADDR_BROADCAST	0xffffffffU	/* must be masked */
#define	INADDR_NONE		0xffffffffU

#define	INADDR_UNSPEC_GROUP	0xe0000000U	/* 224.0.0.0   */
#define	INADDR_ALLHOSTS_GROUP	0xe0000001U	/* 224.0.0.1   */
#define	INADDR_ALLRTRS_GROUP	0xe0000002U	/* 224.0.0.2   */
#define	INADDR_ALLRPTS_GROUP	0xe0000016U	/* 224.0.0.22, IGMPv3 */
#define	INADDR_MAX_LOCAL_GROUP	0xe00000ffU	/* 224.0.0.255 */

/* Scoped IPv4 prefixes (in host byte-order) */
#define	IN_AUTOCONF_NET		0xa9fe0000U	/* 169.254/16 */
#define	IN_AUTOCONF_MASK	0xffff0000U
#define	IN_PRIVATE8_NET		0x0a000000U	/* 10/8 */
#define	IN_PRIVATE8_MASK	0xff000000U
#define	IN_PRIVATE12_NET	0xac100000U	/* 172.16/12 */
#define	IN_PRIVATE12_MASK	0xfff00000U
#define	IN_PRIVATE16_NET	0xc0a80000U	/* 192.168/16 */
#define	IN_PRIVATE16_MASK	0xffff0000U

/* RFC 3927 IPv4 link local address (i in host byte-order) */
#define	IN_LINKLOCAL(i)		(((i) & IN_AUTOCONF_MASK) == IN_AUTOCONF_NET)

/* Well known 6to4 Relay Router Anycast address defined in RFC 3068 */
#if !defined(_XPG4_2) || !defined(__EXTENSIONS__)
#define	INADDR_6TO4RRANYCAST	0xc0586301U 	/* 192.88.99.1 */
#endif	/* !defined(_XPG4_2) || !defined(__EXTENSIONS__) */

#define	IN_LOOPBACKNET		127			/* official! */

/*
 * Define a macro to stuff the loopback address into an Internet address
 */
#if !defined(_XPG4_2) || !defined(__EXTENSIONS__)
#define	IN_SET_LOOPBACK_ADDR(a) \
	{ (a)->sin_addr.s_addr  = htonl(INADDR_LOOPBACK); \
	(a)->sin_family = AF_INET; }
#endif /* !defined(_XPG4_2) || !defined(__EXTENSIONS__) */

/*
 * IPv4 Socket address.
 */
struct sockaddr_in {
	sa_family_t	sin_family;
	in_port_t	sin_port;
	struct	in_addr sin_addr;
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
	char		sin_zero[8];
#else
	unsigned char	sin_zero[8];
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */
};

#if !defined(_XPG4_2) || defined(_XPG6) || defined(__EXTENSIONS__)
/*
 * IPv6 socket address.
 */
struct sockaddr_in6 {
	sa_family_t	sin6_family;
	in_port_t	sin6_port;
	uint32_t	sin6_flowinfo;
	struct in6_addr	sin6_addr;
	uint32_t	sin6_scope_id;  /* Depends on scope of sin6_addr */
	uint32_t	__sin6_src_id;	/* Impl. specific - UDP replies */
};

/*
 * Macros for accessing the traffic class and flow label fields from
 * sin6_flowinfo.
 * These are designed to be applied to a 32-bit value.
 */
#ifdef _BIG_ENDIAN

/* masks */
#define	IPV6_FLOWINFO_FLOWLABEL			0x000fffffU
#define	IPV6_FLOWINFO_TCLASS			0x0ff00000U

#else /* _BIG_ENDIAN */

/* masks */
#define	IPV6_FLOWINFO_FLOWLABEL			0xffff0f00U
#define	IPV6_FLOWINFO_TCLASS			0x0000f00fU

#endif	/* _BIG_ENDIAN */

/*
 * Note: Macros IN6ADDR_ANY_INIT and IN6ADDR_LOOPBACK_INIT are for
 * use as RHS of Static initializers of "struct in6_addr" (or in6_addr_t)
 * only. They need to be different for User/Kernel versions because union
 * component data structure is defined differently (it is identical at
 * binary representation level).
 *
 * const struct in6_addr IN6ADDR_ANY_INIT;
 * const struct in6_addr IN6ADDR_LOOPBACK_INIT;
 */


#ifdef _KERNEL
#define	IN6ADDR_ANY_INIT		{ 0, 0, 0, 0 }

#ifdef _BIG_ENDIAN
#define	IN6ADDR_LOOPBACK_INIT		{ 0, 0, 0, 0x00000001U }
#else /* _BIG_ENDIAN */
#define	IN6ADDR_LOOPBACK_INIT		{ 0, 0, 0, 0x01000000U }
#endif /* _BIG_ENDIAN */

#else

#define	IN6ADDR_ANY_INIT	    {	0, 0, 0, 0,	\
					0, 0, 0, 0,	\
					0, 0, 0, 0, 	\
					0, 0, 0, 0 }

#define	IN6ADDR_LOOPBACK_INIT	    {	0, 0, 0, 0,	\
					0, 0, 0, 0,	\
					0, 0, 0, 0,	\
					0, 0, 0, 0x1U }
#endif /* _KERNEL */

/*
 * RFC 2553 specifies the following macros. Their type is defined
 * as "int" in the RFC but they only have boolean significance
 * (zero or non-zero). For the purposes of our comment notation,
 * we assume a hypothetical type "bool" defined as follows to
 * write the prototypes assumed for macros in our comments better.
 *
 * typedef int bool;
 */

/*
 * IN6 macros used to test for special IPv6 addresses
 * (Mostly from spec)
 *
 * bool  IN6_IS_ADDR_UNSPECIFIED (const struct in6_addr *);
 * bool  IN6_IS_ADDR_LOOPBACK    (const struct in6_addr *);
 * bool  IN6_IS_ADDR_MULTICAST   (const struct in6_addr *);
 * bool  IN6_IS_ADDR_LINKLOCAL   (const struct in6_addr *);
 * bool  IN6_IS_ADDR_SITELOCAL   (const struct in6_addr *);
 * bool  IN6_IS_ADDR_V4MAPPED    (const struct in6_addr *);
 * bool  IN6_IS_ADDR_V4MAPPED_ANY(const struct in6_addr *); -- Not from RFC2553
 * bool  IN6_IS_ADDR_V4COMPAT    (const struct in6_addr *);
 * bool  IN6_IS_ADDR_MC_RESERVED (const struct in6_addr *); -- Not from RFC2553
 * bool  IN6_IS_ADDR_MC_NODELOCAL(const struct in6_addr *);
 * bool  IN6_IS_ADDR_MC_LINKLOCAL(const struct in6_addr *);
 * bool  IN6_IS_ADDR_MC_SITELOCAL(const struct in6_addr *);
 * bool  IN6_IS_ADDR_MC_ORGLOCAL (const struct in6_addr *);
 * bool  IN6_IS_ADDR_MC_GLOBAL   (const struct in6_addr *);
 * bool  IN6_IS_ADDR_6TO4	 (const struct in6_addr *); -- Not from RFC2553
 * bool  IN6_ARE_6TO4_PREFIX_EQUAL(const struct in6_addr *,
 *	     const struct in6_addr *);			    -- Not from RFC2553
 * bool  IN6_IS_ADDR_LINKSCOPE	 (const struct in6addr  *); -- Not from RFC2553
 */

#define	IN6_IS_ADDR_UNSPECIFIED(addr) \
	(((addr)->_S6_un._S6_u32[3] == 0) && \
	((addr)->_S6_un._S6_u32[2] == 0) && \
	((addr)->_S6_un._S6_u32[1] == 0) && \
	((addr)->_S6_un._S6_u32[0] == 0))

#ifdef _BIG_ENDIAN
#define	IN6_IS_ADDR_LOOPBACK(addr) \
	(((addr)->_S6_un._S6_u32[3] == 0x00000001) && \
	((addr)->_S6_un._S6_u32[2] == 0) && \
	((addr)->_S6_un._S6_u32[1] == 0) && \
	((addr)->_S6_un._S6_u32[0] == 0))
#else /* _BIG_ENDIAN */
#define	IN6_IS_ADDR_LOOPBACK(addr) \
	(((addr)->_S6_un._S6_u32[3] == 0x01000000) && \
	((addr)->_S6_un._S6_u32[2] == 0) && \
	((addr)->_S6_un._S6_u32[1] == 0) && \
	((addr)->_S6_un._S6_u32[0] == 0))
#endif /* _BIG_ENDIAN */

#ifdef _BIG_ENDIAN
#define	IN6_IS_ADDR_MULTICAST(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0xff000000) == 0xff000000)
#else /* _BIG_ENDIAN */
#define	IN6_IS_ADDR_MULTICAST(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0x000000ff) == 0x000000ff)
#endif /* _BIG_ENDIAN */

#ifdef _BIG_ENDIAN
#define	IN6_IS_ADDR_LINKLOCAL(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0xffc00000) == 0xfe800000)
#else /* _BIG_ENDIAN */
#define	IN6_IS_ADDR_LINKLOCAL(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0x0000c0ff) == 0x000080fe)
#endif /* _BIG_ENDIAN */

#ifdef _BIG_ENDIAN
#define	IN6_IS_ADDR_SITELOCAL(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0xffc00000) == 0xfec00000)
#else /* _BIG_ENDIAN */
#define	IN6_IS_ADDR_SITELOCAL(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0x0000c0ff) == 0x0000c0fe)
#endif /* _BIG_ENDIAN */

#ifdef _BIG_ENDIAN
#define	IN6_IS_ADDR_V4MAPPED(addr) \
	(((addr)->_S6_un._S6_u32[2] == 0x0000ffff) && \
	((addr)->_S6_un._S6_u32[1] == 0) && \
	((addr)->_S6_un._S6_u32[0] == 0))
#else  /* _BIG_ENDIAN */
#define	IN6_IS_ADDR_V4MAPPED(addr) \
	(((addr)->_S6_un._S6_u32[2] == 0xffff0000U) && \
	((addr)->_S6_un._S6_u32[1] == 0) && \
	((addr)->_S6_un._S6_u32[0] == 0))
#endif /* _BIG_ENDIAN */

/*
 * IN6_IS_ADDR_V4MAPPED - A IPv4 mapped INADDR_ANY
 * Note: This macro is currently NOT defined in RFC2553 specification
 * and not a standard macro that portable applications should use.
 */
#ifdef _BIG_ENDIAN
#define	IN6_IS_ADDR_V4MAPPED_ANY(addr) \
	(((addr)->_S6_un._S6_u32[3] == 0) && \
	((addr)->_S6_un._S6_u32[2] == 0x0000ffff) && \
	((addr)->_S6_un._S6_u32[1] == 0) && \
	((addr)->_S6_un._S6_u32[0] == 0))
#else  /* _BIG_ENDIAN */
#define	IN6_IS_ADDR_V4MAPPED_ANY(addr) \
	(((addr)->_S6_un._S6_u32[3] == 0) && \
	((addr)->_S6_un._S6_u32[2] == 0xffff0000U) && \
	((addr)->_S6_un._S6_u32[1] == 0) && \
	((addr)->_S6_un._S6_u32[0] == 0))
#endif /* _BIG_ENDIAN */

/* Exclude loopback and unspecified address */
#ifdef _BIG_ENDIAN
#define	IN6_IS_ADDR_V4COMPAT(addr) \
	(((addr)->_S6_un._S6_u32[2] == 0) && \
	((addr)->_S6_un._S6_u32[1] == 0) && \
	((addr)->_S6_un._S6_u32[0] == 0) && \
	!((addr)->_S6_un._S6_u32[3] == 0) && \
	!((addr)->_S6_un._S6_u32[3] == 0x00000001))

#else /* _BIG_ENDIAN */
#define	IN6_IS_ADDR_V4COMPAT(addr) \
	(((addr)->_S6_un._S6_u32[2] == 0) && \
	((addr)->_S6_un._S6_u32[1] == 0) && \
	((addr)->_S6_un._S6_u32[0] == 0) && \
	!((addr)->_S6_un._S6_u32[3] == 0) && \
	!((addr)->_S6_un._S6_u32[3] == 0x01000000))
#endif /* _BIG_ENDIAN */

/*
 * Note:
 * IN6_IS_ADDR_MC_RESERVED macro is currently NOT defined in RFC2553
 * specification and not a standard macro that portable applications
 * should use.
 */
#ifdef _BIG_ENDIAN
#define	IN6_IS_ADDR_MC_RESERVED(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0xff0f0000) == 0xff000000)

#else  /* _BIG_ENDIAN */
#define	IN6_IS_ADDR_MC_RESERVED(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0x00000fff) == 0x000000ff)
#endif /* _BIG_ENDIAN */

#ifdef _BIG_ENDIAN
#define	IN6_IS_ADDR_MC_NODELOCAL(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0xff0f0000) == 0xff010000)
#else  /* _BIG_ENDIAN */
#define	IN6_IS_ADDR_MC_NODELOCAL(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0x00000fff) == 0x000001ff)
#endif /* _BIG_ENDIAN */

#ifdef _BIG_ENDIAN
#define	IN6_IS_ADDR_MC_LINKLOCAL(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0xff0f0000) == 0xff020000)
#else  /* _BIG_ENDIAN */
#define	IN6_IS_ADDR_MC_LINKLOCAL(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0x00000fff) == 0x000002ff)
#endif /* _BIG_ENDIAN */

#ifdef _BIG_ENDIAN
#define	IN6_IS_ADDR_MC_SITELOCAL(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0xff0f0000) == 0xff050000)
#else  /* _BIG_ENDIAN */
#define	IN6_IS_ADDR_MC_SITELOCAL(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0x00000fff) == 0x000005ff)
#endif /* _BIG_ENDIAN */

#ifdef _BIG_ENDIAN
#define	IN6_IS_ADDR_MC_ORGLOCAL(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0xff0f0000) == 0xff080000)
#else  /* _BIG_ENDIAN */
#define	IN6_IS_ADDR_MC_ORGLOCAL(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0x00000fff) == 0x000008ff)
#endif /* _BIG_ENDIAN */

#ifdef _BIG_ENDIAN
#define	IN6_IS_ADDR_MC_GLOBAL(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0xff0f0000) == 0xff0e0000)
#else /* _BIG_ENDIAN */
#define	IN6_IS_ADDR_MC_GLOBAL(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0x00000fff) == 0x00000eff)
#endif /* _BIG_ENDIAN */

/*
 * The IN6_IS_ADDR_MC_SOLICITEDNODE macro is not defined in any standard or
 * RFC, and shouldn't be used by portable applications.  It is used to see
 * if an address is a solicited-node multicast address, which is prefixed
 * with ff02:0:0:0:0:1:ff00::/104.
 */
#ifdef _BIG_ENDIAN
#define	IN6_IS_ADDR_MC_SOLICITEDNODE(addr)			\
	(((addr)->_S6_un._S6_u32[0] == 0xff020000) &&		\
	((addr)->_S6_un._S6_u32[1] == 0x00000000) &&		\
	((addr)->_S6_un._S6_u32[2] == 0x00000001) &&		\
	(((addr)->_S6_un._S6_u32[3] & 0xff000000) == 0xff000000))
#else
#define	IN6_IS_ADDR_MC_SOLICITEDNODE(addr)			\
	(((addr)->_S6_un._S6_u32[0] == 0x000002ff) &&		\
	((addr)->_S6_un._S6_u32[1] == 0x00000000) &&		\
	((addr)->_S6_un._S6_u32[2] == 0x01000000) &&		\
	(((addr)->_S6_un._S6_u32[3] & 0x000000ff) == 0x000000ff))
#endif

/*
 * Macros to a) test for 6to4 IPv6 address, and b) to test if two
 * 6to4 addresses have the same /48 prefix, and, hence, are from the
 * same 6to4 site.
 */

#ifdef _BIG_ENDIAN
#define	IN6_IS_ADDR_6TO4(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0xffff0000) == 0x20020000)
#else /* _BIG_ENDIAN */
#define	IN6_IS_ADDR_6TO4(addr) \
	(((addr)->_S6_un._S6_u32[0] & 0x0000ffff) == 0x00000220)
#endif /* _BIG_ENDIAN */

#define	IN6_ARE_6TO4_PREFIX_EQUAL(addr1, addr2) \
	(((addr1)->_S6_un._S6_u32[0] == (addr2)->_S6_un._S6_u32[0]) && \
	((addr1)->_S6_un._S6_u8[4] == (addr2)->_S6_un._S6_u8[4]) && \
	((addr1)->_S6_un._S6_u8[5] == (addr2)->_S6_un._S6_u8[5]))

/*
 * IN6_IS_ADDR_LINKSCOPE
 * Identifies an address as being either link-local, link-local multicast or
 * node-local multicast.  All types of addresses are considered to be unique
 * within the scope of a given link.
 */
#define	IN6_IS_ADDR_LINKSCOPE(addr) \
	(IN6_IS_ADDR_LINKLOCAL(addr) || IN6_IS_ADDR_MC_LINKLOCAL(addr) || \
	IN6_IS_ADDR_MC_NODELOCAL(addr))

/*
 * Useful utility macros for operations with IPv6 addresses
 * Note: These macros are NOT defined in the RFC2553 or any other
 * standard specification and are not standard macros that portable
 * applications should use.
 */

/*
 * IN6_V4MAPPED_TO_INADDR
 * IN6_V4MAPPED_TO_IPADDR
 *	Assign a IPv4-Mapped IPv6 address to an IPv4 address.
 *	Note: These macros are NOT defined in RFC2553 or any other standard
 *	specification and are not macros that portable applications should
 *	use.
 *
 * void IN6_V4MAPPED_TO_INADDR(const in6_addr_t *v6, struct in_addr *v4);
 * void IN6_V4MAPPED_TO_IPADDR(const in6_addr_t *v6, ipaddr_t v4);
 *
 */
#define	IN6_V4MAPPED_TO_INADDR(v6, v4) \
	((v4)->s_addr = (v6)->_S6_un._S6_u32[3])
#define	IN6_V4MAPPED_TO_IPADDR(v6, v4) \
	((v4) = (v6)->_S6_un._S6_u32[3])

/*
 * IN6_INADDR_TO_V4MAPPED
 * IN6_IPADDR_TO_V4MAPPED
 *	Assign a IPv4 address address to an IPv6 address as a IPv4-mapped
 *	address.
 *	Note: These macros are NOT defined in RFC2553 or any other standard
 *	specification and are not macros that portable applications should
 *	use.
 *
 * void IN6_INADDR_TO_V4MAPPED(const struct in_addr *v4, in6_addr_t *v6);
 * void IN6_IPADDR_TO_V4MAPPED(const ipaddr_t v4, in6_addr_t *v6);
 *
 */
#ifdef _BIG_ENDIAN
#define	IN6_INADDR_TO_V4MAPPED(v4, v6) \
	((v6)->_S6_un._S6_u32[3] = (v4)->s_addr, \
	(v6)->_S6_un._S6_u32[2] = 0x0000ffff, \
	(v6)->_S6_un._S6_u32[1] = 0, \
	(v6)->_S6_un._S6_u32[0] = 0)
#define	IN6_IPADDR_TO_V4MAPPED(v4, v6) \
	((v6)->_S6_un._S6_u32[3] = (v4), \
	(v6)->_S6_un._S6_u32[2] = 0x0000ffff, \
	(v6)->_S6_un._S6_u32[1] = 0, \
	(v6)->_S6_un._S6_u32[0] = 0)
#else /* _BIG_ENDIAN */
#define	IN6_INADDR_TO_V4MAPPED(v4, v6) \
	((v6)->_S6_un._S6_u32[3] = (v4)->s_addr, \
	(v6)->_S6_un._S6_u32[2] = 0xffff0000U, \
	(v6)->_S6_un._S6_u32[1] = 0, \
	(v6)->_S6_un._S6_u32[0] = 0)
#define	IN6_IPADDR_TO_V4MAPPED(v4, v6) \
	((v6)->_S6_un._S6_u32[3] = (v4), \
	(v6)->_S6_un._S6_u32[2] = 0xffff0000U, \
	(v6)->_S6_un._S6_u32[1] = 0, \
	(v6)->_S6_un._S6_u32[0] = 0)
#endif /* _BIG_ENDIAN */

/*
 * IN6_6TO4_TO_V4ADDR
 *	Extract the embedded IPv4 address from the prefix to a 6to4 IPv6
 *      address.
 *	Note: This macro is NOT defined in RFC2553 or any other standard
 *	specification and is not a macro that portable applications should
 *	use.
 *	Note: we don't use the IPADDR form of the macro because we need
 *	to do a bytewise copy; the V4ADDR in the 6to4 address is not
 *	32-bit aligned.
 *
 * void IN6_6TO4_TO_V4ADDR(const in6_addr_t *v6, struct in_addr *v4);
 *
 */
#define	IN6_6TO4_TO_V4ADDR(v6, v4) \
	((v4)->_S_un._S_un_b.s_b1 = (v6)->_S6_un._S6_u8[2], \
	(v4)->_S_un._S_un_b.s_b2 = (v6)->_S6_un._S6_u8[3],  \
	(v4)->_S_un._S_un_b.s_b3 = (v6)->_S6_un._S6_u8[4],  \
	(v4)->_S_un._S_un_b.s_b4 = (v6)->_S6_un._S6_u8[5])

/*
 * IN6_V4ADDR_TO_6TO4
 *	Given an IPv4 address and an IPv6 address for output, a 6to4 address
 *	will be created from the IPv4 Address.
 *	Note:  This method for creating 6to4 addresses is not standardized
 *	outside of Solaris.  The newly created 6to4 address will be of the form
 *	2002:<V4ADDR>:<SUBNETID>::<HOSTID>, where SUBNETID will equal 0 and
 *	HOSTID will equal 1.
 *
 * void IN6_V4ADDR_TO_6TO4(const struct in_addr *v4, in6_addr_t *v6)
 *
 */
#ifdef _BIG_ENDIAN
#define	IN6_V4ADDR_TO_6TO4(v4, v6) \
	((v6)->_S6_un._S6_u8[0] = 0x20, \
	(v6)->_S6_un._S6_u8[1] = 0x02, \
	(v6)->_S6_un._S6_u8[2] = (v4)->_S_un._S_un_b.s_b1, \
	(v6)->_S6_un._S6_u8[3] = (v4)->_S_un._S_un_b.s_b2, \
	(v6)->_S6_un._S6_u8[4] = (v4)->_S_un._S_un_b.s_b3, \
	(v6)->_S6_un._S6_u8[5] = (v4)->_S_un._S_un_b.s_b4, \
	(v6)->_S6_un._S6_u8[6] = 0, \
	(v6)->_S6_un._S6_u8[7] = 0, \
	(v6)->_S6_un._S6_u32[2] = 0, \
	(v6)->_S6_un._S6_u32[3] = 0x00000001U)
#else
#define	IN6_V4ADDR_TO_6TO4(v4, v6) \
	((v6)->_S6_un._S6_u8[0] = 0x20, \
	(v6)->_S6_un._S6_u8[1] = 0x02, \
	(v6)->_S6_un._S6_u8[2] = (v4)->_S_un._S_un_b.s_b1, \
	(v6)->_S6_un._S6_u8[3] = (v4)->_S_un._S_un_b.s_b2, \
	(v6)->_S6_un._S6_u8[4] = (v4)->_S_un._S_un_b.s_b3, \
	(v6)->_S6_un._S6_u8[5] = (v4)->_S_un._S_un_b.s_b4, \
	(v6)->_S6_un._S6_u8[6] = 0, \
	(v6)->_S6_un._S6_u8[7] = 0, \
	(v6)->_S6_un._S6_u32[2] = 0, \
	(v6)->_S6_un._S6_u32[3] = 0x01000000U)
#endif /* _BIG_ENDIAN */

/*
 * IN6_ARE_ADDR_EQUAL (defined in RFC2292)
 *	 Compares if IPv6 addresses are equal.
 * Note: Compares in order of high likelyhood of a miss so we minimize
 * compares. (Current heuristic order, compare in reverse order of
 * uint32_t units)
 *
 * bool  IN6_ARE_ADDR_EQUAL(const struct in6_addr *,
 *			    const struct in6_addr *);
 */
#define	IN6_ARE_ADDR_EQUAL(addr1, addr2) \
	(((addr1)->_S6_un._S6_u32[3] == (addr2)->_S6_un._S6_u32[3]) && \
	((addr1)->_S6_un._S6_u32[2] == (addr2)->_S6_un._S6_u32[2]) && \
	((addr1)->_S6_un._S6_u32[1] == (addr2)->_S6_un._S6_u32[1]) && \
	((addr1)->_S6_un._S6_u32[0] == (addr2)->_S6_un._S6_u32[0]))

/*
 * IN6_ARE_PREFIXEDADDR_EQUAL (not defined in RFCs)
 *	Compares if prefixed parts of IPv6 addresses are equal.
 *
 * uint32_t IN6_MASK_FROM_PREFIX(int, int);
 * bool     IN6_ARE_PREFIXEDADDR_EQUAL(const struct in6_addr *,
 *				       const struct in6_addr *,
 *				       int);
 */
#define	IN6_MASK_FROM_PREFIX(qoctet, prefix) \
	((((qoctet) + 1) * 32 < (prefix)) ? 0xFFFFFFFFu : \
	((((qoctet) * 32) >= (prefix)) ? 0x00000000u : \
	0xFFFFFFFFu << (((qoctet) + 1) * 32 - (prefix))))

#define	IN6_ARE_PREFIXEDADDR_EQUAL(addr1, addr2, prefix) \
	(((ntohl((addr1)->_S6_un._S6_u32[0]) & \
	IN6_MASK_FROM_PREFIX(0, prefix)) == \
	(ntohl((addr2)->_S6_un._S6_u32[0]) & \
	IN6_MASK_FROM_PREFIX(0, prefix))) && \
	((ntohl((addr1)->_S6_un._S6_u32[1]) & \
	IN6_MASK_FROM_PREFIX(1, prefix)) == \
	(ntohl((addr2)->_S6_un._S6_u32[1]) & \
	IN6_MASK_FROM_PREFIX(1, prefix))) && \
	((ntohl((addr1)->_S6_un._S6_u32[2]) & \
	IN6_MASK_FROM_PREFIX(2, prefix)) == \
	(ntohl((addr2)->_S6_un._S6_u32[2]) & \
	IN6_MASK_FROM_PREFIX(2, prefix))) && \
	((ntohl((addr1)->_S6_un._S6_u32[3]) & \
	IN6_MASK_FROM_PREFIX(3, prefix)) == \
	(ntohl((addr2)->_S6_un._S6_u32[3]) & \
	IN6_MASK_FROM_PREFIX(3, prefix))))

#endif /* !defined(_XPG4_2) || defined(_XPG6) || defined(__EXTENSIONS__) */


/*
 * Options for use with [gs]etsockopt at the IP level.
 *
 * Note: Some of the IP_ namespace has conflict with and
 * and is exposed through <xti.h>. (It also requires exposing
 * options not implemented). The options with potential
 * for conflicts use #ifndef guards.
 */
#ifndef IP_OPTIONS
#define	IP_OPTIONS	1	/* set/get IP per-packet options   */
#endif

#define	IP_HDRINCL	2	/* int; header is included with data (raw) */

#ifndef IP_TOS
#define	IP_TOS		3	/* int; IP type of service and precedence */
#endif

#ifndef IP_TTL
#define	IP_TTL		4	/* int; IP time to live */
#endif

#define	IP_RECVOPTS	0x5	/* int; receive all IP options w/datagram */
#define	IP_RECVRETOPTS	0x6	/* int; receive IP options for response */
#define	IP_RECVDSTADDR	0x7	/* int; receive IP dst addr w/datagram */
#define	IP_RETOPTS	0x8	/* ip_opts; set/get IP per-packet options */
#define	IP_RECVIF	0x9	/* int; receive the inbound interface index */
#define	IP_RECVSLLA	0xa	/* sockaddr_dl; get source link layer address */
#define	IP_RECVTTL	0xb	/* uint8_t; get TTL for inbound packet */

#define	IP_MULTICAST_IF		0x10	/* set/get IP multicast interface  */
#define	IP_MULTICAST_TTL	0x11	/* set/get IP multicast timetolive */
#define	IP_MULTICAST_LOOP	0x12	/* set/get IP multicast loopback   */
#define	IP_ADD_MEMBERSHIP	0x13	/* add	an IP group membership	   */
#define	IP_DROP_MEMBERSHIP	0x14	/* drop an IP group membership	   */
#define	IP_BLOCK_SOURCE		0x15	/* block   mcast pkts from source  */
#define	IP_UNBLOCK_SOURCE	0x16	/* unblock mcast pkts from source  */
#define	IP_ADD_SOURCE_MEMBERSHIP  0x17	/* add  mcast group/source pair	   */
#define	IP_DROP_SOURCE_MEMBERSHIP 0x18	/* drop mcast group/source pair	   */
#define	IP_NEXTHOP		0x19	/* send directly to next hop	   */
/*
 * IP_PKTINFO and IP_RECVPKTINFO have same value. Size of argument passed in
 * is used to differentiate b/w the two.
 */
#define	IP_PKTINFO		0x1a	/* specify src address and/or index */
#define	IP_RECVPKTINFO		0x1a	/* recv dest/matched addr and index */
#define	IP_DONTFRAG		0x1b	/* don't fragment packets */

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
/*
 * Different preferences that can be requested from IPSEC protocols.
 */
#define	IP_SEC_OPT		0x22	/* Used to set IPSEC options */
#define	IPSEC_PREF_NEVER	0x01
#define	IPSEC_PREF_REQUIRED	0x02
#define	IPSEC_PREF_UNIQUE	0x04
/*
 * This can be used with the setsockopt() call to set per socket security
 * options. When the application uses per-socket API, we will reflect
 * the request on both outbound and inbound packets.
 */

typedef struct ipsec_req {
	uint_t 		ipsr_ah_req;		/* AH request */
	uint_t 		ipsr_esp_req;		/* ESP request */
	uint_t		ipsr_self_encap_req;	/* Self-Encap request */
	uint8_t		ipsr_auth_alg;		/* Auth algs for AH */
	uint8_t		ipsr_esp_alg;		/* Encr algs for ESP */
	uint8_t		ipsr_esp_auth_alg;	/* Auth algs for ESP */
} ipsec_req_t;

/*
 * MCAST_* options are protocol-independent.  The actual definitions
 * are with the v6 options below; this comment is here to note the
 * namespace usage.
 *
 * #define	MCAST_JOIN_GROUP	0x29
 * #define	MCAST_LEAVE_GROUP	0x2a
 * #define	MCAST_BLOCK_SOURCE	0x2b
 * #define	MCAST_UNBLOCK_SOURCE	0x2c
 * #define	MCAST_JOIN_SOURCE_GROUP	0x2d
 * #define	MCAST_LEAVE_SOURCE_GROUP 0x2e
 */
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

/*
 * SunOS private (potentially not portable) IP_ option names
 */
#define	IP_BOUND_IF		0x41	/* bind socket to an ifindex	   */
#define	IP_UNSPEC_SRC		0x42	/* use unspecified source address  */
#define	IP_BROADCAST_TTL	0x43	/* use specific TTL for broadcast  */
/* can be reused		0x44 */
#define	IP_DHCPINIT_IF		0x45	/* accept all unicast DHCP traffic */

/*
 * Option values and names (when !_XPG5) shared with <xti_inet.h>
 */
#ifndef IP_REUSEADDR
#define	IP_REUSEADDR		0x104
#endif

#ifndef IP_DONTROUTE
#define	IP_DONTROUTE		0x105
#endif

#ifndef IP_BROADCAST
#define	IP_BROADCAST		0x106
#endif

/*
 * The following option values are reserved by <xti_inet.h>
 *
 * T_IP_OPTIONS	0x107	 -  IP per-packet options
 * T_IP_TOS	0x108	 -  IP per packet type of service
 */

/*
 * Default value constants for multicast attributes controlled by
 * IP*_MULTICAST_LOOP and IP*_MULTICAST_{TTL,HOPS} options.
 */
#define	IP_DEFAULT_MULTICAST_TTL  1	/* normally limit m'casts to 1 hop */
#define	IP_DEFAULT_MULTICAST_LOOP 1	/* normally hear sends if a member */

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
/*
 * Argument structure for IP_ADD_MEMBERSHIP and IP_DROP_MEMBERSHIP.
 */
struct ip_mreq {
	struct in_addr	imr_multiaddr;	/* IP multicast address of group */
	struct in_addr	imr_interface;	/* local IP address of interface */
};

/*
 * Argument structure for IP_BLOCK_SOURCE, IP_UNBLOCK_SOURCE,
 * IP_ADD_SOURCE_MEMBERSHIP, and IP_DROP_SOURCE_MEMBERSHIP.
 */
struct ip_mreq_source {
	struct in_addr	imr_multiaddr;	/* IP address of group */
	struct in_addr	imr_sourceaddr;	/* IP address of source */
	struct in_addr	imr_interface;	/* IP address of interface */
};

/*
 * Argument structure for IPV6_JOIN_GROUP and IPV6_LEAVE_GROUP on
 * IPv6 addresses.
 */
struct ipv6_mreq {
	struct in6_addr	ipv6mr_multiaddr;	/* IPv6 multicast addr */
	unsigned int	ipv6mr_interface;	/* interface index */
};

/*
 * Use #pragma pack() construct to force 32-bit alignment on amd64.
 * This is needed to keep the structure size and offsets consistent
 * between a 32-bit app and the 64-bit amd64 kernel in structures
 * where 64-bit alignment would create gaps (in this case, structures
 * which have a uint32_t followed by a struct sockaddr_storage).
 */
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

/*
 * Argument structure for MCAST_JOIN_GROUP and MCAST_LEAVE_GROUP.
 */
struct group_req {
	uint32_t		gr_interface;	/* interface index */
	struct sockaddr_storage	gr_group;	/* group address */
};

/*
 * Argument structure for MCAST_BLOCK_SOURCE, MCAST_UNBLOCK_SOURCE,
 * MCAST_JOIN_SOURCE_GROUP, MCAST_LEAVE_SOURCE_GROUP.
 */
struct group_source_req {
	uint32_t		gsr_interface;	/* interface index */
	struct sockaddr_storage	gsr_group;	/* group address */
	struct sockaddr_storage	gsr_source;	/* source address */
};

/*
 * Argument for SIOC[GS]MSFILTER ioctls
 */
struct group_filter {
	uint32_t		gf_interface;	/* interface index */
	struct sockaddr_storage	gf_group;	/* multicast address */
	uint32_t		gf_fmode;	/* filter mode */
	uint32_t		gf_numsrc;	/* number of sources */
	struct sockaddr_storage	gf_slist[1];	/* source address */
};

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#define	GROUP_FILTER_SIZE(numsrc) \
	(sizeof (struct group_filter) - sizeof (struct sockaddr_storage) \
	+ (numsrc) * sizeof (struct sockaddr_storage))

/*
 * Argument for SIOC[GS]IPMSFILTER ioctls (IPv4-specific)
 */
struct ip_msfilter {
	struct in_addr	imsf_multiaddr;	/* IP multicast address of group */
	struct in_addr	imsf_interface;	/* local IP address of interface */
	uint32_t	imsf_fmode;	/* filter mode */
	uint32_t	imsf_numsrc;	/* number of sources in src_list */
	struct in_addr	imsf_slist[1];	/* start of source list */
};

#define	IP_MSFILTER_SIZE(numsrc) \
	(sizeof (struct ip_msfilter) - sizeof (struct in_addr) \
	+ (numsrc) * sizeof (struct in_addr))

/*
 * Multicast source filter manipulation functions in libsocket;
 * defined in RFC 3678.
 */
int setsourcefilter(int, uint32_t, struct sockaddr *, socklen_t, uint32_t,
			uint_t, struct sockaddr_storage *);

int getsourcefilter(int, uint32_t, struct sockaddr *, socklen_t, uint32_t *,
			uint_t *, struct sockaddr_storage *);

int setipv4sourcefilter(int, struct in_addr, struct in_addr, uint32_t,
			uint32_t, struct in_addr *);

int getipv4sourcefilter(int, struct in_addr, struct in_addr, uint32_t *,
			uint32_t *, struct in_addr *);

/*
 * Definitions needed for [gs]etsourcefilter(), [gs]etipv4sourcefilter()
 */
#define	MCAST_INCLUDE	1
#define	MCAST_EXCLUDE	2

/*
 * Argument struct for IP_PKTINFO option
 */
typedef struct in_pktinfo {
	unsigned int		ipi_ifindex;	/* send/recv interface index */
	struct in_addr		ipi_spec_dst;	/* matched source address */
	struct in_addr		ipi_addr;	/* src/dst address in IP hdr */
} in_pktinfo_t;

/*
 * Argument struct for IPV6_PKTINFO option
 */
struct in6_pktinfo {
	struct in6_addr		ipi6_addr;	/* src/dst IPv6 address */
	unsigned int		ipi6_ifindex;	/* send/recv interface index */
};

/*
 * Argument struct for IPV6_MTUINFO option
 */
struct ip6_mtuinfo {
	struct sockaddr_in6	ip6m_addr; /* dst address including zone ID */
	uint32_t		ip6m_mtu;  /* path MTU in host byte order */
};

/*
 * IPv6 routing header types
 */
#define	IPV6_RTHDR_TYPE_0	0

extern socklen_t inet6_rth_space(int type, int segments);
extern void *inet6_rth_init(void *bp, socklen_t bp_len, int type, int segments);
extern int inet6_rth_add(void *bp, const struct in6_addr *addr);
extern int inet6_rth_reverse(const void *in, void *out);
extern int inet6_rth_segments(const void *bp);
extern struct in6_addr *inet6_rth_getaddr(const void *bp, int index);

extern int inet6_opt_init(void *extbuf, socklen_t extlen);
extern int inet6_opt_append(void *extbuf, socklen_t extlen, int offset,
	uint8_t type, socklen_t len, uint_t align, void **databufp);
extern int inet6_opt_finish(void *extbuf, socklen_t extlen, int offset);
extern int inet6_opt_set_val(void *databuf, int offset, void *val,
	socklen_t vallen);
extern int inet6_opt_next(void *extbuf, socklen_t extlen, int offset,
	uint8_t *typep, socklen_t *lenp, void **databufp);
extern int inet6_opt_find(void *extbufp, socklen_t extlen, int offset,
	uint8_t type, socklen_t *lenp, void **databufp);
extern int inet6_opt_get_val(void *databuf, int offset, void *val,
	socklen_t vallen);
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

/*
 * Argument structure for IP_ADD_PROXY_ADDR.
 * Note that this is an unstable, experimental interface. It may change
 * later. Don't use it unless you know what it is.
 */
typedef struct {
	struct in_addr	in_prefix_addr;
	unsigned int	in_prefix_len;
} in_prefix_t;


#if !defined(_XPG4_2) || defined(_XPG6) || defined(__EXTENSIONS__)
/*
 * IPv6 options
 */
#define	IPV6_UNICAST_HOPS	0x5	/* hop limit value for unicast */
					/* packets. */
					/* argument type: uint_t */
#define	IPV6_MULTICAST_IF	0x6	/* outgoing interface for */
					/* multicast packets. */
					/* argument type: struct in6_addr */
#define	IPV6_MULTICAST_HOPS	0x7	/* hop limit value to use for */
					/* multicast packets. */
					/* argument type: uint_t */
#define	IPV6_MULTICAST_LOOP	0x8	/* enable/disable delivery of */
					/* multicast packets on same socket. */
					/* argument type: uint_t */
#define	IPV6_JOIN_GROUP		0x9	/* join an IPv6 multicast group. */
					/* argument type: struct ipv6_mreq */
#define	IPV6_LEAVE_GROUP	0xa	/* leave an IPv6 multicast group */
					/* argument type: struct ipv6_mreq */

/*
 * Other XPG6 constants.
 */
#define	INET_ADDRSTRLEN		16	/* max len IPv4 addr in ascii dotted */
					/* decimal notation. */
#define	INET6_ADDRSTRLEN	46	/* max len of IPv6 addr in ascii */
					/* standard colon-hex notation. */

#endif /* !defined(_XPG4_2) || defined(_XPG6) || defined(__EXTENSIONS__) */

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)

/*
 * IPV6_ADD_MEMBERSHIP and IPV6_DROP_MEMBERSHIP are being kept
 * for backward compatibility. They have the same meaning as IPV6_JOIN_GROUP
 * and IPV6_LEAVE_GROUP respectively.
 */
#define	IPV6_ADD_MEMBERSHIP	0x9	/* join an IPv6 multicast group. */
					/* argument type: struct ipv6_mreq */
#define	IPV6_DROP_MEMBERSHIP	0xa	/* leave an IPv6 multicast group */
					/* argument type: struct ipv6_mreq */

#define	IPV6_PKTINFO		0xb	/* addr plus interface index */
					/* arg type: "struct in6_pktingo" - */
#define	IPV6_HOPLIMIT		0xc	/* hoplimit for datagram */
#define	IPV6_NEXTHOP		0xd	/* next hop address  */
#define	IPV6_HOPOPTS		0xe	/* hop by hop options */
#define	IPV6_DSTOPTS		0xf	/* destination options - after */
					/* the routing header */
#define	IPV6_RTHDR		0x10	/* routing header  */
#define	IPV6_RTHDRDSTOPTS	0x11	/* destination options - before */
					/* the routing header */
#define	IPV6_RECVPKTINFO	0x12	/* enable/disable IPV6_PKTINFO */
#define	IPV6_RECVHOPLIMIT	0x13	/* enable/disable IPV6_HOPLIMIT */
#define	IPV6_RECVHOPOPTS	0x14	/* enable/disable IPV6_HOPOPTS */

/*
 * This options exists for backwards compatability and should no longer be
 * used.  Use IPV6_RECVDSTOPTS instead.
 */
#define	_OLD_IPV6_RECVDSTOPTS	0x15

#define	IPV6_RECVRTHDR		0x16	/* enable/disable IPV6_RTHDR */

/*
 * enable/disable IPV6_RTHDRDSTOPTS.  Now obsolete.  IPV6_RECVDSTOPTS enables
 * the receipt of both headers.
 */
#define	IPV6_RECVRTHDRDSTOPTS	0x17

#define	IPV6_CHECKSUM		0x18	/* Control checksum on raw sockets */
#define	IPV6_RECVTCLASS		0x19	/* enable/disable IPV6_CLASS */
#define	IPV6_USE_MIN_MTU	0x20	/* send packets with minimum MTU */
#define	IPV6_DONTFRAG		0x21	/* don't fragment packets */
#define	IPV6_SEC_OPT		0x22	/* Used to set IPSEC options */
#define	IPV6_SRC_PREFERENCES	0x23	/* Control socket's src addr select */
#define	IPV6_RECVPATHMTU	0x24	/* receive PMTU info */
#define	IPV6_PATHMTU		0x25	/* get the PMTU */
#define	IPV6_TCLASS		0x26	/* traffic class */
#define	IPV6_V6ONLY		0x27	/* v6 only socket option */

/*
 * enable/disable receipt of both both IPV6_DSTOPTS headers.
 */
#define	IPV6_RECVDSTOPTS	0x28

/*
 * protocol-independent multicast membership options.
 */
#define	MCAST_JOIN_GROUP	0x29	/* join group for all sources */
#define	MCAST_LEAVE_GROUP	0x2a	/* leave group */
#define	MCAST_BLOCK_SOURCE	0x2b	/* block specified source */
#define	MCAST_UNBLOCK_SOURCE	0x2c	/* unblock specified source */
#define	MCAST_JOIN_SOURCE_GROUP	0x2d	/* join group for specified source */
#define	MCAST_LEAVE_SOURCE_GROUP 0x2e	/* leave source/group pair */

/* 32Bit field for IPV6_SRC_PREFERENCES */
#define	IPV6_PREFER_SRC_HOME		0x00000001
#define	IPV6_PREFER_SRC_COA		0x00000002
#define	IPV6_PREFER_SRC_PUBLIC		0x00000004
#define	IPV6_PREFER_SRC_TMP		0x00000008
#define	IPV6_PREFER_SRC_NONCGA		0x00000010
#define	IPV6_PREFER_SRC_CGA		0x00000020

#define	IPV6_PREFER_SRC_MIPMASK	(IPV6_PREFER_SRC_HOME | IPV6_PREFER_SRC_COA)
#define	IPV6_PREFER_SRC_MIPDEFAULT	IPV6_PREFER_SRC_HOME
#define	IPV6_PREFER_SRC_TMPMASK	(IPV6_PREFER_SRC_PUBLIC | IPV6_PREFER_SRC_TMP)
#define	IPV6_PREFER_SRC_TMPDEFAULT	IPV6_PREFER_SRC_PUBLIC
#define	IPV6_PREFER_SRC_CGAMASK	(IPV6_PREFER_SRC_NONCGA | IPV6_PREFER_SRC_CGA)
#define	IPV6_PREFER_SRC_CGADEFAULT	IPV6_PREFER_SRC_NONCGA

#define	IPV6_PREFER_SRC_MASK (IPV6_PREFER_SRC_MIPMASK |\
	IPV6_PREFER_SRC_TMPMASK | IPV6_PREFER_SRC_CGAMASK)

#define	IPV6_PREFER_SRC_DEFAULT	(IPV6_PREFER_SRC_MIPDEFAULT |\
	IPV6_PREFER_SRC_TMPDEFAULT | IPV6_PREFER_SRC_CGADEFAULT)

/*
 * SunOS private (potentially not portable) IPV6_ option names
 */
#define	IPV6_BOUND_IF		0x41	/* bind to an ifindex */
#define	IPV6_UNSPEC_SRC		0x42	/* source of packets set to */
					/* unspecified (all zeros) */

/*
 * Miscellaneous IPv6 constants.
 */
#define	IPV6_PAD1_OPT		0	/* pad byte in IPv6 extension hdrs */

#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

/*
 * Extern declarations for pre-defined global const variables
 */
#if !defined(_XPG4_2) || defined(_XPG6) || defined(__EXTENSIONS__)
#ifndef _KERNEL
#ifdef __STDC__
extern const struct in6_addr in6addr_any;
extern const struct in6_addr in6addr_loopback;
#else
extern struct in6_addr in6addr_any;
extern struct in6_addr in6addr_loopback;
#endif
#endif
#endif /* !defined(_XPG4_2) || defined(_XPG6) || defined(__EXTENSIONS__) */

#ifdef	__cplusplus
}
#endif

#endif	/* _NETINET_IN_H */
