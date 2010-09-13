/*	$Id: ppp_defs.h,v 1.14 1999/08/13 01:55:40 paulus Exp $	*/

/*
 * ppp_defs.h - PPP definitions.
 *
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 1994 The Australian National University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied. The Australian National University
 * makes no representations about the suitability of this software for
 * any purpose.
 *
 * IN NO EVENT SHALL THE AUSTRALIAN NATIONAL UNIVERSITY BE LIABLE TO ANY
 * PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAVE BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 */

#ifndef _PPP_DEFS_H_
#define	_PPP_DEFS_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The basic PPP frame.
 */
#define	PPP_HDRLEN	4	/* octets for standard ppp header */
#define	PPP_FCSLEN	2	/* octets for FCS */
#define	PPP_FCS32LEN	4	/* octets for FCS-32 */
#define	PPP_MAX_MUX_LEN	127	/* maximum length of muxed frame */
#define	PFF		0x80	/* protocol field flag */

/*
 * Packet sizes
 */
#define	PPP_MTU		1500	/* Default MTU (size of Info field) */
#define	PPP_MAXMTU	65535 - (PPP_HDRLEN + PPP_FCSLEN)
#define	PPP_MINMTU	64
#define	PPP_MRU		1500	/* default MRU = max length of info field */
#define	PPP_MAXMRU	65000	/* Largest MRU we allow */
#define	PPP_MINMRU	128

#define	PPP_ADDRESS(p)	(((uchar_t *)(p))[0])
#define	PPP_CONTROL(p)	(((uchar_t *)(p))[1])
#define	PPP_PROTOCOL(p)	((((uchar_t *)(p))[2] << 8) + ((uchar_t *)(p))[3])

/*
 * Significant octet values.
 */
#define	PPP_ALLSTATIONS	0xff	/* All-Stations broadcast address */
#define	PPP_UI		0x03	/* Unnumbered Information */
#define	PPP_FLAG	0x7e	/* Flag Sequence */
#define	PPP_ESCAPE	0x7d	/* Asynchronous Control Escape */
#define	PPP_TRANS	0x20	/* Asynchronous transparency modifier */

/*
 * Protocol field values.
 */
#define	PPP_IP		0x21	/* Internet Protocol */
#define	PPP_OSI		0x23	/* OSI Network Layer */
#define	PPP_AT		0x29	/* AppleTalk Protocol */
#define	PPP_IPX		0x2b	/* IPX protocol */
#define	PPP_VJC_COMP	0x2d	/* VJ compressed TCP */
#define	PPP_VJC_UNCOMP	0x2f	/* VJ uncompressed TCP */
#define	PPP_BRIDGE	0x31	/* Bridging */
#define	PPP_MP		0x3d	/* Multilink protocol */
#define	PPP_ENCRYPT	0x53	/* Encryption */
#define	PPP_ENCRYPTFRAG	0x55	/* Individual Link Encryption */
#define	PPP_IPV6	0x57	/* Internet Protocol Version 6 */
#define	PPP_MUX		0x59	/* PPP Muxing */
#define	PPP_FULLHDR	0x61	/* IP Compression; full header */
#define	PPP_COMPTCP	0x63	/* IP Compression; compressed TCP */
#define	PPP_COMPNONTCP	0x65	/* IP Compression; non TCP */
#define	PPP_COMPUDP8	0x67	/* IP Compression; UDP, 8 bit CID */
#define	PPP_COMPRTP8	0x69	/* IP Compression; RTP, 8 bit CID */
#define	PPP_COMPFRAG	0xfb	/* fragment compressed below bundle */
#define	PPP_COMP	0xfd	/* compressed packet */
#define	PPP_802HELLO	0x201	/* 802.1d Hello (OBSOLETE) */
#define	PPP_MPLS	0x281	/* MPLS Unicast */
#define	PPP_MPLSMC	0x283	/* MPLS Multicast */
#define	PPP_COMPTCPND	0x2063	/* IP Compression; compressed TCP no delta */
#define	PPP_COMPSTATE	0x2065	/* IP Compression; state message */
#define	PPP_COMPUDP16	0x2067	/* IP Compression; UDP, 16 bit CID */
#define	PPP_COMPRTP16	0x2069	/* IP Compression; RTP, 16 bit CID */
#define	PPP_IPCP	0x8021	/* IP Control Protocol */
#define	PPP_OSINLCP	0x8023	/* OSI Network Layer Control Protocol */
#define	PPP_ATCP	0x8029	/* AppleTalk Control Protocol */
#define	PPP_IPXCP	0x802b	/* IPX Control Protocol */
#define	PPP_BCP		0x8031	/* Bridging Control Protocol */
#define	PPP_ECP		0x8053	/* Encryption Control Protocol */
#define	PPP_ECPFRAG	0x8055	/* ECP at link level (below MP bundle) */
#define	PPP_IPV6CP	0x8057	/* IPv6 Control Protocol */
#define	PPP_MUXCP	0x8059	/* PPP Muxing Control Protocol */
#define	PPP_CCPFRAG	0x80fb	/* CCP at link level (below MP bundle) */
#define	PPP_CCP		0x80fd	/* Compression Control Protocol */
#define	PPP_MPLSCP	0x8281	/* MPLS Control Protocol */
#define	PPP_LCP		0xc021	/* Link Control Protocol */
#define	PPP_PAP		0xc023	/* Password Authentication Protocol */
#define	PPP_LQR		0xc025	/* Link Quality Report protocol */
#define	PPP_BACP	0xc02b	/* Bandwidth Allocation Control Protocol */
#define	PPP_BAP		0xc02d	/* Bandwidth Allocation Protocol */
#define	PPP_CBCP	0xc029	/* Callback Control Protocol */
#define	PPP_CHAP	0xc223	/* Challenge Handshake Auth. Protocol */
#define	PPP_EAP		0xc227	/* Extensible Authentication Protocol */

/*
 * Values for FCS calculations.
 */
#define	PPP_INITFCS	0xffff	/* Initial FCS value */
#define	PPP_GOODFCS	0xf0b8	/* Good final FCS value */
#define	PPP_FCS(fcs, c)	(((fcs) >> 8) ^ fcstab[((fcs) ^ (c)) & 0xff])

#define	PPPINITFCS16	PPP_INITFCS
#define	PPPGOODFCS16	PPP_GOODFCS
#define	PPPFCS16(fcs, c)	PPP_FCS((fcs), (c))

#define	PPPINITFCS32	0xfffffffful
#define	PPPGOODFCS32	0xdebb20e3ul
#define	PPPFCS32(fcs, c) (((fcs) >> 8) ^ crc32_table[((fcs) ^ (c)) & 0xff])

/* Marker values shared between pppdump and pppd. */
#define	RECMARK_STARTSEND	1
#define	RECMARK_STARTRECV	2
#define	RECMARK_ENDSEND		3
#define	RECMARK_ENDRECV		4
#define	RECMARK_TIMEDELTA32	5
#define	RECMARK_TIMEDELTA8	6
#define	RECMARK_TIMESTART	7

/*
 * A 32-bit unsigned integral type.
 */

#if !defined(__BIT_TYPES_DEFINED__) && !defined(_BITYPES) && \
	!defined(__FreeBSD__) && (NS_TARGET < 40)
#ifdef	UINT32_T
typedef UINT32_T	u_int32_t;
#else
typedef unsigned int	u_int32_t;
typedef unsigned short  u_int16_t;
#endif
#endif

#if defined(__sun) && !defined(_SYS_INT_TYPES_H) && !defined(_UINT32_T)
/* Backward compatibility */
typedef uint_t uint32_t;
typedef ushort_t uint16_t;
typedef uchar_t uint8_t;
typedef unsigned long uintptr_t;
#define	_UINT32_T
#endif

/*
 * Extended asyncmap - allows any character to be escaped.
 */
typedef u_int32_t	ext_accm[8];

/*
 * What to do with network protocol (NP) packets.
 */
enum NPmode {
    NPMODE_PASS,		/* pass the packet through */
    NPMODE_DROP,		/* silently drop the packet */
    NPMODE_ERROR,		/* return an error */
    NPMODE_QUEUE		/* save it up for later. */
};

/*
 * Statistics.
 */
struct pppstat	{
    u_int32_t ppp_ibytes;	/* bytes received */
    u_int32_t ppp_ipackets;	/* packets received */
    u_int32_t ppp_ierrors;	/* receive errors */
    u_int32_t ppp_obytes;	/* bytes sent */
    u_int32_t ppp_opackets;	/* packets sent */
    u_int32_t ppp_oerrors;	/* transmit errors */
};

struct vjstat {
    u_int32_t vjs_packets;	/* outbound packets */
    u_int32_t vjs_compressed; /* outbound compressed packets */
    u_int32_t vjs_searches;	/* searches for connection state */
    u_int32_t vjs_misses;	/* times couldn't find conn. state */
    u_int32_t vjs_uncompressedin; /* inbound uncompressed packets */
    u_int32_t vjs_compressedin; /* inbound compressed packets */
    u_int32_t vjs_errorin;	/* inbound unknown type packets */
    u_int32_t vjs_tossed;	/* inbound packets tossed because of error */
};

struct ppp_stats {
    struct pppstat p;		/* basic PPP statistics */
    struct vjstat vj;		/* VJ header compression statistics */
};

#ifdef SOL2
#define	PPP_COUNTER_F	"llu"
typedef uint64_t	ppp_counter_t;

struct pppstat64 {
	ppp_counter_t ppp_ibytes;	/* bytes received */
	ppp_counter_t ppp_ipackets;	/* packets received */
	ppp_counter_t ppp_ierrors;	/* receive errors */
	ppp_counter_t ppp_obytes;	/* bytes sent */
	ppp_counter_t ppp_opackets;	/* packets sent */
	ppp_counter_t ppp_oerrors;	/* transmit errors */
};

struct ppp_stats64 {
	struct pppstat64 p;
	struct vjstat vj;
};
#else
#define	PPP_COUNTER_F	"u"
typedef u_int32_t	ppp_counter_t;
#endif

struct compstat {
    u_int32_t unc_bytes;	/* total uncompressed bytes */
    u_int32_t unc_packets;	/* total uncompressed packets */
    u_int32_t comp_bytes;	/* compressed bytes */
    u_int32_t comp_packets;	/* compressed packets */
    u_int32_t inc_bytes;	/* incompressible bytes */
    u_int32_t inc_packets;	/* incompressible packets */
    u_int32_t ratio;		/* recent compression ratio << 8 */
};

struct ppp_comp_stats {
    struct compstat c;		/* packet compression statistics */
    struct compstat d;		/* packet decompression statistics */
};

/*
 * The following structure records the time in seconds since
 * the last NP packet was sent or received.
 */
struct ppp_idle {
	/*
	 * Fix the length of these fields to be 32-bit, since
	 * otherwise, a time_t (long) is 64-bit in kernel while 32-bit
	 * in userland when running on a 64-bit CPU with a 64-bit OS.
	 */
    u_int32_t xmit_idle;	/* time since last NP packet sent */
    u_int32_t recv_idle;	/* time since last NP packet received */
};

enum LSstat {
    PPP_LINKSTAT_HANGUP = 0xabcd, /* link is hung up */
    PPP_LINKSTAT_NEEDUP,	/* link is down and needs to be up */
    PPP_LINKSTAT_IPV4_UNBOUND,	/* DL_UNBIND received on IPv4 stream */
    PPP_LINKSTAT_IPV6_UNBOUND,	/* DL_UNBIND received on IPv6 stream */
    PPP_LINKSTAT_IPV4_BOUND,	/* DL_BIND received on IPv4 stream */
    PPP_LINKSTAT_IPV6_BOUND,	/* DL_BIND received on IPv6 stream */
    PPP_LINKSTAT_UP		/* Integrated driver; hardware is up */
};

#define	PPPLSMAGIC	0x53505050

struct ppp_ls {
    u_int32_t magic;		/* magic number identifier (PPPLSMAGIC) */
    u_int32_t ppp_message;	/* link status message */
};

#ifndef __P
#ifdef __STDC__
#define	__P(x)	x
#else
#define	__P(x)	()
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif /* _PPP_DEFS_H_ */
