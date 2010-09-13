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
 * sppptun.h - ioctl and other miscellaneous definitions for PPP
 * tunneling STREAMS module
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * See also:
 *	RFC 2341, Cisco Layer Two Forwarding (Protocol) "L2F"
 *	RFC 2516, A Method for Transmitting PPP Over Ethernet (PPPoE)
 *	RFC 2637, Point-to-Point Tunneling Protocol (PPTP)
 *	RFC 2661, Layer Two Tunneling Protocol "L2TP"
 */

#ifndef __SPPPTUN_H
#define	__SPPPTUN_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Device name */
#define	PPP_TUN_NAME "sppptun"

/* The constant below is "TUN" in hex. */
#define	_PPPTUN(n)	(0x54554E00 + (n))

/*
 * Except where otherwise noted (mod), these apply to the driver side
 * of the PPP tunnel multiplexor.
 */
#define	PPPTUN_SNAME	_PPPTUN(1)	/* set interface name (mod) */
#define	PPPTUN_SINFO	_PPPTUN(3)	/* set multiplex ID/style */
#define	PPPTUN_GINFO	_PPPTUN(4)	/* get multiplex ID/style */
#define	PPPTUN_GNNAME	_PPPTUN(5)	/* get Nth interface name */
#define	PPPTUN_LCLADDR	_PPPTUN(6)	/* set local address */
#define	PPPTUN_SPEER	_PPPTUN(7)	/* set peer ID */
#define	PPPTUN_GPEER	_PPPTUN(8)	/* get peer ID */
#define	PPPTUN_SDATA	_PPPTUN(9)	/* set data channel by name */
#define	PPPTUN_GDATA	_PPPTUN(10)	/* get data channel name */
#define	PPPTUN_SCTL	_PPPTUN(11)	/* set control channel by name */
#define	PPPTUN_GCTL	_PPPTUN(12)	/* get control channel name */
#define	PPPTUN_DCTL	_PPPTUN(13)	/* remove control channel */
#define	PPPTUN_SSAP	_PPPTUN(14)	/* set SAP value; uint_t */

/* Lower layer link name size */
#define	PPPTUNNAMSIZ	32

typedef char ppptun_lname[PPPTUNNAMSIZ];

/*
 * For PPPTUN_SNAME, PPPTUN_GNAME, PPPTUN_SDATA, PPPTUN_GDATA,
 * PPPTUN_SCTL, PPPTUN_GCTL, and PPPTUN_DCTL, just this structure is
 * used.
 *
 * PPPTUN_GNNAME takes in a single int (0...N) and this structure is
 * returned.  Use ptn_index to pass in the index.
 */
union ppptun_name {
	uint32_t	ptn_index;
	ppptun_lname	ptn_name;
};

/* PPPTUN_SINFO and PPPTUN_GINFO use this structure */
struct ppptun_info {
	ppptun_lname	pti_name;
	uint32_t	pti_muxid;	/* ID from I_PLINK (not L2F!) */
	uint32_t	pti_style;	/* One of PTS_* below */
};

#define	PTS_NONE	0		/* Illegal configuration */
#define	PTS_PPPOE	1		/* DLPI PPPoE */
#define	PTS_L2FTP	2		/* TLI L2F or L2TP over UDP GRE */
#define	PTS_PPTP	3		/* TPI PPTP over IP GRE */
#define	PTS__MAX	4		/* one greater than last above */

struct ppptun_gre_addr {
	struct in6_addr	ptga_peer_ip;
	uint16_t	ptga_peer_port;	/* L2TP or L2F, not PPTP */
	uint8_t		ptga_version;	/* one of PTGAV_* below */
};

struct ppptun_mac_addr {
	struct ether_addr	ptma_mac_ether_addr;
#define	ptma_mac	ptma_mac_ether_addr.ether_addr_octet
};

/* Values for ptga_version; corresponds to GRE version number */
#define	PTGAV_L2F	0x01
#define	PTGAV_PPTP	0x01
#define	PTGAV_L2TP	0x02

typedef union {
	struct ppptun_gre_addr	pta_l2f;
	struct ppptun_gre_addr	pta_l2tp;
	struct ppptun_gre_addr	pta_pptp;
	struct ppptun_mac_addr	pta_pppoe;
} ppptun_atype;

/* For PPPTUN_SPEER and PPPTUN_GPEER; the address depends on the style */
struct ppptun_peer {
	uint32_t	ptp_style;	/* Sanity check; must match lower */
	uint32_t	ptp_flags;	/* See PTPF_* below */
	uint32_t	ptp_ltunid;	/* Local Tunnel ID (L2F/L2TP) */
	uint32_t	ptp_rtunid;	/* Remote Tunnel ID (L2F/L2TP) */
	uint32_t	ptp_lsessid;	/* Local Session ID */
	uint32_t	ptp_rsessid;	/* Remote Session ID */
	ppptun_atype	ptp_address;	/* Peer address */
};

#define	PTPF_DAEMON	0x00000001	/* server side; session ID 0 */

/* For M_PROTO (control message) */
struct ppptun_control {
	uint32_t	ptc_discrim;	/* Use PPPOE_DISCRIM */
	uint32_t	ptc_action;	/* See PTCA_* below */
	uint32_t	ptc_rsessid;	/* Remote session ID */
	ppptun_atype	ptc_address;	/* Peer address (if any) */
	ppptun_lname	ptc_name;	/* Lower stream name (if any) */
};

/*
 * This value, currently set to the characters "POE1," is used to
 * distinguish among control messages from multiple lower streams
 * under /dev/sppp.  This feature is needed to support PPP translation
 * (LAC-like behavior), but isn't currently used.
 */
#define	PPPOE_DISCRIM	0x504F4531

#define	PTCA_TEST	1		/* Test/set stream discriminator */
#define	PTCA_CONTROL	2		/* Inbound control message */
#define	PTCA_DISCONNECT	3		/* Client disconnected */
#define	PTCA_UNPLUMB	4		/* Lower stream unplumbed (no addr) */
#define	PTCA_BADCTRL	5		/* Malformed control message */

#ifdef	__cplusplus
}
#endif

#endif /* __SPPPTUN_H */
