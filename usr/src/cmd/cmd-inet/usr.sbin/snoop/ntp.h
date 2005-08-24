/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef	_NTP_H
#define	_NTP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* $Source: /usr/users/louie/ntp/RCS/ntp.h,v $  */
/* $Revision: 3.4.1.5 $ $Date: 89/04/10 15:55:42 $ */

/*
 *  $Log:	ntp.h,v $
 * Revision 3.4.1.5  89/04/10  15:55:42  louie
 * Provide default value for number of bits/byte if not defined.  Compute the
 * Window shift mask inside of conditional code on XTAL so we get the correct
 * value if configured without a crystal controled clock (!!)
 *
 * Revision 3.4.1.4  89/03/31  16:34:50  louie
 * Add bit in flags which allow a peer to be synced to.  Changed a char to a bit
 * field so that it is always signed.
 *
 * Revision 3.4.1.3  89/03/29  12:26:18  louie
 * Removed some unused #defines.  Replaced MAXSTRATUM with NTP_INFIN per new
 * spec.  The variable 'mode' in the peer structure has been renamed 'hmode'
 * per the new spec.
 *
 * Revision 3.4.1.2  89/03/22  18:28:18  louie
 * patch3: Use new RCS headers.
 *
 * Revision 3.4.1.1  89/03/20  00:02:53  louie
 * 1
 *
 * Revision 3.4  89/03/17  18:37:00  louie
 * Latest test release.
 *
 * Revision 3.3.1.1  89/03/17  18:23:49  louie
 * Change CLOCK_FACTOR to be a power of 2.
 *
 * Revision 3.3  89/03/15  14:19:36  louie
 * New baseline for next release.
 *
 * Revision 3.2.1.2  89/03/15  13:46:52  louie
 * The version number for that particular flavor of ntpd <--> ntpdc interaction
 * is now defined by NTPDC_VERSION.  The packet format for the ntpdc program
 * has changed slightly to improve robustness when dealing with multiple packets
 * of status data.
 *
 * Revision 3.2.1.1  89/03/09  17:11:24  louie
 * patch1: Updated constants, which were previously in incorrect units.
 *
 * Revision 3.2  89/03/07  18:21:45  louie
 * New version of UNIX NTP daemon and software based on the 6 March 1989
 * draft of the new NTP protocol specification.  This version doesn't
 * implement authentication, and accepts and send only NTP Version 1
 * packets.
 *
 * Revision 3.1.1.1  89/02/15  08:54:42  louie
 * *** empty log message ***
 *
 *
 * Revision 3.1  89/01/30  14:43:07  louie
 * Second UNIX NTP test release.
 *
 * Revision 3.0  88/12/12  16:01:07  louie
 * Test release of new UNIX NTP software.  This version should conform to the
 * revised NTP protocol specification.
 *
 */

#ifndef FD_SET
#define	NFDBITS		32
#define	FD_SETSIZE	32
#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define	FD_ZERO(p)	bzero((char *)(p), sizeof (*(p)))
#endif

#ifndef	NBBY
#define	NBBY	8	/* number of bits per byte */
#endif

#define	MAXNETIF	10

struct intf {
	int fd;
	char *name;
	struct sockaddr_in sin;
	struct sockaddr_in bcast;
	struct sockaddr_in mask;
	int uses;
	int if_flags;
};
extern struct intf addrs[];
extern int nintf;

/*
 *  Definitions for the masses
 */
#define	JAN_1970	2208988800U	/* 1970 - 1900 in seconds */

/*
 *  Daemon specific (ntpd.c)
 */
#define	SHIFT_MASK	0xff	/* number of intervals to wait */

#ifndef	WAYTOOBIG
#define	WAYTOOBIG	1000.0	/* Too many seconds to correct, something is */
				/* really wrong */
#endif

#ifndef	XTAL
#define	XTAL	1	/* crystal controlled clock by default */
#endif

#ifndef	NTPINITFILE
#define	NTPINITFILE	"/etc/ntp.conf"
#endif

struct list {
	struct ntp_peer *head;
	struct ntp_peer *tail;
	int members;
};

#define	STRMCMP(a, cond, b) \
	(((a) == UNSPECIFIED ? NTP_INFIN+1 : a) cond \
		((b) == UNSPECIFIED ? NTP_INFIN+1 : (b)))


/*
 *  Definitions outlined in the NTP spec
 */
#define	NTP_VERSION	1
#define	NTP_PORT	123	/* for ref only (see /etc/services) */
#define	NTP_INFIN	15
#define	NTP_MAXAGE	86400
#define	NTP_MAXSKW	0.01	/* seconds */
#define	NTP_MINDIST	0.02	/* seconds */
#define	NTP_MINPOLL	6	/* (64) seconds between messages */
#define	NTP_MAXPOLL	10	/* (1024) secs to poll */
#define	NTP_WINDOW	8	/* size of shift register */
#define	NTP_MAXWGT	8	/* maximum allowable dispersion */
#define	NTP_MAXLIST	5	/* max size of selection list */
#define	NTP_MAXSTRA	2	/* max number of strata in selection list */
#define	X_NTP_CANDIDATES 64	/* number of peers to consider when doing */
				/*	clock selection */
#define	NTP_SELECT	0.75	/* weight used to compute dispersion */

#define	PEER_MAXDISP	64.0	/* Maximum dispersion  */
#define	PEER_THRESHOLD	0.5	/* dispersion threshold */
#define	PEER_FILTER	0.5	/* filter weight */

#if	XTAL == 0
#define	PEER_SHIFT	4
#define	NTP_WINDOW_SHIFT_MASK 0x0f
#else
#define	PEER_SHIFT	8
#define	NTP_WINDOW_SHIFT_MASK 0xff
#endif


/*
 *  5.1 Uniform Phase Adjustments
 *  Clock parameters
 */
#define	CLOCK_UPDATE	8	/* update interval (1<<CLOCK_UPDATE secs) */
#if	XTAL
#define	CLOCK_ADJ	2	/* adjustment interval (1<<CLOCK_ADJ secs) */
#define	CLOCK_PHASE	8	/* phase shift */
#define	CLOCK_MAX	0.128	/* maximum aperture (milliseconds) */
#else
#define	CLOCK_ADJ	0
#define	CLOCK_PHASE	6	/* phase shift */
#define	CLOCK_MAX	0.512	/* maximum aperture (milliseconds) */
#endif
#define	CLOCK_FREQ	10	/* frequency shift */
#define	CLOCK_TRACK	8
#define	CLOCK_COMP	4
#define	CLOCK_FACTOR	18

/*
 * Structure definitions for NTP fixed point values
 *
 *    0			  1		      2			  3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |			       Integer Part			     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |			       Fraction Part			     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *    0			  1		      2			  3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |		  Integer Part	     |	   Fraction Part	     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct l_fixedpt {
	ulong_t int_part;
	ulong_t fraction;
};

struct s_fixedpt {
	ushort_t int_part;
	ushort_t fraction;
};

/*
 *  =================  Table 3.3. Packet Variables   =================
 *    0			  1		      2			  3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |LI | VN  | Mode|	  Stratum    |	    Poll     |	 Precision   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |			   Synchronizing Distance		     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |			  Synchronizing Dispersion		     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |			Reference Clock Identifier		     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |								     |
 *   |		       Reference Timestamp (64 bits)		     |
 *   |								     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |								     |
 *   |		       Originate Timestamp (64 bits)		     |
 *   |								     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |								     |
 *   |			Receive Timestamp (64 bits)		     |
 *   |								     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |								     |
 *   |			Transmit Timestamp (64 bits)		     |
 *   |								     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |		     Encryption Keyid (32 bits, when A bit set)	     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |								     |
 *   |		Message Authentication Code/MAC (when A bit set)     |
 *   |								     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define	MAC_OCTETS_DES	8
#define	MAC_OCTETS_MD5	16
#define	MAC_OCTETS_MIN	MAC_OCTETS_DES
#define	MAC_OCTETS_MAX	MAC_OCTETS_MD5
#define	AUTH_OCTETS_V3	(MAC_OCTETS_MAX + sizeof (uint32_t))

struct ntpdata {
	uchar_t li_vn_mode;	/* contains leap indicator, version and mode */
	uchar_t stratum; 	/* Stratum level */
	uchar_t ppoll;		/* poll value */
	int precision:8;
	struct s_fixedpt distance;
	struct s_fixedpt dispersion;
	ulong_t refid;
	struct l_fixedpt reftime;
	struct l_fixedpt org;
	struct l_fixedpt rec;
	struct l_fixedpt xmt;
	uint32_t keyid;
	uchar_t mac[MAC_OCTETS_MAX];
};

#define	LEN_PKT_NOMAC	(sizeof (struct ntpdata) - AUTH_OCTETS_V3)

/*
 *	Leap Second Codes (high order two bits)
 */
#define	NO_WARNING	0x00	/* no warning */
#define	PLUS_SEC	0x40	/* add a second (61 seconds) */
#define	MINUS_SEC	0x80	/* minus a second (59 seconds) */
#define	ALARM		0xc0	/* alarm condition (clock unsynchronized) */

/*
 *	Clock Status Bits that Encode Version
 */
#define	NTPVERSION_1	0x08
#define	VERSIONMASK	0x38
#define	LEAPMASK	0xc0
#define	NTPMODEMASK	0x07

/*
 *	Code values
 */
#define	MODE_UNSPEC	0	/* unspecified */
#define	MODE_SYM_ACT	1	/* symmetric active */
#define	MODE_SYM_PAS	2	/* symmetric passive */
#define	MODE_CLIENT	3	/* client */
#define	MODE_SERVER	4	/* server */
#define	MODE_BROADCAST	5	/* broadcast */
#define	MODE_CONTROL	6	/* control */
#define	MODE_PRIVATE	7	/* private */

/*
 *	Stratum Definitions
 */
#define	UNSPECIFIED	0
#define	PRIM_REF	1	/* radio clock */
#define	INFO_QUERY	62	/* **** THIS implementation dependent **** */
#define	INFO_REPLY	63	/* **** THIS implementation dependent **** */


/* =================  table 3.2 Peer Variables	================= */
struct ntp_peer {
	struct ntp_peer *next, *prev;
	struct sockaddr_in src;		/* both peer.srcadr and peer.srcport */
	int	flags;			/* local flags */
#define	PEER_FL_CONFIG		1
#define	PEER_FL_AUTHENABLE	2
#define	PEER_FL_SYNC		0x1000	/* peer can bet sync'd to */
#define	PEER_FL_BCAST		0x2000	/* broadcast peer */
#define	PEER_FL_SELECTED	0x8000	/* actually used by query routine */

	int	sock;			/* index into sockets to derive */
					/*   peer.dstadr and peer.dstport */
	uchar_t	leap;			/* receive */
	uchar_t	hmode;			/* receive */
	uchar_t	stratum;		/* receive */
	uchar_t	ppoll;			/* receive */
	uchar_t	hpoll;			/* poll update */
	short	precision;		/* receive */
	struct	s_fixedpt distance;	/* receive */
	struct	s_fixedpt dispersion;	/* receive */
	ulong_t	refid;			/* receive */
	struct	l_fixedpt reftime;	/* receive */
	struct	l_fixedpt org;		/* receive, clear */
	struct	l_fixedpt rec;		/* receive, clear */
	struct	l_fixedpt xmt;		/* transmit, clear */
	ulong_t	reach;			/* receive, transmit, clear */
	ulong_t	valid;			/* packet, transmit, clear */
	ulong_t	timer;			/* receive, transmit, poll update */
	long	stopwatch;		/* <<local>> for timing */
	/*
	 * first order offsets
	 */
	struct	filter {
		short samples;		/* <<local>> */
		double offset[PEER_SHIFT];
		double delay[PEER_SHIFT];
	} filter;			/* filter, clear */

	double	estdelay;		/* filter */
	double	estoffset;		/* filter */
	double	estdisp;		/* filter */

	ulong_t	pkt_sent;		/* <<local>> */
	ulong_t pkt_rcvd;		/* <<local>> */
	ulong_t	pkt_dropped;		/* <<local>> */
};

/* ================= table 3.1:  System Variables ================= */

struct sysdata {			/* procedure */
	uchar_t leap;			/* clock update */
	uchar_t stratum;		/* clock update */
	short precision;		/* system */
	struct s_fixedpt distance;	/* clock update */
	struct s_fixedpt dispersion;	/* clock update */
	ulong_t refid;			/* clock update */
	struct l_fixedpt reftime;	/* clock update */
	int hold;			/* clock update */
	struct ntp_peer *peer;		/* selection */
	int maxpeers;			/* <<local>> */
	uchar_t filler;			/* put here for %&*%$$ SUNs */
};

#define	NTPDC_VERSION	2

/*
 *  These structures are used to pass information to the ntpdc (control)
 *  program.  They are unique to this implementation and not part of the
 *  NTP specification.
 */
struct clockinfo {
	ulong_t net_address;
	ulong_t my_address;
	ushort_t port;
	ushort_t flags;
	ulong_t pkt_sent;
	ulong_t pkt_rcvd;
	ulong_t pkt_dropped;
	ulong_t timer;
	uchar_t leap;
	uchar_t stratum;
	uchar_t ppoll;
	int precision:8;

	uchar_t hpoll;
	uchar_t filler1;
	ushort_t reach;

	long	estdisp;			/* scaled by 1000 */
	long	estdelay;			/* in milliseconds */
	long	estoffset;			/* in milliseconds */
	ulong_t refid;
	struct l_fixedpt reftime;
	struct info_filter {
		short index;
		short filler;
		long offset[PEER_SHIFT];	/* in milliseconds */
		long delay[PEER_SHIFT];		/* in milliseconds */
	} info_filter;
};

struct ntpinfo {
	uchar_t version;
	uchar_t type;		/* request type (stratum in ntp packets) */
	uchar_t count;		/* number of entries in this packet */
	uchar_t seq;		/* sequence number of this packet */

	uchar_t npkts;		/* total number of packets */
	uchar_t peers;
	uchar_t fill3;
	uchar_t fill4;
};

/*
 * From usr/src/cmd/xntpd/include/ntp_control.h:
 * Definition of a mode 6 packet.
 */
struct ntp_control {
	uchar_t li_vn_mode;		/* leap, version, mode */
	uchar_t r_m_e_op;		/* response, more, error, opcode */
	ushort_t sequence;		/* sequence number of request */
	ushort_t status;		/* status word for association */
	ushort_t associd;		/* association ID */
	ushort_t offset;		/* offset of this batch of data */
	ushort_t count;			/* count of data in this packet */
	uchar_t data[1];		/* data + auth */
};

#define	NTPC_DATA_MAXLEN	(480 + AUTH_OCTETS_V3)

/*
 * Decoding for the r_m_e_op field
 */
#define	CTL_RESPONSE	0x80
#define	CTL_ERROR	0x40
#define	CTL_MORE	0x20
#define	CTL_OP_MASK	0x1f

/*
 * Opcodes
 */
#define	CTL_OP_UNSPEC		0
#define	CTL_OP_READSTAT		1
#define	CTL_OP_READVAR		2
#define	CTL_OP_WRITEVAR		3
#define	CTL_OP_READCLOCK	4
#define	CTL_OP_WRITECLOCK	5
#define	CTL_OP_SETTRAP		6
#define	CTL_OP_ASYNCMSG		7
#define	CTL_OP_UNSETTRAP	31

/*
 * From usr/src/cmd/xntpd/include/ntp_request.h:
 * A mode 7 packet is used exchanging data between an NTP server
 * and a client for purposes other than time synchronization, e.g.
 * monitoring, statistics gathering and configuration.  A mode 7
 * packet has the following format:
 */

struct ntp_private {
	uchar_t rm_vn_mode;		/* response, more, version, mode */
	uchar_t auth_seq;		/* key, sequence number */
	uchar_t implementation;		/* implementation number */
	uchar_t request;		/* request number */
	ushort_t err_nitems;		/* error code/number of data items */
	ushort_t mbz_itemsize;		/* item size */
	char data[1];			/* data area */
};

#define	RESP_BIT		0x80
#define	MORE_BIT		0x40
#define	INFO_VERSION(rm_vn_mode) ((uchar_t)(((rm_vn_mode)>>3) & 0x7))
#define	INFO_MODE(rm_vn_mode)	((rm_vn_mode) & 0x7)

#define	AUTH_BIT		0x80
#define	INFO_SEQ(auth_seq)	((auth_seq) & 0x7f)

#define	INFO_ERR(err_nitems)	((ushort_t)((ntohs(err_nitems) >> 12) & 0xf))
#define	INFO_NITEMS(err_nitems)	((ushort_t)(ntohs(err_nitems) & 0xfff))

#define	INFO_ITEMSIZE(mbz_itemsize) (ntohs(mbz_itemsize) & 0xfff)

#ifdef __cplusplus
}
#endif

#endif	/* _NTP_H */
