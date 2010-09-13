/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1988, 1989, 1991, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *
 * @(#)$Header: traceroute.c,v 1.49 97/06/13 02:30:23 leres Exp $ (LBL)
 */

#ifndef _TRACEROUTE_H
#define	_TRACEROUTE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	MAX_PORT	65535		/* max port value for UDP */

#define	REPLY_SHORT_PKT		0	/* check_reply() has a short packet */
#define	REPLY_GOT_GATEWAY	1	/* ... rcvd a reply from an inter. gw */
#define	REPLY_GOT_TARGET	2	/* ... rcvd the reply from the target */
#define	REPLY_GOT_OTHER		3	/* ... received other */

/*
 * this is the max it can be, yet another factor is PMTU, which is ignored
 * here
 */
#define	MAX_GWS6	127

/*
 * Maximum number of gateways (include room for one noop).
 * 'in_addr_t' is 32 bits, size of IPv4 address.
 * Note that the actual number of gateways that can be used for source
 * routing is one less than the value below. This is because the API requires
 * the last gateway to be the target address.
 */
#define	MAX_GWS		9

/* maximum of max_gws */
#define	MAXMAX_GWS	MAX(MAX_GWS, MAX_GWS6)

#define	A_CNT(ARRAY)	(sizeof (ARRAY) / sizeof ((ARRAY)[0]))

#define	Fprintf		(void)fprintf
#define	Printf		(void)printf

struct icmptype_table {
	int type;		/* ICMP type */
	char *message;		/* corresponding string message */
};

/* Data section of the probe packet */
struct outdata {
	uchar_t seq;		/* sequence number of this packet */
	uchar_t ttl;		/* ttl packet left with */
	struct timeval tv;	/* time packet left */
};

extern boolean_t docksum;	/* do checksum (IPv4 only) */
extern int gw_count;		/* number of LSRR gateways */
extern char *hostname;
extern ushort_t ident;		/* identity of this traceroute run */
extern boolean_t nflag;		/* numeric flag */
extern ushort_t off;		/* set DF bit (IPv4 only) */
extern int packlen;		/* packet length */
extern ushort_t port;		/* seed of destination port */
extern char *prog;		/* program name */
extern boolean_t raw_req;	/* if sndsock for IPv4 must be raw */
extern boolean_t settos;	/* set type-of-service (IPv4 only) */
extern unsigned char tos;	/* value of tos to set */
extern boolean_t useicmp;	/* use ICMP or UDP */
extern boolean_t verbose;

#ifdef __cplusplus
}
#endif

#endif /* _TRACEROUTE_H */
