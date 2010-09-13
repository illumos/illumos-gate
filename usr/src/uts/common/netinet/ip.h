/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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

/*
 * Definitions for internet protocol version 4.
 * Per RFC 791, September 1981.
 */

#ifndef	_NETINET_IP_H
#define	_NETINET_IP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* ip.h 1.13 88/08/19 SMI; from UCB 7.6.1.1 3/15/88	*/

#include <sys/isa_defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	IPVERSION	4

/*
 * Structure of an internet header, naked of options.
 */
struct ip {
#ifdef _BIT_FIELDS_LTOH
	uchar_t	ip_hl:4,		/* header length */
		ip_v:4;			/* version */
#else
	uchar_t	ip_v:4,			/* version */
		ip_hl:4;		/* header length */
#endif
	uchar_t	ip_tos;			/* type of service */
	ushort_t ip_len;		/* total length */
	ushort_t ip_id;			/* identification */
	ushort_t ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
	uchar_t	ip_ttl;			/* time to live */
	uchar_t	ip_p;			/* protocol */
	ushort_t ip_sum;		/* checksum */
	struct	in_addr ip_src, ip_dst;	/* source and dest address */
};

#define	IP_MAXPACKET	65535		/* maximum packet size */

/*
 * Definitions for IP type of service (ip_tos)
 */
#define	IPTOS_LOWDELAY		0x10
#define	IPTOS_THROUGHPUT	0x08
#define	IPTOS_RELIABILITY	0x04
#define	IPTOS_ECT		0x02	/* ECN-Capable Transport flag */
#define	IPTOS_CE		0x01	/* ECN-Congestion Experienced flag */

/*
 * Definitions for IP precedence (also in ip_tos) (hopefully unused)
 */
#define	IPTOS_PREC_NETCONTROL		0xe0
#define	IPTOS_PREC_INTERNETCONTROL	0xc0
#define	IPTOS_PREC_CRITIC_ECP		0xa0
#define	IPTOS_PREC_FLASHOVERRIDE	0x80
#define	IPTOS_PREC_FLASH		0x60
#define	IPTOS_PREC_IMMEDIATE		0x40
#define	IPTOS_PREC_PRIORITY		0x20
#define	IPTOS_PREC_ROUTINE		0x00

/*
 * Definitions for options.
 */

/* Bits in the option value */
#define	IPOPT_COPY		0x80

#define	IPOPT_COPIED(o)		((o)&0x80)
#define	IPOPT_CLASS(o)		((o)&0x60)
#define	IPOPT_NUMBER(o)		((o)&0x1f)

#define	IPOPT_CONTROL		0x00
#define	IPOPT_RESERVED1		0x20
#define	IPOPT_DEBMEAS		0x40
#define	IPOPT_RESERVED2		0x60

#define	IPOPT_EOL		0x00		/* end of option list */
#define	IPOPT_NOP		0x01		/* no operation */

#define	IPOPT_RR		0x07		/* record packet route */
#define	IPOPT_RTRALERT		0x14		/* router alert */
#define	IPOPT_TS		0x44		/* timestamp */
#define	IPOPT_SECURITY		0x82		/* provide s,c,h,tcc */
#define	IPOPT_LSRR		0x83		/* loose source route */
#define	IPOPT_EXTSEC		0x85
#define	IPOPT_COMSEC		0x86
#define	IPOPT_SATID		0x88		/* satnet id */
#define	IPOPT_SSRR		0x89		/* strict source route */
#define	IPOPT_RA		0x94
#define	IPOPT_SDMDD		0x95

/*
 * Offsets to fields in options other than EOL and NOP.
 */
#define	IPOPT_OPTVAL		0		/* option ID */
#define	IPOPT_OLEN		1		/* option length */
#define	IPOPT_OFFSET		2		/* offset within option */
#define	IPOPT_POS_OV_FLG	3
#define	IPOPT_MINOFF		4		/* min value of IPOPT_OFFSET */


/* Minimum for src and record route options */
#define	IPOPT_MINOFF_SR		IPOPT_MINOFF

/*
 * Time stamp option structure.
 */
struct	ip_timestamp {
	uchar_t	ipt_code;		/* IPOPT_TS */
	uchar_t	ipt_len;		/* size of structure (variable) */
	uchar_t	ipt_ptr;		/* index of current entry */
#ifdef _BIT_FIELDS_LTOH
	uchar_t	ipt_flg:4,		/* flags, see below */
		ipt_oflw:4;		/* overflow counter */
#else
	uchar_t	ipt_oflw:4,		/* overflow counter */
		ipt_flg:4;		/* flags, see below */
#endif
	union ipt_timestamp {
		uint32_t	ipt_time[1];
		struct	ipt_ta {
			struct in_addr	ipt_addr;
			uint32_t	ipt_time;
		} ipt_ta[1];
	} ipt_timestamp;
};

/* flag bits for ipt_flg */
#define	IPOPT_TS_TSONLY		0		/* timestamps only */
#define	IPOPT_TS_TSANDADDR	1		/* timestamps and addresses */
#define	IPOPT_TS_PRESPEC	2		/* specified modules only */
#define	IPOPT_TS_PRESPEC_RFC791	3

/* Minimum for timestamp option */
#define	IPOPT_MINOFF_IT		5
#define	IPOPT_MINLEN_IT		5

#define	IPOPT_TS_TIMELEN	4	/* Timestamp size */

/* bits for security (not byte swapped) */
#define	IPOPT_SECUR_UNCLASS	0x0000
#define	IPOPT_SECUR_CONFID	0xf135
#define	IPOPT_SECUR_EFTO	0x789a
#define	IPOPT_SECUR_MMMM	0xbc4d
#define	IPOPT_SECUR_RESTR	0xaf13
#define	IPOPT_SECUR_SECRET	0xd788
#define	IPOPT_SECUR_TOPSECRET	0x6bc5

/*
 * Internet implementation parameters.
 */
#define	MAXTTL		255		/* maximum time to live (seconds) */
#define	IPFRAGTTL	60		/* time to live for frags, slowhz */
#define	IPTTLDEC	1		/* subtracted when forwarding */

#define	IP_MSS		576		/* default maximum segment size */

#ifdef	__cplusplus
}
#endif

#endif	/* _NETINET_IP_H */
