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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SNOOP_PPP_H
#define	_SNOOP_PPP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Control Protocol (LCP, IPCP, etc.) message code numbers.
 */
#define	CODE_VENDOR	0	/* Vendor Specif Code */
#define	CODE_CONFREQ	1	/* Configuration Request */
#define	CODE_CONFACK	2	/* Configuration Ack */
#define	CODE_CONFNAK	3	/* Configuration Nak */
#define	CODE_CONFREJ	4	/* Configuration Reject */
#define	CODE_TERMREQ	5	/* Termination Request */
#define	CODE_TERMACK	6	/* Termination Ack */
#define	CODE_CODEREJ	7	/* Code Reject */
/*
 * LCP specific codes.
 */
#define	CODE_PROTREJ	8	/* Protocol Reject */
#define	CODE_ECHOREQ	9	/* Echo Request */
#define	CODE_ECHOREP	10	/* Echo Reply */
#define	CODE_DISCREQ	11	/* Discard Request */
#define	CODE_IDENT	12	/* Identification */
#define	CODE_TIMEREMAIN	13	/* Time Remaining */
/*
 * CCP and ECP specific codes.
 */
#define	CODE_RESETREQ	14
#define	CODE_RESETACK	15

/*
 * CHAP codes.
 */
#define	CODE_CHALLENGE	1
#define	CODE_RESPONSE	2
#define	CODE_SUCCESS	3
#define	CODE_FAILURE	4

/*
 * PAP codes.
 */
#define	CODE_AUTHREQ	1
#define	CODE_AUTHACK	2
#define	CODE_AUTHNAK	3

/*
 * Option types for various control protocols.
 */
#define	OPT_LCP_VENDOR		0
#define	OPT_LCP_MRU		1
#define	OPT_LCP_ASYNCMAP	2
#define	OPT_LCP_AUTHTYPE	3
#define	OPT_LCP_QUALITY		4
#define	OPT_LCP_MAGICNUMBER	5
#define	OPT_LCP_PCOMPRESSION	7
#define	OPT_LCP_ACCOMPRESSION	8
#define	OPT_LCP_FCSALTERN	9
#define	OPT_LCP_SELFDESCPAD	10
#define	OPT_LCP_NUMBERED	11
#define	OPT_LCP_MULTILINKPROC	12
#define	OPT_LCP_CALLBACK	13
#define	OPT_LCP_CONNECTTIME	14
#define	OPT_LCP_COMPOUNDFRAMES	15
#define	OPT_LCP_DATAENCAP	16
#define	OPT_LCP_MRRU		17
#define	OPT_LCP_SSNHF		18
#define	OPT_LCP_EPDISC		19
#define	OPT_LCP_DCEIDENT	21
#define	OPT_LCP_MLPLUSPROC	22
#define	OPT_LCP_LINKDISC	23
#define	OPT_LCP_AUTH		24
#define	OPT_LCP_COBS		25
#define	OPT_LCP_PFXELISION	26
#define	OPT_LCP_MPHDRFMT	27
#define	OPT_LCP_I18N		28
#define	OPT_LCP_SDL		29
#define	OPT_LCP_MUXING		30

#define	OPT_IPCP_ADDRS		1
#define	OPT_IPCP_COMPRESSTYPE	2
#define	OPT_IPCP_ADDR		3
#define	OPT_IPCP_MOBILEIPV4	4
#define	OPT_IPCP_DNS1		129
#define	OPT_IPCP_NBNS1		130
#define	OPT_IPCP_DNS2		131
#define	OPT_IPCP_NBNS2		132
#define	OPT_IPCP_SUBNET		144

#define	OPT_IPV6CP_IFACEID	1
#define	OPT_IPV6CP_COMPRESSTYPE	2

#define	OPT_CCP_PROPRIETARY	0
#define	OPT_CCP_PREDICTOR1	1
#define	OPT_CCP_PREDICTOR2	2
#define	OPT_CCP_PUDDLEJUMP	3
#define	OPT_CCP_HPPPC		16
#define	OPT_CCP_STACLZS		17
#define	OPT_CCP_MPPC		18
#define	OPT_CCP_GANDALFFZA	19
#define	OPT_CCP_V42BIS		20
#define	OPT_CCP_BSDCOMP		21
#define	OPT_CCP_LZSDCP		23
#define	OPT_CCP_MAGNALINK	24
#define	OPT_CCP_DEFLATE		26

#define	OPT_ECP_PROPRIETARY	0
#define	OPT_ECP_DESE		1
#define	OPT_ECP_3DESE		2
#define	OPT_ECP_DESEBIS		3

#define	OPT_MUXCP_DEFAULTPID	1

/*
 * ppp_protoinfo_t's contain properties of PPP protocols which
 * interpret_ppp() needs in order to properly decode the protocol data.
 */
typedef struct ppp_protoinfo {
	uint16_t proto;			/* protocol number */
	char *name;			/* protocol name */
	int (*interpret_proto)();	/* interpret function */
	char *prefix;			/* string printed on detail lines */
	char *description;		/* string printed in detail header */
} ppp_protoinfo_t;


/*
 * cp_optinfo contains information on control protocol options.
 */
typedef void optformat_func_t(uchar_t *, uint8_t);
typedef struct cp_optinfo {
	uint8_t	opt_type;
	char *opt_name;
	uint8_t opt_minsize; /* min size of option, including type and len */
	optformat_func_t *opt_formatdata;
} cp_optinfo_t;


/*
 * Packet format for PPP control and authentication protocols.
 */
typedef struct ppp_pkt {
	uint8_t code;
	uint8_t id;
	uint16_t length;
} ppp_pkt_t;

/*
 * Structure of an LQR packet.
 */
typedef struct lqr_pkt {
	uint32_t lqr_magic;
	uint32_t lqr_lastoutlqrs;
	uint32_t lqr_lastoutpackets;
	uint32_t lqr_lastoutoctets;
	uint32_t lqr_peerinlqrs;
	uint32_t lqr_peerinpackets;
	uint32_t lqr_peerindiscards;
	uint32_t lqr_peerinerrors;
	uint32_t lqr_peerinoctets;
	uint32_t lqr_peeroutlqrs;
	uint32_t lqr_peeroutpackets;
	uint32_t lqr_peeroutoctets;
} lqr_pkt_t;

#endif /* _SNOOP_PPP_H */
