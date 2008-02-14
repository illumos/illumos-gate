/*
 * Copyright (c) 2000-2001 Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: netbios.h,v 1.5 2004/03/19 01:49:45 lindak Exp $
 */

#ifndef _NETSMB_NETBIOS_H_
#define	_NETSMB_NETBIOS_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _NETINET_IN_H_
#include <netinet/in.h>
#endif

/*
 * This is a fake address family number, used to
 * recognize our fake sockaddr_nb objects.
 * This is never handed to bind or connect.
 */
#ifndef AF_NETBIOS
#define	AF_NETBIOS (AF_MAX+2)
#endif

#define	PF_NETBIOS	AF_NETBIOS

/*
 * NetBIOS port numbers by the names used in the Darwin code.
 * XXX: Change the code to use IPPORT_xxx from in.h directly.
 * XXX: Add IPPORT_SMB_OVER_TCP or some such (port 445)
 */
#define	NBNS_UDP_PORT		IPPORT_NETBIOS_NS	/* 137 */
#define	SMB_TCP_PORT		IPPORT_NETBIOS_SSN	/* 139 */

#define	NBPROTO_TCPSSN	1		/* NETBIOS session over TCP */

#define	NB_NAMELEN	16
#define	NB_ENCNAMELEN	NB_NAMELEN * 2
#define	NB_MAXLABLEN	63

#define	NB_MINSALEN	(sizeof (struct sockaddr_nb))

/*
 * name types
 */
#define	NBT_WKSTA	0x00
#define	NBT_CLIENT	0x03
#define	NBT_RASSRVR	0x06
#define	NBT_DMB		0x1B
#define	NBT_IP		0x1C
#define	NBT_MB		0x1D
#define	NBT_BS		0x1E
#define	NBT_NETDDE	0x1F
#define	NBT_SERVER	0x20
#define	NBT_RASCLNT	0x21
#define	NBT_NMAGENT	0xBE
#define	NBT_NMUTIL	0xBF

/*
 * Session packet types
 */
#define	NB_SSN_MESSAGE		0x0
#define	NB_SSN_REQUEST		0x81
#define	NB_SSN_POSRESP		0x82
#define	NB_SSN_NEGRESP		0x83
#define	NB_SSN_RTGRESP		0x84
#define	NB_SSN_KEEPALIVE	0x85

/*
 * resolver: Opcodes
 */
#define	NBNS_OPCODE_QUERY	0x00
#define	NBNS_OPCODE_REGISTER	0x05
#define	NBNS_OPCODE_RELEASE	0x06
#define	NBNS_OPCODE_WACK	0x07
#define	NBNS_OPCODE_REFRESH	0x08
#define	NBNS_OPCODE_RESPONSE	0x10	/* or'ed with other opcodes */

/*
 * resolver: NM_FLAGS
 */
#define	NBNS_NMFLAG_BCAST	0x01
#define	NBNS_NMFLAG_RA		0x08	/* recursion available */
#define	NBNS_NMFLAG_RD		0x10	/* recursion desired */
#define	NBNS_NMFLAG_TC		0x20	/* truncation occured */
#define	NBNS_NMFLAG_AA		0x40	/* authoritative answer */

/*
 * resolver: Question types
 */
#define	NBNS_QUESTION_TYPE_NB		0x0020
#define	NBNS_QUESTION_TYPE_NBSTAT	0x0021

/*
 * resolver: Question class
 */
#define	NBNS_QUESTION_CLASS_IN	0x0001

/*
 * resolver: Limits
 */
#define	NBNS_MAXREDIRECTS	3	/* max number of accepted redirects */
#define	NBDG_MAXSIZE		576	/* maximum nbns datagram size */

/*
 * NETBIOS addressing
 */

struct nb_name {
	uint_t		nn_type;
	char		nn_name[NB_NAMELEN];
	char		*nn_scope;
};
typedef struct nb_name nb_name_t;

/*
 * Our private NetBIOS socket address format.
 * Note that it's LARGER than sockaddr.
 *
 * XXX: Also note that the library code is sloppy about
 * casting this to sockaddr_in so let's keep snb_ipaddr
 * at the same offset, at least until that's fixed.
 */
struct sockaddr_nb {
	sa_family_t	snb_family;	/* address family */
	uint16_t    snb_flags;	/* NBNS_GROUPFLG, etc. */
	uint32_t	snb_ipaddr; /* always IPv4 */
	char		snb_name[NB_NAMELEN]; /* NOT encoded */
};
typedef struct sockaddr_nb sockaddr_nb_t;

#endif /* !_NETSMB_NETBIOS_H_ */
