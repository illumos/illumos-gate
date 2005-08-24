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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <protocols/routed.h>
#include <string.h>
#include <arpa/inet.h>
#include "snoop.h"
#include "snoop_mip.h"

/*
 * This defines the length of internal, unbounded buffers. We set
 * this to be MAXLINE (the maximum verbose display line length) -
 * 64, which should be enough for all necessary descriptions.
 */
#define	BUFLEN	MAXLINE - 64

extern char *dlc_header;
extern char *addrtoname();

enum EXT_TYPE { ADV, REG };

/*
 * This defines the interface for all extention interpreter
 * functions. The function will be called with following
 * parameters:
 *
 * type:	IN	The type code for this extention
 * len		IN	The length of the payload (i.e. the
 *			length field in an extension header)
 * payload	IN	A pointer to the beginning of the
 *			extension payload
 */
typedef void interpreter_f(uint8_t type, uint8_t len, uchar_t *payload);

struct ext_dispatch {
	uint8_t type;
	interpreter_f *pfunc;
};

/* Description structure -- maps type to description */
struct ext_desc {
	uint8_t type;
	const char *desc;
};

/*
 * Interpreter function prototypes for both adv and reg. These
 * all must implement the interpret_f interface defined above.
 */
static void spi_ext(uint8_t, uint8_t, uchar_t *);
static void key_ext(uint8_t, uint8_t, uchar_t *);
static void trav_ext(uint8_t, uint8_t, uchar_t *);
static void empty_ext(uint8_t, uint8_t, uchar_t *);
static void nai_ext(uint8_t, uint8_t, uchar_t *);
static void chall_ext(uint8_t, uint8_t, uchar_t *);
static void ma_ext(uint8_t, uint8_t, uchar_t *);
static void prefix_ext(uint8_t, uint8_t, uchar_t *);
static void unk_ext(uint8_t, uint8_t, uchar_t *);

/* R E G I S T R A T I O N */

#define	REG_TBL_LEN	10	/* update this when adding to the table */

/* Reg: type to description mapping table */
static struct ext_desc reg_desc[] = {
	MN_HA_AUTH,	"(Mobile-Home Authentication Extension)",
	MN_FA_AUTH,	"(Mobile-Foreign Authentication Extension",
	FA_HA_AUTH,	"(Foreign-Home Authentication Extension)",
	GEN_AUTH,	"(Generalized Authentication Extension)",
	MN_HA_KEY,	"(Mobile-Home Key Extension)",
	MN_FA_KEY,	"(Mobile-Foreign Key Extension)",
	MN_HA_TRAVERSE,	"(Firewall Traversal Extension)",
	ENCAP_DELIV,	"(Encapsulating Delivery Style Extension)",
	MN_NAI,		"(Mobile Node Network Access Identifier)",
	FA_CHALLENGE,	"(Mobile-Foreign Agent Challenge)",
	0,		"(Unrecognized Extension)"
};

#define	GENAUTH_TBL_LEN	1	/* update this when adding to the table */

/* Subtypes for Generic Authentication Extension type (type 36) */
static struct ext_desc genauth_desc[] = {
	GEN_AUTH_MN_AAA,	"(MN-AAA Authentication Subtype)",
	0,			"(Unrecognized Subtype)"
};

/* Reg: type to function mapping table */
static struct ext_dispatch reg_dispatch[] = {
	MN_HA_AUTH,	spi_ext,
	MN_FA_AUTH,	spi_ext,
	FA_HA_AUTH,	spi_ext,
	GEN_AUTH,	spi_ext,
	MN_HA_KEY,	key_ext,
	MN_FA_KEY,	key_ext,
	MN_HA_TRAVERSE,	trav_ext,
	ENCAP_DELIV,	empty_ext,
	MN_NAI,		nai_ext,
	FA_CHALLENGE,	chall_ext,
	0,		unk_ext
};

/* A D V E R T I S E M E N T */

#define	ADV_TBL_LEN	5	/* update this when adding to the table */

/* Adv: type to description mapping table */
static struct ext_desc adv_desc[] = {
	ICMP_ADV_MSG_PADDING_EXT,	"(Padding)",
	ICMP_ADV_MSG_MOBILITY_AGT_EXT,	"(Mobility Agent Extension)",
	ICMP_ADV_MSG_PREFIX_LENGTH_EXT,	"(Prefix Lengths)",
	ICMP_ADV_MSG_FA_CHALLENGE,	"(Foreign Agent Challenge)",
	ICMP_ADV_MSG_FA_NAI,		"(Foreign Agent NAI)",
	0,				"(Unrecognized Extension)"
};

/* Adv: type to function mapping table */
static struct ext_dispatch adv_dispatch[] = {
	ICMP_ADV_MSG_PADDING_EXT,	NULL,	/* never called */
	ICMP_ADV_MSG_MOBILITY_AGT_EXT,	ma_ext,
	ICMP_ADV_MSG_PREFIX_LENGTH_EXT,	prefix_ext,
	ICMP_ADV_MSG_FA_CHALLENGE,	chall_ext,
	ICMP_ADV_MSG_FA_NAI,		nai_ext,
	0,				unk_ext
};

#define	GETSPI(payload, hi, low) \
	(void) memcpy(&hi, payload, sizeof (hi)); \
	(void) memcpy(&low, payload + sizeof (hi), sizeof (low))

static void dumphex(uchar_t *payload, int payload_len, char *buf, char *msg) {
	int index;

	for (index = 0; index < payload_len; index++) {
		(void) sprintf(&buf[index * 3], " %.2x", payload[index]);
	}

	(void) sprintf(get_line((char *)payload-dlc_header, 1), msg, buf);
}

static const char *get_desc(struct ext_desc table[], uint8_t type, int max) {
	int i;

	for (i = 0; i < max && table[i].type != type; i++)
	    /* NO_OP */;

	return (table[i].desc);
}

/*
 * The following is an accessor for the description table, used by
 * snoop_icmp.c. This maintains the encapsulation of the internal
 * description table.
 */
const char *get_mip_adv_desc(uint8_t type) {
	return (get_desc(adv_desc, type, ADV_TBL_LEN));
}

static interpreter_f *get_interpreter(struct ext_dispatch table[],
				uint8_t type,
				int max) {
	int i;

	for (i = 0; i < max && table[i].type != type; i++)
	    /* NO_OP */;

	return (table[i].pfunc);
}

static int
interpret_extensions(uchar_t *ext,
			int regext_size,
			enum EXT_TYPE etype) {

	int curr_size  =  regext_size; /* remaining total for all exts */
	exthdr_t *exthdr;
	gen_exthdr_t *gen_exthdr;
	const char *st;
	uchar_t	*p;
	interpreter_f *f;
	uint8_t	ext_type;
	uint16_t ext_len;
	uint_t ext_hdrlen;

	show_space();
	exthdr = (exthdr_t *)ALIGN(ext);


	do {
	    ext_type = exthdr->type;
	    if (ext_type == GEN_AUTH) {
		gen_exthdr = (gen_exthdr_t *)exthdr;
		ext_hdrlen = sizeof (gen_exthdr_t);
		ext_len = ntohs(gen_exthdr->length);
	    } else {
		ext_hdrlen = sizeof (exthdr_t);
		ext_len = exthdr->length;
	    }

	    if (!((etype == ADV && ext_type == ICMP_ADV_MSG_PADDING_EXT &&
		curr_size >= 1) ||
		curr_size >= ext_hdrlen + ext_len))
		    break;

	    /* Print description for this extension */
	    if (etype == ADV) {
		st = get_desc(adv_desc, ext_type, ADV_TBL_LEN);
	    } else /* REG */ {
		st = get_desc(reg_desc, ext_type, REG_TBL_LEN);
	    }

	    (void) sprintf(get_line((char *)exthdr-dlc_header, 1),
			"Extension header type = %d  %s", ext_type, st);

	    if (ext_type == GEN_AUTH) {
		st = get_desc(genauth_desc, gen_exthdr->subtype,
		    GENAUTH_TBL_LEN);
		(void) sprintf(get_line((char *)exthdr-dlc_header, 1),
		    "Subtype = %d %s", gen_exthdr->subtype, st);
	    }

	    /* Special case for 1-byte padding */
	    if (etype == ADV && ext_type == ICMP_ADV_MSG_PADDING_EXT) {
		exthdr = (exthdr_t *)((uchar_t *)exthdr + 1);
		curr_size--;
		continue;
	    }

	    (void) sprintf(get_line((char *)&exthdr->length-dlc_header, 1),
			"Length = %d", ext_len);

	    /* Parse out the extension's payload */
	    p = (uchar_t *)exthdr + ext_hdrlen;
	    curr_size -= (ext_hdrlen + ext_len);

	    if (etype == ADV) {
		f = get_interpreter(adv_dispatch, ext_type, ADV_TBL_LEN);
	    } else /* REG */ {
		f = get_interpreter(reg_dispatch, ext_type, REG_TBL_LEN);
	    }

	    f(ext_type, ext_len, p);

	    show_space();
	    exthdr = (exthdr_t *)(p + ext_len);
	} while (B_TRUE);

	return (0);
}

void interpret_icmp_mip_ext(uchar_t *p, int len) {
	show_space();
	show_header("ICMP:  ", " MIP Advertisement Extensions ", len);
	show_space();

	interpret_extensions(p, len, ADV);
}

void
interpret_mip_cntrlmsg(int flags, uchar_t *msg, int fraglen) {
	char		*pt, *pc = NULL;
	char		*line;
	regreq_t	rreq[1];
	regrep_t	rrep[1];
	int		regext_size;
	uchar_t		*regext_data;
	struct in_addr	addr_temp;


	/* First byte of the message should be the type */
	switch (*msg) {
	case REG_TYPE_REQ:
		if (fraglen < sizeof (regreq_t))
			return;
		pt = (flags & F_DTAIL ? "registration request ":"reg rqst ");

		(void) memcpy(rreq, msg, sizeof (*rreq));
		regext_size = fraglen - sizeof (regreq_t);
		regext_data = msg + sizeof (*rreq);
		break;
	case REG_TYPE_REP:
		if (fraglen < sizeof (regrep_t))
			return;
		pt = (flags & F_DTAIL ? "registration reply ":"reg reply ");

		(void) memcpy(rrep, msg, sizeof (*rrep));
		regext_size = fraglen - sizeof (regrep_t);
		regext_data = msg + sizeof (*rrep);

		switch (rrep->code) {
		case  REPLY_CODE_ACK:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL)) ?
			    "OK" : "OK code 0";
			break;
		case  REPLY_CODE_ACK_NO_SIMULTANEOUS:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "OK simultaneous bindings" : "OK code 1";
			break;
		case  REPLY_CODE_FA_NACK_UNSPECIFIED:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: unspecified":"FA denial: code 64";
			break;
		case  REPLY_CODE_FA_NACK_PROHIBITED:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: prohibited":"FA denial: code 65";
			break;
		case  REPLY_CODE_FA_NACK_RESOURCES:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: no resources":"FA denial: code 66";
			break;
		case  REPLY_CODE_FA_NACK_MN_AUTH:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: MN auth failed":"FA denial: code 67";
			break;
		case  REPLY_CODE_FA_NACK_HA_AUTH:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: HA auth failed":
			    "FA denial: code 68";
			break;
		case  REPLY_CODE_FA_NACK_LIFETIME:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: lifetime":"FA denial: code 69";
			break;
		case  REPLY_CODE_FA_NACK_BAD_REQUEST:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: bad request": "FA: code 70";
			break;
		case  REPLY_CODE_FA_NACK_BAD_REPLY:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: bad Reply":"FA denial: code 71";
			break;
		case  REPLY_CODE_FA_NACK_ENCAP_UNAVAILABLE:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: encapsulation":"FA denial: code 72";
			break;
		case  REPLY_CODE_FA_NACK_VJ_UNAVAILABLE:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: VJ compression":"FA denial: code 73";
			break;
		case  REPLY_CODE_FA_NACK_BIDIR_TUNNEL_UNAVAILABLE:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: reverse tunnel unavailable":
				"FA denial: code 74";
			break;
		case  REPLY_CODE_FA_NACK_BIDIR_TUNNEL_NO_TBIT:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: reverse tunnel: missing T-bit":
				"FA denial: code 75";
			break;
		case  REPLY_CODE_FA_NACK_BIDIR_TUNNEL_TOO_DISTANT:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: reverse tunnel: too distant":
				"FA denial: code 76";
			break;
		case  REPLY_CODE_FA_NACK_ICMP_HA_NET_UNREACHABLE:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: home network unreachable":
			    "FA denial: code 80";
			break;
		case  REPLY_CODE_FA_NACK_ICMP_HA_HOST_UNREACHABLE:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: HA host unreachable":
			    "FA denial: code 81";
			break;
		case  REPLY_CODE_FA_NACK_ICMP_HA_PORT_UNREACHABLE:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: HA port unreachable":
			    "FA denial: code 82";
			break;
		case  REPLY_CODE_FA_NACK_ICMP_HA_UNREACHABLE:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: HA unreachable":"FA denial: code 88";
			break;
		case REPLY_CODE_FA_NACK_UNIQUE_HOMEADDR_REQD:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: Unique Home Addr Required":
				"FA denial: code 96";
			break;
		case REPLY_CODE_FA_NACK_MISSING_NAI:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: Missing NAI":
				"FA denial: code 97";
			break;
		case REPLY_CODE_FA_NACK_MISSING_HOME_AGENT:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: Missing Home Agent":
				"FA denial: code 98";
			break;
		case REPLY_CODE_FA_NACK_UNKNOWN_CHALLENGE:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: Unknown Challenge":
				"FA denial: code 104";
			break;
		case REPLY_CODE_FA_NACK_MISSING_CHALLENGE:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: Missing Challenge":
				"FA denial: code 105";
			break;
		case REPLY_CODE_FA_NACK_MISSING_MN_FA:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "FA denial: Missing Mobile-Foreign Key Extension":
				"FA denial: code 106";
			break;
		case  REPLY_CODE_HA_NACK_UNSPECIFIED:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "HA denial: unspecified":"HA denial: code 128";
			break;
		case  REPLY_CODE_HA_NACK_PROHIBITED:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "HA denial: prohibited":"HA denial: code 129";
			break;
		case  REPLY_CODE_HA_NACK_RESOURCES:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "HA denial: no resources":"HA denial: code 130";
			break;
		case  REPLY_CODE_HA_NACK_MN_AUTH:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "HA denial: MN auth failed":"HA denial: code 131";
			break;
		case  REPLY_CODE_HA_NACK_FA_AUTH:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "HA denial: FA auth failed":"HA denial: code 132";
			break;
		case  REPLY_CODE_HA_NACK_ID_MISMATCH:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "HA denial: ID mismatch":"HA denial: code 133";
			break;
		case  REPLY_CODE_HA_NACK_BAD_REQUEST:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "HA denial: bad request":"HA denial: code 134";
			break;
		case  REPLY_CODE_HA_NACK_TOO_MANY_BINDINGS:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "HA denial: too many bindings":
			    "HA denial: code 135";
			break;
		case  REPLY_CODE_HA_NACK_BAD_HA_ADDRESS:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "HA denial: bad HA address":"HA denial: code 136";
			break;
		case  REPLY_CODE_HA_NACK_BIDIR_TUNNEL_UNAVAILABLE:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "HA denial: no reverse tunnel":
			    "HA denial: code 137";
			break;
		case  REPLY_CODE_HA_NACK_BIDIR_TUNNEL_NO_TBIT:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "HA denial: reverse tunnel: no T-bit":
			    "HA denial: code 138";
			break;
		case  REPLY_CODE_HA_NACK_BIDIR_ENCAP_UNAVAILABLE:
			pc = ((flags & F_ALLSUM) || (flags & F_DTAIL))?
			    "HA denial: encapsulation unavailable":
			    "HA denial: code 139";
			break;
		default:
			pc = "?";
			break;
		}
		break;

	default :
		break;
	}
	if (flags & F_SUM) {
		line = get_sum_line();

		if (pc != NULL)
			(void) sprintf(line, "Mobile IP %s(%s)", pt, pc);
		else
			(void) sprintf(line, "Mobile IP %s", pt);
	}

	if (flags & F_DTAIL) {
		show_header("MIP:  ", "Mobile IP Header", fraglen);
		show_space();

		if (*msg == REG_TYPE_REQ) {
			(void) sprintf(get_line((char *)&rreq -
			    dlc_header, 1), "Registration header type = %s",
			    pt);
			(void) sprintf(get_line(
			    (char *)(((uchar_t *)&rreq) + 1) - dlc_header, 1),
			    "%d... .... = %s simultaneous bindings  ",
			    (rreq->Simultaneous_registration == 1)? 1 : 0,
			    (rreq->Simultaneous_registration == 1)? "":"no");
			(void) sprintf(get_line(
			    (char *)(((uchar_t *)&rreq) + 1) - dlc_header, 1),
			    ".%d.. .... = %s broadcast datagrams ",
			    (rreq->Broadcasts_desired == 1) ?  1 : 0,
			    (rreq->Broadcasts_desired == 1) ? "":"no");
			(void) sprintf(get_line(
			    (char *)(((uchar_t *)&rreq) + 1) - dlc_header, 1),
			    "..%d. .... = %s decapsulation by MN",
			    (rreq->Decapsulation_done_locally == 1) ? 1 : 0,
			    (rreq->Decapsulation_done_locally == 1) ?
				"" : "no");
			(void) sprintf(get_line(
			    (char *)(((uchar_t *)&rreq) + 1) - dlc_header, 1),
			    "...%d .... = %s minimum encapsulation ",
			    (rreq->Minimal_encap_desired == 1) ? 1 : 0,
			    (rreq->Minimal_encap_desired == 1) ? "" : "no");
			(void) sprintf(get_line(
			    (char *)(((uchar_t *)&rreq) + 1) - dlc_header, 1),
			    ".... %d... = %s GRE encapsulation ",
			    (rreq->GRE_encap_desired == 1) ? 1 : 0,
			    (rreq->GRE_encap_desired == 1) ? "" : "no");
			(void) sprintf(get_line(
			    (char *)(((uchar_t *)&rreq) + 1) - dlc_header, 1),
			    ".... .%d.. = %s VJ hdr Compression ",
			    (rreq->VJ_compression_desired == 1) ? 1 : 0,
			    (rreq->VJ_compression_desired == 1) ? "" : "no");
			(void) sprintf(get_line(
			    (char *)(((uchar_t *)&rreq) + 1) - dlc_header, 1),
			    ".... ..%d. = %s reverse tunnel",
			    (rreq->BiDirectional_Tunnel_desired == 1) ? 1 : 0,
			    (rreq->BiDirectional_Tunnel_desired == 1) ?
				"" : "no");
			if (ntohs(rreq->lifetime) == 0xffff) {
				(void) sprintf(get_line(
				    (char *)&rreq->lifetime - dlc_header, 1),
				    "Life Time = 0xFFFF (infinity)");
			} else if (ntohs(rreq->lifetime) == 0) {
				(void) sprintf(get_line(
				    (char *)&rreq->lifetime - dlc_header, 1),
				    "Life Time = 0 "
				    "(request for de-registration)");
			} else {
				(void) sprintf(get_line(
				    (char *)&rreq->lifetime - dlc_header, 1),
				    "Life time = %d seconds",
				    ntohs(rreq->lifetime));
			}
			addr_temp.s_addr = rreq->home_addr;
			(void) sprintf(get_line(
			    (char *)&rreq->home_addr - dlc_header, 1),
			    "Home address = %s, %s",
			    inet_ntoa(addr_temp),
			    addrtoname(AF_INET, &addr_temp));
			addr_temp.s_addr = rreq->home_agent_addr;
			(void) sprintf(get_line(
			    (char *)&rreq->home_agent_addr - dlc_header, 1),
			    "Home Agent address = %s, %s",
			    inet_ntoa(addr_temp),
			    addrtoname(AF_INET, &addr_temp));
			addr_temp.s_addr = rreq->care_of_addr;
			(void) sprintf(get_line(
			    (char *)&rreq->care_of_addr - dlc_header, 1),
			    "Care of address = %s, %s",
			    inet_ntoa(addr_temp),
			    addrtoname(AF_INET, &addr_temp));
			(void) sprintf(get_line(
			    (char *)&rreq->identification - dlc_header, 1),
			    "Identification = 0x%x-%x",
			    ntohl(rreq->identification.high_bits),
			    ntohl(rreq->identification.low_bits));
		} else if (*msg == REG_TYPE_REP) {
			(void) sprintf(
			    get_line((char *)&rrep->type - dlc_header, 1),
			    "Registration header type = %d (%s)",
			    (int)rrep->type, pt);
			(void) sprintf(get_line((char *)&rrep - dlc_header, 1),
			    "Code = %d %s", (int)rrep->code, pc);
			if (ntohs(rrep->lifetime) == 0xffff) {
				(void) sprintf(get_line(
				    (char *)&rrep->lifetime - dlc_header, 1),
				    "Life time = 0xFFFF (infinity)");
			} else if (ntohs(rrep->lifetime) == 0) {
				(void) sprintf(get_line(
				    (char *)&rrep->lifetime - dlc_header, 1),
				    ((rrep->code == REPLY_CODE_ACK) ||
				    (rrep->code ==
					REPLY_CODE_ACK_NO_SIMULTANEOUS))?
				    "Life time = 0 (de-registeration success)" :
				    "Life time = 0 (de-registration failed)");
			} else {
				(void) sprintf(get_line(
				    (char *)&rrep->lifetime - dlc_header, 1),
				    "Life time = %d seconds",
				    ntohs(rrep->lifetime));
			}
			addr_temp.s_addr = rrep->home_addr;
			(void) sprintf(
			    get_line((char *)&rrep->home_addr - dlc_header, 1),
			    "Home address = %s, %s",
			    inet_ntoa(addr_temp),
			    addrtoname(AF_INET, &addr_temp));
			addr_temp.s_addr = rrep->home_agent_addr;
			(void) sprintf(get_line(
			    (char *)&rrep->home_agent_addr - dlc_header, 1),
			    "Home Agent address = %s, %s",
			    inet_ntoa(addr_temp),
			    addrtoname(AF_INET, &addr_temp));
			(void) sprintf(get_line(
			    (char *)&rrep->identification - dlc_header, 1),
			    "Identification = 0x%x-%x",
			    ntohl(rrep->identification.high_bits),
			    ntohl(rrep->identification.low_bits));
		}
		fraglen = interpret_extensions(regext_data, regext_size, REG);
	}
}

/*ARGSUSED*/
static void spi_ext(uint8_t type, uint8_t this_ext_len, uchar_t *p) {
	uint16_t spi_hi, spi_low;
	char	auth_prn_str[BUFLEN];

	/* SPI */
	GETSPI(p, spi_hi, spi_low);
	(void) sprintf(get_line((char *)p - dlc_header, 1),
			"Security Parameter Index = 0x%x%x",
			ntohs(spi_hi), ntohs(spi_low));
	p += sizeof (spi_hi) + sizeof (spi_low);
	this_ext_len -= sizeof (spi_hi) + sizeof (spi_low);

	/* The rest is the authenticator; dump it in hex */
	dumphex(p,
		/* don't write past our string buffer ... */
		(this_ext_len*3 > BUFLEN ? BUFLEN : this_ext_len),
		auth_prn_str,
		"Authenticator = %s");
}

static void key_ext(uint8_t type, uint8_t this_ext_len, uchar_t *p) {
	uint16_t alg, spi_hi, spi_low;
	char *alg_string;
	char *hafa = (type == MN_HA_KEY ? "HA" : "FA");
	char sec_msg[32];
	char auth_prn_str[BUFLEN];

	/* Algorithm Type */
	(void) memcpy(&alg, p, sizeof (alg));
	alg = ntohs(alg);
	switch (alg) {
	case KEY_ALG_NONE:
	    alg_string = "None";
	    break;
	case SA_MD5_MODE_PREF_SUF:
	    alg_string = "MD5/prefix+suffix";
	    break;
	case SA_HMAC_MD5:
	    alg_string = "HMAC MD5";
	    break;
	default:
	    alg_string = "Unknown";
	    break;
	}
	(void) sprintf(get_line((char *)p-dlc_header, 1),
			"Algorithm = 0x%x: %s", alg, alg_string);
	p += sizeof (alg);
	this_ext_len -= sizeof (alg);

	/* AAA SPI */
	GETSPI(p, spi_hi, spi_low);
	(void) sprintf(get_line((char *)p - dlc_header, 1),
			"AAA Security Parameter Index = 0x%x%x",
			ntohs(spi_hi), ntohs(spi_low));
	p += sizeof (spi_hi) + sizeof (spi_low);
	this_ext_len -= sizeof (spi_hi) + sizeof (spi_low);

	/* HA / FA SPI */
	GETSPI(p, spi_hi, spi_low);
	(void) sprintf(get_line((char *)p - dlc_header, 1),
			"%s Security Parameter Index = 0x%x%x",
			hafa, ntohs(spi_hi), ntohs(spi_low));
	p += sizeof (spi_hi) + sizeof (spi_low);
	this_ext_len -= sizeof (spi_hi) + sizeof (spi_low);

	/* The rest is the security info; dump it in hex */
	sprintf(sec_msg, "%s Security Info = %%s", hafa);
	dumphex(p,
		/* don't write past our string buffer ... */
		(this_ext_len*3 > BUFLEN ? BUFLEN : this_ext_len),
		auth_prn_str,
		sec_msg);
}

/*ARGSUSED*/
static void trav_ext(uint8_t type, uint8_t this_ext_len, uchar_t *p) {
	struct in_addr addr_temp;

	/* skip reserved */
	p += 2;
	this_ext_len -= 2;

	/* Mobile-Home Traversal Address */
	(void) memcpy(&(addr_temp.s_addr), p, sizeof (addr_temp.s_addr));
	(void) sprintf(get_line((char *)p-dlc_header, 1),
			"Mobile-Home Traversal Address= %s, %s",
			inet_ntoa(addr_temp),
			addrtoname(AF_INET, &addr_temp));
	p += sizeof (addr_temp.s_addr);
	this_ext_len -= sizeof (addr_temp.s_addr);

	/* Home-Mobile Traversal Address */
	(void) memcpy(&(addr_temp.s_addr), p, sizeof (addr_temp.s_addr));
	(void) sprintf(get_line((char *)p-dlc_header, 1),
			"Home-Mobile Traversal Address= %s, %s",
			inet_ntoa(addr_temp),
			addrtoname(AF_INET, &addr_temp));
}

/*ARGSUSED*/
static void empty_ext(uint8_t type, uint8_t this_ext_len, uchar_t *p) {
	/* no payload */
}

/*ARGSUSED*/
static void nai_ext(uint8_t type, uint8_t this_ext_len, uchar_t *p) {
	/* payload points to the NAI */
	char *desc = "Network Access Identifier = ";
	size_t desclen = strlen(desc) + 1 + this_ext_len;

	(void) snprintf(get_line((char *)p-dlc_header, 1),
			desclen > MAXLINE ? MAXLINE : desclen,
			"%s%s", desc, p);
}

/*ARGSUSED*/
static void chall_ext(uint8_t type, uint8_t this_ext_len, uchar_t *p) {
	char	auth_prn_str[BUFLEN];

	/* payload points to the challenge */
	dumphex(p,
		/* don't write past our string buffer ... */
		(this_ext_len*3 > BUFLEN ? BUFLEN / 3 : this_ext_len),
		auth_prn_str,
		"Challenge = %s");
}

/*ARGSUSED*/
static void ma_ext(uint8_t type, uint8_t this_ext_len, uchar_t *p) {
	mobagtadvext_t adv_ext[1];
	int i, len;
	struct in_addr temp_addr;

	(void) memcpy(adv_ext, p - sizeof (exthdr_t), sizeof (*adv_ext));
	(void) sprintf(get_line(0, 0), "Sequence number = %d",
			ntohs(adv_ext->sequence_num));
	(void) sprintf(get_line(0, 0),
			"Registration lifetime = %d seconds",
			ntohs(adv_ext->reg_lifetime));
	if (adv_ext->reg_bit) {
	    (void) sprintf(get_line(0, 0),
				"1... .... = registration required "
				"through FA");
	} else {
	    (void) sprintf(get_line(0, 0),
				"0... .... = registration not required "
				"through FA");
	}
	if (adv_ext->busy_bit) {
	    (void) sprintf(get_line(0, 0), ".1.. .... = FA busy");
	} else {
	    (void) sprintf(get_line(0, 0), ".0.. .... = FA not busy");
	}
	if (adv_ext->ha_bit) {
	    (void) sprintf(get_line(0, 0), "..1. .... = node is HA");
	} else {
	    (void) sprintf(get_line(0, 0), "..0. .... = node not HA");
	}
	if (adv_ext->fa_bit) {
	    (void) sprintf(get_line(0, 0), "...1 .... = node is FA ");
	} else {
	    (void) sprintf(get_line(0, 0), "...0 .... = node not FA ");
	}
	if (adv_ext->minencap_bit) {
	    (void) sprintf(get_line(0, 0), ".... 1... = minimal encapsulation "
							"supported");
	} else {
	    (void) sprintf(get_line(0, 0),
				".... 0... = no minimal encapsulation");
	}
	if (adv_ext->greencap_bit) {
	    (void) sprintf(get_line(0, 0),
				".... .1.. =  GRE encapsulation supported");
	} else {
	    (void) sprintf(get_line(0, 0),
				".... .0.. = no GRE encapsulation");
	}
	if (adv_ext->vanjacob_hdr_comp_bit) {
	    (void) sprintf(get_line(0, 0),
				".... ..1. = VJ header compression");
	} else {
	    (void) sprintf(get_line(0, 0),
				".... ..0. = no VJ header compression");
	}
	if (adv_ext->reverse_tunnel_bit) {
	    (void) sprintf(get_line(0, 0),
				".... ...1 = reverse tunneling supported");
	} else {
	    (void) sprintf(get_line(0, 0),
				".... ...0 = no reverse tunneling");
	}
	(void) sprintf(get_line(0, 0),
			"Reserved Byte = 0x%x", adv_ext->reserved);

	/* Parse out COA's */
	p += sizeof (*adv_ext);
	len = this_ext_len + sizeof (exthdr_t);
	/* this_ext_len is unsigned, and here we need a signed number */
	len -= sizeof (*adv_ext);

	for (i = 0; len >= sizeof (temp_addr.s_addr); i++) {
	    memcpy(&(temp_addr.s_addr), p - sizeof (exthdr_t),
		sizeof (temp_addr.s_addr));

	    (void) sprintf(get_line(0, 0),
				"Care of address-%d = %s, %s", i,
				inet_ntoa(temp_addr),
				addrtoname(AF_INET, &temp_addr));

	    p += sizeof (temp_addr);
	    len -= sizeof (temp_addr);
	}
}

/*ARGSUSED*/
static void prefix_ext(uint8_t type, uint8_t this_ext_len, uchar_t *p) {
	int i;

	for (i = 0; i < this_ext_len; i++) {
	    (void) sprintf(get_line(0, 0),
				"Prefix length of router address[%d] "
				"= %d bits",
				i, p[i]);
	}
}

/*ARGSUSED*/
static void unk_ext(uint8_t type, uint8_t this_ext_len, uchar_t *p) {
	char	auth_prn_str[BUFLEN];

	/* Unknown extension; just dump the rest of the payload */
	dumphex(p,
		/* don't write past our string buffer ... */
		(this_ext_len*3 > BUFLEN ? BUFLEN : this_ext_len),
		auth_prn_str,
		"Payload = %s");
}
