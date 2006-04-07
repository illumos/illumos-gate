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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <inet/common.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
#include <string.h>
#include "snoop.h"

/*
 * Snoop interpreter for SCTP (rfc2960).
 *
 * To add support for an upper-layer protocol, modify either
 * the port-dispatcher in snoop_rport.c, or the protocol ID
 * dispatcher at the bottom of this file (or both).
 */

static void interpret_protoid(int, uint32_t, char *, int);
extern char *prot_prefix;

/*
 * This defines the length of internal, unbounded buffers. We set
 * this to be MAXLINE (the maximum verbose display line length) -
 * 64, which should be enough for all necessary descriptions. 64
 * bytes seems like a reasonably conservative estimate of the
 * maximum prefix length snoop may add to any text buffer it hands out.
 */
#define	BUFLEN	MAXLINE - 64

/*
 * Common structure to hold descriptions and parsers for all
 * chunks, parameters, and errors. Each parser should implement
 * this interface:
 *
 * void parse(int flags, uint8_t cflags, void *data, int datalen);
 *
 * Where flags is the snoop flags, cflags are the chunk flags, data
 * is the chunk or parameter data (not including the chunk or
 * parameter header), and datalen is the length of the chunk or
 * parameter data (again not including any headers).
 */
typedef void parse_func_t(int, uint8_t, const void *, int);

typedef struct {
	uint16_t id;
	const char *sdesc;	/* short description */
	const char *vdesc;	/* verbose description */
	parse_func_t *parse;	/* parser function */
} dispatch_t;

static void interpret_params(const void *, int, char *, const dispatch_t *,
    int, int);

/*
 * Chunk parsers
 */
static parse_func_t parse_abort_chunk, parse_data_chunk, parse_error_chunk,
    parse_init_chunk, parse_opaque_chunk, parse_sack_chunk,
    parse_shutdone_chunk, parse_shutdown_chunk, parse_asconf_chunk,
    parse_ftsn_chunk;


/*
 * Chunk parser dispatch table. There are few enough chunks defined
 * in the core protocol, and they are sequential, so the chunk code
 * can be used as the index into this array for the common case.
 * It is still necessary to check that the code and index match,
 * since optional extensions will not follow sequentially the
 * core chunks.
 */
static const dispatch_t chunk_dispatch_table[] = {
/*	code	F_SUM desc	F_DTAIL desc		parser function */
	{ CHUNK_DATA,			"Data",		"Data Chunk",
	    parse_data_chunk },
	{ CHUNK_INIT,			"Init",		"Init Chunk",
	    parse_init_chunk },
	{ CHUNK_INIT_ACK,		"Init ACK",	"Init ACK Chunk",
	    parse_init_chunk },
	{ CHUNK_SACK,			"SACK",		"SACK Chunk",
	    parse_sack_chunk },
	{ CHUNK_HEARTBEAT,		"Heartbeat",	"Heartbeat Chunk",
	    parse_opaque_chunk },
	{ CHUNK_HEARTBEAT_ACK,		"Heartbeat ACK", "Heartbeat ACK Chunk",
	    parse_opaque_chunk },
	{ CHUNK_ABORT,			"Abort",	"Abort Chunk",
	    parse_abort_chunk },
	{ CHUNK_SHUTDOWN,		"Shutdown",	"Shutdown Chunk",
	    parse_shutdown_chunk },
	{ CHUNK_SHUTDOWN_ACK,		"Shutdown ACK",	"Shutdown ACK Chunk",
	    NULL },
	{ CHUNK_ERROR,			"Err",		"Error Chunk",
	    parse_error_chunk },
	{ CHUNK_COOKIE,			"Cookie",	"Cookie Chunk",
	    parse_opaque_chunk },
	{ CHUNK_COOKIE_ACK,		"Cookie ACK",	"Cookie ACK Chunk",
	    parse_opaque_chunk },
	{ CHUNK_ECNE,			"ECN Echo",	"ECN Echo Chunk",
	    parse_opaque_chunk },
	{ CHUNK_CWR,			"CWR",		"CWR Chunk",
	    parse_opaque_chunk },
	{ CHUNK_SHUTDOWN_COMPLETE,	"Shutdown Done", "Shutdown Done",
	    parse_shutdone_chunk },
	{ CHUNK_FORWARD_TSN,		"FORWARD TSN", 	"Forward TSN Chunk",
	    parse_ftsn_chunk },
	{ CHUNK_ASCONF_ACK,		"ASCONF ACK", 	"ASCONF ACK Chunk",
	    parse_asconf_chunk },
	{ CHUNK_ASCONF,			"ASCONF", 	"ASCONF Chunk",
	    parse_asconf_chunk }
};

/*
 * Parameter Parsers
 */
static parse_func_t parse_encap_param, parse_int32_param, parse_ip4_param,
    parse_ip6_param, parse_opaque_param, parse_suppaddr_param,
    parse_unrec_chunk, parse_addip_param, parse_asconferr_param,
    parse_asconfok_param, parse_addiperr_param;

/*
 * Parameter parser dispatch table. The summary description is not
 * used here. Strictly speaking, parameter types are defined within
 * the context of a chunk type. However, thus far the IETF WG has
 * agreed to follow the convention that parameter types are globally
 * unique (and why not, with a 16-bit namespace). However, if this
 * ever changes, there will need to be different parameter dispatch
 * tables for each chunk type.
 */
static const dispatch_t parm_dispatch_table[] = {
/*	code	F_SUM desc	F_DTAIL desc		parser function */
	{ PARM_UNKNOWN,	"",		"Unknown Parameter",
	    parse_opaque_param },
	{ PARM_HBINFO,	"",		"Heartbeat Info",
	    parse_opaque_param },
	{ PARM_ADDR4,	"",		"IPv4 Address",
	    parse_ip4_param },
	{ PARM_ADDR6,	"",		"IPv6 Address",
	    parse_ip6_param },
	{ PARM_COOKIE,	"",		"Cookie",
	    parse_opaque_param },
	{ PARM_UNRECOGNIZED,	"",	"Unrecognized Param",
	    parse_encap_param },
	{ PARM_COOKIE_PRESERVE,	"",	"Cookie Preservative",
	    parse_opaque_param },
	{ 10,	"",			"Reserved for ECN",
	    parse_opaque_param },
	{ PARM_ADDR_HOST_NAME,	"",	"Host Name Parameter",
	    parse_opaque_param },
	{ PARM_SUPP_ADDRS,	"",	"Supported Addresses",
	    parse_suppaddr_param },
	{ PARM_ECN_CAPABLE,	"",	"ECN Capable",
	    parse_opaque_param },
	{ PARM_ADD_IP,	"",		"Add IP",
	    parse_addip_param },
	{ PARM_DEL_IP,	"",		"Del IP",
	    parse_addip_param },
	{ PARM_ASCONF_ERROR,	"",	"ASCONF Error Ind",
	    parse_asconferr_param },
	{ PARM_PRIMARY_ADDR,	"",	"Set Primary Address",
	    parse_addip_param },
	{ PARM_FORWARD_TSN,	"",	"Forward TSN",
	    NULL },
	{ PARM_ASCONF_SUCCESS,	"",	"ASCONF Success Ind",
	    parse_asconfok_param }
};

/*
 * Errors have the same wire format at parameters.
 */
static const dispatch_t err_dispatch_table[] = {
/*	code	F_SUM desc	F_DTAIL desc		parser function */
	{ SCTP_ERR_UNKNOWN,	"",		"Unknown Error",
	    parse_opaque_param },
	{ SCTP_ERR_BAD_SID,	"",		"Invalid Stream ID",
	    parse_opaque_param },
	{ SCTP_ERR_MISSING_PARM,	"",	"Missing Parameter",
	    parse_opaque_param },
	{ SCTP_ERR_STALE_COOKIE,	"",	"Stale Cookie",
	    parse_int32_param },
	{ SCTP_ERR_NO_RESOURCES,	"",	"Out Of Resources",
	    parse_opaque_param },
	{ SCTP_ERR_BAD_ADDR,	"",		"Unresolvable Address",
	    parse_opaque_param },
	{ SCTP_ERR_UNREC_CHUNK,	"",		"Unrecognized Chunk",
	    parse_unrec_chunk },
	{ SCTP_ERR_BAD_MANDPARM,	"",	"Bad Mandatory Parameter",
	    parse_opaque_param },
	{ SCTP_ERR_UNREC_PARM,	"",		"Unrecognized Parameter",
	    parse_opaque_param },
	{ SCTP_ERR_NO_USR_DATA,	"",		"No User Data",
	    parse_int32_param },
	{ SCTP_ERR_COOKIE_SHUT,	"",		"Cookie During Shutdown",
	    parse_opaque_param },
	{ SCTP_ERR_DELETE_LASTADDR,	"",	"Delete Last Remaining Address",
	    parse_addiperr_param },
	{ SCTP_ERR_RESOURCE_SHORTAGE,	"",	"Resource Shortage",
	    parse_addiperr_param },
	{ SCTP_ERR_DELETE_SRCADDR,	"",	"Delete Source IP Address",
	    parse_addiperr_param },
	{ SCTP_ERR_AUTH_ERR,	"",		"Not authorized",
	    parse_addiperr_param }
};

/*
 * These are global because the data chunk parser needs them to dispatch
 * to ULPs. The alternative is to add source and dest port arguments
 * to every parser, which seems even messier (since *only* the data
 * chunk parser needs it)...
 */
static in_port_t sport, dport;

/* Summary line miscellany */
static int sumlen;
static char scratch[MAXLINE];
static char *sumline;

#define	SUMAPPEND(fmt) \
	sumlen -= snprintf fmt; \
	(void) strlcat(sumline, scratch, sumlen)

#define	DUMPHEX_MAX	16

static const dispatch_t *
lookup_dispatch(int id, const dispatch_t *tbl, int tblsz)
{
	int i;

	/*
	 * Try fast lookup first. The common chunks defined in RFC2960
	 * will have indices aligned with their IDs, so this works for
	 * the common case.
	 */
	if (id < (tblsz - 1)) {
		if (id == tbl[id].id) {
			return (tbl + id);
		}
	}

	/*
	 * Nope - probably an extension. Search the whole table,
	 * starting from the end, since extensions are at the end.
	 */
	for (i = tblsz - 1; i >= 0; i--) {
		if (id == tbl[i].id) {
			return (tbl + i);
		}
	}

	return (NULL);
}

/*
 * Dumps no more than the first DUMPHEX_MAX bytes in hex. If
 * the user wants more, they can use the -x option to snoop.
 */
static void
dumphex(const uchar_t *payload, int payload_len, char *msg)
{
	int index;
	int end;
	char buf[BUFLEN];

	if (payload_len == 0) {
		return;
	}

	end = payload_len > DUMPHEX_MAX ? DUMPHEX_MAX : payload_len;

	for (index = 0; index < end; index++) {
		(void) snprintf(&buf[index * 3], 4, " %.2x", payload[index]);
	}

	if (payload_len > DUMPHEX_MAX) {
		(void) strlcat(buf, " ...", BUFLEN);
	}

	(void) snprintf(get_line(0, 0), BUFLEN, msg, buf);
}

/*
 * Present perscribed action for unknowns according to rfc2960. Works
 * for chunks and parameters as well if the parameter type is
 * shifted 8 bits right.
 */
static const char *
get_action_desc(uint8_t id)
{
	if ((id & 0xc0) == 0xc0) {
		return (": skip on unknown, return error");
	} else if ((id & 0x80) == 0x80) {
		return (": skip on unknown, no error");
	} else if ((id & 0x40) == 0x40) {
		return (": stop on unknown, return error");
	}

	/* Top two bits are clear */
	return (": stop on unknown, no error");
}

/* ARGSUSED */
static void
parse_asconfok_param(int flags, uint8_t notused, const void *data, int dlen)
{
	uint32_t	*cid;

	if (dlen < sizeof (*cid)) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "  ==> Incomplete ASCONF Success Ind parameter");
		return;
	}
	cid = (uint32_t *)data;
	(void) snprintf(get_line(0, 0), get_line_remain(), "  ASCONF CID = %u",
	    ntohl(*cid));
}

/* ARGSUSED */
static void
parse_asconferr_param(int flags, uint8_t notused, const void *data, int dlen)
{
	uint32_t	*cid;

	if (dlen < sizeof (*cid)) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "  ==> Incomplete ASCONF Error Ind parameter");
		return;
	}
	cid = (uint32_t *)data;
	(void) snprintf(get_line(0, 0), get_line_remain(), "  ASCONF CID = %u",
	    ntohl(*cid));

	interpret_params(cid + 1, dlen - sizeof (*cid), "Error",
	    err_dispatch_table, A_CNT(err_dispatch_table), flags);
}

/* ARGSUSED */
static void
parse_addiperr_param(int flags, uint8_t notused, const void *data, int dlen)
{

	interpret_params(data, dlen, "Parameter",
	    parm_dispatch_table, A_CNT(parm_dispatch_table), flags);
}

/* ARGSUSED */
static void
parse_addip_param(int flags, uint8_t notused, const void *data, int dlen)
{

	uint32_t	*cid;

	if (dlen < sizeof (*cid)) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "  ==> Incomplete ASCONF Error Ind parameter");
		return;
	}
	cid = (uint32_t *)data;
	(void) snprintf(get_line(0, 0), get_line_remain(), "  ASCONF CID = %u",
	    ntohl(*cid));

	interpret_params(cid + 1, dlen - sizeof (*cid), "Parameter",
	    parm_dispatch_table, A_CNT(parm_dispatch_table), flags);
}

/* ARGSUSED */
static void
parse_ip4_param(int flags, uint8_t notused, const void *data, int datalen)
{
	char abuf[INET_ADDRSTRLEN];
	char *ap;

	if (datalen < sizeof (in_addr_t)) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "  ==> Incomplete IPv4 Addr parameter");
		return;
	}

	ap = (char *)inet_ntop(AF_INET, data, abuf, INET_ADDRSTRLEN);
	if (ap == NULL) {
		ap = "<Bad Address>";
	}

	(void) snprintf(get_line(0, 0), get_line_remain(), "  Addr = %s", ap);
}

/* ARGSUSED */
static void
parse_ip6_param(int flags, uint8_t notused, const void *data, int datalen)
{
	char abuf[INET6_ADDRSTRLEN];
	char *ap;

	if (datalen < sizeof (in6_addr_t)) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "  ==> Incomplete IPv6 Addr parameter");
		return;
	}

	ap = (char *)inet_ntop(AF_INET6, data, abuf, INET6_ADDRSTRLEN);
	if (ap == NULL) {
		ap = "<Bad Address>";
	}

	(void) snprintf(get_line(0, 0), get_line_remain(), "  Addr = %s", ap);
}

/* ARGSUSED */
static void
parse_int32_param(int flags, uint8_t notused, const void *data, int datalen)
{
	if (datalen < 4) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "  ==> Incomplete INT32 parameter");
		return;
	}
	(void) snprintf(get_line(0, 0), get_line_remain(), "  INT32 = %u",
	    ntohl(*(uint32_t *)data));
}

/* ARGSUSED */
static void
parse_suppaddr_param(int flags, uint8_t notused, const void *data, int dlen)
{
	const uint16_t *type;

	if (dlen < 2) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "==> Incomplete Supported Addr parameter");
		return;
	}

	type = data;
	while (dlen > 0) {
		switch (ntohs(*type)) {
		case PARM_ADDR4:
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "  IPv4");
			break;
		case PARM_ADDR6:
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "  IPv6");
			break;
		case PARM_ADDR_HOST_NAME:
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "  Host Name");
			break;
		default:
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Unknown Type (%hu)", ntohs(*type));
			break;
		}
		dlen -= sizeof (*type);
		type++;
	}
}

/*ARGSUSED*/
static void
parse_encap_param(int flags, uint8_t notused, const void *data, int dlen)
{
	if (dlen < sizeof (sctp_parm_hdr_t)) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "==> Incomplete Parameter");
		return;
	}

	interpret_params(data, dlen, "Parameter",
	    parm_dispatch_table, A_CNT(parm_dispatch_table), flags);
}

/* ARGSUSED */
static void
parse_unrec_chunk(int flags, uint8_t cflags, const void *data, int datalen)
{
	const sctp_chunk_hdr_t *cp = data;
	const dispatch_t *dp;
	const char *actstr;

	if (datalen < sizeof (*cp)) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "==> Incomplete Unrecognized Chunk Error");
		return;
	}

	/* Maybe snoop knows about this chunk? */
	dp = lookup_dispatch(cp->sch_id, chunk_dispatch_table,
	    A_CNT(chunk_dispatch_table));
	if (dp != NULL) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "  Chunk Type = %u (%s)", cp->sch_id, dp->vdesc);
	} else {
		actstr = get_action_desc(cp->sch_id);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "  Chunk Type = %u%s", cp->sch_id, actstr);
	}
}

/*
 * Same as parse_opaque_chunk except for the indentation.
 */
/* ARGSUSED */
static void
parse_opaque_param(int flags, uint8_t cflags, const void *data, int datalen)
{
	dumphex(data, datalen, " Data = %s");
}

/*
 * Loops through all parameters (or errors) until it has read
 * datalen bytes of information, finding a parser for each.
 * The tbl argument allows the caller to specify which dispatch
 * table to use, making this function useful for both parameters
 * and errors. The type argument is used to denote whether this
 * is an error or parameter in detailed mode.
 */
static void
interpret_params(const void *data, int datalen, char *type,
    const dispatch_t *tbl, int tbl_size, int flags)
{
	const sctp_parm_hdr_t *hdr = data;
	uint16_t plen;
	uint16_t ptype;
	const char *desc;
	parse_func_t *parse;
	int pad;
	const dispatch_t *dp;
	const char *actstr;

	for (;;) {
		/*
		 * Adjust for padding: if the address isn't aligned, there
		 * should be some padding. So skip over the padding and
		 * adjust hdr accordingly. RFC2960 mandates that all
		 * parameters must be 32-bit aligned WRT the enclosing chunk,
		 * which ensures that this parameter header will
		 * be 32-bit aligned in memory. We must, of course, bounds
		 * check fraglen before actually trying to use hdr, in
		 * case the packet has been mangled or is the product
		 * of a buggy implementation.
		 */
		if ((pad = (uintptr_t)hdr % SCTP_ALIGN) != 0) {
			pad = SCTP_ALIGN - pad;
			datalen -= pad;
		/* LINTED pointer cast may result in improper alignment */
			hdr = (sctp_parm_hdr_t *)((char *)hdr + pad);
		}

		/* Need to compare against 0 1st, since sizeof is unsigned */
		if (datalen < 0 || datalen < sizeof (*hdr)) {
			if (datalen > 0) {
				(void) snprintf(get_line(0, 0),
				    get_line_remain(),
				    "==> Extra data after last parameter");
			}
			return;
		}
		plen = ntohs(hdr->sph_len);
		if (datalen < plen || plen < sizeof (*hdr)) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "  ==> Incomplete %s", type);
			return;
		}

		/* Get description and parser */
		ptype = ntohs(hdr->sph_type);
		desc = "Unknown Parameter Type";
		parse = parse_opaque_param;
		dp = lookup_dispatch(ptype, tbl, tbl_size);
		if (dp != NULL) {
			desc = dp->vdesc;
			parse = dp->parse;
		}

		show_space();
		if (dp != NULL) {
			actstr = "";
		} else {
			actstr = get_action_desc((uint8_t)(ptype >> 8));
		}
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "  ------- SCTP %s Type = %s (%u%s)", type, desc, ptype,
		    actstr);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "  Data length = %hu", plen - sizeof (*hdr));

		if (parse != NULL) {
			parse(flags, 0, (char *)(hdr + 1),
			    plen - sizeof (*hdr));
		}
		datalen -= plen;
		/* LINTED pointer cast may result in improper alignment */
		hdr = (sctp_parm_hdr_t *)((char *)hdr + plen);
	}
}

/* ARGSUSED */
static void
parse_ftsn_chunk(int flags, uint8_t cflags, const void *data, int datalen)
{
	uint32_t	*ftsn;
	ftsn_entry_t	*ftsn_entry;

	if (datalen < (sizeof (*ftsn) + sizeof (*ftsn_entry))) {
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "==> Incomplete FORWARD-TSN chunk");
		}
		return;
	}

	ftsn = (uint32_t *)data;
	if (flags & F_SUM) {
		SUMAPPEND((scratch, MAXLINE, "CTSN %x ", ntohl(*ftsn)));
		return;
	}
	(void) snprintf(get_line(0, 0), get_line_remain(), "Cum TSN=  %x",
	    ntohl(*ftsn));

	datalen -= sizeof (*ftsn);
	ftsn_entry = (ftsn_entry_t *)(ftsn + 1);
	while (datalen >= sizeof (*ftsn_entry)) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "SID =  %u : SSN = %u", ntohs(ftsn_entry->ftsn_sid),
		    ntohs(ftsn_entry->ftsn_ssn));
		datalen -= sizeof (*ftsn_entry);
		ftsn_entry++;
	}
}

/* ARGSUSED */
static void
parse_asconf_chunk(int flags, uint8_t cflags, const void *data, int datalen)
{
	uint32_t	*sn;

	if (datalen < sizeof (*sn)) {
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "==> Incomplete ASCONF chunk");
		}
		return;
	}

	sn = (uint32_t *)data;
	if (flags & F_SUM) {
		SUMAPPEND((scratch, MAXLINE, "sn %x ", ntohl(*sn)));
		return;
	}
	(void) snprintf(get_line(0, 0), get_line_remain(), "Serial Number=  %x",
	    ntohl(*sn));
	interpret_params(sn + 1, datalen - sizeof (*sn), "Parameter",
	    parm_dispatch_table, A_CNT(parm_dispatch_table), flags);
}

static void
parse_init_chunk(int flags, uint8_t cflags, const void *data, int datalen)
{
	const sctp_init_chunk_t *icp = data;

	if (datalen < sizeof (*icp)) {
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "==> Incomplete INIT chunk");
		}
		return;
	}

	if (flags & F_SUM) {
		SUMAPPEND((scratch, MAXLINE, "tsn %x str %hu/%hu win %u ",
		    ntohl(icp->sic_inittsn), ntohs(icp->sic_outstr),
		    ntohs(icp->sic_instr), ntohl(icp->sic_a_rwnd)));
		return;
	}

	(void) snprintf(get_line(0, 0), get_line_remain(), "Flags = 0x%.2x",
	    cflags);
	(void) snprintf(get_line(0, 0), get_line_remain(),
	    "Initiate tag = 0x%.8x", ntohl(icp->sic_inittag));
	(void) snprintf(get_line(0, 0), get_line_remain(),
	    "Advertised receiver window credit = %u", ntohl(icp->sic_a_rwnd));
	(void) snprintf(get_line(0, 0), get_line_remain(),
	    "Outbound streams = %hu", ntohs(icp->sic_outstr));
	(void) snprintf(get_line(0, 0), get_line_remain(),
	    "Inbound streams = %hu", ntohs(icp->sic_instr));
	(void) snprintf(get_line(0, 0), get_line_remain(),
	    "Initial TSN = 0x%.8x", ntohl(icp->sic_inittsn));

	if (datalen > sizeof (*icp)) {
		interpret_params(icp + 1, datalen - sizeof (*icp),
		    "Parameter", parm_dispatch_table,
		    A_CNT(parm_dispatch_table), flags);
	}
}

static void
parse_data_chunk(int flags, uint8_t cflags, const void *data, int datalen)
{
	const sctp_data_chunk_t	*dcp = data;
	char			*payload;
	uint32_t		ppid;

	if (datalen < sizeof (*dcp)) {
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "==> Incomplete DATA chunk %d (%d)", datalen,
			    sizeof (*dcp));
		}
		return;
	}

	ppid = ntohl(dcp->sdc_payload_id);
	/* This is the actual data len, excluding the data chunk header. */
	datalen -= sizeof (*dcp);

	if (flags & F_DTAIL) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "flags = 0x%.2x", cflags);
		(void) snprintf(get_line(0, 0), get_line_remain(), "      %s",
		    getflag(cflags, SCTP_DATA_UBIT, "unordered", "ordered"));
		(void) snprintf(get_line(0, 0), get_line_remain(), "      %s",
		    getflag(cflags, SCTP_DATA_BBIT,
		    "beginning", "(beginning unset)"));
		(void) snprintf(get_line(0, 0), get_line_remain(), "      %s",
		    getflag(cflags, SCTP_DATA_EBIT, "end", "(end unset)"));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "TSN = 0x%.8x", ntohl(dcp->sdc_tsn));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Stream ID = %hu", ntohs(dcp->sdc_sid));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Stream Sequence Number = %hu", ntohs(dcp->sdc_ssn));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Payload Protocol ID = 0x%.8x", ppid);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Data Length = %d", datalen);
		show_space();
	}
	if (flags & F_SUM) {
		SUMAPPEND((scratch, MAXLINE, "len %d tsn %x str %hu/%hu "
		    "ppid %x ", datalen, ntohl(dcp->sdc_tsn),
		    ntohs(dcp->sdc_sid), ntohs(dcp->sdc_ssn), ppid));
	}

	/*
	 * Go to the next protocol layer, but not if we are in
	 * summary mode only. In summary mode, each ULP parse would
	 * create a new line, and if there were several data chunks
	 * bundled together in the packet, this would confuse snoop's
	 * packet numbering and timestamping.
	 *
	 * SCTP carries two ways to determine an ULP: ports and the
	 * payload protocol identifier (ppid). Since ports are the
	 * better entrenched convention, we first try interpret_reserved().
	 * If that fails to find a parser, we try by the PPID.
	 */
	if (!(flags & F_ALLSUM) && !(flags & F_DTAIL)) {
		return;
	}

	payload = (char *)(dcp + 1);
	if (!interpret_reserved(flags, IPPROTO_SCTP, sport, dport, payload,
	    datalen) && ppid != 0) {

		interpret_protoid(flags, ppid, payload, datalen);
	}

	/*
	 * Reset the protocol prefix, since it may have been changed
	 * by a ULP interpreter.
	 */
	prot_prefix = "SCTP:  ";
}

/* ARGSUSED */
static void
parse_sack_chunk(int flags, uint8_t cflags, const void *data, int datalen)
{
	const sctp_sack_chunk_t *scp = data;
	uint16_t numfrags, numdups;
	sctp_sack_frag_t *frag;
	int i;
	uint32_t *tsn;

	if (datalen < sizeof (*scp)) {
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "==> Incomplete SACK chunk");
		}
		return;
	}

	if (flags & F_DTAIL) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Cumulative TSN ACK = 0x%.8x", ntohl(scp->ssc_cumtsn));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Advertised Receiver Window Credit = %u",
		    ntohl(scp->ssc_a_rwnd));
		numfrags = ntohs(scp->ssc_numfrags);
		numdups = ntohs(scp->ssc_numdups);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Number of Fragments = %hu", numfrags);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Number of Duplicates = %hu", numdups);

		/* Display any gap reports */
		datalen -= sizeof (*scp);
		if (datalen < (numfrags * sizeof (*frag))) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "  ==> Malformed gap report listing");
			return;
		}
		frag = (sctp_sack_frag_t *)(scp + 1);
		for (i = 0; i < numfrags; i++) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "  Fragment #%d: Start = %hu, end = %hu", i,
			    ntohs(frag->ssf_start), ntohs(frag->ssf_end));
			frag += 1;
		}

		/* Display any duplicate reports */
		datalen -= numfrags * sizeof (*frag);
		if (datalen < (numdups * sizeof (*tsn))) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "  ==> Malformed duplicate report listing");
			return;
		}
		/* LINTED pointer cast may result in improper alignment */
		tsn = (uint32_t *)frag;
		for (i = 0; i < numdups; i++) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "  Duplicate #%d: TSN = %x", i, *tsn);
			tsn++;
		}
	}
	if (flags & F_SUM) {
		SUMAPPEND((scratch, MAXLINE,
		    "tsn %x win %u gaps/dups %hu/%hu ", ntohl(scp->ssc_cumtsn),
		    ntohl(scp->ssc_a_rwnd), ntohs(scp->ssc_numfrags),
		    ntohs(scp->ssc_numdups)));
	}
}

/* ARGSUSED */
static void
parse_shutdown_chunk(int flags, uint8_t cflags, const void *data, int datalen)
{
	const uint32_t *cumtsn = data;

	if (datalen < sizeof (*cumtsn)) {
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "==> Incomplete Shutdown chunk");
		}
		return;
	}

	if (flags & F_DTAIL) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Cumulative TSN = 0x%.8x", ntohl(*cumtsn));
	}
	if (flags & F_SUM) {
		SUMAPPEND((scratch, MAXLINE, "tsn %x", ntohl(*cumtsn)));
	}
}

/* ARGSUSED */
static void
parse_error_chunk(int flags, uint8_t cflags, const void *data, int datalen)
{
	if (!(flags & F_DTAIL)) {
		return;
	}

	interpret_params(data, datalen, "Error", err_dispatch_table,
	    A_CNT(err_dispatch_table), flags);
}

static void
parse_abort_chunk(int flags, uint8_t cflags, const void *data, int datalen)
{
	if (!(flags & F_DTAIL)) {
		return;
	}

	(void) snprintf(get_line(0, 0), get_line_remain(), "flags = 0x%.2x",
	    cflags);
	(void) snprintf(get_line(0, 0), get_line_remain(), "      %s",
	    getflag(cflags, SCTP_TBIT, "TCB not destroyed", "TCB destroyed"));

	interpret_params(data, datalen, "Error", err_dispatch_table,
	    A_CNT(err_dispatch_table), flags);
}

/* ARGSUSED2 */
static void
parse_shutdone_chunk(int flags, uint8_t cflags, const void *data, int datalen)
{
	if (!(flags & F_DTAIL)) {
		return;
	}

	(void) snprintf(get_line(0, 0), get_line_remain(), "flags = 0x%.2x",
	    cflags);
	(void) snprintf(get_line(0, 0), get_line_remain(), "      %s",
	    getflag(cflags, SCTP_TBIT, "TCB not destroyed", "TCB destroyed"));
}

/* ARGSUSED */
static void
parse_opaque_chunk(int flags, uint8_t cflags, const void *data, int datalen)
{
	if (!(flags & F_DTAIL)) {
		return;
	}
	if (datalen == 0) {
		return;
	}

	dumphex(data, datalen, "Data = %s");
}

/*
 * Loops through all chunks until it has read fraglen bytes of
 * information, finding a parser for each. If any parameters are
 * present, interpret_params() is then called. Returns the remaining
 * fraglen.
 */
static int
interpret_chunks(int flags, sctp_chunk_hdr_t *cp, int fraglen)
{
	uint16_t clen;
	int signed_len;
	int pad;
	const char *desc;
	parse_func_t *parse;
	const dispatch_t *dp;
	const char *actstr;

	for (;;) {
		/*
		 * Adjust for padding: if the address isn't aligned, there
		 * should be some padding. So skip over the padding and
		 * adjust hdr accordingly. RFC2960 mandates that all
		 * chunks must be 32-bit aligned WRT the SCTP common hdr,
		 * which ensures that this chunk header will
		 * be 32-bit aligned in memory. We must, of course, bounds
		 * check fraglen before actually trying to use hdr, in
		 * case the packet has been mangled or is the product
		 * of a buggy implementation.
		 */
		if ((pad = (uintptr_t)cp % SCTP_ALIGN) != 0) {
			pad = SCTP_ALIGN - pad;
			fraglen -= pad;
		/* LINTED pointer cast may result in improper alignment */
			cp = (sctp_chunk_hdr_t *)((char *)cp + pad);
		}

		/* Need to compare against 0 1st, since sizeof is unsigned */
		if (fraglen < 0 || fraglen < sizeof (*cp)) {
			if (fraglen > 0 && flags & F_DTAIL) {
				(void) snprintf(get_line(0, 0),
				    get_line_remain(),
				    "==> Extra data after last chunk");
			}
			return (fraglen);
		}

		clen = ntohs(cp->sch_len);
		if (fraglen < clen) {
			if (flags & F_DTAIL) {
				(void) snprintf(get_line(0, 0),
				    get_line_remain(), "==> Corrupted chunk");
			}
			return (fraglen);
		}

		signed_len = clen - sizeof (*cp);
		if (signed_len < 0) {
			if (flags & F_DTAIL) {
				(void) snprintf(get_line(0, 0),
				    get_line_remain(),
				    "==> Incomplete or corrupted chunk");
			}
			return (0);
		}

		/* Get description and parser */
		dp = lookup_dispatch(cp->sch_id, chunk_dispatch_table,
		    A_CNT(chunk_dispatch_table));
		if (dp != NULL) {
			if (flags & F_SUM) {
				desc = dp->sdesc;
			} else if (flags & F_DTAIL) {
				desc = dp->vdesc;
			}
			parse = dp->parse;
		} else {
			if (flags & F_SUM) {
				desc = "UNK";
			} else if (flags & F_DTAIL) {
				desc = "Unknown Chunk Type";
			}
			parse = parse_opaque_chunk;
		}

		if (flags & F_SUM) {
			SUMAPPEND((scratch, MAXLINE, "%s ", desc));
		}
		if (flags & F_DTAIL) {
			show_space();

			if (dp != NULL) {
				actstr = "";
			} else {
				actstr = get_action_desc(cp->sch_id);
			}
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "------- SCTP Chunk Type = %s (%u%s)", desc,
			    cp->sch_id, actstr);

			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Chunk length = %hu", clen);
		}

		if (parse != NULL) {
			parse(flags, cp->sch_flags, (char *)(cp + 1),
			    signed_len);
		}

		fraglen -= clen;

		/* LINTED pointer cast may result in improper alignment */
		cp = (sctp_chunk_hdr_t *)((char *)cp + clen);
	}
}

void
interpret_sctp(int flags, sctp_hdr_t *sctp, int iplen, int fraglen)
{
	int len_from_iphdr;
	sctp_chunk_hdr_t *cp;
	char *pn;
	char buff[32];

	/*
	 * Alignment check. If the header is 32-bit aligned, all other
	 * protocol units will also be aligned, as mandated by rfc2960.
	 * Buggy packets will be caught and flagged by chunk and
	 * parameter bounds checking.
	 * If the header is not aligned, however, we drop the packet.
	 */
	if (!IS_P2ALIGNED(sctp, SCTP_ALIGN)) {
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "==> SCTP header not aligned, dropping");
		}
		return;
	}

	fraglen -= sizeof (*sctp);
	if (fraglen < 0) {
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "==> Incomplete sctp header");
		}
		return;
	}
	/* If fraglen is somehow longer than the IP payload, adjust it */
	len_from_iphdr = iplen - sizeof (*sctp);
	if (fraglen > len_from_iphdr) {
		fraglen = len_from_iphdr;
	}

	/* Keep track of the ports */
	sport = ntohs(sctp->sh_sport);
	dport = ntohs(sctp->sh_dport);

	/* Set pointer to first chunk */
	cp = (sctp_chunk_hdr_t *)(sctp + 1);

	if (flags & F_SUM) {
		sumline = get_sum_line();
		*sumline = '\0';
		sumlen = MAXLINE;

		SUMAPPEND((scratch, MAXLINE, "SCTP D=%d S=%d ", dport, sport));
	}

	if (flags & F_DTAIL) {
		show_header("SCTP:  ", "SCTP Header", fraglen);
		show_space();

		pn = getportname(IPPROTO_SCTP, (ushort_t)sport);
		if (pn == NULL) {
			pn = "";
		} else {
			(void) snprintf(buff, sizeof (buff), "(%s)", pn);
			pn = buff;
		}
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Source port = %hu %s", sport, pn);

		pn = getportname(IPPROTO_SCTP, (ushort_t)dport);
		if (pn == NULL) {
			pn = "";
		} else {
			(void) snprintf(buff, sizeof (buff), "(%s)", pn);
			pn = buff;
		}
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Destination port = %hu %s", dport, pn);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Verification tag = 0x%.8x", ntohl(sctp->sh_verf));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "CRC-32c = 0x%.8x", ntohl(sctp->sh_chksum));
	}

	(void) interpret_chunks(flags, cp, fraglen);

	if (flags & F_DTAIL) {
		show_space();
	}
}

/*
 * Payload protocol ID table. Add new ULP information and parsers
 * here.
 */

struct protoid_table {
	int	pid_num;
	char	*pid_short;
	char	*pid_long;
};

static struct protoid_table pid_sctp[] = {
	1,	"IUA",		"ISDN Q.921 User Adaption Layer",
	2,	"M2UA",		"SS7 MTP2 User Adaption Layer",
	3,	"M3UA",		"SS7 MTP3 User Adaption Layer",
	4,	"SUA",		"SS7 SCCP User Adaption Layer",
	5,	"M2PA",		"SS7 MTP2-User Peer-to-Peer Adaption Layer",
	6,	"V5UA",		"V5UA",
	0,	NULL,		"",
};

static void
interpret_protoid(int flags, uint32_t ppid, char *data, int dlen)
{
	struct protoid_table *p;
	char pbuf[16];

	/*
	 * Branch to a ULP interpreter here, or continue on to
	 * the default parser, which just tries to display
	 * printable characters from the payload.
	 */

	for (p = pid_sctp; p->pid_num; p++) {
		if (ppid == p->pid_num) {
			if (flags & F_SUM) {
				(void) snprintf(get_sum_line(), MAXLINE,
				    "D=%d S=%d %s %s", dport, sport,
				    p->pid_short, show_string(data, dlen, 20));
			}

			if (flags & F_DTAIL) {
				(void) snprintf(pbuf, MAXLINE, "%s:  ",
				    p->pid_short);
				show_header(pbuf, p->pid_long, dlen);
				show_space();
				(void) snprintf(get_line(0, 0),
				    get_line_remain(), "\"%s\"",
				    show_string(data, dlen, 60));
				show_trailer();
			}

			return;
		}
	}
}
