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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <net/ppp_defs.h>
#include <net/ppp-comp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include "snoop.h"
#include "snoop_ppp.h"

static int interpret_ppp_cp(int, uchar_t *, int, ppp_protoinfo_t *);
static int interpret_cp_options(uchar_t *, int, ppp_protoinfo_t *);
static int interpret_ppp_chap(int, uchar_t *, int, ppp_protoinfo_t *);
static int interpret_ppp_pap(int, uchar_t *, int, ppp_protoinfo_t *);
static int interpret_ppp_lqr(int, uchar_t *, int, ppp_protoinfo_t *);
static ppp_protoinfo_t *ppp_getprotoinfo(uint16_t);
static cp_optinfo_t *ppp_getoptinfo(cp_optinfo_t *, uint16_t);
static optformat_func_t opt_format_vendor;
static optformat_func_t opt_format_mru;
static optformat_func_t opt_format_accm;
static optformat_func_t opt_format_authproto;
static optformat_func_t opt_format_qualproto;
static optformat_func_t opt_format_magicnum;
static optformat_func_t opt_format_fcs;
static optformat_func_t opt_format_sdp;
static optformat_func_t opt_format_nummode;
static optformat_func_t opt_format_callback;
static optformat_func_t opt_format_mrru;
static optformat_func_t opt_format_epdisc;
static optformat_func_t opt_format_dce;
static optformat_func_t opt_format_linkdisc;
static optformat_func_t opt_format_i18n;
static optformat_func_t opt_format_ipaddresses;
static optformat_func_t opt_format_ipcompproto;
static optformat_func_t opt_format_ipaddress;
static optformat_func_t opt_format_mobileipv4;
static optformat_func_t opt_format_ifaceid;
static optformat_func_t opt_format_ipv6compproto;
static optformat_func_t opt_format_compoui;
static optformat_func_t opt_format_bsdcomp;
static optformat_func_t opt_format_staclzs;
static optformat_func_t opt_format_mppc;
static optformat_func_t opt_format_gandalf;
static optformat_func_t opt_format_lzsdcp;
static optformat_func_t opt_format_magnalink;
static optformat_func_t opt_format_deflate;
static optformat_func_t opt_format_encroui;
static optformat_func_t opt_format_dese;
static optformat_func_t opt_format_muxpid;

/*
 * Many strings below are initialized with "Unknown".
 */
static char unknown_string[] = "Unknown";

/*
 * Each known PPP protocol has an associated ppp_protoinfo_t in this array.
 * Even if we can't decode the protocol (interpret_proto() == NULL),
 * interpret_ppp() will at least print the protocol's name.  There is no
 * dependency on the ordering of the entries in this array.  They have been
 * ordered such that the most commonly used protocols are near the front.
 * The array is delimited by a last entry of protocol of type
 * PPP_PROTO_UNKNOWN.
 */
static ppp_protoinfo_t protoinfo_array[] = {
	{ PPP_IP,	"IP",		interpret_ip,	NULL,	NULL },
	{ PPP_IPV6,	"IPv6",		interpret_ipv6,	NULL,	NULL },
	{ PPP_COMP,	"Compressed Data",	NULL,	NULL,	NULL },
	{ PPP_OSI,	"OSI",			NULL,	NULL,	NULL },
	{ PPP_AT,	"AppleTalk",		NULL,	NULL,	NULL },
	{ PPP_IPX,	"IPX",			NULL,	NULL,	NULL },
	{ PPP_VJC_COMP,	"VJ Compressed TCP",    NULL,	NULL,	NULL },
	{ PPP_VJC_UNCOMP, "VJ Uncompressed TCP", NULL,	NULL,	NULL },
	{ PPP_BRIDGE,	"Bridging",		NULL,	NULL,	NULL },
	{ PPP_802HELLO,	"802.1d Hello",		NULL,	NULL,	NULL },
	{ PPP_MP,	"MP",			NULL,	NULL,	NULL },
	{ PPP_ENCRYPT,	"Encryption",		NULL,	NULL,	NULL },
	{ PPP_ENCRYPTFRAG, "Individual Link Encryption", NULL,	NULL,	NULL },
	{ PPP_MUX,	"PPP Muxing",		NULL,	NULL,	NULL },
	{ PPP_COMPFRAG,	"Single Link Compressed Data",	NULL,	NULL,	NULL },
	{ PPP_FULLHDR,	"IP Compression",	NULL,	NULL,	NULL },
	{ PPP_COMPTCP,	"IP Compression",	NULL,	NULL,	NULL },
	{ PPP_COMPNONTCP, "IP Compression",	NULL,	NULL,	NULL },
	{ PPP_COMPUDP8,	"IP Compression",	NULL,	NULL,	NULL },
	{ PPP_COMPRTP8,	"IP Compression",	NULL,	NULL,	NULL },
	{ PPP_COMPTCPND, "IP Compression",	NULL,	NULL,	NULL },
	{ PPP_COMPSTATE, "IP Compression",	NULL,	NULL,	NULL },
	{ PPP_COMPUDP16, "IP Compression",	NULL,	NULL,	NULL },
	{ PPP_COMPRTP16, "IP Compression",	NULL,	NULL,	NULL },
	{ PPP_MPLS,	"MPLS",			NULL,	NULL,	NULL },
	{ PPP_MPLSMC,	"MPLS M/C",		NULL,	NULL,	NULL },
	{ PPP_LQR,	"LQR",		interpret_ppp_lqr,	"PPP-LQR:  ",
	    "Link Quality Report" },
	{ PPP_LCP,	"LCP",		interpret_ppp_cp,	"PPP-LCP:  ",
	    "Link Control Protocol" },
	{ PPP_IPCP,	"IPCP",		interpret_ppp_cp,	"PPP-IPCP: ",
	    "IP Control Protocol" },
	{ PPP_IPV6CP,	"IPV6CP",	interpret_ppp_cp,	"PPP-IPV6CP:  ",
	    "IPv6 Control Protocol" },
	{ PPP_CCP,	"CCP",		interpret_ppp_cp,	"PPP-CCP:  ",
	    "Compression Control Protocol" },
	{ PPP_CCPFRAG,	"CCP-Link",	interpret_ppp_cp, "PPP-CCP-Link:  ",
	    "Per-Link Compression Control Protocol" },
	{ PPP_ECP,	"ECP",		interpret_ppp_cp,	"PPP-ECP:  ",
	    "Encryption Control Protocol" },
	{ PPP_ECPFRAG,	"ECP-Link",	interpret_ppp_cp, "PPP-ECP-Link:  ",
	    "Per-Link Encryption Control Protocol" },
	{ PPP_MPLSCP,	"MPLSCP",		NULL,	NULL,	NULL },
	{ PPP_OSINLCP,	"OSINLCP",		NULL,	NULL,	NULL },
	{ PPP_ATCP,	"ATCP",			NULL,	NULL,	NULL },
	{ PPP_IPXCP,	"IPXCP",		NULL,	NULL,	NULL },
	{ PPP_BACP,	"BACP",			NULL,	NULL,	NULL },
	{ PPP_BCP,	"BCP",			NULL,	NULL,	NULL },
	{ PPP_CBCP,	"CBCP",			NULL,	NULL,	NULL },
	{ PPP_BAP,	"BAP",			NULL,	NULL,	NULL },
	{ PPP_CHAP,	"CHAP",		interpret_ppp_chap,	"CHAP:  ",
	    "Challenge Handshake Authentication Protocl" },
	{ PPP_PAP,	"PAP",		interpret_ppp_pap,	"PAP:   ",
	    "Password Authentication Protocol" },
	{ PPP_EAP,	"EAP",			NULL,	NULL,	NULL },
	{ 0,		unknown_string,		NULL,	NULL,	NULL }
};

static cp_optinfo_t lcp_optinfo[] = {
	{ OPT_LCP_VENDOR,	"Vendor-Specific",		6,
	    opt_format_vendor },
	{ OPT_LCP_MRU,		"Maximum-Receive-Unit",		4,
	    opt_format_mru },
	{ OPT_LCP_ASYNCMAP,	"Async-Control-Character-Map",	6,
	    opt_format_accm },
	{ OPT_LCP_AUTHTYPE,	"Authentication-Protocol",	4,
	    opt_format_authproto },
	{ OPT_LCP_QUALITY,	"Quality-Protocol",		4,
	    opt_format_qualproto },
	{ OPT_LCP_MAGICNUMBER,	"Magic-Number",			6,
	    opt_format_magicnum },
	{ OPT_LCP_PCOMPRESSION,	"Protocol-Field-Compression",	2,	NULL },
	{ OPT_LCP_ACCOMPRESSION, "Address-and-Control-Field-Compression", 2,
	    NULL },
	{ OPT_LCP_FCSALTERN,	"FCS-Alternative",		3,
	    opt_format_fcs },
	{ OPT_LCP_SELFDESCPAD,	"Self-Describing-Padding",	3,
	    opt_format_sdp },
	{ OPT_LCP_NUMBERED,	"Numbered-Mode",		3,
	    opt_format_nummode },
	{ OPT_LCP_MULTILINKPROC, "Multi-Link-Procedure",	2,	NULL },
	{ OPT_LCP_CALLBACK,	"Callback",			3,
	    opt_format_callback },
	{ OPT_LCP_CONNECTTIME,	"Connect-Time",			2,	NULL },
	{ OPT_LCP_COMPOUNDFRAMES, "Compound-Frames",		2,	NULL },
	{ OPT_LCP_DATAENCAP,	"Nominal-Data-Encapsulation",	2,	NULL },
	{ OPT_LCP_MRRU,		"Multilink-MRRU",		4,
	    opt_format_mrru },
	{ OPT_LCP_SSNHF,	"Multilink-Short-Sequence-Number-Header-Format",
	    2, NULL },
	{ OPT_LCP_EPDISC,	"Multilink-Endpoint-Discriminator",	3,
	    opt_format_epdisc },
	{ OPT_LCP_DCEIDENT,	"DCE-Identifier",		3,
	    opt_format_dce },
	{ OPT_LCP_MLPLUSPROC,	"Multi-Link-Plus-Procedure",	2,	NULL },
	{ OPT_LCP_LINKDISC,	"Link Discriminator for BACP",	4,
	    opt_format_linkdisc },
	{ OPT_LCP_AUTH,		"LCP-Authentication-Option",	2,	NULL },
	{ OPT_LCP_COBS,		"COBS",				2,	NULL },
	{ OPT_LCP_PFXELISION,	"Prefix elision",		2,	NULL },
	{ OPT_LCP_MPHDRFMT,	"Multilink header format",	2,	NULL },
	{ OPT_LCP_I18N,		"Internationalization",		6,
	    opt_format_i18n },
	{ OPT_LCP_SDL,		"Simple Data Link on SONET/SDH", 2,	NULL },
	{ OPT_LCP_MUXING,	"Old PPP Multiplexing",		2,	NULL },
	{ 0,			unknown_string,			0,	NULL }
};

static cp_optinfo_t ipcp_optinfo[] = {
	{ OPT_IPCP_ADDRS,	"IP-Addresses",			10,
	    opt_format_ipaddresses },
	{ OPT_IPCP_COMPRESSTYPE, "IP-Compression-Protocol",	4,
	    opt_format_ipcompproto },
	{ OPT_IPCP_ADDR,	"IP-Address",			6,
	    opt_format_ipaddress },
	{ OPT_IPCP_MOBILEIPV4,	"Mobile-IPv4",			6,
	    opt_format_mobileipv4 },
	{ OPT_IPCP_DNS1,	"Primary DNS Address",		6,
	    opt_format_ipaddress },
	{ OPT_IPCP_NBNS1,	"Primary NBNS Address",		6,
	    opt_format_ipaddress },
	{ OPT_IPCP_DNS2,	"Secondary DNS Address", 	6,
	    opt_format_ipaddress },
	{ OPT_IPCP_NBNS2,	"Secondary NBNS Address",	6,
	    opt_format_ipaddress },
	{ OPT_IPCP_SUBNET,	"IP-Subnet",			6,
	    opt_format_ipaddress },
	{ 0,			unknown_string,			0,	NULL }
};

static cp_optinfo_t ipv6cp_optinfo[] = {
	{ OPT_IPV6CP_IFACEID,	"Interface-Identifier",		10,
	    opt_format_ifaceid },
	{ OPT_IPV6CP_COMPRESSTYPE, "IPv6-Compression-Protocol",	4,
	    opt_format_ipv6compproto },
	{ 0,			unknown_string,			0,	NULL }
};

static cp_optinfo_t ccp_optinfo[] = {
	{ OPT_CCP_PROPRIETARY,	"Proprietary Compression OUI",	6,
	    opt_format_compoui },
	{ OPT_CCP_PREDICTOR1,	"Predictor type 1",		2,	NULL },
	{ OPT_CCP_PREDICTOR2,	"Predictor type 2",		2,	NULL },
	{ OPT_CCP_PUDDLEJUMP,	"Puddle Jumper",		2,	NULL },
	{ OPT_CCP_HPPPC,	"Hewlett-Packard PPC",		2,	NULL },
	{ OPT_CCP_STACLZS,	"Stac Electronics LZS",		5,
	    opt_format_staclzs },
	{ OPT_CCP_MPPC,		"Microsoft PPC",		6,
	    opt_format_mppc },
	{ OPT_CCP_GANDALFFZA,	"Gandalf FZA",			3,
	    opt_format_gandalf },
	{ OPT_CCP_V42BIS,	"V.42bis compression",		2,
	    NULL },
	{ OPT_CCP_BSDCOMP,	"BSD LZW Compress",		3,
	    opt_format_bsdcomp },
	{ OPT_CCP_LZSDCP,	"LZS-DCP",			6,
	    opt_format_lzsdcp },
	{ OPT_CCP_MAGNALINK,	"Magnalink",			4,
	    opt_format_magnalink },
	{ OPT_CCP_DEFLATE,	"Deflate",			4,
	    opt_format_deflate },
	{ 0,			unknown_string,			0,	NULL }
};

static cp_optinfo_t ecp_optinfo[] = {
	{ OPT_ECP_PROPRIETARY,	"Proprietary Encryption OUI",	6,
	    opt_format_encroui },
	{ OPT_ECP_DESE,		"DESE",				10,
	    opt_format_dese },
	{ OPT_ECP_3DESE,	"3DESE",			10,
	    opt_format_dese },
	{ OPT_ECP_DESEBIS,	"DESE-bis",			10,
	    opt_format_dese },
	{ 0,			unknown_string,			0,	NULL }
};

static cp_optinfo_t muxcp_optinfo[] = {
	{ OPT_MUXCP_DEFAULTPID,	"Default PID",			4,
	    opt_format_muxpid },
	{ 0,			unknown_string,			0,	NULL }
};

static char *cp_codearray[] = {
	"(Vendor Specific)",
	"(Configure-Request)",
	"(Configure-Ack)",
	"(Configure-Nak)",
	"(Configure-Reject)",
	"(Terminate-Request)",
	"(Terminate-Ack)",
	"(Code-Reject)",
	"(Protocol-Reject)",
	"(Echo-Request)",
	"(Echo-Reply)",
	"(Discard-Request)",
	"(Identification)",
	"(Time-Remaining)",
	"(Reset-Request)",
	"(Reset-Ack)"
};
#define	MAX_CPCODE	((sizeof (cp_codearray) / sizeof (char *)) - 1)

static char *pap_codearray[] = {
	"(Unknown)",
	"(Authenticate-Request)",
	"(Authenticate-Ack)",
	"(Authenticate-Nak)"
};
#define	MAX_PAPCODE	((sizeof (pap_codearray) / sizeof (char *)) - 1)

static char *chap_codearray[] = {
	"(Unknown)",
	"(Challenge)",
	"(Response)",
	"(Success)",
	"(Failure)"
};
#define	MAX_CHAPCODE	((sizeof (chap_codearray) / sizeof (char *)) - 1)


int
interpret_ppp(int flags, uchar_t *data, int len)
{
	uint16_t protocol;
	ppp_protoinfo_t *protoinfo;
	uchar_t *payload = data;

	if (len < 2)
		return (len);

	GETINT16(protocol, payload);
	len -= sizeof (uint16_t);

	protoinfo = ppp_getprotoinfo(protocol);

	if (flags & F_SUM) {
		(void) sprintf(get_sum_line(),
		    "PPP Protocol=0x%x (%s)", protocol, protoinfo->name);
	} else { /* F_DTAIL */
		show_header("PPP:    ", "Point-to-Point Protocol", len);
		show_space();
		(void) sprintf(get_line(0, 0), "Protocol = 0x%x (%s)",
		    protocol, protoinfo->name);
		show_space();
	}

	if (protoinfo->interpret_proto != NULL) {
		len = protoinfo->interpret_proto(flags, payload, len,
		    protoinfo);
	}

	return (len);
}

/*
 * interpret_ppp_cp() - Interpret PPP control protocols.  It is convenient
 * to do some of the decoding of these protocols in a common function since
 * they share packet formats.  This function expects to receive data
 * starting with the code field.
 */
static int
interpret_ppp_cp(int flags, uchar_t *data, int len, ppp_protoinfo_t *protoinfo)
{
	uint8_t code;
	uint8_t id;
	char *codestr;
	uint16_t length;
	uchar_t *datap = data;

	if (len < sizeof (ppp_pkt_t))
		return (len);

	GETINT8(code, datap);
	GETINT8(id, datap);
	GETINT16(length, datap);

	len -= sizeof (ppp_pkt_t);

	if (code <= MAX_CPCODE)
		codestr = cp_codearray[code];
	else
		codestr = "";

	if (flags & F_SUM) {
		(void) sprintf(get_sum_line(),
		    "%s%s", protoinfo->prefix, codestr);
	} else { /* (flags & F_DTAIL) */
		show_header(protoinfo->prefix, protoinfo->description, len);
		show_space();

		(void) sprintf(get_line(0, 0), "Code = %d %s", code, codestr);
		(void) sprintf(get_line(0, 0), "Identifier = %d", id);
		(void) sprintf(get_line(0, 0), "Length = %d", length);

		show_space();

		len = MIN(len, length - sizeof (ppp_pkt_t));
		if (len == 0)
			return (len);

		switch (code) {
		case CODE_VENDOR: {
			uint32_t magicnum;
			uint32_t oui;
			char *ouistr;
			uint8_t kind;

			if (len < sizeof (magicnum) + sizeof (oui))
				return (len);

			GETINT32(magicnum, datap);
			(void) sprintf(get_line(0, 0), "Magic-Number = 0x%08x",
			    magicnum);

			GETINT32(oui, datap);
			kind = oui & 0x000000ff;
			oui >>= 8;

			ouistr = ether_ouiname(oui);
			if (ouistr == NULL)
				ouistr = unknown_string;

			(void) sprintf(get_line(0, 0), "OUI = 0x%06x (%s)",
			    oui, ouistr);
			(void) sprintf(get_line(0, 0), "Kind = %d", kind);
			show_space();
			break;
		}

		case CODE_CONFREQ:
		case CODE_CONFACK:
		case CODE_CONFNAK:
		case CODE_CONFREJ:
			/*
			 * The above all contain protocol specific
			 * configuration options.  Parse these options.
			 */
			interpret_cp_options(datap, len, protoinfo);
			break;

		case CODE_TERMREQ:
		case CODE_TERMACK:
			/*
			 * The arbitrary data in these two packet types
			 * is almost always plain text.  Print it as such.
			 */
			(void) sprintf(get_line(0, 0), "Data = %.*s",
			    length - sizeof (ppp_pkt_t), datap);
			show_space();
			break;

		case CODE_CODEREJ:
			/*
			 * What follows is the rejected control protocol
			 * packet, starting with the code field.
			 * Conveniently, we can call interpret_ppp_cp() to
			 * decode this.
			 */
			prot_nest_prefix = protoinfo->prefix;
			interpret_ppp_cp(flags, datap, len, protoinfo);
			prot_nest_prefix = "";
			break;

		case CODE_PROTREJ:
			/*
			 * We don't print the rejected-protocol field
			 * explicitely.  Instead, we cheat and pretend that
			 * the rejected-protocol field is actually the
			 * protocol field in the included PPP packet.  This
			 * way, we can invoke interpret_ppp() and have it
			 * treat the included packet normally.
			 */
			prot_nest_prefix = protoinfo->prefix;
			interpret_ppp(flags, datap, len);
			prot_nest_prefix = "";
			break;

		case CODE_ECHOREQ:
		case CODE_ECHOREP:
		case CODE_DISCREQ:
		case CODE_IDENT:
		case CODE_TIMEREMAIN: {
			uint32_t magicnum;
			char *message_label = "Identification = %.*s";

			if (len < sizeof (uint32_t))
				break;

			GETINT32(magicnum, datap);
			len -= sizeof (uint32_t);
			(void) sprintf(get_line(0, 0), "Magic-Number = 0x%08x",
			    magicnum);
			/*
			 * Unless this is an identification or
			 * time-remaining packet, arbitrary data follows
			 * the magic number field.  The user can take a
			 * look at the hex dump for enlightenment.
			 */
			if (code == CODE_TIMEREMAIN) {
				uint32_t timeremaining;

				if (len < sizeof (uint32_t))
					break;

				message_label = "Message = %.*s";

				GETINT32(timeremaining, datap);
				len -= sizeof (uint32_t);
				(void) sprintf(get_line(0, 0),
				    "Seconds Remaining = %d", timeremaining);
			}

			if (code == CODE_IDENT || code == CODE_TIMEREMAIN) {
				if (len == 0)
					break;

				(void) sprintf(get_line(0, 0), message_label,
				    len, datap);
			}
			show_space();
			break;
		}

		/*
		 * Reset-Request and Reset-Ack contain arbitrary data which
		 * the user can sift through using the -x option.
		 */
		case CODE_RESETREQ:
		case CODE_RESETACK:
		default:
			break;
		}
	}
	return (len);
}


/*
 * interpret_cp_options() decodes control protocol configuration options.
 * Since each control protocol has a different set of options whose type
 * numbers overlap, the protoinfo parameter is used to get a handle on
 * which option set to use for decoding.
 */
static int
interpret_cp_options(uchar_t *optptr, int len, ppp_protoinfo_t *protoinfo)
{
	cp_optinfo_t *optinfo;
	cp_optinfo_t *optinfo_ptr;
	uint8_t optlen;
	uint8_t opttype;

	switch (protoinfo->proto) {
	case PPP_LCP:
		optinfo = lcp_optinfo;
		break;
	case PPP_IPCP:
		optinfo = ipcp_optinfo;
		break;
	case PPP_IPV6CP:
		optinfo = ipv6cp_optinfo;
		break;
	case PPP_CCP:
		optinfo = ccp_optinfo;
		break;
	case PPP_ECP:
		optinfo = ecp_optinfo;
		break;
	case PPP_MUXCP:
		optinfo = muxcp_optinfo;
		break;
	default:
		return (len);
		break;
	}

	if (len >= 2) {
		(void) sprintf(get_line(0, 0), "%s Configuration Options",
		    protoinfo->name);
		show_space();
	}

	while (len >= 2) {
		GETINT8(opttype, optptr);
		GETINT8(optlen, optptr);

		optinfo_ptr = ppp_getoptinfo(optinfo, opttype);

		(void) sprintf(get_line(0, 0), "Option Type = %d (%s)", opttype,
		    optinfo_ptr->opt_name);
		(void) sprintf(get_line(0, 0), "Option Length = %d", optlen);

		/*
		 * Don't continue if there isn't enough data to
		 * contain this option, or if this type of option
		 * should contain more data than the length field
		 * claims there is.
		 */
		if (optlen > len || optlen < optinfo_ptr->opt_minsize) {
			(void) sprintf(get_line(0, 0),
			    "Warning: Incomplete Option");
			show_space();
			break;
		}

		if (optinfo_ptr->opt_formatdata != NULL) {
			optinfo_ptr->opt_formatdata(optptr,
			    MIN(optlen - 2, len - 2));
		}

		len -= optlen;
		optptr += optlen - 2;

		show_space();
	}

	return (len);
}

static int
interpret_ppp_chap(int flags, uchar_t *data, int len,
    ppp_protoinfo_t *protoinfo)
{
	uint8_t code;
	uint8_t id;
	char *codestr;
	uint16_t length;
	int lengthleft;
	uchar_t *datap = data;


	if (len < sizeof (ppp_pkt_t))
		return (len);

	GETINT8(code, datap);
	GETINT8(id, datap);
	GETINT8(length, datap);

	if (code <= MAX_CHAPCODE)
		codestr = chap_codearray[code];
	else
		codestr = "";

	if (flags & F_SUM) {
		(void) sprintf(get_sum_line(),
		    "%s%s", protoinfo->prefix, codestr);
	} else { /* (flags & F_DTAIL) */
		show_header(protoinfo->prefix, protoinfo->description, len);
		show_space();

		(void) sprintf(get_line(0, 0), "Code = %d %s", code, codestr);
		(void) sprintf(get_line(0, 0), "Identifier = %d", id);
		(void) sprintf(get_line(0, 0), "Length = %d", length);

		show_space();

		if (len < length)
			return (len);

		lengthleft = len - sizeof (ppp_pkt_t);

		switch (code) {
		case CODE_CHALLENGE:
		case CODE_RESPONSE: {
			uint8_t value_size;
			uint16_t peername_size;

			if (lengthleft < sizeof (value_size))
				break;

			GETINT8(value_size, datap);
			lengthleft -= sizeof (value_size);
			(void) sprintf(get_line(0, 0), "Value-Size = %d",
			    value_size);

			if (lengthleft < sizeof (peername_size))
				break;
			peername_size = MIN(length - sizeof (ppp_pkt_t) -
			    value_size, lengthleft);
			(void) sprintf(get_line(0, 0), "Name = %.*s",
			    peername_size, datap + value_size);

			break;
		}
		case CODE_SUCCESS:
		case CODE_FAILURE: {
			uint16_t message_size = MIN(length - sizeof (ppp_pkt_t),
			    lengthleft);

			(void) sprintf(get_line(0, 0), "Message = %.*s",
			    message_size, datap);
			break;
		}
		default:
			break;
		}
	}

	show_space();
	len -= length;
	return (len);
}

static int
interpret_ppp_pap(int flags, uchar_t *data, int len,
    ppp_protoinfo_t *protoinfo)
{
	uint8_t code;
	uint8_t id;
	char *codestr;
	uint16_t length;
	int lengthleft;
	uchar_t *datap = data;

	if (len < sizeof (ppp_pkt_t))
		return (len);

	GETINT8(code, datap);
	GETINT8(id, datap);
	GETINT16(length, datap);

	lengthleft = len - sizeof (ppp_pkt_t);

	if (code <= MAX_PAPCODE)
		codestr = pap_codearray[code];
	else
		codestr = "";

	if (flags & F_SUM) {
		(void) sprintf(get_sum_line(),
		    "%s%s", protoinfo->prefix, codestr);
	} else { /* (flags & F_DTAIL) */
		show_header(protoinfo->prefix, protoinfo->description, len);
		show_space();

		(void) sprintf(get_line(0, 0), "Code = %d %s", code, codestr);
		(void) sprintf(get_line(0, 0), "Identifier = %d", id);
		(void) sprintf(get_line(0, 0), "Length = %d", length);

		show_space();

		if (len < length)
			return (len);

		switch (code) {
		case CODE_AUTHREQ: {
			uint8_t fieldlen;

			if (lengthleft < sizeof (fieldlen))
				break;
			GETINT8(fieldlen, datap);
			(void) sprintf(get_line(0, 0), "Peer-Id Length = %d",
			    fieldlen);
			lengthleft -= sizeof (fieldlen);

			if (lengthleft < fieldlen)
				break;
			(void) sprintf(get_line(0, 0), "Peer-Id = %.*s",
			    fieldlen, datap);
			lengthleft -= fieldlen;

			datap += fieldlen;

			if (lengthleft < sizeof (fieldlen))
				break;
			GETINT8(fieldlen, datap);
			(void) sprintf(get_line(0, 0), "Password Length = %d",
			    fieldlen);
			lengthleft -= sizeof (fieldlen);

			if (lengthleft < fieldlen)
				break;
			(void) sprintf(get_line(0, 0), "Password = %.*s",
			    fieldlen, datap);

			break;
		}
		case CODE_AUTHACK:
		case CODE_AUTHNAK: {
			uint8_t msglen;

			if (lengthleft < sizeof (msglen))
				break;
			GETINT8(msglen, datap);
			(void) sprintf(get_line(0, 0), "Msg-Length = %d",
			    msglen);
			lengthleft -= sizeof (msglen);

			if (lengthleft < msglen)
				break;
			(void) sprintf(get_line(0, 0), "Message = %.*s",
			    msglen, datap);

			break;
		}
		default:
			break;
		}
	}

	show_space();
	len -= length;
	return (len);
}


static int
interpret_ppp_lqr(int flags, uchar_t *data, int len,
    ppp_protoinfo_t *protoinfo)
{
	lqr_pkt_t lqr_pkt;
	if (len < sizeof (lqr_pkt_t))
		return (len);

	(void) memcpy(&lqr_pkt, data, sizeof (lqr_pkt_t));

	if (flags & F_SUM) {
		(void) sprintf(get_sum_line(), protoinfo->prefix);
	} else { /* (flags & F_DTAIL) */
		show_header(protoinfo->prefix, protoinfo->description, len);
		show_space();

		(void) sprintf(get_line(0, 0), "Magic-Number =   0x%08x",
		    ntohl(lqr_pkt.lqr_magic));
		(void) sprintf(get_line(0, 0), "LastOutLQRs =    %d",
		    ntohl(lqr_pkt.lqr_lastoutlqrs));
		(void) sprintf(get_line(0, 0), "LastOutPackets = %d",
		    ntohl(lqr_pkt.lqr_lastoutpackets));
		(void) sprintf(get_line(0, 0), "LastOutOctets =  %d",
		    ntohl(lqr_pkt.lqr_lastoutoctets));
		(void) sprintf(get_line(0, 0), "PeerInLQRs =     %d",
		    ntohl(lqr_pkt.lqr_peerinlqrs));
		(void) sprintf(get_line(0, 0), "PeerInPackets =  %d",
		    ntohl(lqr_pkt.lqr_peerinpackets));
		(void) sprintf(get_line(0, 0), "PeerInDiscards = %d",
		    ntohl(lqr_pkt.lqr_peerindiscards));
		(void) sprintf(get_line(0, 0), "PeerInErrors =   %d",
		    ntohl(lqr_pkt.lqr_peerinerrors));
		(void) sprintf(get_line(0, 0), "PeerInOctets =   %d",
		    ntohl(lqr_pkt.lqr_peerinoctets));
		(void) sprintf(get_line(0, 0), "PeerOutLQRs =    %d",
		    ntohl(lqr_pkt.lqr_peeroutlqrs));
		(void) sprintf(get_line(0, 0), "PeerOutPackets = %d",
		    ntohl(lqr_pkt.lqr_peeroutpackets));
		(void) sprintf(get_line(0, 0), "PeerOutOctets =  %d",
		    ntohl(lqr_pkt.lqr_peeroutoctets));

		show_space();
	}

	len -= sizeof (lqr_pkt_t);
	return (len);
}

static ppp_protoinfo_t *
ppp_getprotoinfo(uint16_t proto)
{
	ppp_protoinfo_t *protoinfo_ptr = &protoinfo_array[0];

	while (protoinfo_ptr->proto != proto && protoinfo_ptr->proto != 0) {
		protoinfo_ptr++;
	}

	return (protoinfo_ptr);
}


static cp_optinfo_t *
ppp_getoptinfo(cp_optinfo_t optinfo_list[], uint16_t opt_type)
{
	cp_optinfo_t *optinfo_ptr = &optinfo_list[0];

	while (optinfo_ptr->opt_type != opt_type &&
	    optinfo_ptr->opt_name != unknown_string) {
		optinfo_ptr++;
	}

	return (optinfo_ptr);
}


/*
 * Below are the functions which parse control protocol configuration
 * options.  The first argument to these functions (optdata) points to the
 * first byte of the option after the length field.  The second argument
 * (size) is the number of bytes in the option after the length field
 * (length - 2).
 */

/*
 * The format of the Vendor-Specific option (rfc2153) is:
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |              OUI
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        ...      |     Kind      |  Value(s) ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 */
/*ARGSUSED1*/
static void
opt_format_vendor(uchar_t *optdata, uint8_t size)
{
	uint32_t oui;
	char *ouistr;
	uint8_t kind;

	GETINT32(oui, optdata);
	kind = oui & 0x000000ff;
	oui >>= 8;

	ouistr = ether_ouiname(oui);
	if (ouistr == NULL)
		ouistr = unknown_string;

	(void) sprintf(get_line(0, 0), "OUI = 0x%06x (%s)", oui, ouistr);
	(void) sprintf(get_line(0, 0), "Kind = %d", kind);
}

/*
 * The format of the MRU option (rfc1661) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |      Maximum-Receive-Unit     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_mru(uchar_t *optdata, uint8_t size)
{
	uint16_t mru;

	GETINT16(mru, optdata);
	(void) sprintf(get_line(0, 0), "MRU = %d", mru);
}

/*
 * The format of the accm option (rfc1662) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |               ACCM
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *           ACCM (cont)           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_accm(uchar_t *optdata, uint8_t size)
{
	uint32_t accm;

	GETINT32(accm, optdata);
	(void) sprintf(get_line(0, 0), "ACCM = 0x%08x", accm);
}

/*
 * The format of the Authentication-Protocol option (rfc1661) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |     Authentication-Protocol   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Data ...
 * +-+-+-+-+
 *
 * For PAP (rfc1334), there is no data.  For CHAP (rfc1994), there is one
 * byte of data representing the algorithm.
 */
static void
opt_format_authproto(uchar_t *optdata, uint8_t size)
{
	uint16_t proto;
	ppp_protoinfo_t *auth_protoinfo;

	GETINT16(proto, optdata);

	auth_protoinfo = ppp_getprotoinfo(proto);

	(void) sprintf(get_line(0, 0), "Protocol = 0x%x (%s)", proto,
	    auth_protoinfo->name);

	switch (proto) {
	case PPP_CHAP: {
		uint8_t algo;
		char *algostr;

		if (size < sizeof (proto) + sizeof (algo))
			return;

		GETINT8(algo, optdata);
		switch (algo) {
		case 5:
			algostr = "CHAP with MD5";
			break;
		case 128:
			algostr = "MS-CHAP";
			break;
		case 129:
			algostr = "MS-CHAP-2";
			break;
		default:
			algostr = unknown_string;
			break;
		}
		(void) sprintf(get_line(0, 0), "Algorithm = %d (%s)", algo,
		    algostr);
		break;
	}
	default:
		break;
	}
}

/*
 * The format of the Quality Protocol option (rfc1661) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |        Quality-Protocol       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Data ...
 * +-+-+-+-+
 *
 * For LQR, the data consists of a 4 byte reporting period.
 */
static void
opt_format_qualproto(uchar_t *optdata, uint8_t size)
{
	uint16_t proto;
	ppp_protoinfo_t *qual_protoinfo;

	GETINT16(proto, optdata);

	qual_protoinfo = ppp_getprotoinfo(proto);

	(void) sprintf(get_line(0, 0), "Protocol = 0x%x (%s)", proto,
	    qual_protoinfo->name);

	switch (proto) {
	case PPP_LQR: {
		uint32_t reporting_period;

		if (size < sizeof (proto) + sizeof (reporting_period))
			return;

		GETINT32(reporting_period, optdata);
		(void) sprintf(get_line(0, 0), "Reporting-Period = %d",
		    reporting_period);
		break;
	}
	default:
		break;
	}
}

/*
 * The format of the Magic Number option (rfc1661) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |          Magic-Number
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       Magic-Number (cont)       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_magicnum(uchar_t *optdata, uint8_t size)
{
	uint32_t magicnum;

	GETINT32(magicnum, optdata);
	(void) sprintf(get_line(0, 0), "Magic Number = 0x%08x", magicnum);
}

/*
 * The format of the FCS-Alternatives option (rfc1570) is:
 *
 *  0                   1                   2
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |    Options    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_fcs(uchar_t *optdata, uint8_t size)
{
	uint8_t options;

	GETINT8(options, optdata);

	(void) sprintf(get_line(0, 0), "Options = 0x%02x", options);
	(void) sprintf(get_line(0, 0), "     %s",
	    getflag(options, 0x01, "NULL FCS", ""));
	(void) sprintf(get_line(0, 0), "     %s",
	    getflag(options, 0x02, "CCITT 16-bit FCS", ""));
	(void) sprintf(get_line(0, 0), "     %s",
	    getflag(options, 0x04, "CCITT 32-bit FCS", ""));
}

/*
 * The format of the Self-Describing-Padding option (rfc1570) is:
 *
 *  0                   1                   2
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |    Maximum    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_sdp(uchar_t *optdata, uint8_t size)
{
	uint8_t max;

	GETINT8(max, optdata);

	(void) sprintf(get_line(0, 0), "Maximum = %d", max);
}

/*
 * The format of the Numbered-Mode option (rfc1663) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |     Length    |    Window     |   Address...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_nummode(uchar_t *optdata, uint8_t size)
{
	uint8_t window;

	GETINT8(window, optdata);
	(void) sprintf(get_line(0, 0), "Window = %d", window);
}

/*
 * The format of the Callback option (rfc1570) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |   Operation   |  Message ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static void
opt_format_callback(uchar_t *optdata, uint8_t size)
{
	uint8_t operation;
	char *opstr;

	GETINT8(operation, optdata);
	switch (operation) {
	case 0:
		opstr = "User Authentication";
		break;
	case 1:
		opstr = "Dialing String";
		break;
	case 2:
		opstr = "Location Identifier";
		break;
	case 3:
		opstr = "E.164 Number";
		break;
	case 4:
		opstr = "X.500 Distinguished Name";
		break;
	case 6:
		opstr = "CBCP Negotiation";
		break;
	default:
		opstr = unknown_string;
		break;
	}

	(void) sprintf(get_line(0, 0), "Operation = %d (%s)", operation, opstr);

	if (size > sizeof (operation)) {
		(void) sprintf(get_line(0, 0), "Message = %.*s",
		    size - sizeof (operation), optdata);
	}
}

/*
 * The format of the Multilink-MRRU option (rfc1990) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Type = 17   |   Length = 4  | Max-Receive-Reconstructed-Unit|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_mrru(uchar_t *optdata, uint8_t size)
{
	uint16_t mrru;

	GETINT16(mrru, optdata);
	(void) sprintf(get_line(0, 0), "MRRU = %d", mrru);
}

/*
 * The format of the Endpoint Discriminator option (rfc1990) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Type = 19   |     Length    |    Class      |  Address ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static void
opt_format_epdisc(uchar_t *optdata, uint8_t size)
{
	uint8_t class;
	char *classstr;
	uint8_t addrlen = size - sizeof (class);
	char *addr;

	GETINT8(class, optdata);

	switch (class) {
	case 0:
		classstr = "Null Class";
		break;
	case 1:
		classstr = "Locally Assigned Address";
		break;
	case 2:
		classstr = "IPv4 Address";
		break;
	case 3:
		classstr = "IEE 802.1 Global MAC Address";
		break;
	case 4:
		classstr = "PPP Magic-Number Block";
		break;
	case 5:
		classstr = "Public Switched Network Directory Number";
		break;
	default:
		classstr = unknown_string;
		break;
	}

	(void) sprintf(get_line(0, 0), "Address Class = %d (%s)", class,
	    classstr);

	if (addrlen == 0)
		return;

	addr = (char *)malloc(addrlen);
	(void) memcpy(addr, optdata, addrlen);
	switch (class) {
	case 2: {
		char addrstr[INET_ADDRSTRLEN];

		if (addrlen != sizeof (in_addr_t))
			break;
		if (inet_ntop(AF_INET, addr, addrstr, INET_ADDRSTRLEN) !=
		    NULL) {
			(void) sprintf(get_line(0, 0), "Address = %s", addrstr);
		}
		break;
	}
	case 3: {
		char *addrstr;

		if (addrlen != sizeof (struct ether_addr))
			break;
		if ((addrstr = ether_ntoa((struct ether_addr *)addr)) != NULL) {
			(void) sprintf(get_line(0, 0), "Address = %s", addrstr);
		}
		break;
	}
	case 5: {
		/*
		 * For this case, the address is supposed to be a plain
		 * text telephone number.
		 */
		(void) sprintf(get_line(0, 0), "Address = %.*s", addrlen,
		    addr);
	}
	default:
		break;
	}

	free(addr);
}

/*
 * The DCE identifier option has the following format (from rfc1976):
 *
 *     0                   1                   2
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |     Type      |    Length     |      Mode     |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_dce(uchar_t *optdata, uint8_t size)
{
	uint8_t mode;
	char *modestr;

	GETINT8(mode, optdata);
	switch (mode) {
	case 1:
		modestr = "No Additional Negotiation";
		break;
	case 2:
		modestr = "Full PPP Negotiation and State Machine";
		break;
	default:
		modestr = unknown_string;
		break;
	}
	(void) sprintf(get_line(0, 0), "Mode = %d (%s)", mode, modestr);
}

/*
 * The format of the Link Discriminator option (rfc2125) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |     Length    |       Link Discriminator      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_linkdisc(uchar_t *optdata, uint8_t size)
{
	uint16_t discrim;

	GETINT16(discrim, optdata);

	(void) sprintf(get_line(0, 0), "Link Discriminator = %d", discrim);
}


/*
 * The format of the Internationalization option (rfc2484) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |          MIBenum
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *           MIBenum (cont)        |        Language-Tag...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static void
opt_format_i18n(uchar_t *optdata, uint8_t size)
{
	uint32_t mibenum;
	uint8_t taglen;

	taglen = size - sizeof (mibenum);

	GETINT32(mibenum, optdata);
	(void) sprintf(get_line(0, 0), "MIBenum = %d", mibenum);

	if (taglen > 0) {
		(void) sprintf(get_line(0, 0), "Language Tag = %.*s", taglen,
		    optdata);
	}
}

/*
 * The format of the obsolete IP-Addresses option (rfc1172) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |     Source-IP-Address
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   Source-IP-Address (cont)      |  Destination-IP-Address
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  Destination-IP-Address (cont)  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_ipaddresses(uchar_t *optdata, uint8_t size)
{
	in_addr_t addr;
	char addrstr[INET_ADDRSTRLEN];

	(void) memcpy(&addr, optdata, sizeof (in_addr_t));
	if (inet_ntop(AF_INET, &addr, addrstr, INET_ADDRSTRLEN) != NULL) {
		(void) sprintf(get_line(0, 0), "Source Address =      %s",
		    addrstr);
	}

	optdata += sizeof (in_addr_t);

	(void) memcpy(&addr, optdata, sizeof (in_addr_t));
	if (inet_ntop(AF_INET, &addr, addrstr, INET_ADDRSTRLEN) != NULL) {
		(void) sprintf(get_line(0, 0), "Destination Address = %s",
		    addrstr);
	}
}

/*
 * The format of the IP-Compression-Protocol option (rfc1332) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |     IP-Compression-Protocol   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Data ...
 * +-+-+-+-+
 *
 * For VJ Compressed TCP/IP, data consists of:
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Max-Slot-Id  | Comp-Slot-Id  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * For IPHC (rfc2509), data consists of:
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           TCP_SPACE           |         NON_TCP_SPACE         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         F_MAX_PERIOD          |          F_MAX_TIME           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           MAX_HEADER          |          suboptions...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static void
opt_format_ipcompproto(uchar_t *optdata, uint8_t size)
{
	uint16_t proto;
	ppp_protoinfo_t *comp_protoinfo;

	GETINT16(proto, optdata);

	comp_protoinfo = ppp_getprotoinfo(proto);

	(void) sprintf(get_line(0, 0), "Protocol = 0x%x (%s)", proto,
	    comp_protoinfo->name);

	switch (proto) {
	case PPP_VJC_COMP: {
		uint8_t maxslotid;
		uint8_t compslotid;

		if (size < sizeof (proto) + sizeof (maxslotid) +
		    sizeof (compslotid))
			break;

		GETINT8(maxslotid, optdata);
		GETINT8(compslotid, optdata);
		(void) sprintf(get_line(0, 0), "Max-Slot-Id = %d", maxslotid);
		(void) sprintf(get_line(0, 0), "Comp-Slot Flag = 0x%x",
		    compslotid);
		break;
	}
	case PPP_FULLHDR: {
		uint16_t tcp_space;
		uint16_t non_tcp_space;
		uint16_t f_max_period;
		uint16_t f_max_time;
		uint16_t max_header;

		if (size < sizeof (proto) + sizeof (tcp_space) +
		    sizeof (non_tcp_space) + sizeof (f_max_period) +
		    sizeof (f_max_time) + sizeof (max_header))
			break;

		GETINT16(tcp_space, optdata);
		GETINT16(non_tcp_space, optdata);
		GETINT16(f_max_period, optdata);
		GETINT16(f_max_time, optdata);
		GETINT16(max_header, optdata);

		(void) sprintf(get_line(0, 0), "TCP_SPACE = %d", tcp_space);
		(void) sprintf(get_line(0, 0), "NON_TCP_SPACE = %d",
		    non_tcp_space);
		(void) sprintf(get_line(0, 0), "F_MAX_PERIOD = %d",
		    f_max_period);
		(void) sprintf(get_line(0, 0), "F_MAX_TIME = %d", f_max_time);
		(void) sprintf(get_line(0, 0), "MAX_HEADER = %d octets",
		    max_header);
	}
	default:
		break;
	}
}

/*
 * The format of the IP-Address option (rfc1332) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |           IP-Address
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *         IP-Address (cont)       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_ipaddress(uchar_t *optdata, uint8_t size)
{
	in_addr_t ipaddr;
	char addrstr[INET_ADDRSTRLEN];

	(void) memcpy(&ipaddr, optdata, sizeof (in_addr_t));
	if (inet_ntop(AF_INET, &ipaddr, addrstr, INET_ADDRSTRLEN) != NULL) {
		(void) sprintf(get_line(0, 0), "Address = %s", addrstr);
	}
}

/*
 * The format of the Mobile-IPv4 option (rfc2290) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |         Mobile Node's ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       ...  Home Address         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_mobileipv4(uchar_t *optdata, uint8_t size)
{
	in_addr_t ipaddr;
	char addrstr[INET_ADDRSTRLEN];

	(void) memcpy(&ipaddr, optdata, sizeof (in_addr_t));
	if (inet_ntop(AF_INET, &ipaddr, addrstr, INET_ADDRSTRLEN) != NULL) {
		(void) sprintf(get_line(0, 0),
		    "Mobile Node's Home Address = %s", addrstr);
	}
}

/*
 * The format of the Interface-Identifier option (rfc2472) is:
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     | Interface-Identifier (MS Bytes)
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                      Interface-Identifier (cont)
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * Interface-Identifier (LS Bytes) |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_ifaceid(uchar_t *optdata, uint8_t size)
{
	in6_addr_t id;
	char idstr[INET6_ADDRSTRLEN];

	(void) memset(&id, 0, sizeof (in6_addr_t));
	(void) memcpy(&id.s6_addr[8], optdata, 8);

	if (inet_ntop(AF_INET6, &id, idstr, INET6_ADDRSTRLEN) != NULL) {
		(void) sprintf(get_line(0, 0), "Interface ID = %s", idstr);
	}
}

/*
 * The format of the IPv6-Compression-Protocol option (rfc2472) is:
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |   IPv6-Compression-Protocol   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Data ...
 * +-+-+-+-+
 */
static void
opt_format_ipv6compproto(uchar_t *optdata, uint8_t size)
{
	uint16_t proto;
	ppp_protoinfo_t *comp_protoinfo;

	GETINT16(proto, optdata);

	comp_protoinfo = ppp_getprotoinfo(proto);

	(void) sprintf(get_line(0, 0), "Protocol = 0x%x (%s)", proto,
	    comp_protoinfo->name);

	switch (proto) {
	case PPP_FULLHDR: {
		uint16_t tcp_space;
		uint16_t non_tcp_space;
		uint16_t f_max_period;
		uint16_t f_max_time;
		uint16_t max_header;

		if (size < sizeof (proto) + sizeof (tcp_space) +
		    sizeof (non_tcp_space) + sizeof (f_max_period) +
		    sizeof (f_max_time) + sizeof (max_header))
			return;

		GETINT16(tcp_space, optdata);
		GETINT16(non_tcp_space, optdata);
		GETINT16(f_max_period, optdata);
		GETINT16(f_max_time, optdata);
		GETINT16(max_header, optdata);

		(void) sprintf(get_line(0, 0), "TCP_SPACE = %d", tcp_space);
		(void) sprintf(get_line(0, 0), "NON_TCP_SPACE = %d",
		    non_tcp_space);
		(void) sprintf(get_line(0, 0), "F_MAX_PERIOD = %d",
		    f_max_period);
		(void) sprintf(get_line(0, 0), "F_MAX_TIME = %d", f_max_time);
		(void) sprintf(get_line(0, 0), "MAX_HEADER = %d octets",
		    max_header);
	}
	default:
		break;
	}
}

/*
 * The format of the Proprietary Compression OUI option (rfc1962) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |       OUI ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       OUI       |    Subtype    |  Values...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 */
/*ARGSUSED1*/
static void
opt_format_compoui(uchar_t *optdata, uint8_t size)
{
	uint32_t oui;
	uint8_t subtype;
	char *ouistr;

	GETINT32(oui, optdata);
	subtype = oui & 0x000000ff;
	oui >>= 8;

	ouistr = ether_ouiname(oui);
	if (ouistr == NULL)
		ouistr = unknown_string;
	(void) sprintf(get_line(0, 0), "OUI = 0x%06x (%s)", oui, ouistr);
	(void) sprintf(get_line(0, 0), "Subtype = 0x%x", subtype);
}

/*
 * The format of the Stac LZS configuration option (rfc1974) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |        History Count          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Check Mode  |
 * +-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_staclzs(uchar_t *optdata, uint8_t size)
{
	uint16_t hcount;
	uint8_t cmode;

	GETINT16(hcount, optdata);
	GETINT8(cmode, optdata);

	cmode &= 0x07;

	(void) sprintf(get_line(0, 0), "History Count = %d", hcount);
	(void) sprintf(get_line(0, 0), "Check Mode = %d", cmode);
}

/*
 * The format of MPPC configuration option (rfc2118) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |        Supported Bits         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |       Supported Bits          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_mppc(uchar_t *optdata, uint8_t size)
{
	uint32_t sb;

	GETINT32(sb, optdata);

	(void) sprintf(get_line(0, 0), "Supported Bits = 0x%x", sb);
}

/*
 * The format of the Gandalf FZA configuration option (rfc1993) is:
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |   History   |    Version ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_gandalf(uchar_t *optdata, uint8_t size)
{
	uint8_t history;

	GETINT8(history, optdata);
	(void) sprintf(get_line(0, 0), "Maximum History Size = %d bits",
	    history);
}

/*
 * The format of the BSD Compress configuration option (rfc1977) is:
 *
 *  0                   1                   2
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     | Vers|   Dict  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_bsdcomp(uchar_t *optdata, uint8_t size)
{
	uint8_t version;
	uint8_t codesize;

	GETINT8(codesize, optdata);

	version = codesize >> 5;
	codesize &= 0x1f;

	(void) sprintf(get_line(0, 0), "Version = 0x%x", version);
	(void) sprintf(get_line(0, 0), "Maximum Code Size = %d bits", codesize);
}

/*
 * The format of the LZS-DCP configuration option (rfc1967) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |        History Count          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Check Mode  | Process Mode  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_lzsdcp(uchar_t *optdata, uint8_t size)
{
	uint16_t history;
	uint8_t mode;
	char *modestr;

	GETINT16(history, optdata);
	(void) sprintf(get_line(0, 0), "History Count = %d", history);

	/* check mode */
	GETINT8(mode, optdata);
	switch (mode) {
	case 0:
		modestr = "None";
		break;
	case 1:
		modestr = "LCB";
		break;
	case 2:
		modestr = "Sequence Number";
		break;
	case 3:
		modestr = "Sequence Number + LCB (default)";
		break;
	default:
		modestr = unknown_string;
		break;
	}
	(void) sprintf(get_line(0, 0), "Check Mode = %d (%s)", mode, modestr);

	/* process mode */
	GETINT8(mode, optdata);
	switch (mode) {
	case 0:
		modestr = "None (default)";
		break;
	case 1:
		modestr = "Process-Uncompressed";
		break;
	default:
		modestr = unknown_string;
		break;
	}
	(void) sprintf(get_line(0, 0), "Process Mode = %d (%s)", mode, modestr);

}

/*
 * The format of the Magnalink configuration option (rfc1975) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |FE |P| History |  # Contexts   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_magnalink(uchar_t *optdata, uint8_t size)
{
	uint8_t features;
	uint8_t pflag;
	uint8_t history;
	uint8_t contexts;

	GETINT8(history, optdata);
	GETINT8(contexts, optdata);

	features = history >> 6;
	pflag = (history >> 5) & 0x01;
	history &= 0x1f;

	(void) sprintf(get_line(0, 0), "Features = 0x%d", features);
	(void) sprintf(get_line(0, 0), "Packet Flag = %d", pflag);
	(void) sprintf(get_line(0, 0), "History Size = %d", history);
	(void) sprintf(get_line(0, 0), "Contexts = %d", contexts);
}

/*
 * The format of the Deflate configuration option (rfc1979) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |Window | Method|    MBZ    |Chk|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_deflate(uchar_t *optdata, uint8_t size)
{
	uint8_t window;
	uint8_t method;
	uint8_t chk;

	GETINT8(method, optdata);
	window = method >> 4;
	method &= 0x0f;

	GETINT8(chk, optdata);
	chk &= 0x03;

	(void) sprintf(get_line(0, 0), "Maximum Window Size = %d", window);
	(void) sprintf(get_line(0, 0), "Compression Method = 0x%x", method);
	(void) sprintf(get_line(0, 0), "Check Method = 0x%x", chk);
}

/*
 * The format of the Proprietary Encryption OUI option (rfc1968) is:
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    Length     |       OUI ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       OUI       |    Subtype    |  Values...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 */
/*ARGSUSED1*/
static void
opt_format_encroui(uchar_t *optdata, uint8_t size)
{
	uint32_t oui;
	uint8_t subtype;
	char *ouistr;

	GETINT32(oui, optdata);
	subtype = oui & 0x000000ff;
	oui >>= 8;

	ouistr = ether_ouiname(oui);
	if (ouistr == NULL)
		ouistr = unknown_string;
	(void) sprintf(get_line(0, 0), "OUI = 0x%06x (%s)", oui, ouistr);
	(void) sprintf(get_line(0, 0), "Subtype = 0x%x", subtype);
}

/*
 * The format of the DESE, DESE-bis, and 3DESE configuration options
 * (rfc1969, rfc2419, and rfc2420) are:
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Type = 3    |    Length     |         Initial Nonce ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_dese(uchar_t *optdata, uint8_t size)
{
	(void) sprintf(get_line(0, 0),
	    "Initial Nonce = 0x%02x%02x%02x%02x%02x%02x%02x%02x",
	    optdata[0], optdata[1], optdata[2], optdata[3], optdata[4],
	    optdata[5], optdata[6], optdata[7]);
}

/*
 * The format of the PPPMux Default Protocol Id option
 * (draft-ietf-pppext-pppmux-02.txt) is:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Type = 1    |   Length = 4  |        Default PID            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED1*/
static void
opt_format_muxpid(uchar_t *optdata, uint8_t size)
{
	uint16_t defpid;

	GETINT16(defpid, optdata);
	(void) sprintf(get_line(0, 0), "Default PID = %d", defpid);
}
