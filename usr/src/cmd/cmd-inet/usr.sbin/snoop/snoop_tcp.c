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
 *
 * Copyright 2024 Oxide Computer Company
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include "snoop.h"

extern char *dlc_header;

#define	TCPOPT_HEADER_LEN	2
#define	TCPOPT_TSTAMP_LEN	10
#define	TCPOPT_SACK_LEN		8
#define	TCPOPT_MD5_LEN		18

/*
 * Convert a network byte order 32 bit integer to a host order integer.
 * ntohl() cannot be used because option values may not be aligned properly.
 */
#define	GET_UINT32(opt)	(((uint_t)*((uchar_t *)(opt) + 0) << 24) | \
	((uint_t)*((uchar_t *)(opt) + 1) << 16) | \
	((uint_t)*((uchar_t *)(opt) + 2) << 8) | \
	((uint_t)*((uchar_t *)(opt) + 3)))

static void print_tcpoptions_summary(uchar_t *, int, char *);
static void print_tcpoptions(uchar_t *, int);

static const struct {
	unsigned int	tf_flag;
	const char	*tf_name;
} tcp_flags[] = {
	{ TH_SYN,	"Syn"	},
	{ TH_FIN,	"Fin"	},
	{ TH_RST,	"Rst"	},
	{ TH_PUSH,	"Push"	},
	{ TH_ECE,	"ECE"	},
	{ TH_CWR,	"CWR"	},
	{ 0,		NULL	}
};

int
interpret_tcp(int flags, struct tcphdr *tcp, int iplen, int fraglen)
{
	char *data;
	int hdrlen, tcplen;
	int sunrpc = 0;
	char *pname;
	char buff[32];
	char *line, *endline;
	unsigned int i;

	hdrlen = tcp->th_off * 4;
	data = (char *)tcp + hdrlen;
	tcplen = iplen - hdrlen;
	fraglen -= hdrlen;
	if (fraglen < 0)
		return (fraglen + hdrlen);	/* incomplete header */
	if (fraglen > tcplen)
		fraglen = tcplen;

	if (flags & F_SUM) {
		line = get_sum_line();
		endline = line + MAXLINE;
		(void) snprintf(line, endline - line, "TCP D=%d S=%d",
		    ntohs(tcp->th_dport), ntohs(tcp->th_sport));
		line += strlen(line);

		for (i = 0; tcp_flags[i].tf_name != NULL; i++) {
			if (tcp->th_flags & tcp_flags[i].tf_flag) {
				(void) snprintf(line, endline - line, " %s",
				    tcp_flags[i].tf_name);
				line += strlen(line);
			}
		}

		if (tcp->th_flags & TH_URG) {
			(void) snprintf(line, endline - line, " Urg=%u",
			    ntohs(tcp->th_urp));
			line += strlen(line);
		}
		if (tcp->th_flags & TH_ACK) {
			(void) snprintf(line, endline - line, " Ack=%u",
			    ntohl(tcp->th_ack));
			line += strlen(line);
		}
		if (ntohl(tcp->th_seq)) {
			(void) snprintf(line, endline - line, " Seq=%u Len=%d",
			    ntohl(tcp->th_seq), tcplen);
			line += strlen(line);
		}
		(void) snprintf(line, endline - line, " Win=%d",
		    ntohs(tcp->th_win));
		print_tcpoptions_summary((uchar_t *)(tcp + 1),
		    (int)(tcp->th_off * 4 - sizeof (struct tcphdr)), line);
	}

	sunrpc = !reservedport(IPPROTO_TCP, ntohs(tcp->th_dport)) &&
	    !reservedport(IPPROTO_TCP, ntohs(tcp->th_sport)) &&
	    valid_rpc(data + 4, fraglen - 4);

	if (flags & F_DTAIL) {

	show_header("TCP:  ", "TCP Header", tcplen);
	show_space();
	(void) sprintf(get_line((char *)(uintptr_t)tcp->th_sport -
	    dlc_header, 2), "Source port = %d", ntohs(tcp->th_sport));

	if (sunrpc) {
		pname = "(Sun RPC)";
	} else {
		pname = getportname(IPPROTO_TCP, ntohs(tcp->th_dport));
		if (pname == NULL) {
			pname = "";
		} else {
			(void) sprintf(buff, "(%s)", pname);
			pname = buff;
		}
	}
	(void) sprintf(get_line((char *)(uintptr_t)tcp->th_dport -
	    dlc_header, 2), "Destination port = %d %s",
	    ntohs(tcp->th_dport), pname);
	(void) sprintf(get_line((char *)(uintptr_t)tcp->th_seq -
	    dlc_header, 4),	"Sequence number = %u",
	    ntohl(tcp->th_seq));
	(void) sprintf(get_line((char *)(uintptr_t)tcp->th_ack - dlc_header, 4),
	    "Acknowledgement number = %u",
	    ntohl(tcp->th_ack));
	(void) sprintf(get_line(((char *)(uintptr_t)tcp->th_ack - dlc_header) +
	    4, 1), "Data offset = %d bytes", tcp->th_off * 4);
	(void) sprintf(get_line(((char *)(uintptr_t)tcp->th_flags -
	    dlc_header) + 4, 1), "Flags = 0x%02x", tcp->th_flags);
	(void) sprintf(get_line(((char *)(uintptr_t)tcp->th_flags -
	    dlc_header) + 4, 1), "      %s", getflag(tcp->th_flags, TH_CWR,
	    "ECN congestion window reduced",
	    "No ECN congestion window reduced"));
	(void) sprintf(get_line(((char *)(uintptr_t)tcp->th_flags -
	    dlc_header) + 4, 1), "      %s", getflag(tcp->th_flags, TH_ECE,
	    "ECN echo", "No ECN echo"));
	(void) sprintf(
	    get_line(((char *)(uintptr_t)tcp->th_flags - dlc_header) + 4, 1),
	    "      %s", getflag(tcp->th_flags, TH_URG,
	    "Urgent pointer", "No urgent pointer"));
	(void) sprintf(get_line(((char *)(uintptr_t)tcp->th_flags -
	    dlc_header) + 4, 1), "      %s", getflag(tcp->th_flags, TH_ACK,
	    "Acknowledgement", "No acknowledgement"));
	(void) sprintf(get_line(((char *)(uintptr_t)tcp->th_flags -
	    dlc_header) + 4, 1), "      %s", getflag(tcp->th_flags, TH_PUSH,
	    "Push", "No push"));
	(void) sprintf(get_line(((char *)(uintptr_t)tcp->th_flags -
	    dlc_header) + 4, 1), "      %s", getflag(tcp->th_flags, TH_RST,
	    "Reset", "No reset"));
	(void) sprintf(get_line(((char *)(uintptr_t)tcp->th_flags -
	    dlc_header) + 4, 1), "      %s", getflag(tcp->th_flags, TH_SYN,
	    "Syn", "No Syn"));
	(void) sprintf(get_line(((char *)(uintptr_t)tcp->th_flags -
	    dlc_header) + 4, 1), "      %s", getflag(tcp->th_flags, TH_FIN,
	    "Fin", "No Fin"));
	(void) sprintf(get_line(((char *)(uintptr_t)tcp->th_win - dlc_header) +
	    4, 1), "Window = %d", ntohs(tcp->th_win));
	/* XXX need to compute checksum and print whether correct */
	(void) sprintf(get_line(((char *)(uintptr_t)tcp->th_sum - dlc_header) +
	    4, 1), "Checksum = 0x%04x", ntohs(tcp->th_sum));
	(void) sprintf(get_line(((char *)(uintptr_t)tcp->th_urp - dlc_header) +
	    4, 1), "Urgent pointer = %d", ntohs(tcp->th_urp));

	/* Print TCP options - if any */

	print_tcpoptions((uchar_t *)(tcp + 1),
	    tcp->th_off * 4 - sizeof (struct tcphdr));

	show_space();
	}

	/* is there any data? */
	if (tcplen == 0)
		return (tcplen);

	/* go to the next protocol layer */

	if (!interpret_reserved(flags, IPPROTO_TCP,
	    ntohs(tcp->th_sport), ntohs(tcp->th_dport), data, fraglen)) {
		if (sunrpc && fraglen > 0)
			interpret_rpc(flags, data, fraglen, IPPROTO_TCP);
	}

	return (tcplen);
}

static void
print_tcpoptions(uchar_t *opt, int optlen)
{
	int	 len;
	char	 *line;

	if (optlen <= 0) {
		(void) sprintf(get_line((char *)&opt - dlc_header, 1),
		"No options");
		return;
	}

	(void) sprintf(get_line((char *)&opt - dlc_header, 1),
	"Options: (%d bytes)", optlen);

	while (optlen > 0) {
		line = get_line((char *)&opt - dlc_header, 1);
		len = opt[1];
		switch (opt[0]) {
		case TCPOPT_EOL:
			(void) strcpy(line, "  - End of option list");
			return;
		case TCPOPT_NOP:
			(void) strcpy(line, "  - No operation");
			len = 1;
			break;
		case TCPOPT_MAXSEG:
			(void) sprintf(line,
			    "  - Maximum segment size = %d bytes",
			    (opt[2] << 8) + opt[3]);
			break;
		case TCPOPT_WSCALE:
			(void) sprintf(line, "  - Window scale = %d", opt[2]);
			break;
		case TCPOPT_TSTAMP:
			/* Sanity check. */
			if (optlen < TCPOPT_TSTAMP_LEN) {
				(void) sprintf(line,
				    "  - Incomplete TS option");
			} else {
				(void) sprintf(line,
				    "  - TS Val = %u, TS Echo = %u",
				    GET_UINT32(opt + 2),
				    GET_UINT32(opt + 6));
			}
			break;
		case TCPOPT_SACK_PERMITTED:
			(void) sprintf(line, "  - SACK permitted option");
			break;
		case TCPOPT_SACK: {
			uchar_t *sack_opt, *end_opt;
			int sack_len;

			/*
			 * Sanity check.  Total length should be greater
			 * than just the option header length.
			 */
			if (optlen <= TCPOPT_HEADER_LEN ||
			    len < TCPOPT_HEADER_LEN) {
				(void) sprintf(line,
				    "  - Incomplete SACK option");
				break;
			}
			sack_len = len - TCPOPT_HEADER_LEN;
			sack_opt = opt + TCPOPT_HEADER_LEN;
			end_opt = opt + optlen;

			(void) sprintf(line, "  - SACK blocks:");
			line = get_line((char *)&opt - dlc_header, 1);
			(void) sprintf(line, "        ");
			while (sack_len > 0) {
				char sack_blk[MAXLINE + 1];

				/*
				 * sack_len may not tell us the truth about
				 * the real length...  Need to be careful
				 * not to step beyond the option buffer.
				 */
				if (sack_opt + TCPOPT_SACK_LEN > end_opt) {
					(void) strcat(line,
					    "...incomplete SACK block");
					break;
				}
				(void) sprintf(sack_blk, "(%u-%u) ",
				    GET_UINT32(sack_opt),
				    GET_UINT32(sack_opt + 4));
				(void) strcat(line, sack_blk);
				sack_opt += TCPOPT_SACK_LEN;
				sack_len -= TCPOPT_SACK_LEN;
			}
			break;
		}
		case TCPOPT_MD5: {
			uint_t i;

			if (optlen < TCPOPT_MD5_LEN || len != TCPOPT_MD5_LEN) {
				(void) sprintf(line,
				    "  - Incomplete MD5 option");
				break;
			}

			(void) sprintf(line, "  - TCP MD5 Signature = 0x");
			for (i = 2; i < len; i++) {
				char options[3];

				(void) sprintf(options, "%02x", opt[i]);
				(void) strcat(line, options);
			}
			break;
		}
		default:
			(void) sprintf(line,
			    "  - Option %d (unknown - %d bytes) %s",
			    opt[0], len - 2, tohex((char *)&opt[2], len - 2));
			break;
		}
		if (len <= 0) {
			(void) sprintf(line, "  - Incomplete option len %d",
			    len);
			break;
		}
		opt += len;
		optlen -= len;
	}
}

/*
 * This function is basically the same as print_tcpoptions() except that
 * all options are printed on the same line.
 */
static void
print_tcpoptions_summary(uchar_t *opt, int optlen, char *line)
{
	int	 len;
	char	options[MAXLINE + 1];

	if (optlen <= 0) {
		return;
	}

	(void) strcat(line, " Options=<");
	while (optlen > 0) {
		len = opt[1];
		switch (opt[0]) {
		case TCPOPT_EOL:
			(void) strcat(line, "eol>");
			return;
		case TCPOPT_NOP:
			(void) strcat(line, "nop");
			len = 1;
			break;
		case TCPOPT_MAXSEG:
			(void) sprintf(options, "mss %d",
			    (opt[2] << 8) + opt[3]);
			(void) strcat(line, options);
			break;
		case TCPOPT_WSCALE:
			(void) sprintf(options, "wscale %d", opt[2]);
			(void) strcat(line, options);
			break;
		case TCPOPT_TSTAMP:
			/* Sanity check. */
			if (optlen < TCPOPT_TSTAMP_LEN) {
				(void) strcat(line, "tstamp|");
			} else {
				(void) sprintf(options,
				    "tstamp %u %u", GET_UINT32(opt + 2),
				    GET_UINT32(opt + 6));
				(void) strcat(line, options);
			}
			break;
		case TCPOPT_SACK_PERMITTED:
			(void) strcat(line, "sackOK");
			break;
		case TCPOPT_SACK: {
			uchar_t *sack_opt, *end_opt;
			int sack_len;

			/*
			 * Sanity check.  Total length should be greater
			 * than just the option header length.
			 */
			if (optlen <= TCPOPT_HEADER_LEN ||
			    len < TCPOPT_HEADER_LEN) {
				(void) strcat(line, "sack|");
				break;
			}
			sack_len = len - TCPOPT_HEADER_LEN;
			sack_opt = opt + TCPOPT_HEADER_LEN;
			end_opt = opt + optlen;

			(void) strcat(line, "sack");
			while (sack_len > 0) {
				/*
				 * sack_len may not tell us the truth about
				 * the real length...  Need to be careful
				 * not to step beyond the option buffer.
				 */
				if (sack_opt + TCPOPT_SACK_LEN > end_opt) {
					(void) strcat(line, "|");
					break;
				}
				(void) sprintf(options, " %u-%u",
				    GET_UINT32(sack_opt),
				    GET_UINT32(sack_opt + 4));
				(void) strcat(line, options);
				sack_opt += TCPOPT_SACK_LEN;
				sack_len -= TCPOPT_SACK_LEN;
			}
			break;
		}
		case TCPOPT_MD5: {
			uint_t i;

			if (optlen < TCPOPT_MD5_LEN || len != TCPOPT_MD5_LEN) {
				(void) strcat(line, "md5|");
				break;
			}

			(void) strcat(line, "md5 0x");
			for (i = 2; i < len; i++) {
				(void) sprintf(options, "%02x", opt[i]);
				(void) strcat(line, options);
			}
			break;
		}
		default:
			(void) sprintf(options, "unknown %d", opt[0]);
			(void) strcat(line, options);
			break;
		}
		if (len <= 0) {
			(void) sprintf(options, "optlen %d", len);
			(void) strcat(line, options);
			break;
		}
		opt += len;
		optlen -= len;
		if (optlen > 0) {
			(void) strcat(line, ",");
		}
	}
	(void) strcat(line, ">");
}
