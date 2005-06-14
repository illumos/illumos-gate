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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS */

#include <ctype.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include "snoop.h"

#define	NULL 0

extern void interpret_mip_cntrlmsg(int, uchar_t *, int);

struct porttable {
	int	pt_num;
	char	*pt_short;
	char	*pt_long;
};

struct porttable pt_udp[] = {
	7,	"ECHO",		"Echo",
	9,	"DISCARD",	"Discard",
	13,	"DAYTIME",	"Daytime",
	19,	"CHARGEN",	"Character generator",
	37,	"TIME",		"Time",
	42,	"NAME",		"Host name server",
	53,	"DNS",		"Domain Name Server",
	67,	"BOOTPS",	"Bootstrap Protocol Server",
	68,	"BOOTPC",	"Boostrap Protocol Client",
	69,	"TFTP",		"Trivial File Transfer Protocol",
	79,	"FINGER",	"Finger",
/*	111,	"PORTMAP",	"Portmapper", Just Sun RPC */
	123,	"NTP",		"Network Time Protocol",
	137,	"NBNS",		"Netbios name service",
	138,	"NBDG",		"Netbios datagram service",
	389,	"LDAP",		"Lightweight Directory Access Protocol",
	427,	"SLP",		"Service Location Protocol",
/* Mobile IP defines a set of new control messages sent over UDP port 434 */
	434,	"Mobile IP",	"Mobile IP Control Messages",
	512,	"BIFF",		"BIFF",
	513,	"WHO",		"WHO",
	514,	"SYSLOG",	"SYSLOG",
	517,	"TALK",		"TALK",
	520,	"RIP",		"Routing Information Protocol",
	550,	"NEW-RWHO",	"NEW-RWHO",
	560,	"RMONITOR",	"RMONITOR",
	561,	"MONITOR",	"MONITOR",
	521,	"RIPng",	"Routing Information Protocol for IPv6",
	1080,	"SOCKS",	"SOCKS Gateway",
	0,	NULL,		"",
};

struct porttable pt_tcp[] = {
	1,	"TCPMUX",	"TCPMUX",
	7,	"ECHO",		"Echo",
	9,	"DISCARD",	"Discard",
	11,	"SYSTAT",	"Active users",
	13,	"DAYTIME",	"Daytime",
	15,	"NETSTAT",	"Who is up",
	19,	"CHARGEN",	"Character generator",
	20,	"FTP-DATA",	"File Transfer Protocol (data)",
	21,	"FTP",		"File Transfer Protocol",
	23,	"TELNET",	"Terminal connection",
	25,	"SMTP",		"Simple Mail Transport Protocol",
	37,	"TIME",		"Time",
	39,	"RLP",		"Resource Location Protocol",
	42,	"NAMESERVER",	"Host Name Server",
	43,	"NICNAME",	"Who is",
	53,	"DNS",		"Domain Name Server",
	67,	"BOOTPS",	"Bootstrap Protocol Server",
	68,	"BOOTPC",	"Bootstrap Protocol Client",
	69,	"TFTP",		"Trivial File Transfer Protocol",
	70,	"GOPHER",	"Internet Gopher Protocol",
	77,	"RJE",		"RJE service (private)",
	79,	"FINGER",	"Finger",
	80,	"HTTP",		"HyperText Transfer Protocol",
	87,	"LINK",		"Link",
	95,	"SUPDUP",	"SUPDUP Protocol",
	101,	"HOSTNAME",	"NIC Host Name Server",
	102,	"ISO-TSAP",	"ISO-TSAP",
	103,	"X400",		"X400 Mail service",
	104,	"X400-SND",	"X400 Mail service",
	105,	"CSNET-NS",	"CSNET-NS",
	109,	"POP-2",	"POP-2",
/*	111,	"PORTMAP",	"Portmapper", Just Sun RPC */
	113,	"AUTH",		"Authentication Service",
	117,	"UUCP-PATH",	"UUCP Path Service",
	119,	"NNTP",		"Network News Transfer Protocol",
	123,	"NTP",		"Network Time Protocol",
	139,	"NBT",		"Netbios over TCP",
	143,	"IMAP",		"Internet Message Access Protocol",
	144,	"NeWS",		"Network extensible Window System",
	389,	"LDAP",		"Lightweight Directory Access Protocol",
	427,	"SLP",		"Service Location Protocol",
	443,	"HTTPS",	"HTTP over SSL",
	445,    "SMB",          "Direct Hosted Server Message Block",
	512,	"EXEC",		"EXEC",
	513,	"RLOGIN",	"RLOGIN",
	514,	"RSHELL",	"RSHELL",
	515,	"PRINTER",	"PRINTER",
	530,	"COURIER",	"COURIER",
	540,	"UUCP",		"UUCP",
	600,	"PCSERVER",	"PCSERVER",
	1524,	"INGRESLOCK",	"INGRESLOCK",
	1080,	"SOCKS",	"SOCKS Gateway",
	2904,	"M2UA",		"SS7 MTP2 User Adaption Layer",
	2905,	"M3UA",		"SS7 MTP3 User Adaption Layer",
	6000,	"XWIN",		"X Window System",
	8080,	"HTTP (proxy)",	"HyperText Transfer Protocol (proxy)",
	9900,	"IUA",		"ISDN Q.921 User Adaption Layer",
	0,	NULL,		"",
};

char *
getportname(int proto, in_port_t port)
{
	struct porttable *p, *pt;

	switch (proto) {
	case IPPROTO_SCTP: /* fallthru */
	case IPPROTO_TCP: pt = pt_tcp; break;
	case IPPROTO_UDP: pt = pt_udp; break;
	default: return (NULL);
	}

	for (p = pt; p->pt_num; p++) {
		if (port == p->pt_num)
			return (p->pt_short);
	}
	return (NULL);
}

int
reservedport(int proto, int port)
{
	struct porttable *p, *pt;

	switch (proto) {
	case IPPROTO_TCP: pt = pt_tcp; break;
	case IPPROTO_UDP: pt = pt_udp; break;
	default: return (NULL);
	}
	for (p = pt; p->pt_num; p++) {
		if (port == p->pt_num)
			return (1);
	}
	return (0);
}

/*
 * Need to be able to register an
 * interpreter for transient ports.
 * See TFTP interpreter.
 */
#define	MAXTRANS 64
struct ttable {
	int t_port;
	int (*t_proc)();
} transients [MAXTRANS];

int
add_transient(int port, int (*proc)())
{
	static struct ttable *next = transients;

	next->t_port = port;
	next->t_proc = proc;

	if (++next >= &transients[MAXTRANS])
		next = transients;

	return (1);
}

static struct ttable *
is_transient(int port)
{
	struct ttable *p;

	for (p = transients; p->t_port && p < &transients[MAXTRANS]; p++) {
		if (port == p->t_port)
			return (p);
	}

	return (NULL);
}

void
del_transient(int port)
{
	struct ttable *p;

	for (p = transients; p->t_port && p < &transients[MAXTRANS]; p++) {
		if (port == p->t_port)
			p->t_port = -1;
	}
}

static void
interpret_syslog(int flags, char dir, int port, const char *syslogstr,
    int dlen)
{
	static const char *pris[] = {
	    "emerg", "alert", "crit", "error", "warn", "notice", "info", "debug"
	};
	static const char *facs[] = {
	    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
	    "uucp", NULL, NULL, NULL, NULL, "audit", NULL, "cron", "local0",
	    "local1", "local2", "local3", "local4", "local5", "local6", "local7"
	};

	int composit;
	int pri = -1;
	int facil = -1;
	boolean_t bogus = B_TRUE;
	int priostrlen = 0;
	int datalen = dlen;
	char unknown[4];	/* for unrecognized ones */
	const char *facilstr = "BAD";
	const char *pristr = "FMT";
	const char *data = syslogstr;

	/*
	 * Is there enough data to interpret (left bracket + at least 3 chars
	 * which could be digits, right bracket, or space)?
	 */
	if (datalen >= 4 && data != NULL) {
		if (*data == '<') {
			const int FACS_LEN = sizeof (facs) / sizeof (facs[0]);
			char buffer[4];
			char *end;

			data++;
			datalen--;

			strlcpy(buffer, data, sizeof (buffer));
			composit = strtoul(buffer, &end, 0);
			data += end - buffer;
			if (*data == '>') {
				data++;
				datalen -= end - buffer + 1;

				pri = composit & 0x7;
				facil = (composit & 0xF8) >> 3;

				if ((facil >= FACS_LEN) ||
				    (facs[facil] == NULL)) {
					snprintf(unknown, sizeof (unknown),
					    "%d", facil);
					facilstr = unknown;
				} else {
					facilstr = facs[facil];
				}
				pristr = pris[pri];
				priostrlen = dlen - datalen;
				bogus = B_FALSE;
			} else {
				data = syslogstr;
				datalen = dlen;
			}
		}
	}

	if (flags & F_SUM) {
		(void) snprintf(get_sum_line(), MAXLINE,
		    "SYSLOG %c port=%d %s.%s: %s",
		    dir, port, facilstr, pristr,
		    show_string(syslogstr, dlen, 20));

	}

	if (flags & F_DTAIL) {
		static char syslog[] = "SYSLOG:  ";
		show_header(syslog, syslog, dlen);
		show_space();
		(void) sprintf(get_detail_line(0, 80),
		    "%s%sPriority: %.*s%s(%s.%s)", prot_nest_prefix, syslog,
		    priostrlen, syslogstr, bogus ? "" : " ",
		    facilstr, pristr);
		(void) sprintf(get_line(0, 0),
			"\"%s\"",
			show_string(syslogstr, dlen, 60));
		show_trailer();
	}
}

int src_port, dst_port, curr_proto;

int
interpret_reserved(int flags, int proto, in_port_t src, in_port_t dst,
    char *data, int dlen)
{
	char *pn;
	int dir, port, which;
	char pbuff[16], hbuff[32];
	struct ttable *ttabp;

	src_port = src;
	dst_port = dst;
	curr_proto = proto;

	pn = getportname(proto, src);
	if (pn != NULL) {
		dir = 'R';
		port = dst;
		which = src;
	} else {
		pn = getportname(proto, dst);
		if (pn == NULL) {
			ttabp = is_transient(src);
			if (ttabp) {
				(ttabp->t_proc)(flags, data, dlen);
				return (1);
			}
			ttabp = is_transient(dst);
			if (ttabp) {
				(ttabp->t_proc)(flags, data, dlen);
				return (1);
			}
			return (0);
		}

		dir = 'C';
		port = src;
		which = dst;
	}

	if ((dst == 53 || src == 53) && proto != IPPROTO_TCP) {
		interpret_dns(flags, proto, (uchar_t *)data, dlen);
		return (1);
	}

	if (dst == 514 && proto != IPPROTO_TCP) {
		/*
		 * TCP port 514 is rshell.  UDP port 514 is syslog.
		 */
		interpret_syslog(flags, dir, port, (const char *)data, dlen);
		return (1);
	}

	if (dlen > 0) {
		switch (which) {
		case  67:
		case  68:
			interpret_dhcp(flags, data, dlen);
			return (1);
		case  69:
			interpret_tftp(flags, data, dlen);
			return (1);
		case  80:
		case  8080:
			interpret_http(flags, data, dlen);
			return (1);
		case 123:
			interpret_ntp(flags, data, dlen);
			return (1);
		case 137:
			interpret_netbios_ns(flags, data, dlen);
			return (1);
		case 138:
			interpret_netbios_datagram(flags, data, dlen);
			return (1);
		case 139:
		case 445:
			/*
			 * SMB on port 445 is a subset of NetBIOS SMB
			 * on port 139.  The same interpreter can be used
			 * for both.
			 */
			interpret_netbios_ses(flags, data, dlen);
			return (1);
		case 389:
			interpret_ldap(flags, data, dlen, src, dst);
			return (1);
		case 427:
			interpret_slp(flags, data, dlen);
			return (1);
		case 434:
			interpret_mip_cntrlmsg(flags, (uchar_t *)data, dlen);
			return (1);
		case 520:
			interpret_rip(flags, data, dlen);
			return (1);
		case 521:
			interpret_rip6(flags, data, dlen);
			return (1);
		case 1080:
			if (dir == 'C')
				interpret_socks_call(flags, data, dlen);
			else
				interpret_socks_reply(flags, data, dlen);
			return (1);
		}
	}

	if (flags & F_SUM) {
		(void) sprintf(get_sum_line(),
			"%s %c port=%d %s",
			pn, dir, port,
			show_string(data, dlen, 20));
	}

	if (flags & F_DTAIL) {
		(void) sprintf(pbuff, "%s:  ", pn);
		(void) sprintf(hbuff, "%s:  ", pn);
		show_header(pbuff, hbuff, dlen);
		show_space();
		(void) sprintf(get_line(0, 0),
			"\"%s\"",
			show_string(data, dlen, 60));
		show_trailer();
	}
	return (1);
}

char *
show_string(const char *str, int dlen, int maxlen)
/*
 *   Prints len bytes from str enclosed in quotes.
 *   If len is negative, length is taken from strlen(str).
 *   No more than maxlen bytes will be printed.  Longer
 *   strings are flagged with ".." after the closing quote.
 *   Non-printing characters are converted to C-style escape
 *   codes or octal digits.
 */
{
#define	TBSIZE	256
	static char tbuff[TBSIZE];
	const char *p;
	char *pp;
	int printable = 0;
	int c, len;

	len = dlen > maxlen ? maxlen : dlen;
	dlen = len;

	for (p = str, pp = tbuff; len; p++, len--) {
		switch (c = *p & 0xFF) {
		case '\n': (void) strcpy(pp, "\\n"); pp += 2; break;
		case '\b': (void) strcpy(pp, "\\b"); pp += 2; break;
		case '\t': (void) strcpy(pp, "\\t"); pp += 2; break;
		case '\r': (void) strcpy(pp, "\\r"); pp += 2; break;
		case '\f': (void) strcpy(pp, "\\f"); pp += 2; break;
		default:
			if (isascii(c) && isprint(c)) {
				*pp++ = c;
				printable++;
			} else {
				(void) sprintf(pp,
					isdigit(*(p + 1)) ?
					"\\%03o" : "\\%o", c);
				pp += strlen(pp);
			}
			break;
		}
		*pp = '\0';
		/*
		 * Check for overflow of temporary buffer.  Allow for
		 * the next character to be a \nnn followed by a trailing
		 * null.  If not, then just bail with what we have.
		 */
		if (pp + 5 >= &tbuff[TBSIZE]) {
			break;
		}
	}
	return (printable > dlen / 2 ? tbuff : "");
}
