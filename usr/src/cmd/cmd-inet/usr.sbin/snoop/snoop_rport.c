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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2018, Joyent, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
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

struct porttable {
	int	pt_num;
	char	*pt_short;
};

static const struct porttable pt_udp[] = {
	{ IPPORT_ECHO,		"ECHO" },
	{ IPPORT_DISCARD,	"DISCARD" },
	{ IPPORT_DAYTIME,	"DAYTIME" },
	{ IPPORT_CHARGEN,	"CHARGEN" },
	{ IPPORT_TIMESERVER,	"TIME" },
	{ IPPORT_NAMESERVER,	"NAME" },
	{ IPPORT_DOMAIN,	"DNS" },
	{ IPPORT_MDNS,		"MDNS" },
	{ IPPORT_BOOTPS,	"BOOTPS" },
	{ IPPORT_BOOTPC,	"BOOTPC" },
	{ IPPORT_TFTP,		"TFTP" },
	{ IPPORT_FINGER,	"FINGER" },
/*	{ 111,			"PORTMAP" }, Just Sun RPC */
	{ IPPORT_NTP,		"NTP" },
	{ IPPORT_NETBIOS_NS,	"NBNS" },
	{ IPPORT_NETBIOS_DGM,	"NBDG" },
	{ IPPORT_LDAP,		"LDAP" },
	{ IPPORT_SLP,		"SLP" },
/* Mobile IP defines a set of new control messages sent over UDP port 434 */
	{ IPPORT_MIP,		"Mobile IP" },
	{ IPPORT_BIFFUDP,	"BIFF" },
	{ IPPORT_WHOSERVER,	"WHO" },
	{ IPPORT_SYSLOG,	"SYSLOG" },
	{ IPPORT_TALK,		"TALK" },
	{ IPPORT_ROUTESERVER,	"RIP" },
	{ IPPORT_RIPNG,		"RIPng" },
	{ IPPORT_DHCPV6C,	"DHCPv6C" },
	{ IPPORT_DHCPV6S,	"DHCPv6S" },
	{ 550,			"NEW-RWHO" },
	{ 560,			"RMONITOR" },
	{ 561,			"MONITOR" },
	{ IPPORT_SOCKS,		"SOCKS" },
	{ IPPORT_VXLAN,		"VXLAN" },
	{ 0,			NULL }
};

static struct porttable pt_tcp[] = {
	{ 1,			"TCPMUX" },
	{ IPPORT_ECHO,		"ECHO" },
	{ IPPORT_DISCARD,	"DISCARD" },
	{ IPPORT_SYSTAT,	"SYSTAT" },
	{ IPPORT_DAYTIME,	"DAYTIME" },
	{ IPPORT_NETSTAT,	"NETSTAT" },
	{ IPPORT_CHARGEN,	"CHARGEN" },
	{ 20,			"FTP-DATA" },
	{ IPPORT_FTP,		"FTP" },
	{ IPPORT_TELNET,	"TELNET" },
	{ IPPORT_SMTP,		"SMTP" },
	{ IPPORT_TIMESERVER,	"TIME" },
	{ 39,			"RLP" },
	{ IPPORT_NAMESERVER,	"NAMESERVER" },
	{ IPPORT_WHOIS,		"NICNAME" },
	{ IPPORT_DOMAIN,	"DNS" },
	{ 70,			"GOPHER" },
	{ IPPORT_RJE,		"RJE" },
	{ IPPORT_FINGER,	"FINGER" },
	{ IPPORT_HTTP,		"HTTP" },
	{ IPPORT_TTYLINK,	"LINK" },
	{ IPPORT_SUPDUP,	"SUPDUP" },
	{ 101,			"HOSTNAME" },
	{ 102,			"ISO-TSAP" },
	{ 103,			"X400" },
	{ 104,			"X400-SND" },
	{ 105,			"CSNET-NS" },
	{ 109,			"POP-2" },
/*	{ 111,			"PORTMAP" }, Just Sun RPC */
	{ 113,			"AUTH" },
	{ 117,			"UUCP-PATH" },
	{ 119,			"NNTP" },
	{ IPPORT_NTP,		"NTP" },
	{ IPPORT_NETBIOS_SSN,	"NBT" },
	{ 143,			"IMAP" },
	{ 144,			"NeWS" },
	{ IPPORT_LDAP,		"LDAP" },
	{ IPPORT_SLP,		"SLP" },
	{ 443,			"HTTPS" },
	{ 445,			"SMB" },
	{ IPPORT_EXECSERVER,	"EXEC" },
	{ IPPORT_LOGINSERVER,	"RLOGIN" },
	{ IPPORT_CMDSERVER,	"RSHELL" },
	{ IPPORT_PRINTER,	"PRINTER" },
	{ 530,			"COURIER" },
	{ 540,			"UUCP" },
	{ 600,			"PCSERVER" },
	{ IPPORT_SOCKS,		"SOCKS" },
	{ 1296,			"SVP" },
	{ 1524,			"INGRESLOCK" },
	{ 2904,			"M2UA" },
	{ 2905,			"M3UA" },
	{ 6000,			"XWIN" },
	{ IPPORT_HTTP_ALT,	"HTTP (proxy)" },
	{ 9900,			"IUA" },
	{ 0,			NULL },
};

char *
getportname(int proto, in_port_t port)
{
	const struct porttable *p, *pt;

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
	const struct porttable *p, *pt;

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
static struct ttable transients [MAXTRANS];

int
add_transient(int port, int (*proc)(int, void *, int))
{
	static struct ttable *next = transients;

	next->t_port = port;
	next->t_proc = proc;

	if (++next >= &transients[MAXTRANS])
		next = transients;

	return (1);
}

struct ttable *
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

			(void) strlcpy(buffer, data, sizeof (buffer));
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
		(void) snprintf(get_detail_line(0, 0), MAXLINE,
		    "%s%sPriority: %.*s%s(%s.%s)", prot_nest_prefix, syslog,
		    priostrlen, syslogstr, bogus ? "" : " ",
		    facilstr, pristr);
		(void) snprintf(get_line(0, 0), get_line_remain(),
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
	const char *pn;
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

	if ((dst == IPPORT_DOMAIN || src == IPPORT_DOMAIN ||
	    dst == IPPORT_MDNS || src == IPPORT_MDNS) &&
	    proto != IPPROTO_TCP) {
		interpret_dns(flags, proto, (uchar_t *)data, dlen, which);
		return (1);
	}

	if (dst == IPPORT_SYSLOG && proto != IPPROTO_TCP) {
		/*
		 * TCP port 514 is rshell.  UDP port 514 is syslog.
		 */
		interpret_syslog(flags, dir, port, (const char *)data, dlen);
		return (1);
	}

	if (dlen > 0) {
		switch (which) {
		case  IPPORT_BOOTPS:
		case  IPPORT_BOOTPC:
			(void) interpret_dhcp(flags, (struct dhcp *)data,
			    dlen);
			return (1);
		case IPPORT_DHCPV6S:
		case IPPORT_DHCPV6C:
			(void) interpret_dhcpv6(flags, (uint8_t *)data, dlen);
			return (1);
		case  IPPORT_TFTP:
			(void) interpret_tftp(flags, (struct tftphdr *)data,
			    dlen);
			return (1);
		case  IPPORT_HTTP:
		case  IPPORT_HTTP_ALT:
			(void) interpret_http(flags, data, dlen);
			return (1);
		case IPPORT_NTP:
			(void) interpret_ntp(flags, (struct ntpdata *)data,
			    dlen);
			return (1);
		case IPPORT_NETBIOS_NS:
			interpret_netbios_ns(flags, (uchar_t *)data, dlen);
			return (1);
		case IPPORT_NETBIOS_DGM:
			interpret_netbios_datagram(flags, (uchar_t *)data,
			    dlen);
			return (1);
		case IPPORT_NETBIOS_SSN:
		case 445:
			/*
			 * SMB on port 445 is a subset of NetBIOS SMB
			 * on port 139.  The same interpreter can be used
			 * for both.
			 */
			interpret_netbios_ses(flags, (uchar_t *)data, dlen);
			return (1);
		case IPPORT_LDAP:
			interpret_ldap(flags, data, dlen, src, dst);
			return (1);
		case IPPORT_SLP:
			interpret_slp(flags, data, dlen);
			return (1);
		case IPPORT_MIP:
			interpret_mip_cntrlmsg(flags, (uchar_t *)data, dlen);
			return (1);
		case IPPORT_ROUTESERVER:
			(void) interpret_rip(flags, (struct rip *)data, dlen);
			return (1);
		case IPPORT_RIPNG:
			(void) interpret_rip6(flags, (struct rip6 *)data,
			    dlen);
			return (1);
		case IPPORT_SOCKS:
			if (dir == 'C')
				(void) interpret_socks_call(flags, data, dlen);
			else
				(void) interpret_socks_reply(flags, data,
				    dlen);
			return (1);
		case IPPORT_VXLAN:
			(void) interpret_vxlan(flags, data, dlen);
			return (1);
		case 1296:
			if (proto == IPPROTO_TCP) {
				(void) interpret_svp(flags, data, dlen);
				return (1);
			}
			break;
		}
	}

	if (flags & F_SUM) {
		(void) snprintf(get_sum_line(), MAXLINE,
		    "%s %c port=%d %s",
		    pn, dir, port,
		    show_string(data, dlen, 20));
	}

	if (flags & F_DTAIL) {
		(void) snprintf(pbuff, sizeof (pbuff), "%s:  ", pn);
		(void) snprintf(hbuff, sizeof (hbuff), "%s:  ", pn);
		show_header(pbuff, hbuff, dlen);
		show_space();
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "\"%s\"",
		    show_string(data, dlen, 60));
		show_trailer();
	}
	return (1);
}
