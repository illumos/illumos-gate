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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <netinet/in.h>
#include <netinet/dhcp.h>
#include <arpa/inet.h>
#include <dhcp_inittab.h>
#include <dhcp_symbol.h>
#include "snoop.h"

static const char *show_msgtype(unsigned char);
static int show_options(unsigned char *, int);
static void display_ip(int, char *, char *, unsigned char **);
static void display_ascii(char *, char *, unsigned char **);
static void display_number(char *, char *, unsigned char **);
static void display_ascii_hex(char *, unsigned char **);
static unsigned char bootmagic[] = BOOTMAGIC;	/* rfc 1048 */

static char *option_types[] = {
"",					/* 0 */
"Subnet Mask",				/* 1 */
"UTC Time Offset",			/* 2 */
"Router",				/* 3 */
"RFC868 Time Servers",			/* 4 */
"IEN 116 Name Servers",			/* 5 */
"DNS Servers",				/* 6 */
"UDP LOG Servers",			/* 7 */
"RFC 865 Cookie Servers",		/* 8 */
"RFC 1179 Line Printer Servers (LPR)",	/* 9 */
"Impress Servers",			/* 10 */
"RFC 887 Resource Location Servers",	/* 11 */
"Client Hostname",			/* 12 */
"Boot File size in 512 byte Blocks",	/* 13 */
"Merit Dump File",			/* 14 */
"DNS Domain Name",			/* 15 */
"SWAP Server",				/* 16 */
"Client Root Path",			/* 17 */
"BOOTP options extensions path",	/* 18 */
"IP Forwarding Flag",			/* 19 */
"NonLocal Source Routing Flag",		/* 20 */
"Policy Filters for NonLocal Routing",	/* 21 */
"Maximum Datagram Reassembly Size",	/* 22 */
"Default IP Time To Live",		/* 23 */
"Path MTU Aging Timeout",		/* 24 */
"Path MTU Size Plateau Table",		/* 25 */
"Interface MTU Size",			/* 26 */
"All Subnets are Local Flag",		/* 27 */
"Broadcast Address",			/* 28 */
"Perform Mask Discovery Flag",		/* 29 */
"Mask Supplier Flag",			/* 30 */
"Perform Router Discovery Flag",	/* 31 */
"Router Solicitation Address",		/* 32 */
"Static Routes",			/* 33 */
"Trailer Encapsulation Flag",		/* 34 */
"ARP Cache Timeout Seconds",		/* 35 */
"Ethernet Encapsulation Flag",		/* 36 */
"TCP Default Time To Live",		/* 37 */
"TCP Keepalive Interval Seconds",	/* 38 */
"TCP Keepalive Garbage Flag",		/* 39 */
"NIS Domainname",			/* 40 */
"NIS Servers",				/* 41 */
"Network Time Protocol Servers",	/* 42 */
"Vendor Specific Options",		/* 43 */
"NetBIOS RFC 1001/1002 Name Servers",	/* 44 */
"NetBIOS Datagram Dist. Servers",	/* 45 */
"NetBIOS Node Type",			/* 46 */
"NetBIOS Scope",			/* 47 */
"X Window Font Servers",		/* 48 */
"X Window Display Manager Servers",	/* 49 */
"Requested IP Address",			/* 50 */
"IP Address Lease Time",		/* 51 */
"Option Field Overload Flag",		/* 52 */
"DHCP Message Type",			/* 53 */
"DHCP Server Identifier",		/* 54 */
"Option Request List",			/* 55 */
"Error Message",			/* 56 */
"Maximum DHCP Message Size",		/* 57 */
"Renewal (T1) Time Value",		/* 58 */
"Rebinding (T2) Time Value",		/* 59 */
"Client Class Identifier =",		/* 60 */
"Client Identifier =",			/* 61 */
"Netware IP Domain =",			/* 62 */
"Netware IP Options =",			/* 63 */
"NIS+ v3 Client Domain Name =",		/* 64 */
"NIS+ v3 Server Addresses =",		/* 65 */
"TFTP Server Name",			/* 66 */
"Option BootFile Name",			/* 67 */
"Mobile IP Agents",			/* 68 */
"Simple Mail (SMTP) Servers",		/* 69 */
"Post Office (POP3) Servers",		/* 70 */
"Net News (NNTP) Servers",		/* 71 */
"WorldWideWeb Servers",			/* 72 */
"Finger Servers",			/* 73 */
"Internet Relay Chat (IRC) Servers",	/* 74 */
"StreetTalk Servers",			/* 75 */
"StreetTalk Directory Assist. Servers",	/* 76 */
"User Class Identifier",		/* 77 */
};

#define	OPTIONS_ARRAY_SIZE	78

int
interpret_dhcp(int flags, struct dhcp *dp, int len)
{
	if (flags & F_SUM) {
		if ((memcmp(dp->cookie, bootmagic, sizeof (bootmagic)) == 0) &&
		    (len >= BASE_PKT_SIZE + 3) &&
		    dp->options[0] == CD_DHCP_TYPE) {
			(void) sprintf(get_sum_line(),
			    "DHCP/BOOTP %s", show_msgtype(dp->options[2]));
		} else {
			switch (ntohs(dp->op)) {
			case BOOTREQUEST:
				(void) sprintf(get_sum_line(),
				    "DHCP/BOOTP BOOTREQUEST");
				break;
			case BOOTREPLY:
				(void) sprintf(get_sum_line(),
				    "DHCP/BOOTP BOOTREPLY");
				break;
			}
		}
	}
	if (flags & F_DTAIL) {
		show_header("DHCP: ", "Dynamic Host Configuration Protocol",
		    len);
		show_space();
		(void) sprintf(get_line((char *)(uintptr_t)dp->htype -
		    dlc_header, 1),
		    "Hardware address type (htype) =  %d (%s)", dp->htype,
		    arp_htype(dp->htype));
		(void) sprintf(get_line((char *)(uintptr_t)dp->hlen -
		    dlc_header, 1),
		    "Hardware address length (hlen) = %d octets", dp->hlen);
		(void) sprintf(get_line((char *)(uintptr_t)dp->hops -
		    dlc_header, 1),
		    "Relay agent hops = %d", dp->hops);
		(void) sprintf(get_line((char *)(uintptr_t)dp->xid -
		    dlc_header, 4),
		    "Transaction ID = 0x%x", ntohl(dp->xid));
		(void) sprintf(get_line((char *)(uintptr_t)dp->secs -
		    dlc_header, 2),
		    "Time since boot = %d seconds", ntohs(dp->secs));
		(void) sprintf(get_line((char *)(uintptr_t)dp->flags -
		    dlc_header, 2),
		    "Flags = 0x%.4x", ntohs(dp->flags));
		(void) sprintf(get_line((char *)&dp->ciaddr - dlc_header, 4),
		    "Client address (ciaddr) = %s", inet_ntoa(dp->ciaddr));
		(void) sprintf(get_line((char *)&dp->yiaddr - dlc_header, 4),
		    "Your client address (yiaddr) = %s",
		    inet_ntoa(dp->yiaddr));
		(void) sprintf(get_line((char *)&dp->siaddr - dlc_header, 4),
		    "Next server address (siaddr) = %s",
		    inet_ntoa(dp->siaddr));
		(void) sprintf(get_line((char *)&dp->giaddr - dlc_header, 4),
		    "Relay agent address (giaddr) = %s",
		    inet_ntoa(dp->giaddr));
		if (dp->htype == 1) {
			(void) sprintf(get_line((char *)dp->chaddr -
			    dlc_header, dp->hlen),
	"Client hardware address (chaddr) = %.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
			    dp->chaddr[0],
			    dp->chaddr[1],
			    dp->chaddr[2],
			    dp->chaddr[3],
			    dp->chaddr[4],
			    dp->chaddr[5]);
		}
		/*
		 * Check cookie, process options
		 */
		if (memcmp(dp->cookie, bootmagic, sizeof (bootmagic)) != 0) {
			(void) sprintf(get_line(0, 0),
			    "Unrecognized cookie: 0x%.2X%.2X%.2X%.2X\n",
			    dp->cookie[0],
			    dp->cookie[1],
			    dp->cookie[2],
			    dp->cookie[3]);
			return (0);
		}
		show_space();
		show_header("DHCP: ", "(Options) field options", len);
		show_space();
		switch (show_options(dp->options, (len - BASE_PKT_SIZE))) {
		case 0:
			/* No option overloading */
			if (*(unsigned char *)(dp->sname) != '\0') {
				(void) sprintf(get_line(0, 0),
				    "Server Name = %s", dp->sname);
			}
			if (*(unsigned char *)(dp->file) != '\0') {
				(void) sprintf(get_line(0, 0),
				    "Boot File Name = %s", dp->file);
			}
			break;
		case 1:
			/* file field used */
			if (*(unsigned char *)(dp->sname) != '\0') {
				(void) sprintf(get_line(0, 0),
				    "Server Name = %s", dp->sname);
			}
			show_space();
			show_header("DHCP: ", "(File) field options", len);
			show_space();
			(void) show_options(dp->file, 128);
			break;
		case 2:
			/* sname field used for options */
			if (*(unsigned char *)(dp->file) != '\0') {
				(void) sprintf(get_line(0, 0),
				    "Boot File Name = %s", dp->file);
			}
			show_space();
			show_header("DHCP: ", "(Sname) field options", len);
			show_space();
			(void) show_options(dp->sname, 64);
			break;
		case 3:
			show_space();
			show_header("DHCP: ", "(File) field options", len);
			show_space();
			(void) show_options(dp->file, 128);
			show_space();
			show_header("DHCP: ", "(Sname) field options", len);
			show_space();
			(void) show_options(dp->sname, 64);
			break;
		};
	}
	return (len);
}

static int
show_options(unsigned char  *cp, int len)
{
	char *prmpt;
	unsigned char *end, *vend;
	unsigned char *start, save;
	int items, i;
	int nooverload = 0;
	ushort_t	s_buf;
	struct in_addr	tmp;
	char scratch[128];
	dhcp_symbol_t *entry;
	char *decoded_opt;
	int opt_len;

	start = cp;
	end = (unsigned char *)cp + len;

	while (start < end) {
		if (*start == CD_PAD) {
			start++;
			continue;
		}
		if (*start == CD_END)
			break;	/* done */

		save = *start++;
		switch (save) {
		/* Network order IP address(es) */
		case CD_SUBNETMASK:
		case CD_ROUTER_SOLICIT_SERV:
		case CD_BROADCASTADDR:
		case CD_REQUESTED_IP_ADDR:
		case CD_SERVER_ID:
			/* Single IP address */
			if (*start != 4) {
				(void) sprintf(get_line(0, 0),
				    "Error: Bad %s", option_types[save]);
			} else {
				start++;
				display_ip(1, "%s = %s", option_types[save],
				    &start);
			}
			break;
		case CD_ROUTER:
		case CD_TIMESERV:
		case CD_IEN116_NAME_SERV:
		case CD_DNSSERV:
		case CD_LOG_SERV:
		case CD_COOKIE_SERV:
		case CD_LPR_SERV:
		case CD_IMPRESS_SERV:
		case CD_RESOURCE_SERV:
		case CD_SWAP_SERV:
		case CD_NIS_SERV:
		case CD_NTP_SERV:
		case CD_NETBIOS_NAME_SERV:
		case CD_NETBIOS_DIST_SERV:
		case CD_XWIN_FONT_SERV:
		case CD_XWIN_DISP_SERV:
		case CD_MOBILE_IP_AGENT:
		case CD_SMTP_SERVS:
		case CD_POP3_SERVS:
		case CD_NNTP_SERVS:
		case CD_WWW_SERVS:
		case CD_FINGER_SERVS:
		case CD_IRC_SERVS:
		case CD_STREETTALK_SERVS:
		case CD_STREETTALK_DA_SERVS:
			/* Multiple IP addresses */
			if ((*start % 4) != 0) {
				(void) sprintf(get_line(0, 0),
				    "Error: Bad %s address",
				    option_types[save]);
			} else {
				items = *start++ / 4;
				display_ip(items, "%s at = %s",
				    option_types[save], &start);
			}
			break;
		case CD_TFTP_SERV_NAME:
		case CD_HOSTNAME:
		case CD_DUMP_FILE:
		case CD_DNSDOMAIN:
		case CD_ROOT_PATH:
		case CD_NIS_DOMAIN:
		case CD_NETBIOS_SCOPE:
		case CD_MESSAGE:
		case CD_OPT_BOOTFILE_NAME:
		case CD_USER_CLASS_ID:
			/* Ascii strings */
			display_ascii("%s = %s", option_types[save], &start);
			break;
		case CD_TIMEOFFSET:
		case CD_IPTTL:
		case CD_PATH_MTU_TIMEOUT:
		case CD_ARP_TIMEOUT:
		case CD_TCP_TTL:
		case CD_TCP_KALIVE_INTVL:
		case CD_T1_TIME:
		case CD_T2_TIME:
		case CD_LEASE_TIME:
			/* Number: seconds */
			display_number("%s = %d seconds", option_types[save],
			    &start);
			break;
		case CD_IP_FORWARDING_ON:
		case CD_NON_LCL_ROUTE_ON:
		case CD_ALL_SUBNETS_LCL_ON:
		case CD_MASK_DISCVRY_ON:
		case CD_MASK_SUPPLIER_ON:
		case CD_ROUTER_DISCVRY_ON:
		case CD_TRAILER_ENCAPS_ON:
		case CD_ETHERNET_ENCAPS_ON:
		case CD_TCP_KALIVE_GRBG_ON:
			/* Number:  hex flag */
			display_number("%s flag = 0x%x", option_types[save],
			    &start);
			break;
		case CD_MAXIPSIZE:
		case CD_MTU:
		case CD_MAX_DHCP_SIZE:
			/* Number: bytes */
			display_number("%s = %d bytes", option_types[save],
			    &start);
			break;
		case CD_CLASS_ID:
		case CD_CLIENT_ID:
		case CD_NW_IP_DOMAIN:
		case CD_NW_IP_OPTIONS:
			/* Hex ascii strings */
			display_ascii_hex(option_types[save], &start);
			break;
		case CD_BOOT_SIZE:
			display_number("%s = %d 512 byte blocks",
			    "Boot file size", &start);
			break;
		case CD_POLICY_FILTER:
			if ((*start % 8) != 0) {
				(void) sprintf(get_line(0, 0),
				    "Error: Bad Policy Filter option");
			} else {
				items = *start++ / 8;
				for (i = 0; i < items; i++) {
					display_ip(1,
					    "%s = %s",
					    "Policy Destination",
					    &start);
					display_ip(1, "%s = %s", "Mask",
					    &start);
				}
			}
			break;
		case CD_PATH_MTU_TABLE_SZ:
			if (*start % 2 != 0) {
				(void) sprintf(get_line(0, 0),
				    "Error: Bad Path MTU Table");
			} else {
				(void) sprintf(get_line(0, 0),
				    "\tPath MTU Plateau Table:");
				(void) sprintf(get_line(0, 0),
				    "\t=======================");
				items = *start / sizeof (ushort_t);
				++start;
				for (i = 0; i < items; i++) {
					if (IS_P2ALIGNED(start,
					    sizeof (ushort_t))) {
						/* LINTED: improper alignment */
						s_buf = *(ushort_t *)start;
					} else {
						memcpy((char *)&s_buf,
						    start, sizeof (short));
					}
					(void) sprintf(get_line(0, 0),
					    "\t\tEntry %d:\t\t%d", i,
					    ntohs(s_buf));
					start += sizeof (ushort_t);
				}
			}
			break;
		case CD_STATIC_ROUTE:
			if ((*start % 8) != 0) {
				(void) sprintf(get_line(0, 0),
				    "Error: Bad Static Route option: %d",
				    *start);
			} else {
				items = *start++ / 8;
				for (i = 0; i < items; i++) {
					memcpy((char *)&tmp, start,
					    sizeof (struct in_addr));
					(void) strcpy(scratch, inet_ntoa(tmp));
					start += sizeof (ulong_t);
					memcpy((char *)&tmp, start,
					    sizeof (struct in_addr));
					(void) sprintf(get_line(0, 0),
					    "Static route from %s to %s",
					    scratch, inet_ntoa(tmp));
					start += sizeof (ulong_t);
				}
			}
			break;
		case CD_VENDOR_SPEC:
			i = *start++;
			(void) sprintf(get_line(0, 0),
			    "Vendor-specific Options (%d total octets):", i);
			/*
			 * We don't know what these things are, so just
			 * display the option number, length, and value
			 * (hex).
			 */
			vend = (uchar_t *)((uchar_t *)start + i);
			while (start < vend && *start != CD_END) {
				if (*start == CD_PAD) {
					start++;
					continue;
				}
				(void) sprintf(scratch,
				    "\t(%.2d) %.2d octets", *start,
				    *(uchar_t *)((uchar_t *)start + 1));
				start++;
				display_ascii_hex(scratch, &start);
			}
			start = vend;	/* in case CD_END found */
			break;
		case CD_NETBIOS_NODE_TYPE:
			if (*start != 1) {
				(void) sprintf(get_line(0, 0),
				    "Error: Bad '%s' parameter",
				    option_types[CD_NETBIOS_NODE_TYPE]);
			} else {
				char *type;
				start++;
				switch (*start) {
				case 0x1:
					type = "Broadcast Node";
					break;
				case 0x2:
					type = "Point To Point Node";
					break;
				case 0x4:
					type = "Mixed Mode Node";
					break;
				case 0x8:
					type = "Hybrid Node";
					break;
				default:
					type = "??? Node";
					break;
				};
				(void) sprintf(get_line(0, 0),
				    "%s = %s (%d)",
				    option_types[CD_NETBIOS_NODE_TYPE],
				    type, *start);
				start++;
			}
			break;
		case CD_OPTION_OVERLOAD:
			if (*start != 1) {
				(void) sprintf(get_line(0, 0),
				    "Bad Option Overload value.");
			} else {
				start++;
				nooverload = *start++;
			}
			break;
		case CD_DHCP_TYPE:
			if (*start < 1 || *start > 7) {
				(void) sprintf(get_line(0, 0),
				    "Bad DHCP Message Type.");
			} else {
				start++;
				(void) sprintf(get_line(0, 0),
				    "Message type = %s",
				    show_msgtype(*start));
				start++;
			}
			break;
		case CD_REQUEST_LIST:
			opt_len = *start++;
			(void) sprintf(get_line(0, 0),
			    "Requested Options:");
			for (i = 0; i < opt_len; i++) {
				entry = NULL;
				if (*start < OPTIONS_ARRAY_SIZE) {
					prmpt = option_types[*start];
				} else {
					entry = inittab_getbycode(
					    ITAB_CAT_STANDARD|ITAB_CAT_SITE,
					    ITAB_CONS_SNOOP, *start);
					if (entry == NULL) {
						if (*start >= DHCP_SITE_OPT &&
						    *start <= DHCP_END_SITE) {
							prmpt = "Site Option";
						} else {
							prmpt = "Unrecognized "
							    "Option";
						}
					} else {
						prmpt = entry->ds_name;
					}
				}
				(void) sprintf(get_line(0, 0),
				    "\t%2d (%s)", *start, prmpt);
				start++;
				free(entry);
			}
			break;
		default:
			opt_len = *start++;
			entry = inittab_getbycode(
			    ITAB_CAT_STANDARD|ITAB_CAT_SITE,
			    ITAB_CONS_SNOOP, save);
			if (entry == NULL) {
				if (save >= DHCP_SITE_OPT &&
				    save <= DHCP_END_SITE)
					prmpt = "Site";
				else
					prmpt = "Unrecognized";
				decoded_opt = NULL;
			} else {
				if (save < OPTIONS_ARRAY_SIZE) {
					prmpt = option_types[save];
				} else {
					prmpt = entry->ds_name;
				}
				decoded_opt = inittab_decode(entry, start,
				    opt_len, B_TRUE);
			}
			if (decoded_opt == NULL) {
				(void) sprintf(get_line(0, 0),
				    "%s Option = %d, length = %d octets",
				    prmpt, save, opt_len);
				start--;
				display_ascii_hex("\tValue =", &start);
			} else {
				(void) sprintf(get_line(0, 0), "%s = %s", prmpt,
				    decoded_opt);
				start += opt_len;
				free(decoded_opt);
			}
			free(entry);
			break;
		};
	}
	return (nooverload);
}

static const char *
show_msgtype(unsigned char type)
{
	/*
	 * note: the ordering here allows direct indexing of the table
	 *	 based on the RFC2131 packet type value passed in.
	 */

	static const char *types[] = {
		"BOOTP",
		"DHCPDISCOVER", "DHCPOFFER",   "DHCPREQUEST", "DHCPDECLINE",
		"DHCPACK",    "DHCPNAK",      "DHCPRELEASE", "DHCPINFORM"
	};

	if (type >= (sizeof (types) / sizeof (*types)) || types[type] == NULL)
		return ("UNKNOWN");

	return (types[type]);
}

static void
display_ip(int items, char *fmt, char *msg, unsigned char **opt)
{
	struct in_addr tmp;
	int i;

	for (i = 0; i < items; i++) {
		memcpy((char *)&tmp, *opt, sizeof (struct in_addr));
		(void) sprintf(get_line(0, 0), fmt, msg, inet_ntoa(tmp));
		*opt += 4;
	}
}

static void
display_ascii(char *fmt, char *msg, unsigned char **opt)
{
	static unsigned char buf[256];
	int len = **opt;
	unsigned char slen = len;

	if (len >= sizeof (buf))
		len = sizeof (buf) - 1;
	(*opt)++;
	memcpy(buf, *opt, len);
	*(unsigned char *)(buf + len) = '\0';
	(void) sprintf(get_line(0, 0), fmt, msg, buf);
	(*opt) += slen;
}

static void
display_number(char *fmt, char *msg, unsigned char **opt)
{
	int len = **opt;
	unsigned long l_buf = 0;
	unsigned short s_buf = 0;

	if (len > 4) {
		(*opt)++;
		(void) sprintf(get_line(0, 0), fmt, msg, 0xdeadbeef);
		return;
	}
	switch (len) {
	case sizeof (uchar_t):
		(*opt)++;
		(void) sprintf(get_line(0, 0), fmt, msg, **opt);
		break;
	case sizeof (ushort_t):
		(*opt)++;
		if (IS_P2ALIGNED(*opt, sizeof (ushort_t)))
			/* LINTED: improper alignment */
			s_buf = *(unsigned short *)*opt;
		else
			memcpy((char *)&s_buf, *opt, len);
		(void) sprintf(get_line(0, 0), fmt, msg, ntohs(s_buf));
		break;
	case sizeof (ulong_t):
		(*opt)++;
		if (IS_P2ALIGNED(*opt, sizeof (ulong_t)))
			/* LINTED: improper alignment */
			l_buf = *(unsigned long *)*opt;
		else
			memcpy((char *)&l_buf, *opt, len);
		(void) sprintf(get_line(0, 0), fmt, msg, ntohl(l_buf));
		break;
	}
	(*opt) += len;
}

static void
display_ascii_hex(char *msg, unsigned char **opt)
{
	int printable;
	char	buffer[512];
	char  *line, *tmp, *ap, *fmt;
	int	i, len = **opt;

	line = get_line(0, 0);

	(*opt)++;

	if (len >= 255) {
		(void) sprintf(line, "\t%s <TOO LONG>", msg);
		return;
	}

	for (printable = 1, tmp = (char *)(*opt), ap = buffer;
	    tmp < (char *)&((*opt)[len]); tmp++) {
		if (isprint(*tmp))
			*ap++ = *tmp;
		else {
			*ap++ = '.';
			printable = 0;
		}
	}
	*ap = '\0';

	if (!printable) {
		for (tmp = (char *)(*opt), ap = buffer;
		    (tmp < (char *)&((*opt)[len])) && ((ap + 5) < &buffer[512]);
		    tmp++) {
			ap += sprintf(ap, "0x%02X ", *(uchar_t *)(tmp));
		}
		/* Truncate the trailing space */
		*(--ap) = '\0';
		/* More bytes to print in hex but no space in buffer */
		if (tmp < (char *)&((*opt)[len])) {
			i = ap - buffer;
			buffer[i - 1] = '.';
			buffer[i - 2] = '.';
			buffer[i - 3] = '.';
		}
		fmt = "%s\t%s (unprintable)";
	} else {
		fmt = "%s\t\"%s\"";
	}
	(*opt) += len;
	(void) sprintf(line, fmt, msg, buffer);
}
