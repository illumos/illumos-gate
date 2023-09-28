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
 * Copyright (c) 1998-1999,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include "snoop.h"

static void put_method(char *cp, int method);
static void put_socks5_addr(char *cp, const unsigned char *buf, int fraglen);
static void put_socks4_res(char *cp, int code);
static void put_socks5_res(char *cp, int code);

int
interpret_socks_call(flags, line, fraglen)
	int flags;
	char *line;
	int fraglen;
{
	unsigned char	*buf = (unsigned char *)line;
	char		*cp;
	struct in_addr	ipaddr;
	int		i, n;

	if (flags & F_SUM) {
	cp = get_sum_line();
	if (fraglen >= 2) {
		switch (buf[0]) {
		case 4:		/* SOCKS4 */
			n = buf[1];
			switch (n) {
			case 1:
			case 2:
				if (fraglen >= 8) {
					(void) memcpy(&ipaddr, &buf[4],
					    sizeof (ipaddr));
					(void) sprintf(cp,
					    "SOCKS4 %s %s:%u",
					    addrtoname(AF_INET, &ipaddr),
					    (n == 1)? "CONNECT": "BIND",
					    (buf[2] << 8) | buf[3]);
					cp += strlen(cp);
					if (fraglen > 8) {
						(void) sprintf(cp, " User=");
						cp += strlen(cp);
						for (i = 8;
							i < 40 && i < fraglen;
							++i) {
							if (buf[i] == '\0')
								break;
							*cp++ = buf[i];
						}
						if (i == 40) {
							*cp++ = '.';
							*cp++ = '.';
							*cp++ = '.';
						}
						*cp = '\0';
					}
				}
				break;
			default:
				(void) sprintf(cp, "SOCKS4 OP=%u", n);
			}
			break;
		case 5:		/* SOCKS5 */
			n = buf[1];
			if (2 + n == fraglen) {
				(void) sprintf(cp,
					"SOCKS5 CONTACT NMETHODS=%d:", n);
				cp += strlen(cp);
				for (i = 0; i < n && 2 + i < fraglen; ++i) {
					put_method(cp, buf[2 + i]);
					cp += strlen(cp);
				}
			} else if (fraglen >= 6 && buf[2] == 0) {
				const char	*cmd;

				if (n < 1 || n > 3) {
					(void) sprintf(cp,
						"SOCKS (send data): %s",
						show_string(line, fraglen, 20));
				} else {
					switch (n) {
					case 1:
						cmd = "CONNECT";
						break;
					case 2:
						cmd = "BIND";
						break;
					case 3:
						cmd = "ASSOCIATE_UDP";
						break;
					}
					(void) sprintf(cp, "SOCKS5 %s ", cmd);
					cp += strlen(cp);
					put_socks5_addr(cp, &buf[3],
						fraglen - 3);
				}
			} else {
				(void) sprintf(cp, "SOCKS (send data): %s",
					show_string(line, fraglen, 20));
			}
			break;
		default:
			(void) sprintf(cp, "SOCKS (send data): %s",
				show_string(line, fraglen, 20));
		}
	} else {
		(void) sprintf(cp, "SOCKS (send data): %s",
			show_string(line, fraglen, 20));
	}

	} /* if (flags & F_SUM) */

	if (flags & F_DTAIL) {
		show_header("SOCKS: ", "SOCKS Header", fraglen);
		show_space();
		cp = get_line(0, 0);
		if (fraglen >= 2) {
			switch (buf[0]) {
			case 4:
				(void) sprintf(cp, "Version = 4");
				n = buf[1];
				switch (n) {
				case 1:
				case 2:
					(void) sprintf(get_line(0, 0),
					    "Operation = %s",
					    (n == 1)? "CONNECT": "BIND");
					if (fraglen >= 8) {
						(void) memcpy(&ipaddr, &buf[4],
						    sizeof (ipaddr));
						(void) sprintf(get_line(0, 0),
						    "Destination = %s:%u",
						    addrtoname(AF_INET,
						    &ipaddr),
						    (buf[2] << 8) | buf[3]);
						if (fraglen > 8) {
							cp = get_line(0, 0);
							(void) sprintf(cp,
							    "User = ");
							cp += strlen(cp);
							for (i = 8;
								i < 40; ++i) {
								if
								(buf[i] == '\0')
									break;
								*cp++ = buf[i];
							}
							if (i == 40) {
								*cp++ = '.';
								*cp++ = '.';
								*cp++ = '.';
							}
							*cp = '\0';
						}
					}
					break;
				default:
					(void) sprintf(get_line(0, 0),
					    "Operation = %u (unknown)", n);
				}
				break;
			case 5:		/* SOCKS5 */
				(void) sprintf(cp, "Version = 5");
				n = buf[1];
				if (2 + n == fraglen) {
					(void) sprintf(get_line(0, 0),
					    "Number of methods = %u", n);
					for (i = 0;
						i < n && 2 + i < fraglen; ++i) {
						cp = get_line(0, 0);
						(void) sprintf(cp,
							"Method %3u =", i);
						cp += strlen(cp);
						put_method(cp, buf[2 + i]);
					}
				} else if (fraglen >= 6 && buf[2] == 0) {
					const char	*cmd;
					if (n < 1 || n > 3) {
						(void) sprintf(cp,
							"SOCKS (send data): %s",
							show_string(line,
							fraglen, 20));
					} else {
						switch (n) {
						case 1:
							cmd = "CONNECT";
							break;
						case 2:
							cmd = "BIND";
							break;
						case 3:
							cmd = "ASSOCIATE_UDP";
							break;
						}
						(void) sprintf(get_line(0, 0),
						    "Operation = %s ", cmd);
						put_socks5_addr(get_line(0, 0),
						    &buf[3], fraglen - 3);
						break;
					}
				} else
					(void) sprintf(cp,
						" SOCKS (send data): %s",
						show_string(line, fraglen,
						20));
				break;
			default:
				(void) sprintf(cp,
					"SOCKS (send data): %s",
					show_string(line, fraglen, 20));
			}
			show_space();
		} else
			(void) sprintf(cp,
				"SOCKS (send data): %s",
				show_string(line, fraglen, 20));
	}

	return (fraglen);
}

int
interpret_socks_reply(flags, line, fraglen)
	int flags;
	char *line;
	int fraglen;
{
	unsigned char	*buf = (unsigned char *)line;
	char		*cp;
	struct in_addr	ipaddr;

	if (flags & F_SUM) {
		cp = get_sum_line();
		if (fraglen >= 2) {
			switch (buf[0]) {
			case 0:
				(void) sprintf(cp, "SOCKS4 ");
				cp += strlen(cp);
				if (fraglen >= 8) {
					(void) memcpy(&ipaddr, &buf[4],
					    sizeof (ipaddr));
					(void) sprintf(cp, "%s:%u ",
					    addrtoname(AF_INET, &ipaddr),
					    (buf[2] << 8) | buf[3]);
					cp += strlen(cp);
				}
				/* reply version, no SOCKS version in v4 */
				put_socks4_res(cp, buf[1]);
				break;
			case 5:
				(void) sprintf(cp, "SOCKS5 method accepted:");
				cp += strlen(cp);
				put_method(cp, buf[1]);
				break;
			default:
				(void) sprintf(cp, "SOCKS (recv data)");
			}
		} else
			(void) sprintf(cp, "SOCKS (recv data)");
	}

	if (flags & F_DTAIL) {
		show_header("SOCKS: ", "SOCKS Header", fraglen);
		show_space();
		cp = get_line(0, 0);
		if (fraglen >= 2) {
			switch (buf[0]) {
			case 0:
				/* reply version, no SOCKS version in v4 */
				(void) sprintf(cp,
				    "Reply version = 0 (SOCKS version 4)");
				if (fraglen >= 8) {
					(void) memcpy(&ipaddr, &buf[4],
					    sizeof (ipaddr));
					(void) sprintf(get_line(0, 0),
					    "Destination %s:%u ",
					    addrtoname(AF_INET, &ipaddr),
					    (buf[2] << 8) | buf[3]);
				}
				cp = get_line(0, 0);
				(void) sprintf(cp, "Result code = %u ", buf[1]);
				cp += strlen(cp);
				put_socks4_res(cp, buf[1]);
				break;
			case 5:
				(void) sprintf(cp, "Reply version = 5");
				if (fraglen == 2) {
					cp = get_line(0, 0);
					(void) sprintf(cp, "Method accepted =");
					cp += strlen(cp);
					put_method(cp, buf[1]);
				} else if (fraglen >= 6 && buf[2] == 0x00) {
					cp = get_line(0, 0);
					(void) sprintf(cp, "Status = ");
					cp += strlen(cp);
					put_socks5_res(cp, buf[1]);
					put_socks5_addr(get_line(0, 0),
					    &buf[3], fraglen - 3);
				}
				break;
			default:
				(void) sprintf(cp, "(recv data)");
			}
		} else
			(void) sprintf(cp, "(recv data)");
		show_space();
	}

	return (fraglen);
}

static void
put_method(char *cp, int method)
{
	switch (method) {
	case 0:
		(void) sprintf(cp, " NOAUTH");
		break;
	case 1:
		(void) sprintf(cp, " GSSAPI");
		break;
	case 2:
		(void) sprintf(cp, " USERNAME/PASSWD");
		break;
	case 255:
		(void) sprintf(cp, " NONE");
		break;
	default:
		(void) sprintf(cp, " 0x%02x (unknown)", method);
	}
}

static void
put_socks5_addr(char *cp, const unsigned char *buf, int fraglen)
{
	struct in_addr	ipaddr;
	int		i;

	switch (buf[0]) {
	case 1:
		/* IPv4 */
		(void) sprintf(cp, "Address = ");
		cp += strlen(cp);
		if (1 + 4 + 2 <= fraglen) {
			(void) memcpy(&ipaddr, &buf[1], sizeof (ipaddr));
			(void) sprintf(cp, "%s:%u",
			    addrtoname(AF_INET, &ipaddr),
			    (buf[5] << 8) | buf[5 + 1]);
		} else
			(void) strcat(cp, "(IPv4)");
		break;
	case 3:
		/* domain name */
		(void) sprintf(cp, "Domain name = ");
		cp += strlen(cp);
		for (i = 0; i <= buf[1] && 1 + i < fraglen; ++i)
			*cp++ = buf[1 + i];
		if (1 + i + 2 <= fraglen)
			(void) sprintf(cp, ":%u",
			    (buf[1 + i] << 8) | buf[1 + i + 1]);
		else
			*cp = '\0';
		break;
	case 4:
		/* IPv6 */
		(void) sprintf(cp, "Address = ");
		if (1 + 16 <= fraglen) {
			for (i = 0; i < 16; ++i) {
				if (i > 0)
					*cp++ = '.';
				(void) sprintf(cp, "%u", buf[1 + i]);
				cp += strlen(cp);
			}
			if (1 + 16 + 2 <= fraglen) {
				(void) sprintf(cp, ":%u",
				    (buf[1 + 16] << 8) | buf[1 + 16 + 1]);
			}
		} else
			(void) strcat(cp, "(IPv6)");
		break;
	default:
		(void) sprintf(cp, "Address type = 0x%02x (unknown)", buf[0]);
	}
}

static void
put_socks4_res(char *cp, int code)
{
	switch (code) {
	case 90:
		(void) sprintf(cp, "request granted");
		break;
	case 91:
		(void) sprintf(cp, "request rejected or failed");
		break;
	case 92:
		(void) sprintf(cp, "socksd can't connect to client's identd");
		break;
	case 93:
		(void) sprintf(cp, "identity mismatch");
		break;
	default:
		(void) sprintf(cp, "0x%02x (unknown)", code);
	}
}

static void
put_socks5_res(char *cp, int code)
{
	switch (code) {
	case 0:
		(void) strcpy(cp, "succeeded");
		break;
	case 1:
		(void) strcpy(cp, "general SOCKS server failure");
		break;
	case 2:
		(void) strcpy(cp, "connection not allowed by ruleset");
		break;
	case 3:
		(void) strcpy(cp, "network unreachable");
		break;
	case 4:
		(void) strcpy(cp, "host unreachable");
		break;
	case 5:
		(void) strcpy(cp, "connection refused");
		break;
	case 6:
		(void) strcpy(cp, "TTL expired");
		break;
	case 7:
		(void) strcpy(cp, "command not supported");
		break;
	case 8:
		(void) strcpy(cp, "address type not supported");
		break;
	default:
		(void) sprintf(cp, "code 0x%02x", code);
	}
}
