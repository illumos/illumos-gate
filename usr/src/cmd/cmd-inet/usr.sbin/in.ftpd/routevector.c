/*
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/****************************************************************************    
  Copyright (c) 1999,2000 WU-FTPD Development Group.  
  All rights reserved.
   
  Portions Copyright (c) 1980, 1985, 1988, 1989, 1990, 1991, 1993, 1994  
    The Regents of the University of California. 
  Portions Copyright (c) 1993, 1994 Washington University in Saint Louis.  
  Portions Copyright (c) 1996, 1998 Berkeley Software Design, Inc.  
  Portions Copyright (c) 1989 Massachusetts Institute of Technology.  
  Portions Copyright (c) 1998 Sendmail, Inc.  
  Portions Copyright (c) 1983, 1995, 1996, 1997 Eric P.  Allman.  
  Portions Copyright (c) 1997 by Stan Barber.  
  Portions Copyright (c) 1997 by Kent Landfield.  
  Portions Copyright (c) 1991, 1992, 1993, 1994, 1995, 1996, 1997  
    Free Software Foundation, Inc.    
   
  Use and distribution of this software and its source code are governed   
  by the terms and conditions of the WU-FTPD Software License ("LICENSE").  
   
  If you did not receive a copy of the license, it may be obtained online  
  at http://www.wu-ftpd.org/license.html.  
   
  $Id: routevector.c,v 1.13 2000/07/01 18:17:39 wuftpd Exp $  
   
****************************************************************************/
/*
 * Parse the entire ftpaccess file looking for:
 *
 * passive address <externalip> <address/CIDR>
 * passive ports <address/CIDR> <min> <max>
 *
 * vect_addr, passive_port_min and passive_port_max store the external IP
 * address, min and max ports found whose associated address is the most
 * specific match of the address the client connected from.
 *
 * The optional CIDR denotes the number of significant bits in the address,
 * the higher the CIDR the more specific the address. If no CIDR is specified,
 * the whole address is significant.
 *
 * When a passive data connection is requested the server listens on a port
 * randomly selected between passive_port_min and passive_port_max
 * (inclusive), if vect_addr is set its address is reported (if not the
 * local address of the control connection is reported). Note this does not
 * change the address the server actually listens on, only the address
 * reported to the client.
 *
 * For example if the ftpaccess file includes:
 * passive address 194.80.17.14  0.0.0.0/0
 * passive address 10.0.1.15     10.0.0.0/8
 *
 * Clients connecting from the class-A network 10 will be told the passive
 * connection is listening on IP address 10.0.1.15, while clients connecting
 * from all other addresses will be told the connection is listening on
 * 194.80.17.14 (a CIDR of /0 matches all addresses of the same address
 * family, if IPv6 support is enabled then IPv4 and IPv6 addresses are
 * supported).
 */

#include "config.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#include <syslog.h>
#endif
#include "extensions.h"
#include "proto.h"

extern struct SOCKSTORAGE his_addr;
extern struct SOCKSTORAGE vect_addr; /* best matching external IP address */
extern int passive_port_min;
extern int passive_port_max;

/* significance of the external IP address and port entries */
static int vect_sig = -1;
static int port_sig = -1;

#ifdef INET6
static int his_addr_family = AF_INET;
static int his_v4mapped = 0;
#endif

/*
 * Compares the address the client connected from (in his_addr) with the
 * supplied address, with the specified number of bits being significant
 * in the comparison. Returns 0 if the addresses match, non-zero otherwise.
 */
static int addr_cmp(void *addr, int sig)
{
    uint32_t addr32[4], rem32[4];
    int bitstozero, i, start = 0, len = sizeof(uint32_t);
    char *ptr;

#ifdef INET6
    if (his_addr_family == AF_INET) {
	if (his_v4mapped) {
	    ptr = (char *)&((struct sockaddr_in6 *)&his_addr)->sin6_addr;
	    /* move to the IPv4 part of an IPv4-mapped IPv6 address */
	    ptr += 12;
	}
	else
#endif
	    ptr = (char *)&((struct sockaddr_in *)&his_addr)->sin_addr;

	/* IPv4 addresses are 32-bits long */
	bitstozero = 32 - sig;
	memcpy(addr32, addr, sizeof(uint32_t));
	memcpy(rem32, ptr, sizeof(uint32_t));
#ifdef INET6
    }
    else {
	/* IPv6 addresses are 128-bits long */
	bitstozero = 128 - sig;
	start = 3;
	len = sizeof(addr32);
	memcpy(addr32, addr, sizeof(addr32));
	memcpy(rem32, &((struct sockaddr_in6 *)&his_addr)->sin6_addr, sizeof(rem32));
    }
#endif

    /* zero bits starting with the least significant */
    for (i = start; (bitstozero > 0) && (i >= 0); i--, bitstozero -= 32) {
	if (bitstozero >= 32)
	    addr32[i] = rem32[i] = 0;
	else {
	    addr32[i] = (ntohl(addr32[i]) >> bitstozero) << bitstozero;
	    rem32[i] = (ntohl(rem32[i]) >> bitstozero) << bitstozero;
	}
    }

    /* compare the IP addresses */
    return memcmp(addr32, rem32, len);
}

/*
 * Matches a supplied IP address string against the address the client
 * connected from (in his_addr). Returns 1 and updates sig if the addresses
 * match and there hasn't already been a more specific match, zero otherwise.
 */
static int better_match(char *addrstr, int *sig)
{
    int addr_sig, max_sig = 32;
    char *ptr;
    void *addr;
#ifdef INET6
    int rval;
    struct in6_addr in6;
#else
    struct in_addr in;
#endif

    /* look for the optional significance (/CIDR) */
    if ((ptr = strstr(addrstr, "/")))
	*ptr = '\0';

#ifdef INET6
    if (his_addr_family == AF_INET6)
	max_sig = 128;
#endif

    if (ptr) {
	addr_sig = atoi(++ptr);
	if (addr_sig < 0)
	    addr_sig = 0;
	else if (addr_sig > max_sig)
	    addr_sig = max_sig;
    }
    else
	addr_sig = max_sig;

    /* return if we already have a more specific match */
    if (addr_sig < *sig) {
	if (ptr)
	    *--ptr = '/';
	return 0;
    }

#ifdef INET6
    rval = inet_pton6(addrstr, &in6);
    if (ptr)
	*--ptr = '/';
    if (rval != 1)
	return 0;

    if (his_addr_family == AF_INET) {
	/* convert IPv4-mapped IPv6 addresses to IPv4 addresses */
	if (IN6_IS_ADDR_V4MAPPED(&in6))
	    addr = &in6.s6_addr[12];
	else
	    return 0;
    }
    else
	addr = &in6.s6_addr;
#else
    in.s_addr = inet_addr(addrstr);
    if (ptr)
	*--ptr = '/';
    if ((int)in.s_addr == -1)
	return 0;
    addr = &in.s_addr;
#endif

    if (addr_cmp(addr, addr_sig) == 0) {
	*sig = addr_sig;
	return 1;
    }
    return 0;
}

static void update_address(char *externalip, char *addrstr)
{
    struct SOCKSTORAGE ext_addr;
#ifndef INET6
    struct in_addr in;
#endif

    /* validate the external IP address string */
#ifdef INET6
    SET_SOCK_FAMILY(ext_addr, AF_INET6);
    if (inet_pton6(externalip, SOCK_ADDR(ext_addr)) != 1)
	return;
    if ((his_addr_family == AF_INET) &&
	!IN6_IS_ADDR_V4MAPPED((struct in6_addr *)SOCK_ADDR(ext_addr)))
	return;
#else
    if ((int)(in.s_addr = inet_addr(externalip)) == -1)
	return;
    SET_SOCK_FAMILY(ext_addr, AF_INET);
    SET_SOCK_ADDR4(ext_addr, in);
#endif

    if (better_match(addrstr, &vect_sig))
	vect_addr = ext_addr;
}

static void update_ports(char *addrstr, char *minport, char *maxport)
{
    int min, max;

    min = atoi(minport);
    max = atoi(maxport);

    /* validate the ports supplied */
    if ((min > max) || (min < 0) || (max > 65535) || (min == 0 && max != 0)) {
	syslog(LOG_WARNING, "ftpaccess passive ports entry invalid: %s %s %s", addrstr, minport, maxport);
	return;
    }

    if (better_match(addrstr, &port_sig)) {
	passive_port_min = min;
	passive_port_max = max;
    }
}

int routevector(void)
{
    struct aclmember *entry = NULL;

#ifdef INET6
    if (SOCK_FAMILY(his_addr) == AF_INET6) {
	if (IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)&(his_addr))->sin6_addr))
	    his_v4mapped = 1;
	else
	    his_addr_family = AF_INET6;
    }
#endif

    while (getaclentry("passive", &entry)) {
	if (!strcasecmp(ARG0, "address")) {
	    if (!ARG1 || !ARG2)
		continue;
	    update_address(ARG1, ARG2);
	}
	if (!strcasecmp(ARG0, "ports")) {
	    if (!ARG1 || !ARG2 || !ARG3)
		continue;
	    update_ports(ARG1, ARG2, ARG3);
	}
    }
    return vect_sig != -1;
}
