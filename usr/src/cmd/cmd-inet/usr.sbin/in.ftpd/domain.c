/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
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
 
  $Id: domain.c,v 1.11 2000/07/01 18:17:38 wuftpd Exp $
 
****************************************************************************/
/*
 * domain.c  - Name and address lookup and checking functions
 *
 * INITIAL AUTHOR - *      Nikos Mouat    <nikm@cyberflunk.com>
 */

#include "config.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#include <syslog.h>
#endif
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "extensions.h"
#include "proto.h"

/* these should go in a new ftpd.h perhaps? config.h doesn't seem appropriate */
/* and there does not appear to be a global include file                      */
#ifndef TRUE
#define  TRUE   1
#endif

#ifndef FALSE
#define  FALSE  !TRUE
#endif

/****************************************************************************
 * check_name_for_ip()
 *   This routine checks if the IP address in remote_socket is a valid IP
 *   address for name.
 ***************************************************************************/
static int check_name_for_ip(char *name, struct SOCKSTORAGE *remote_socket)
{
#ifdef INET6
    int family;
    size_t sockaddrlen, addrlen;
    char *raddr, *addr;
    struct addrinfo hints, *result, *ai;

    family = SOCK_FAMILY(*remote_socket);
    raddr = SOCK_ADDR(*remote_socket);
    if ((family == AF_INET6) &&
	IN6_IS_ADDR_V4MAPPED((struct in6_addr *)raddr)) {
	family =  AF_INET;
	/* move to the IPv4 part of an IPv4-mapped IPv6 address */
	raddr += 12;
    }

    if (family == AF_INET6) {
	sockaddrlen = sizeof(struct sockaddr_in6);
	addrlen = sizeof(struct in6_addr);
    }
    else {
	sockaddrlen = sizeof(struct sockaddr_in);
	addrlen = sizeof(struct in_addr);
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;

    if (getaddrinfo(name, NULL, &hints, &result) == 0) {
	for (ai = result; ai != NULL; ai = ai->ai_next) {
	    if ((family == ai->ai_family) && (sockaddrlen == ai->ai_addrlen)) {
		if (family == AF_INET6)
		    addr = (void *)&((struct sockaddr_in6 *)(ai->ai_addr))->sin6_addr;
		else
		    addr = (void *)&((struct sockaddr_in *)(ai->ai_addr))->sin_addr;
		if (memcmp(addr, raddr, addrlen) == 0) {
		    freeaddrinfo(result);
		    return TRUE;
		}
	    }
	}
	freeaddrinfo(result);
    }
#else
    char **addrl;
    struct hostent *hp;

    if ((hp = gethostbyname(name)) != NULL) {
	for (addrl = hp->h_addr_list; addrl != NULL; addrl++) {
		if (memcmp(&remote_socket->sin_addr, *addrl,
		    sizeof(struct in_addr)) == 0)
		return TRUE;
	}
    }
#endif /* INET6 */

    /* no matching IP's */
    return FALSE;
}

/****************************************************************************
 * lookup()
 *   This routine returns the result of the lookup specified by dnsarg,
 *   which is either "refuse_no_reverse" or "refuse_mismatch", using the
 *   remote host's IP address.
 ***************************************************************************/
static int lookup(char *dnsarg)
{
    static int rhost_matches = FALSE;
    static int rhost_matches_set = FALSE;
    extern struct SOCKSTORAGE his_addr;
    extern int rhlookup, nameserved;
    extern char remotehost[];

    /* skip lookups when not looking up the remote host's name */
    if (!rhlookup)
	return FALSE;

    if (strcasecmp(dnsarg, "refuse_no_reverse") == 0)
	return nameserved;

    /* refuse_mismatch */
    if (!rhost_matches_set) {
	if (nameserved) {
	    /*
	     * We have the hostname based on the real IP address. Lookup
	     * the hostname to make sure the real IP address is listed as
	     * a valid address for the hostname.
	     */
	    rhost_matches = check_name_for_ip(remotehost, &his_addr);
	}
	else
	    rhost_matches = TRUE;	/* no reverse, nothing to match */
	rhost_matches_set = TRUE;
    }
    return rhost_matches;
}

/****************************************************************************
 * dns_check()
 *   This routine returns FALSE if the operation specified by dnsarg is
 *   FALSE and "override" wasn't specified, otherwise it returns TRUE.
 ***************************************************************************/
static int dns_check(char *dnsarg)
{
    struct aclmember *entry = NULL;
    int rc = TRUE;

    /* check the config to see if we care */
    /* dns refuse_mismatch|refuse_no_reverse <filename> [override] */
    while (getaclentry("dns", &entry)) {
	if (!ARG0 || !ARG1)
	    continue;
	if (!strcasecmp(ARG0, dnsarg)) {
	    FILE *msg_file;
	    char linebuf[MAXPATHLEN];
	    char outbuf[MAXPATHLEN];
	    int code = 530;
	    char *crptr;

	    /* lookups can be slow, so only call now result is needed */
	    if (!lookup(dnsarg)) {
		/* ok, so we need to kick out this user */

		/* check to see if admin wants to override */
		if (ARG2 && (!strcasecmp(ARG2, "override"))) {
		    /* Administrative override - but display warning anyway */
		    code = 220;
		}

		msg_file = fopen(ARG1, "r");
		if (msg_file != NULL) {
		    while (fgets(linebuf, sizeof(linebuf), msg_file)) {
			if ((crptr = strchr(linebuf, '\n')) != NULL)
			    *crptr = '\0';
			msg_massage(linebuf, outbuf, sizeof(outbuf));
			lreply(code, "%s", outbuf);
		    }
		    fclose(msg_file);
#ifndef NO_SUCKING_NEWLINES
		    lreply(code, "");
#endif
		    if (code == 530) {
			reply(code, "");
			rc = FALSE;
		    }
		    else {
			lreply(code, "Administrative Override. Permission granted.");
			lreply(code, "");
		    }
		}
	    }
	}
    }
    return rc;
}

/****************************************************************************
 * check_rhost_reverse()
 *   This routine returns FALSE if the remote host's IP address has no
 *   associated name and access should be refused, otherwise it returns TRUE.
 ***************************************************************************/
int check_rhost_reverse(void)
{
    return dns_check("refuse_no_reverse");
}

/****************************************************************************
 * check_rhost_matches()
 *   This routine returns FALSE if the remote host's IP address isn't listed
 *   as a valid IP address for the remote hostname and access should be
 *   refused, otherwise it returns TRUE.
 ***************************************************************************/
int check_rhost_matches(void)
{
    return dns_check("refuse_mismatch");
}

/****************************************************************************
 * rhostlookup()
 *   This routine returns TRUE if the remote host's name of a connection
 *   from remoteaddr should be looked up, otherwise it returns FALSE.
 ***************************************************************************/
int rhostlookup(char *remoteaddr)
{
    int found, lookup, set, which;
    struct aclmember *entry = NULL;

    /* default is to lookup the remote host's name */
    lookup = TRUE;
    found = FALSE;

    /* rhostlookup yes|no [<addrglob> ...] */
    while (!found && getaclentry("rhostlookup", &entry)) {
	if (!ARG0)
	    continue;
	if (strcasecmp(ARG0, "yes") == 0)
	    set = TRUE;
	else if (strcasecmp(ARG0, "no") == 0)
	    set = FALSE;
	else
	    continue;

	if (!ARG1)
	    lookup = set;
	else {
	    for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
		if (hostmatch(ARG[which], remoteaddr, NULL)) {
		    lookup = set;
		    found = TRUE;
		    break;
		}
	    }
	}
    }
    return lookup;
}

/****************************************************************************
 * set_res_options()
 *   set resolver options by setting the RES_OPTIONS environment variable.
 *   Note: name and address lookups are no longer done using DNS directly,
 *   so setting resolver options may have no effect.
 ***************************************************************************/
void set_res_options(void)
{
    int which;
    struct aclmember *entry = NULL;
    static char envbuf[BUFSIZ];

    envbuf[0] = '\0';

    /* dns resolveroptions [options] */
    while (getaclentry("dns", &entry)) {
	if (!ARG0 || !ARG1)
	    continue;
	/* there are other DNS options, we only care about 'resolveroptions' */
	if (strcasecmp(ARG0, "resolveroptions") == 0) {
	    for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
		if (envbuf[0] == '\0')
		    (void) strlcpy(envbuf, "RES_OPTIONS=", sizeof(envbuf));
		else
		    (void) strlcat(envbuf, " ", sizeof(envbuf));
		(void) strlcat(envbuf, ARG[which], sizeof(envbuf));
	    }
	}
    }
    if (envbuf[0] != '\0') {
	if (putenv(envbuf) != 0)
	    syslog(LOG_WARNING, "putenv(\"%s\") failed", envbuf);
    }
}
