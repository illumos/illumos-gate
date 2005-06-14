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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * Global defines and variables for resolver stub.
 */

#ifndef	_RESOLV_H
#define	_RESOLV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Resolver configuration file.
 * Normally not present, but may contain the address of the
 * inital name server(s) to query and the domain search list.
 */

#ifndef	_PATH_RESCONF
#define	_PATH_RESCONF	"/etc/resolv.conf"
#endif

#define	ADDRSORT	1		/* enable the address-sorting option */
#define	MAXADDR		10		/* max # addresses to sort by */

#define	MAXNS		3		/* max # name servers we'll track */
#define	MAXDFLSRCH	3		/* # default domain levels to try */
#define	MAXDNSRCH	6		/* max # default domain levels to try */
#define	LOCALDOMAINPARTS 2		/* min levels in name that is "local" */

#define	RES_TIMEOUT	6		/* seconds between retries */

struct state {
	int	retrans;		/* retransmition time interval */
	int	retry;			/* number of times to retransmit */
	long	options;		/* option flags - see below. */
	int	nscount;		/* number of name servers */
	struct	sockaddr_in nsaddr_list[MAXNS];	/* address of name server */
#define	nsaddr	nsaddr_list[0]		/* for backward compatibility */
	u_short	id;			/* current packet id */
	char	defdname[MAXDNAME];	/* default domain */
	char	*dnsrch[MAXDNSRCH+1];	/* components of domain to search */
	int	ascount;		/* number of addresses */
	struct  in_addr sort_list[MAXADDR]; /* address sorting list */
};

/*
 * Resolver options
 */
#define	RES_INIT	0x0001		/* address initialized */
#define	RES_DEBUG	0x0002		/* print debug messages */
#define	RES_AAONLY	0x0004		/* authoritative answers only */
#define	RES_USEVC	0x0008		/* use virtual circuit */
#define	RES_PRIMARY	0x0010		/* query primary server only */
#define	RES_IGNTC	0x0020		/* ignore trucation errors */
#define	RES_RECURSE	0x0040		/* recursion desired */
#define	RES_DEFNAMES	0x0080		/* use default domain name */
#define	RES_STAYOPEN	0x0100		/* Keep TCP socket open */
#define	RES_DNSRCH	0x0200		/* search up local domain tree */

#define	RES_DEFAULT	(RES_RECURSE | RES_DEFNAMES | RES_DNSRCH)

extern struct state _res;

#ifdef __STDC__
extern char *p_cdname(char *, char *, FILE *);
extern char *p_rr(char *, char *, FILE *);
extern char *p_type(int);
extern char *p_class(int);
extern char *p_time(unsigned long);
#else
extern char *p_cdname(), *p_rr(), *p_type(), *p_class(), *p_time();
#endif	/* __STDC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _RESOLV_H */
