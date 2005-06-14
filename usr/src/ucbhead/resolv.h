/*
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1983, 1987 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Global defines and variables for resolver stub.
 */

#ifndef _RESOLV_H
#define	_RESOLV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	ADDRSORT	1		/* enable the address-sorting option */
#define	MAXADDR		10		/* max # addresses to sort by */

#define	MAXDNAME	256
#define	MAXNS		3		/* max # name servers we'll track */
#define	MAXDNSRCH	3		/* max # default domain levels to try */
#define	LOCALDOMAINPARTS 2		/* min levels in name that is "local" */

#define	RES_TIMEOUT	6		/* seconds between retries */

struct state {
	int	retrans;		/* retransmition time interval */
	int	retry;			/* number of times to retransmit */
	int	options;		/* option flags - see below. */
	int	nscount;		/* number of name servers */
	struct	sockaddr_in nsaddr_list[MAXNS];	/* address of name server */
#define	nsaddr	nsaddr_list[0]		/* for backward compatibility */
	ushort_t id;			/* current packet id */
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
extern char *p_cdname(), *p_rr(), *p_type(), *p_class();

#ifdef	__cplusplus
}
#endif

#endif /* _RESOLV_H */

