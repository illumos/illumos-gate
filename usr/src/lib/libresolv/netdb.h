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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * Structures returned by network data base library.
 * All addresses are supplied in host order, and
 * returned in network order (suitable for use in system calls).
 */

#ifndef _NETDB_H
#define	_NETDB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	_PATH_HEQUIV	"/etc/hosts.equiv"
#define	_PATH_HOSTS	"/etc/hosts"
#define	_PATH_NETWORKS	"/etc/networks"
#define	_PATH_PROTOCOLS	"/etc/protocols"
#define	_PATH_SERVICES	"/etc/services"

struct	hostent {
	char	*h_name;	/* official name of host */
	char	**h_aliases;	/* alias list */
	int	h_addrtype;	/* host address type */
	int	h_length;	/* length of address */
	char	**h_addr_list;	/* list of addresses from name server */
#define	h_addr	h_addr_list[0]	/* address, for backward compatiblity */
};

/*
 * Assumption here is that a network number
 * fits in 32 bits -- probably a poor one.
 */
struct	netent {
	char		*n_name;	/* official name of net */
	char		**n_aliases;	/* alias list */
	int		n_addrtype;	/* net address type */
	unsigned long	n_net;		/* network # */
};

struct	servent {
	char	*s_name;	/* official service name */
	char	**s_aliases;	/* alias list */
	int	s_port;		/* port # */
	char	*s_proto;	/* protocol to use */
};

struct	protoent {
	char	*p_name;	/* official protocol name */
	char	**p_aliases;	/* alias list */
	int	p_proto;	/* protocol # */
};

#ifdef	__STDC__
struct hostent	*gethostbyname_r
	(const char *,		 struct hostent *, char *, int, int *h_errnop);
struct hostent	*gethostbyaddr_r
	(const char *, int, int, struct hostent *, char *, int, int *h_errnop);
struct hostent	*gethostent_r(struct hostent *, char *, int, int *h_errnop);

struct servent	*getservbyname_r
	(const char *name, const char *, struct servent *, char *, int);
struct servent	*getservbyport_r
	(int port,	   const char *, struct servent *, char *, int);
struct servent	*getservent_r(struct	servent *, char *, int);

struct netent	*getnetbyname_r
	(const char *, struct netent *, char *, int);
struct netent	*getnetbyaddr_r(long, int, struct netent *, char *, int);
struct netent	*getnetent_r(struct netent *, char *, int);

struct protoent	*getprotobyname_r
	(const char *, struct protoent *, char *, int);
struct protoent	*getprotobynumber_r
	(int, struct protoent *, char *, int);
struct protoent	*getprotoent_r(struct protoent *, char *, int);

int getnetgrent_r(char **, char **, char **, char *, int);
int innetgr(const char *, const char *, const char *, const char *);

/* Old interfaces that return a pointer to a static area;  MT-unsafe */
struct hostent	*gethostbyname(const char *);
struct hostent	*gethostbyaddr(const char *, int, int);
struct hostent	*gethostent(void);
struct netent	*getnetbyname(const char *);
struct netent	*getnetbyaddr(long, int);
struct netent	*getnetent(void);
struct servent	*getservbyname(const char *, const char *);
struct servent	*getservbyport(int, const char *);
struct servent	*getservent(void);
struct protoent	*getprotobyname(const char *);
struct protoent	*getprotobynumber(int);
struct protoent	*getprotoent(void);
int		 getnetgrent(char **, char **, char **);

int sethostent(int);
int endhostent(void);
int setnetent(int);
int endnetent(void);
int setservent(int);
int endservent(void);
int setprotoent(int);
int endprotoent(void);
int setnetgrent(const char *);
int endnetgrent(void);
int rcmd(char **ahost, unsigned short inport,
	const char *luser, const char *ruser, const char *cmd, int *fd2p);
int rexec(char **ahost, unsigned short inport,
	const char *user, const char *passwd, const char *cmd, int *fd2p);
int rresvport(int *);
int ruserok(const char *rhost, int suser, const char *ruser, const char *luser);
#else
struct hostent	*gethostbyname_r();
struct hostent	*gethostbyaddr_r();
struct hostent	*gethostent_r();
struct servent	*getservbyname_r();
struct servent	*getservbyport_r();
struct servent	*getservent_r();
struct netent	*getnetbyname_r();
struct netent	*getnetbyaddr_r();
struct netent	*getnetent_r();
struct protoent	*getprotobyname_r();
struct protoent	*getprotobynumber_r();
struct protoent	*getprotoent_r();
int		 getnetgrent_r();
int		 innetgr();

/* Old interfaces that return a pointer to a static area;  MT-unsafe */
struct hostent	*gethostbyname();
struct hostent	*gethostbyaddr();
struct hostent	*gethostent();
struct netent	*getnetbyname();
struct netent	*getnetbyaddr();
struct netent	*getnetent();
struct servent	*getservbyname();
struct servent	*getservbyport();
struct servent	*getservent();
struct protoent	*getprotobyname();
struct protoent	*getprotobynumber();
struct protoent	*getprotoent();
int		 getnetgrent();

int sethostent();
int endhostent();
int setnetent();
int endnetent();
int setservent();
int endservent();
int setprotoent();
int endprotoent();
int setnetgrent();
int endnetgrent();
int rcmd();
int rexec();
int rresvport();
int ruserok();
#endif

/*
 * Error return codes from gethostbyname() and gethostbyaddr()
 * (when using the resolver)
 */

extern  int h_errno;

#define	HOST_NOT_FOUND	1 /* Authoritive Answer Host not found */
#define	TRY_AGAIN	2 /* Non-Authoritive Host not found, or SERVERFAIL */
#define	NO_RECOVERY	3 /* Non recoverable errors, FORMERR, REFUSED, NOTIMP */
#define	NO_DATA		4 /* Valid name, no data record of requested type */
#define	NO_ADDRESS	NO_DATA		/* no address, look for MX record */

#define	MAXHOSTNAMELEN	256

#define	MAXALIASES	35
#define	MAXADDRS	35

#ifdef	__cplusplus
}
#endif

#endif	/* _NETDB_H */
