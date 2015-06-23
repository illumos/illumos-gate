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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * rpcinfo: ping a particular rpc program
 * 	or dump the the registered programs on the remote machine.
 */

/*
 * We are for now defining PORTMAP here.  It doesn't even compile
 * unless it is defined.
 */
#ifndef	PORTMAP
#define	PORTMAP
#endif

/*
 * If PORTMAP is defined, rpcinfo will talk to both portmapper and
 * rpcbind programs; else it talks only to rpcbind. In the latter case
 * all the portmapper specific options such as -u, -t, -p become void.
 */
#include <rpc/rpc.h>
#include <stdio.h>
#include <rpc/rpcb_prot.h>
#include <rpc/nettype.h>
#include <netdir.h>
#include <rpc/rpcent.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef PORTMAP		/* Support for version 2 portmapper */
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <rpc/pmap_prot.h>
#include <rpc/pmap_clnt.h>
#endif

#define	MAXHOSTLEN	256
#define	MIN_VERS	((ulong_t)0)
#define	MAX_VERS	(4294967295UL)
#define	UNKNOWN		"unknown"

#define	MAX(a, b) (((a) > (b)) ? (a) : (b))

extern int	t_errno;
extern long	strtol();
static char *spaces();

#ifdef PORTMAP
static void	ip_ping(/*ushort_t portflag, char *trans,
				int argc, char **argv*/);
static CLIENT	*clnt_com_create(/* struct sockaddr_in *addr, long prog,
			long vers, int *fd, char *trans*/);
static void	pmapdump(/*int argc, char **argv*/);
static void	get_inet_address(/*struct sockaddr_in *addr, char *host*/);
#endif

static bool_t	reply_proc(/*void *res, struct netbuf *who*,
			struct netconfig *nconf*/);
static void	brdcst(/*int argc, char **argv*/);
static void	addrping(/*char *address, char *netid,
				int argc, char **argv*/);
static void	progping(/* char *netid, int argc, char **argv*/);
static CLIENT	*clnt_addr_create(/* char *addr, struct netconfig *nconf,
				long prog, long vers*/);
static CLIENT   *clnt_rpcbind_create(/* char *host, int vers */);
static CLIENT   *getclnthandle(/* host, nconf, rpcbversnum */);
static int	pstatus(/*CLIENT *client, ulong_t prognum, ulong_t vers*/);
static void	rpcbdump(/*char *netid, int argc, char **argv*/);
static void	rpcbgetstat(/* int argc, char **argv*/);
static void	rpcbaddrlist(/*char *netid, int argc, char **argv*/);
static void	deletereg(/*char *netid, int argc, char **argv */);
static void	print_rmtcallstat(/* rtype, infp */);
static void	print_getaddrstat(/* rtype, infp */);
static void	usage(/*void*/);
static ulong_t	getprognum(/*char *arg*/);
static ulong_t	getvers(/*char *arg*/);

/*
 * Functions to be performed.
 */
#define	NONE		0	/* no function */
#define	PMAPDUMP	1	/* dump portmapper registrations */
#define	TCPPING		2	/* ping TCP service */
#define	UDPPING		3	/* ping UDP service */
#define	BROADCAST	4	/* ping broadcast service */
#define	DELETES		5	/* delete registration for the service */
#define	ADDRPING	6	/* pings at the given address */
#define	PROGPING	7	/* pings a program on a given host */
#define	RPCBDUMP	8	/* dump rpcbind registrations */
#define	RPCBDUMP_SHORT	9	/* dump rpcbind registrations - short version */
#define	RPCBADDRLIST	10	/* dump addr list about one prog */
#define	RPCBGETSTAT	11	/* Get statistics */

struct netidlist {
	char *netid;
	struct netidlist *next;
};

struct verslist {
	int vers;
	struct verslist *next;
};

struct rpcbdump_short {
	ulong_t prog;
	struct verslist *vlist;
	struct netidlist *nlist;
	struct rpcbdump_short *next;
	char *owner;
};


char *loopback_netid = NULL;
struct netconfig *loopback_nconf;

int
main(argc, argv)
	int argc;
	char **argv;
{
	register int c;
	extern char *optarg;
	extern int optind;
	int errflg;
	int function;
	char *netid = NULL;
	char *address = NULL;
	void *handle;
#ifdef PORTMAP
	char *strptr;
	ushort_t portnum = 0;
#endif

	function = NONE;
	errflg = 0;
#ifdef PORTMAP
	while ((c = getopt(argc, argv, "a:bdlmn:pstT:u")) != EOF) {
#else
	while ((c = getopt(argc, argv, "a:bdlmn:sT:")) != EOF) {
#endif
		switch (c) {
#ifdef PORTMAP
		case 'p':
			if (function != NONE)
				errflg = 1;
			else
				function = PMAPDUMP;
			break;

		case 't':
			if (function != NONE)
				errflg = 1;
			else
				function = TCPPING;
			break;

		case 'u':
			if (function != NONE)
				errflg = 1;
			else
				function = UDPPING;
			break;

		case 'n':
			portnum = (ushort_t)strtol(optarg, &strptr, 10);
			if (strptr == optarg || *strptr != '\0') {
				(void) fprintf(stderr,
			"rpcinfo: %s is illegal port number\n",
					optarg);
				exit(1);
			}
			break;
#endif
		case 'a':
			address = optarg;
			if (function != NONE)
				errflg = 1;
			else
				function = ADDRPING;
			break;
		case 'b':
			if (function != NONE)
				errflg = 1;
			else
				function = BROADCAST;
			break;

		case 'd':
			if (function != NONE)
				errflg = 1;
			else
				function = DELETES;
			break;

		case 'l':
			if (function != NONE)
				errflg = 1;
			else
				function = RPCBADDRLIST;
			break;

		case 'm':
			if (function != NONE)
				errflg = 1;
			else
				function = RPCBGETSTAT;
			break;

		case 's':
			if (function != NONE)
				errflg = 1;
			else
				function = RPCBDUMP_SHORT;
			break;

		case 'T':
			netid = optarg;
			break;
		case '?':
			errflg = 1;
			break;
		}
	}

	if (errflg || ((function == ADDRPING) && !netid)) {
		usage();
		return (1);
	}
	if (netid == NULL) {	/* user has not selected transport to use */
		/*
		 * See if a COTS loopback transport is available, in case we
		 * will be talking to the local system.
		 */
		handle = setnetconfig();
		while ((loopback_nconf = getnetconfig(handle)) != NULL) {
			if (strcmp(loopback_nconf->nc_protofmly,
				NC_LOOPBACK) == 0 &&
			    (loopback_nconf->nc_semantics == NC_TPI_COTS ||
			    loopback_nconf->nc_semantics == NC_TPI_COTS_ORD)) {
				loopback_netid = loopback_nconf->nc_netid;
				break;
			}
		}
		if (loopback_netid == NULL) {
			(void) endnetconfig(handle);
		}
	}
	if (function == NONE) {
		if (argc - optind > 1)
			function = PROGPING;
		else
			function = RPCBDUMP;
	}

	switch (function) {
#ifdef PORTMAP
	case PMAPDUMP:
		if (portnum != 0) {
			usage();
			return (1);
		}
		pmapdump(argc - optind, argv + optind);
		break;

	case UDPPING:
		ip_ping(portnum, "udp", argc - optind, argv + optind);
		break;

	case TCPPING:
		ip_ping(portnum, "tcp", argc - optind, argv + optind);
		break;
#endif
	case BROADCAST:
		brdcst(argc - optind, argv + optind);
		break;
	case DELETES:
		deletereg(netid, argc - optind, argv + optind);
		break;
	case ADDRPING:
		addrping(address, netid, argc - optind, argv + optind);
		break;
	case PROGPING:
		progping(netid, argc - optind, argv + optind);
		break;
	case RPCBDUMP:
	case RPCBDUMP_SHORT:
		rpcbdump(function, netid, argc - optind, argv + optind);
		break;
	case RPCBGETSTAT:
		rpcbgetstat(argc - optind, argv + optind);
		break;
	case RPCBADDRLIST:
		rpcbaddrlist(netid, argc - optind, argv + optind);
		break;
	}
	return (0);
}

#ifdef PORTMAP
static CLIENT *
clnt_com_create(addr, prog, vers, fdp, trans)
	struct sockaddr_in *addr;
	ulong_t prog;
	ulong_t vers;
	int *fdp;
	char *trans;
{
	CLIENT *clnt;

	if (strcmp(trans, "tcp") == 0) {
		clnt = clnttcp_create(addr, prog, vers, fdp, 0, 0);
	} else {
		struct timeval to;

		to.tv_sec = 5;
		to.tv_usec = 0;
		clnt = clntudp_create(addr, prog, vers, to, fdp);
	}
	if (clnt == (CLIENT *)NULL) {
		clnt_pcreateerror("rpcinfo");
		if (vers == MIN_VERS)
			(void) printf("program %lu is not available\n", prog);
		else
			(void) printf(
				"program %lu version %lu is not available\n",
							prog, vers);
		exit(1);
	}
	return (clnt);
}

/*
 * If portnum is 0, then go and get the address from portmapper, which happens
 * transparently through clnt*_create(); If version number is not given, it
 * tries to find out the version number by making a call to version 0 and if
 * that fails, it obtains the high order and the low order version number. If
 * version 0 calls succeeds, it tries for MAXVERS call and repeats the same.
 */
static void
ip_ping(portnum, trans, argc, argv)
	ushort_t portnum;
	char *trans;
	int argc;
	char **argv;
{
	CLIENT *client;
	int fd = RPC_ANYFD;
	struct timeval to;
	struct sockaddr_in addr;
	enum clnt_stat rpc_stat;
	ulong_t prognum, vers, minvers, maxvers;
	struct rpc_err rpcerr;
	int failure = 0;

	if (argc < 2 || argc > 3) {
		usage();
		exit(1);
	}
	to.tv_sec = 10;
	to.tv_usec = 0;
	prognum = getprognum(argv[1]);
	get_inet_address(&addr, argv[0]);
	if (argc == 2) {	/* Version number not known */
		/*
		 * A call to version 0 should fail with a program/version
		 * mismatch, and give us the range of versions supported.
		 */
		vers = MIN_VERS;
	} else {
		vers = getvers(argv[2]);
	}
	addr.sin_port = htons(portnum);
	client = clnt_com_create(&addr, prognum, vers, &fd, trans);
	rpc_stat = CLNT_CALL(client, NULLPROC, (xdrproc_t)xdr_void,
			(char *)NULL, (xdrproc_t)xdr_void, (char *)NULL,
			to);
	if (argc != 2) {
		/* Version number was known */
		if (pstatus(client, prognum, vers) < 0)
			exit(1);
		(void) CLNT_DESTROY(client);
		return;
	}
	/* Version number not known */
	(void) CLNT_CONTROL(client, CLSET_FD_NCLOSE, (char *)NULL);
	if (rpc_stat == RPC_PROGVERSMISMATCH) {
		clnt_geterr(client, &rpcerr);
		minvers = rpcerr.re_vers.low;
		maxvers = rpcerr.re_vers.high;
	} else if (rpc_stat == RPC_SUCCESS) {
		/*
		 * Oh dear, it DOES support version 0.
		 * Let's try version MAX_VERS.
		 */
		(void) CLNT_DESTROY(client);
		addr.sin_port = htons(portnum);
		client = clnt_com_create(&addr, prognum, MAX_VERS, &fd, trans);
		rpc_stat = CLNT_CALL(client, NULLPROC, (xdrproc_t)xdr_void,
				(char *)NULL, (xdrproc_t)xdr_void,
				(char *)NULL, to);
		if (rpc_stat == RPC_PROGVERSMISMATCH) {
			clnt_geterr(client, &rpcerr);
			minvers = rpcerr.re_vers.low;
			maxvers = rpcerr.re_vers.high;
		} else if (rpc_stat == RPC_SUCCESS) {
			/*
			 * It also supports version MAX_VERS.
			 * Looks like we have a wise guy.
			 * OK, we give them information on all
			 * 4 billion versions they support...
			 */
			minvers = 0;
			maxvers = MAX_VERS;
		} else {
			(void) pstatus(client, prognum, MAX_VERS);
			exit(1);
		}
	} else {
		(void) pstatus(client, prognum, (ulong_t)0);
		exit(1);
	}
	(void) CLNT_DESTROY(client);
	for (vers = minvers; vers <= maxvers; vers++) {
		addr.sin_port = htons(portnum);
		client = clnt_com_create(&addr, prognum, vers, &fd, trans);
		rpc_stat = CLNT_CALL(client, NULLPROC, (xdrproc_t)xdr_void,
				(char *)NULL, (xdrproc_t)xdr_void,
				(char *)NULL, to);
		if (pstatus(client, prognum, vers) < 0)
				failure = 1;
		(void) CLNT_DESTROY(client);
	}
	if (failure)
		exit(1);
	(void) t_close(fd);
}

/*
 * Dump all the portmapper registerations
 */
static void
pmapdump(argc, argv)
	int argc;
	char **argv;
{
	struct sockaddr_in server_addr;
	pmaplist_ptr head = NULL;
	int socket = RPC_ANYSOCK;
	struct timeval minutetimeout;
	register CLIENT *client;
	struct rpcent *rpc;
	enum clnt_stat clnt_st;
	struct rpc_err err;
	char *host;

	if (argc > 1) {
		usage();
		exit(1);
	}
	if (argc == 1) {
		host = argv[0];
	} else {
		host = HOST_SELF_CONNECT;
	}
	get_inet_address(&server_addr, host);

	minutetimeout.tv_sec = 60;
	minutetimeout.tv_usec = 0;
	server_addr.sin_port = htons(PMAPPORT);
	if ((client = clnttcp_create(&server_addr, PMAPPROG,
		PMAPVERS, &socket, 50, 500)) == NULL) {
		if (rpc_createerr.cf_stat == RPC_TLIERROR) {
			/*
			 * "Misc. TLI error" is not too helpful. Most likely
			 * the connection to the remote server timed out, so
			 * this error is at least less perplexing.
			 */
			rpc_createerr.cf_stat = RPC_PMAPFAILURE;
			rpc_createerr.cf_error.re_status = RPC_FAILED;
		}
		clnt_pcreateerror("rpcinfo: can't contact portmapper");
		exit(1);
	}
	clnt_st = CLNT_CALL(client, PMAPPROC_DUMP, (xdrproc_t)xdr_void,
		NULL, (xdrproc_t)xdr_pmaplist_ptr, (char *)&head,
		minutetimeout);
	if (clnt_st != RPC_SUCCESS) {
		if ((clnt_st == RPC_PROGVERSMISMATCH) ||
		    (clnt_st == RPC_PROGUNAVAIL)) {
			CLNT_GETERR(client, &err);
			if (err.re_vers.low > PMAPVERS)
				(void) fprintf(stderr,
		"%s does not support portmapper.  Try rpcinfo %s instead\n",
					host, host);
			exit(1);
		}
		clnt_perror(client, "rpcinfo: can't contact portmapper");
		exit(1);
	}
	if (head == NULL) {
		(void) printf("No remote programs registered.\n");
	} else {
		(void) printf("   program vers proto   port  service\n");
		for (; head != NULL; head = head->pml_next) {
			(void) printf("%10ld%5ld",
				head->pml_map.pm_prog,
				head->pml_map.pm_vers);
			if (head->pml_map.pm_prot == IPPROTO_UDP)
				(void) printf("%6s", "udp");
			else if (head->pml_map.pm_prot == IPPROTO_TCP)
				(void) printf("%6s", "tcp");
			else
				(void) printf("%6ld", head->pml_map.pm_prot);
			(void) printf("%7ld", head->pml_map.pm_port);
			rpc = getrpcbynumber(head->pml_map.pm_prog);
			if (rpc)
				(void) printf("  %s\n", rpc->r_name);
			else
				(void) printf("\n");
		}
	}
}

static void
get_inet_address(addr, host)
	struct sockaddr_in *addr;
	char *host;
{
	struct netconfig *nconf;
	struct nd_hostserv service;
	struct nd_addrlist *naddrs;

	(void) memset((char *)addr, 0, sizeof (*addr));
	addr->sin_addr.s_addr = inet_addr(host);
	if (addr->sin_addr.s_addr == (uint32_t)-1 ||
	    addr->sin_addr.s_addr == 0) {
		if ((nconf = __rpc_getconfip("udp")) == NULL &&
		    (nconf = __rpc_getconfip("tcp")) == NULL) {
			(void) fprintf(stderr,
			"rpcinfo: couldn't find a suitable transport\n");
			exit(1);
		} else {
			service.h_host = host;
			service.h_serv = "rpcbind";
			if (netdir_getbyname(nconf, &service, &naddrs)) {
				(void) fprintf(stderr, "rpcinfo: %s: %s\n",
						host, netdir_sperror());
				exit(1);
			} else {
				(void) memcpy((caddr_t)addr,
				    naddrs->n_addrs->buf, naddrs->n_addrs->len);
				(void) netdir_free((char *)naddrs, ND_ADDRLIST);
			}
			(void) freenetconfigent(nconf);
		}
	} else {
		addr->sin_family = AF_INET;
	}
}
#endif /* PORTMAP */

/*
 * reply_proc collects replies from the broadcast.
 * to get a unique list of responses the output of rpcinfo should
 * be piped through sort(1) and then uniq(1).
 */

/*ARGSUSED*/
static bool_t
reply_proc(res, who, nconf)
	void *res;		/* Nothing comes back */
	struct netbuf *who;	/* Who sent us the reply */
	struct netconfig *nconf; /* On which transport the reply came */
{
	struct nd_hostservlist *serv;
	char *uaddr;
	char *hostname;

	if (netdir_getbyaddr(nconf, &serv, who)) {
		hostname = UNKNOWN;
	} else {
		hostname = serv->h_hostservs->h_host;
	}
	if (!(uaddr = taddr2uaddr(nconf, who))) {
		uaddr = UNKNOWN;
	}
	(void) printf("%s\t%s\n", uaddr, hostname);
	if (strcmp(hostname, UNKNOWN))
		netdir_free((char *)serv, ND_HOSTSERVLIST);
	if (strcmp(uaddr, UNKNOWN))
		free((char *)uaddr);
	return (FALSE);
}

static void
brdcst(argc, argv)
	int argc;
	char **argv;
{
	enum clnt_stat rpc_stat;
	ulong_t prognum, vers;

	if (argc != 2) {
		usage();
		exit(1);
	}
	prognum = getprognum(argv[0]);
	vers = getvers(argv[1]);
	rpc_stat = rpc_broadcast(prognum, vers, NULLPROC,
		(xdrproc_t)xdr_void, (char *)NULL, (xdrproc_t)xdr_void,
		(char *)NULL, (resultproc_t)reply_proc, NULL);
	if ((rpc_stat != RPC_SUCCESS) && (rpc_stat != RPC_TIMEDOUT)) {
		(void) fprintf(stderr, "rpcinfo: broadcast failed: %s\n",
			clnt_sperrno(rpc_stat));
		exit(1);
	}
	exit(0);
}

static bool_t
add_version(rs, vers)
	struct rpcbdump_short *rs;
	ulong_t vers;
{
	struct verslist *vl;

	for (vl = rs->vlist; vl; vl = vl->next)
		if (vl->vers == vers)
			break;
	if (vl)
		return (TRUE);
	vl = (struct verslist *)malloc(sizeof (struct verslist));
	if (vl == NULL)
		return (FALSE);
	vl->vers = vers;
	vl->next = rs->vlist;
	rs->vlist = vl;
	return (TRUE);
}

static bool_t
add_netid(rs, netid)
	struct rpcbdump_short *rs;
	char *netid;
{
	struct netidlist *nl;

	for (nl = rs->nlist; nl; nl = nl->next)
		if (strcmp(nl->netid, netid) == 0)
			break;
	if (nl)
		return (TRUE);
	nl = (struct netidlist *)malloc(sizeof (struct netidlist));
	if (nl == NULL)
		return (FALSE);
	nl->netid = netid;
	nl->next = rs->nlist;
	rs->nlist = nl;
	return (TRUE);
}

static void
rpcbdump(dumptype, netid, argc, argv)
	int dumptype;
	char *netid;
	int argc;
	char **argv;
{
	rpcblist_ptr head = NULL;
	struct timeval minutetimeout;
	register CLIENT *client;
	struct rpcent *rpc;
	char *host;
	struct netidlist *nl;
	struct verslist *vl;
	struct rpcbdump_short *rs, *rs_tail;
	enum clnt_stat clnt_st;
	struct rpc_err err;
	struct rpcbdump_short *rs_head = NULL;

	if (argc > 1) {
		usage();
		exit(1);
	}
	if (argc == 1) {
		host = argv[0];
	} else {
		host = HOST_SELF_CONNECT;
	}
	if (netid == NULL) {
	    if (loopback_netid == NULL) {
		client = clnt_rpcbind_create(host, RPCBVERS, NULL);
	    } else {
		client = getclnthandle(host, loopback_nconf, RPCBVERS, NULL);
		if (client == NULL && rpc_createerr.cf_stat ==
				RPC_N2AXLATEFAILURE) {
			client = clnt_rpcbind_create(host, RPCBVERS, NULL);
		}
	    }
	} else {
		struct netconfig *nconf;

		nconf = getnetconfigent(netid);
		if (nconf == NULL) {
			nc_perror("rpcinfo: invalid transport");
			exit(1);
		}
		client = getclnthandle(host, nconf, RPCBVERS, NULL);
		if (nconf)
			(void) freenetconfigent(nconf);
	}
	if (client == (CLIENT *)NULL) {
		clnt_pcreateerror("rpcinfo: can't contact rpcbind");
		exit(1);
	}
	minutetimeout.tv_sec = 60;
	minutetimeout.tv_usec = 0;
	clnt_st = CLNT_CALL(client, RPCBPROC_DUMP, (xdrproc_t)xdr_void,
		NULL, (xdrproc_t)xdr_rpcblist_ptr, (char *)&head,
		minutetimeout);
	if (clnt_st != RPC_SUCCESS) {
	    if ((clnt_st == RPC_PROGVERSMISMATCH) ||
		(clnt_st == RPC_PROGUNAVAIL)) {
		int vers;

		CLNT_GETERR(client, &err);
		if (err.re_vers.low == RPCBVERS4) {
		    vers = RPCBVERS4;
		    clnt_control(client, CLSET_VERS, (char *)&vers);
		    clnt_st = CLNT_CALL(client, RPCBPROC_DUMP,
			(xdrproc_t)xdr_void, NULL,
			(xdrproc_t)xdr_rpcblist_ptr, (char *)&head,
			minutetimeout);
		    if (clnt_st != RPC_SUCCESS)
			goto failed;
		} else {
		    if (err.re_vers.high == PMAPVERS) {
			int high, low;
			pmaplist_ptr pmaphead = NULL;
			rpcblist_ptr list, prev = NULL;

			vers = PMAPVERS;
			clnt_control(client, CLSET_VERS, (char *)&vers);
			clnt_st = CLNT_CALL(client, PMAPPROC_DUMP,
				(xdrproc_t)xdr_void, NULL,
				(xdrproc_t)xdr_pmaplist_ptr,
				(char *)&pmaphead, minutetimeout);
			if (clnt_st != RPC_SUCCESS)
				goto failed;
			/*
			 * convert to rpcblist_ptr format
			 */
			for (head = NULL; pmaphead != NULL;
				pmaphead = pmaphead->pml_next) {
			    list = (rpcblist *)malloc(sizeof (rpcblist));
			    if (list == NULL)
				goto error;
			    if (head == NULL)
				head = list;
			    else
				prev->rpcb_next = (rpcblist_ptr) list;

			    list->rpcb_next = NULL;
			    list->rpcb_map.r_prog = pmaphead->pml_map.pm_prog;
			    list->rpcb_map.r_vers = pmaphead->pml_map.pm_vers;
			    if (pmaphead->pml_map.pm_prot == IPPROTO_UDP)
				list->rpcb_map.r_netid = "udp";
			    else if (pmaphead->pml_map.pm_prot == IPPROTO_TCP)
				list->rpcb_map.r_netid = "tcp";
			    else {
#define	MAXLONG_AS_STRING	"2147483648"
				list->rpcb_map.r_netid =
					malloc(strlen(MAXLONG_AS_STRING) + 1);
				if (list->rpcb_map.r_netid == NULL)
					goto error;
				(void) sprintf(list->rpcb_map.r_netid, "%6ld",
					pmaphead->pml_map.pm_prot);
			    }
			    list->rpcb_map.r_owner = UNKNOWN;
			    low = pmaphead->pml_map.pm_port & 0xff;
			    high = (pmaphead->pml_map.pm_port >> 8) & 0xff;
			    list->rpcb_map.r_addr = strdup("0.0.0.0.XXX.XXX");
			    (void) sprintf(&list->rpcb_map.r_addr[8], "%d.%d",
				high, low);
			    prev = list;
			}
		    }
		}
	    } else {	/* any other error */
failed:
		    clnt_perror(client, "rpcinfo: can't contact rpcbind: ");
		    exit(1);
	    }
	}
	if (head == NULL) {
		(void) printf("No remote programs registered.\n");
	} else if (dumptype == RPCBDUMP) {
		(void) printf(
"   program version netid     address             service    owner\n");
		for (; head != NULL; head = head->rpcb_next) {
			(void) printf("%10ld%5ld    ",
				head->rpcb_map.r_prog, head->rpcb_map.r_vers);
			(void) printf("%-9s ", head->rpcb_map.r_netid);
			(void) printf("%-19s", head->rpcb_map.r_addr);
			rpc = getrpcbynumber(head->rpcb_map.r_prog);
			if (rpc)
				(void) printf(" %-10s", rpc->r_name);
			else
				(void) printf(" %-10s", "-");
			(void) printf(" %s\n", head->rpcb_map.r_owner);
		}
	} else if (dumptype == RPCBDUMP_SHORT) {
		for (; head != NULL; head = head->rpcb_next) {
			for (rs = rs_head; rs; rs = rs->next)
				if (head->rpcb_map.r_prog == rs->prog)
					break;
			if (rs == NULL) {
				rs = (struct rpcbdump_short *)
					malloc(sizeof (struct rpcbdump_short));
				if (rs == NULL)
					goto error;
				rs->next = NULL;
				if (rs_head == NULL) {
					rs_head = rs;
					rs_tail = rs;
				} else {
					rs_tail->next = rs;
					rs_tail = rs;
				}
				rs->prog = head->rpcb_map.r_prog;
				rs->owner = head->rpcb_map.r_owner;
				rs->nlist = NULL;
				rs->vlist = NULL;
			}
			if (add_version(rs, head->rpcb_map.r_vers) == FALSE)
				goto error;
			if (add_netid(rs, head->rpcb_map.r_netid) == FALSE)
				goto error;
		}
		(void) printf(
"   program version(s) netid(s)                         service     owner\n");
		for (rs = rs_head; rs; rs = rs->next) {
			int bytes_trans = 0;
			int len;

			(void) printf("%10ld  ", rs->prog);
			for (vl = rs->vlist; vl; vl = vl->next) {
				bytes_trans += (len = printf("%d", vl->vers))
				    < 0 ? 0 : len;
				if (vl->next)
					bytes_trans += (len = printf(",")) < 0
					    ? 0 : len;
			}
			/*
			 * If number of bytes transferred is less than 10,
			 * align 10 bytes for version(s) column. If bytes
			 * transferred is more than 10, add a trailing white
			 * space.
			 */
			if (bytes_trans < 10)
				(void) printf("%*s", (bytes_trans - 10), " ");
			else
				(void) printf(" ");

			bytes_trans = 0;
			for (nl = rs->nlist; nl; nl = nl->next) {
				bytes_trans += (len = printf("%s", nl->netid))
				    < 0 ? 0 : len;
				if (nl->next)
					bytes_trans += (len = printf(",")) < 0
					    ? 0 : len;
			}
			/*
			 * Align netid(s) column output for 32 bytes.
			 */
			if (bytes_trans < 32)
				(void) printf("%*s", (bytes_trans - 32), " ");

			rpc = getrpcbynumber(rs->prog);
			if (rpc)
				(void) printf(" %-11s", rpc->r_name);
			else
				(void) printf(" %-11s", "-");
			(void) printf(" %s\n", rs->owner);
		}
	}
	clnt_destroy(client);
	return;

error:	(void) fprintf(stderr, "rpcinfo: no memory\n");
}

static char nullstring[] = "\000";

static void
rpcbaddrlist(netid, argc, argv)
	char *netid;
	int argc;
	char **argv;
{
	rpcb_entry_list_ptr head = NULL;
	struct timeval minutetimeout;
	register CLIENT *client;
	struct rpcent *rpc;
	char *host;
	RPCB parms;
	struct netbuf *targaddr;

	if (argc != 3) {
		usage();
		exit(1);
	}
	host = argv[0];
	if (netid == NULL) {
	    if (loopback_netid == NULL) {
		client = clnt_rpcbind_create(host, RPCBVERS4, &targaddr);
	    } else {
		client = getclnthandle(host, loopback_nconf, RPCBVERS4,
			&targaddr);
		if (client == NULL && rpc_createerr.cf_stat ==
				RPC_N2AXLATEFAILURE) {
		    client = clnt_rpcbind_create(host, RPCBVERS4, &targaddr);
		}
	    }
	} else {
		struct netconfig *nconf;

		nconf = getnetconfigent(netid);
		if (nconf == NULL) {
			nc_perror("rpcinfo: invalid transport");
			exit(1);
		}
		client = getclnthandle(host, nconf, RPCBVERS4, &targaddr);
		if (nconf)
			(void) freenetconfigent(nconf);
	}
	if (client == (CLIENT *)NULL) {
		clnt_pcreateerror("rpcinfo: can't contact rpcbind");
		exit(1);
	}
	minutetimeout.tv_sec = 60;
	minutetimeout.tv_usec = 0;

	parms.r_prog = 	getprognum(argv[1]);
	parms.r_vers = 	getvers(argv[2]);
	parms.r_netid = client->cl_netid;
	if (targaddr == NULL) {
		parms.r_addr = nullstring;	/* for XDRing */
	} else {
		/*
		 * We also send the remote system the address we
		 * used to contact it in case it can help it
		 * connect back with us
		 */
		struct netconfig *nconf;

		nconf = getnetconfigent(client->cl_netid);
		if (nconf != NULL) {
			parms.r_addr = taddr2uaddr(nconf, targaddr);
			if (parms.r_addr == NULL)
				parms.r_addr = nullstring;
			freenetconfigent(nconf);
		} else {
			parms.r_addr = nullstring;	/* for XDRing */
		}
		free(targaddr->buf);
		free(targaddr);
	}
	parms.r_owner = nullstring;

	if (CLNT_CALL(client, RPCBPROC_GETADDRLIST, (xdrproc_t)xdr_rpcb,
		(char *)&parms, (xdrproc_t)xdr_rpcb_entry_list_ptr,
		(char *)&head, minutetimeout) != RPC_SUCCESS) {
		clnt_perror(client, "rpcinfo: can't contact rpcbind: ");
		exit(1);
	}
	if (head == NULL) {
		(void) printf("No remote programs registered.\n");
	} else {
		(void) printf(
	"   program vers  tp_family/name/class    address\t\t  service\n");
		for (; head != NULL; head = head->rpcb_entry_next) {
			rpcb_entry *re;
			char buf[128];

			re = &head->rpcb_entry_map;
			(void) printf("%10ld%3ld    ",
				parms.r_prog, parms.r_vers);
			(void) snprintf(buf, sizeof (buf), "%s/%s/%s ",
				re->r_nc_protofmly, re->r_nc_proto,
				re->r_nc_semantics == NC_TPI_CLTS ? "clts" :
				re->r_nc_semantics == NC_TPI_COTS ? "cots" :
						"cots_ord");
			(void) printf("%-24s", buf);
			(void) printf("%-24s", re->r_maddr);
			rpc = getrpcbynumber(parms.r_prog);
			if (rpc)
				(void) printf(" %-13s", rpc->r_name);
			else
				(void) printf(" %-13s", "-");
			(void) printf("\n");
		}
	}
	clnt_destroy(client);
}

/*
 * monitor rpcbind
 */
static void
rpcbgetstat(argc, argv)
	int argc;
	char **argv;
{
	rpcb_stat_byvers inf;
	struct timeval minutetimeout;
	register CLIENT *client;
	char *host;
	int i, j;
	rpcbs_addrlist *pa;
	rpcbs_rmtcalllist *pr;
	int cnt, flen;
#define	MAXFIELD	64
	char fieldbuf[MAXFIELD];
#define	MAXLINE		256
	char linebuf[MAXLINE];
	char *cp, *lp;
	char *pmaphdr[] = {
		"NULL", "SET", "UNSET", "GETPORT",
		"DUMP", "CALLIT"
	};
	char *rpcb3hdr[] = {
		"NULL", "SET", "UNSET", "GETADDR", "DUMP", "CALLIT", "TIME",
		"U2T", "T2U"
	};
	char *rpcb4hdr[] = {
		"NULL", "SET", "UNSET", "GETADDR", "DUMP", "CALLIT", "TIME",
		"U2T",  "T2U", "VERADDR", "INDRECT", "GETLIST", "GETSTAT"
	};

#define	TABSTOP	8

	if (argc >= 1) {
		host = argv[0];
	} else {
		host = HOST_SELF_CONNECT;
	}
	if (loopback_netid != NULL) {
		client = getclnthandle(host, loopback_nconf, RPCBVERS4, NULL);
		if (client == NULL && rpc_createerr.cf_stat ==
				RPC_N2AXLATEFAILURE) {
			client = clnt_rpcbind_create(host, RPCBVERS4, NULL);
		}
	} else {
		client = clnt_rpcbind_create(host, RPCBVERS4, NULL);
	}
	if (client == (CLIENT *)NULL) {
		clnt_pcreateerror("rpcinfo: can't contact rpcbind");
		exit(1);
	}
	minutetimeout.tv_sec = 60;
	minutetimeout.tv_usec = 0;
	(void) memset((char *)&inf, 0, sizeof (rpcb_stat_byvers));
	if (CLNT_CALL(client, RPCBPROC_GETSTAT, (xdrproc_t)xdr_void, NULL,
		(xdrproc_t)xdr_rpcb_stat_byvers, (char *)&inf, minutetimeout)
			!= RPC_SUCCESS) {
		clnt_perror(client, "rpcinfo: can't contact rpcbind: ");
		exit(1);
	}
	(void) printf("PORTMAP (version 2) statistics\n");
	lp = linebuf;
	for (i = 0; i <= rpcb_highproc_2; i++) {
		fieldbuf[0] = '\0';
		switch (i) {
		case PMAPPROC_SET:
			(void) sprintf(fieldbuf, "%d/",
				inf[RPCBVERS_2_STAT].setinfo);
			break;
		case PMAPPROC_UNSET:
			(void) sprintf(fieldbuf, "%d/",
				inf[RPCBVERS_2_STAT].unsetinfo);
			break;
		case PMAPPROC_GETPORT:
			cnt = 0;
			for (pa = inf[RPCBVERS_2_STAT].addrinfo; pa;
				pa = pa->next)
				cnt += pa->success;
			(void) sprintf(fieldbuf, "%d/", cnt);
			break;
		case PMAPPROC_CALLIT:
			cnt = 0;
			for (pr = inf[RPCBVERS_2_STAT].rmtinfo; pr;
				pr = pr->next)
				cnt += pr->success;
			(void) sprintf(fieldbuf, "%d/", cnt);
			break;
		default: break;  /* For the remaining ones */
		}
		cp = &fieldbuf[0] + strlen(fieldbuf);
		(void) sprintf(cp, "%d", inf[RPCBVERS_2_STAT].info[i]);
		flen = strlen(fieldbuf);
		(void) printf("%s%s", pmaphdr[i],
			spaces((int)((TABSTOP * (1 + flen / TABSTOP))
			- strlen(pmaphdr[i]))));
		(void) snprintf(lp, (MAXLINE - (lp - linebuf)), "%s%s",
			fieldbuf, spaces(cnt = ((TABSTOP * (1 + flen / TABSTOP))
			- flen)));
		lp += (flen + cnt);
	}
	(void) printf("\n%s\n\n", linebuf);

	if (inf[RPCBVERS_2_STAT].info[PMAPPROC_CALLIT]) {
		(void) printf("PMAP_RMTCALL call statistics\n");
		print_rmtcallstat(RPCBVERS_2_STAT, &inf[RPCBVERS_2_STAT]);
		(void) printf("\n");
	}

	if (inf[RPCBVERS_2_STAT].info[PMAPPROC_GETPORT]) {
		(void) printf("PMAP_GETPORT call statistics\n");
		print_getaddrstat(RPCBVERS_2_STAT, &inf[RPCBVERS_2_STAT]);
		(void) printf("\n");
	}

	(void) printf("RPCBIND (version 3) statistics\n");
	lp = linebuf;
	for (i = 0; i <= rpcb_highproc_3; i++) {
		fieldbuf[0] = '\0';
		switch (i) {
		case RPCBPROC_SET:
			(void) sprintf(fieldbuf, "%d/",
				inf[RPCBVERS_3_STAT].setinfo);
			break;
		case RPCBPROC_UNSET:
			(void) sprintf(fieldbuf, "%d/",
				inf[RPCBVERS_3_STAT].unsetinfo);
			break;
		case RPCBPROC_GETADDR:
			cnt = 0;
			for (pa = inf[RPCBVERS_3_STAT].addrinfo; pa;
				pa = pa->next)
				cnt += pa->success;
			(void) sprintf(fieldbuf, "%d/", cnt);
			break;
		case RPCBPROC_CALLIT:
			cnt = 0;
			for (pr = inf[RPCBVERS_3_STAT].rmtinfo; pr;
				pr = pr->next)
				cnt += pr->success;
			(void) sprintf(fieldbuf, "%d/", cnt);
			break;
		default: break;  /* For the remaining ones */
		}
		cp = &fieldbuf[0] + strlen(fieldbuf);
		(void) sprintf(cp, "%d", inf[RPCBVERS_3_STAT].info[i]);
		flen = strlen(fieldbuf);
		(void) printf("%s%s", rpcb3hdr[i],
			spaces((int)((TABSTOP * (1 + flen / TABSTOP))
			- strlen(rpcb3hdr[i]))));
		(void) snprintf(lp, (MAXLINE - (lp - linebuf)), "%s%s",
			fieldbuf, spaces(cnt = ((TABSTOP * (1 + flen / TABSTOP))
			- flen)));
		lp += (flen + cnt);
	}
	(void) printf("\n%s\n\n", linebuf);

	if (inf[RPCBVERS_3_STAT].info[RPCBPROC_CALLIT]) {
		(void) printf("RPCB_RMTCALL (version 3) call statistics\n");
		print_rmtcallstat(RPCBVERS_3_STAT, &inf[RPCBVERS_3_STAT]);
		(void) printf("\n");
	}

	if (inf[RPCBVERS_3_STAT].info[RPCBPROC_GETADDR]) {
		(void) printf("RPCB_GETADDR (version 3) call statistics\n");
		print_getaddrstat(RPCBVERS_3_STAT, &inf[RPCBVERS_3_STAT]);
		(void) printf("\n");
	}

	(void) printf("RPCBIND (version 4) statistics\n");

	for (j = 0; j <= 9; j += 9) { /* Just two iterations for printing */
		lp = linebuf;
		for (i = j; i <= MAX(8, rpcb_highproc_4 - 9 + j); i++) {
			fieldbuf[0] = '\0';
			switch (i) {
			case RPCBPROC_SET:
				(void) sprintf(fieldbuf, "%d/",
					inf[RPCBVERS_4_STAT].setinfo);
				break;
			case RPCBPROC_UNSET:
				(void) sprintf(fieldbuf, "%d/",
					inf[RPCBVERS_4_STAT].unsetinfo);
				break;
			case RPCBPROC_GETADDR:
				cnt = 0;
				for (pa = inf[RPCBVERS_4_STAT].addrinfo; pa;
					pa = pa->next)
					cnt += pa->success;
				(void) sprintf(fieldbuf, "%d/", cnt);
				break;
			case RPCBPROC_CALLIT:
				cnt = 0;
				for (pr = inf[RPCBVERS_4_STAT].rmtinfo; pr;
					pr = pr->next)
					cnt += pr->success;
				(void) sprintf(fieldbuf, "%d/", cnt);
				break;
			default: break;  /* For the remaining ones */
			}
			cp = &fieldbuf[0] + strlen(fieldbuf);
			/*
			 * XXX: We also add RPCBPROC_GETADDRLIST queries to
			 * RPCB_GETADDR because rpcbind includes the
			 * RPCB_GETADDRLIST successes in RPCB_GETADDR.
			 */
			if (i != RPCBPROC_GETADDR)
			    (void) sprintf(cp, "%d",
				inf[RPCBVERS_4_STAT].info[i]);
			else
			    (void) sprintf(cp, "%d",
			    inf[RPCBVERS_4_STAT].info[i] +
			    inf[RPCBVERS_4_STAT].info[RPCBPROC_GETADDRLIST]);
			flen = strlen(fieldbuf);
			(void) printf("%s%s", rpcb4hdr[i],
				spaces((int)((TABSTOP * (1 + flen / TABSTOP))
				- strlen(rpcb4hdr[i]))));
			(void) snprintf(lp, MAXLINE - (lp - linebuf), "%s%s",
				fieldbuf, spaces(cnt =
				((TABSTOP * (1 + flen / TABSTOP)) - flen)));
			lp += (flen + cnt);
		}
		(void) printf("\n%s\n", linebuf);
	}

	if (inf[RPCBVERS_4_STAT].info[RPCBPROC_CALLIT] ||
			    inf[RPCBVERS_4_STAT].info[RPCBPROC_INDIRECT]) {
		(void) printf("\n");
		(void) printf("RPCB_RMTCALL (version 4) call statistics\n");
		print_rmtcallstat(RPCBVERS_4_STAT, &inf[RPCBVERS_4_STAT]);
	}

	if (inf[RPCBVERS_4_STAT].info[RPCBPROC_GETADDR]) {
		(void) printf("\n");
		(void) printf("RPCB_GETADDR (version 4) call statistics\n");
		print_getaddrstat(RPCBVERS_4_STAT, &inf[RPCBVERS_4_STAT]);
	}
	clnt_destroy(client);
}

/*
 * Delete registeration for this (prog, vers, netid)
 */
static void
deletereg(netid, argc, argv)
	char *netid;
	int argc;
	char **argv;
{
	struct netconfig *nconf = NULL;

	if (argc != 2) {
		usage();
		exit(1);
	}
	if (netid) {
		nconf = getnetconfigent(netid);
		if (nconf == NULL) {
			(void) fprintf(stderr,
				"rpcinfo: netid %s not supported\n", netid);
			exit(1);
		}
	}
	if ((rpcb_unset(getprognum(argv[0]), getvers(argv[1]), nconf)) == 0) {
		(void) fprintf(stderr,
	"rpcinfo: Could not delete registration for prog %s version %s\n",
			argv[0], argv[1]);
		exit(1);
	}
}

/*
 * Create and return a handle for the given nconf.
 * Exit if cannot create handle.
 */
static CLIENT *
clnt_addr_create(address, nconf, prog, vers)
	char *address;
	struct netconfig *nconf;
	ulong_t prog;
	ulong_t vers;
{
	CLIENT *client;
	static struct netbuf *nbuf;
	static int fd = RPC_ANYFD;
	struct t_info tinfo;

	if (fd == RPC_ANYFD) {
		if ((fd = t_open(nconf->nc_device, O_RDWR, &tinfo)) == -1) {
			rpc_createerr.cf_stat = RPC_TLIERROR;
			rpc_createerr.cf_error.re_terrno = t_errno;
			clnt_pcreateerror("rpcinfo");
			exit(1);
		}
		/* Convert the uaddr to taddr */
		nbuf = uaddr2taddr(nconf, address);
		if (nbuf == NULL) {
			netdir_perror("rpcinfo");
			exit(1);
		}
	}
	client = clnt_tli_create(fd, nconf, nbuf, prog, vers, 0, 0);
	if (client == (CLIENT *)NULL) {
		clnt_pcreateerror("rpcinfo");
		exit(1);
	}
	return (client);
}

/*
 * If the version number is given, ping that (prog, vers); else try to find
 * the version numbers supported for that prog and ping all the versions.
 * Remote rpcbind is not contacted for this service. The requests are
 * sent directly to the services themselves.
 */
static void
addrping(address, netid, argc, argv)
	char *address;
	char *netid;
	int argc;
	char **argv;
{
	CLIENT *client;
	struct timeval to;
	enum clnt_stat rpc_stat;
	ulong_t prognum, versnum, minvers, maxvers;
	struct rpc_err rpcerr;
	int failure = 0;
	struct netconfig *nconf;
	int fd;

	if (argc < 1 || argc > 2 || (netid == NULL)) {
		usage();
		exit(1);
	}
	nconf = getnetconfigent(netid);
	if (nconf == (struct netconfig *)NULL) {
		(void) fprintf(stderr, "rpcinfo: Could not find %s\n", netid);
		exit(1);
	}
	to.tv_sec = 10;
	to.tv_usec = 0;
	prognum = getprognum(argv[0]);
	if (argc == 1) {	/* Version number not known */
		/*
		 * A call to version 0 should fail with a program/version
		 * mismatch, and give us the range of versions supported.
		 */
		versnum = MIN_VERS;
	} else {
		versnum = getvers(argv[1]);
	}
	client = clnt_addr_create(address, nconf, prognum, versnum);
	rpc_stat = CLNT_CALL(client, NULLPROC, (xdrproc_t)xdr_void,
			(char *)NULL, (xdrproc_t)xdr_void,
			(char *)NULL, to);
	if (argc == 2) {
		/* Version number was known */
		if (pstatus(client, prognum, versnum) < 0)
			failure = 1;
		(void) CLNT_DESTROY(client);
		if (failure)
			exit(1);
		return;
	}
	/* Version number not known */
	(void) CLNT_CONTROL(client, CLSET_FD_NCLOSE, (char *)NULL);
	(void) CLNT_CONTROL(client, CLGET_FD, (char *)&fd);
	if (rpc_stat == RPC_PROGVERSMISMATCH) {
		clnt_geterr(client, &rpcerr);
		minvers = rpcerr.re_vers.low;
		maxvers = rpcerr.re_vers.high;
	} else if (rpc_stat == RPC_SUCCESS) {
		/*
		 * Oh dear, it DOES support version 0.
		 * Let's try version MAX_VERS.
		 */
		(void) CLNT_DESTROY(client);
		client = clnt_addr_create(address, nconf, prognum, MAX_VERS);
		rpc_stat = CLNT_CALL(client, NULLPROC, (xdrproc_t)xdr_void,
				(char *)NULL, (xdrproc_t)xdr_void,
				(char *)NULL, to);
		if (rpc_stat == RPC_PROGVERSMISMATCH) {
			clnt_geterr(client, &rpcerr);
			minvers = rpcerr.re_vers.low;
			maxvers = rpcerr.re_vers.high;
		} else if (rpc_stat == RPC_SUCCESS) {
			/*
			 * It also supports version MAX_VERS.
			 * Looks like we have a wise guy.
			 * OK, we give them information on all
			 * 4 billion versions they support...
			 */
			minvers = 0;
			maxvers = MAX_VERS;
		} else {
			(void) pstatus(client, prognum, MAX_VERS);
			exit(1);
		}
	} else {
		(void) pstatus(client, prognum, (ulong_t)0);
		exit(1);
	}
	(void) CLNT_DESTROY(client);
	for (versnum = minvers; versnum <= maxvers; versnum++) {
		client = clnt_addr_create(address, nconf, prognum, versnum);
		rpc_stat = CLNT_CALL(client, NULLPROC, (xdrproc_t)xdr_void,
				(char *)NULL, (xdrproc_t)xdr_void,
				(char *)NULL, to);
		if (pstatus(client, prognum, versnum) < 0)
				failure = 1;
		(void) CLNT_DESTROY(client);
	}
	(void) t_close(fd);
	if (failure)
		exit(1);
}

/*
 * If the version number is given, ping that (prog, vers); else try to find
 * the version numbers supported for that prog and ping all the versions.
 * Remote rpcbind is *contacted* for this service. The requests are
 * then sent directly to the services themselves.
 */
static void
progping(netid, argc, argv)
	char *netid;
	int argc;
	char **argv;
{
	CLIENT *client;
	struct timeval to;
	enum clnt_stat rpc_stat;
	ulong_t prognum, versnum, minvers, maxvers;
	struct rpc_err rpcerr;
	int failure = 0;
	struct netconfig *nconf;

	if (argc < 2 || argc > 3 || (netid == NULL)) {
		usage();
		exit(1);
	}
	prognum = getprognum(argv[1]);
	if (argc == 2) { /* Version number not known */
		/*
		 * A call to version 0 should fail with a program/version
		 * mismatch, and give us the range of versions supported.
		 */
		versnum = MIN_VERS;
	} else {
		versnum = getvers(argv[2]);
	}
	if (netid) {
		nconf = getnetconfigent(netid);
		if (nconf == (struct netconfig *)NULL) {
			(void) fprintf(stderr,
				"rpcinfo: Could not find %s\n", netid);
			exit(1);
		}
		client = clnt_tp_create(argv[0], prognum, versnum, nconf);
	} else {
		client = clnt_create(argv[0], prognum, versnum, "NETPATH");
	}
	if (client == (CLIENT *)NULL) {
		clnt_pcreateerror("rpcinfo");
		exit(1);
	}
	to.tv_sec = 10;
	to.tv_usec = 0;
	rpc_stat = CLNT_CALL(client, NULLPROC, (xdrproc_t)xdr_void,
			(char *)NULL, (xdrproc_t)xdr_void,
			(char *)NULL, to);
	if (argc == 3) {
		/* Version number was known */
		if (pstatus(client, prognum, versnum) < 0)
			failure = 1;
		(void) CLNT_DESTROY(client);
		if (failure)
			exit(1);
		return;
	}
	/* Version number not known */
	if (rpc_stat == RPC_PROGVERSMISMATCH) {
		clnt_geterr(client, &rpcerr);
		minvers = rpcerr.re_vers.low;
		maxvers = rpcerr.re_vers.high;
	} else if (rpc_stat == RPC_SUCCESS) {
		/*
		 * Oh dear, it DOES support version 0.
		 * Let's try version MAX_VERS.
		 */
		versnum = MAX_VERS;
		(void) CLNT_CONTROL(client, CLSET_VERS, (char *)&versnum);
		rpc_stat = CLNT_CALL(client, NULLPROC,
				(xdrproc_t)xdr_void, (char *)NULL,
				(xdrproc_t)xdr_void, (char *)NULL, to);
		if (rpc_stat == RPC_PROGVERSMISMATCH) {
			clnt_geterr(client, &rpcerr);
			minvers = rpcerr.re_vers.low;
			maxvers = rpcerr.re_vers.high;
		} else if (rpc_stat == RPC_SUCCESS) {
			/*
			 * It also supports version MAX_VERS.
			 * Looks like we have a wise guy.
			 * OK, we give them information on all
			 * 4 billion versions they support...
			 */
			minvers = 0;
			maxvers = MAX_VERS;
		} else {
			(void) pstatus(client, prognum, MAX_VERS);
			exit(1);
		}
	} else {
		(void) pstatus(client, prognum, (ulong_t)0);
		exit(1);
	}
	for (versnum = minvers; versnum <= maxvers; versnum++) {
		(void) CLNT_CONTROL(client, CLSET_VERS, (char *)&versnum);
		rpc_stat = CLNT_CALL(client, NULLPROC, (xdrproc_t)xdr_void,
					(char *)NULL, (xdrproc_t)xdr_void,
					(char *)NULL, to);
		if (pstatus(client, prognum, versnum) < 0)
				failure = 1;
	}
	(void) CLNT_DESTROY(client);
	if (failure)
		exit(1);
}

static void
usage()
{
	(void) fprintf(stderr, "Usage: rpcinfo [-T netid] [-m | -s] [host]\n");
#ifdef PORTMAP
	(void) fprintf(stderr, "       rpcinfo -p [host]\n");
#endif
	(void) fprintf(stderr,
	    "       rpcinfo -T netid host prognum [versnum]\n");
	(void) fprintf(stderr,
	    "       rpcinfo -l [-T netid] host prognum versnum\n");
#ifdef PORTMAP
	(void) fprintf(stderr,
	    "       rpcinfo [-n portnum] -u | -t host prognum [versnum]\n");
#endif
	(void) fprintf(stderr,
	    "       rpcinfo -a serv_address -T netid prognum [versnum]\n");
	(void) fprintf(stderr,
	    "       rpcinfo -b [-T netid] prognum versnum\n");
	(void) fprintf(stderr,
	    "       rpcinfo -d [-T netid] prognum versnum\n");
}

static ulong_t
getprognum  (arg)
	char *arg;
{
	char *strptr;
	register struct rpcent *rpc;
	register ulong_t prognum;
	char *tptr = arg;

	while (*tptr && isdigit(*tptr++));
	if (*tptr || isalpha(*(tptr - 1))) {
		rpc = getrpcbyname(arg);
		if (rpc == NULL) {
			(void) fprintf(stderr,
				"rpcinfo: %s is unknown service\n", arg);
			exit(1);
		}
		prognum = rpc->r_number;
	} else {
		prognum = strtol(arg, &strptr, 10);
		if (strptr == arg || *strptr != '\0') {
			(void) fprintf(stderr,
		"rpcinfo: %s is illegal program number\n", arg);
			exit(1);
		}
	}
	return (prognum);
}

static ulong_t
getvers(arg)
	char *arg;
{
	char *strptr;
	register ulong_t vers;

	vers = (int)strtol(arg, &strptr, 10);
	if (strptr == arg || *strptr != '\0') {
		(void) fprintf(stderr,
			"rpcinfo: %s is illegal version number\n", arg);
		exit(1);
	}
	return (vers);
}

/*
 * This routine should take a pointer to an "rpc_err" structure, rather than
 * a pointer to a CLIENT structure, but "clnt_perror" takes a pointer to
 * a CLIENT structure rather than a pointer to an "rpc_err" structure.
 * As such, we have to keep the CLIENT structure around in order to print
 * a good error message.
 */
static int
pstatus(client, prog, vers)
	register CLIENT *client;
	ulong_t prog;
	ulong_t vers;
{
	struct rpc_err rpcerr;

	clnt_geterr(client, &rpcerr);
	if (rpcerr.re_status != RPC_SUCCESS) {
		clnt_perror(client, "rpcinfo");
		(void) printf("program %lu version %lu is not available\n",
			prog, vers);
		return (-1);
	} else {
		(void) printf("program %lu version %lu ready and waiting\n",
			prog, vers);
		return (0);
	}
}

static CLIENT *
clnt_rpcbind_create(host, rpcbversnum, targaddr)
	char *host;
	ulong_t rpcbversnum;
	struct netbuf **targaddr;
{
	static char *tlist[3] = {
		"circuit_n", "circuit_v", "datagram_v"
	};
	int i;
	struct netconfig *nconf;
	CLIENT *clnt = NULL;
	void *handle;

	rpc_createerr.cf_stat = RPC_SUCCESS;
	for (i = 0; i < 3; i++) {
		if ((handle = __rpc_setconf(tlist[i])) == NULL)
			continue;
		while (clnt == (CLIENT *)NULL) {
			if ((nconf = __rpc_getconf(handle)) == NULL) {
				if (rpc_createerr.cf_stat == RPC_SUCCESS)
				    rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
				break;
			}
			clnt = getclnthandle(host, nconf, rpcbversnum,
					targaddr);
		}
		if (clnt)
			break;
		__rpc_endconf(handle);
	}
	return (clnt);
}

static CLIENT*
getclnthandle(host, nconf, rpcbversnum, targaddr)
	char *host;
	struct netconfig *nconf;
	ulong_t rpcbversnum;
	struct netbuf **targaddr;
{
	struct netbuf *addr;
	struct nd_addrlist *nas;
	struct nd_hostserv rpcbind_hs;
	CLIENT *client = NULL;

	/* Get the address of the rpcbind */
	rpcbind_hs.h_host = host;
	rpcbind_hs.h_serv = "rpcbind";
	if (netdir_getbyname(nconf, &rpcbind_hs, &nas)) {
		rpc_createerr.cf_stat = RPC_N2AXLATEFAILURE;
		return (NULL);
	}
	addr = nas->n_addrs;
	client = clnt_tli_create(RPC_ANYFD, nconf, addr, RPCBPROG,
			rpcbversnum, 0, 0);
	if (client) {
		if (targaddr != NULL) {
			*targaddr =
			    (struct netbuf *)malloc(sizeof (struct netbuf));
			if (*targaddr != NULL) {
				(*targaddr)->maxlen = addr->maxlen;
				(*targaddr)->len = addr->len;
				(*targaddr)->buf = (char *)malloc(addr->len);
				if ((*targaddr)->buf != NULL) {
					(void) memcpy((*targaddr)->buf,
						addr->buf, addr->len);
				}
			}
		}
	} else {
		if (rpc_createerr.cf_stat == RPC_TLIERROR) {
			/*
			 * Assume that the other system is dead; this is a
			 * better error to display to the user.
			 */
			rpc_createerr.cf_stat = RPC_RPCBFAILURE;
			rpc_createerr.cf_error.re_status = RPC_FAILED;
		}
	}
	netdir_free((char *)nas, ND_ADDRLIST);
	return (client);
}

static void
print_rmtcallstat(rtype, infp)
	int rtype;
	rpcb_stat *infp;
{
	register rpcbs_rmtcalllist_ptr pr;
	struct rpcent *rpc;

	if (rtype == RPCBVERS_4_STAT)
		(void) printf(
		"prog\t\tvers\tproc\tnetid\tindirect success failure\n");
	else
		(void) printf("prog\t\tvers\tproc\tnetid\tsuccess\tfailure\n");
	for (pr = infp->rmtinfo; pr; pr = pr->next) {
		rpc = getrpcbynumber(pr->prog);
		if (rpc)
			(void) printf("%-16s", rpc->r_name);
		else
#if defined(_LP64) || defined(_I32LPx)
			(void) printf("%-16u", pr->prog);
		(void) printf("%u\t%u\t%-7s ",
#else
			(void) printf("%-16lu", pr->prog);
		(void) printf("%lu\t%lu\t%-7s ",
#endif
			pr->vers, pr->proc, pr->netid);
		if (rtype == RPCBVERS_4_STAT)
			(void) printf("%d\t ", pr->indirect);
		(void) printf("%d\t%d\n", pr->success, pr->failure);
	}
}

static void
/* LINTED E_FUNC_ARG_UNUSED for 1st arg rtype */
print_getaddrstat(rtype, infp)
	int rtype;
	rpcb_stat *infp;
{
	rpcbs_addrlist_ptr al;
	register struct rpcent *rpc;

	(void) printf("prog\t\tvers\tnetid\t  success\tfailure\n");
	for (al = infp->addrinfo; al; al = al->next) {
		rpc = getrpcbynumber(al->prog);
		if (rpc)
			(void) printf("%-16s", rpc->r_name);
		else
#if defined(_LP64) || defined(_I32LPx)
			(void) printf("%-16u", al->prog);
		(void) printf("%u\t%-9s %-12d\t%d\n",
#else
			(void) printf("%-16lu", al->prog);
		(void) printf("%lu\t%-9s %-12d\t%d\n",
#endif
			al->vers, al->netid,
			al->success, al->failure);
	}
}

static char *
spaces(howmany)
int howmany;
{
	static char space_array[] =		/* 64 spaces */
	"                                                                ";

	if (howmany <= 0 || howmany > sizeof (space_array)) {
		return ("");
	}
	return (&space_array[sizeof (space_array) - howmany - 1]);
}
