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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, 2016 by Delphix. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <string.h>
#include <syslog.h>
#include <sys/param.h>
#include <rpc/rpc.h>
#include <sys/stat.h>
#include <netconfig.h>
#include <netdir.h>

#include <sys/file.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <rpcsvc/mount.h>

#include <signal.h>
#include <locale.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <thread.h>
#include <assert.h>

#include <limits.h>

#define	TESTPROG	987654

uint32_t test_vers_max = 2;
uint32_t test_vers_min = 1;

int debug;
int verbose;
int testd_port;

static void mysvc(struct svc_req *, SVCXPRT *);
static void bind2(void);

/*
 * This function is called for each configured network type to
 * bind and register our RPC service programs.
 *
 * On TCP or UDP, we want to bind TESTPROG on a specific port
 * (when testd_port is specified) in which case we'll use the
 * variant of svc_tp_create() that lets us pass a bind address.
 */
static void
test_svc_tp_create(struct netconfig *nconf)
{
	char port_str[8];
	struct nd_hostserv hs;
	struct nd_addrlist *al = NULL;
	SVCXPRT *xprt = NULL;
	rpcvers_t vers;

	vers = test_vers_max;

	/*
	 * If testd_port is set and this is an inet transport,
	 * bind this service on the specified port.
	 */
	if (testd_port != 0 &&
	    (strcmp(nconf->nc_protofmly, NC_INET) == 0 ||
	    strcmp(nconf->nc_protofmly, NC_INET6) == 0)) {
		int err;

		snprintf(port_str, sizeof (port_str), "%u",
		    (unsigned short)testd_port);

		hs.h_host = HOST_SELF_BIND;
		hs.h_serv = port_str;
		err = netdir_getbyname((struct netconfig *)nconf, &hs, &al);
		if (err == 0 && al != NULL) {
			xprt = svc_tp_create_addr(mysvc, TESTPROG, vers,
			    nconf, al->n_addrs);
			netdir_free(al, ND_ADDRLIST);
		}
		if (xprt == NULL) {
			printf("testd: unable to create "
			    "(TESTD,%d) on transport %s (port %d)\n",
			    (int)vers, nconf->nc_netid, testd_port);
		}
		/* fall-back to default bind */
	}
	if (xprt == NULL) {
		/*
		 * Had testd_port=0, or non-inet transport,
		 * or the bind to a specific port failed.
		 * Do a default bind.
		 */
		xprt = svc_tp_create(mysvc, TESTPROG, vers, nconf);
	}
	if (xprt == NULL) {
		printf("testd: unable to create "
		    "(TESTD,%d) on transport %s\n",
		    (int)vers, nconf->nc_netid);
		return;
	}

	/*
	 * Register additional versions on this transport.
	 */
	while (--vers >= test_vers_min) {
		if (!svc_reg(xprt, TESTPROG, vers, mysvc, nconf)) {
			printf("testd: "
			    "failed to register vers %d on %s\n",
			    (int)vers, nconf->nc_netid);
		}
	}
}

static void
test_svc_unreg(void)
{
	rpcvers_t vers;

	for (vers = test_vers_min; vers <= test_vers_max; vers++)
		svc_unreg(TESTPROG, vers);
}

int
main(int argc, char *argv[])
{
	int	c;
	bool_t	exclbind = TRUE;
	int tmp;
	struct netconfig *nconf;
	NCONF_HANDLE *nc;

	while ((c = getopt(argc, argv, "dvp:")) != EOF) {
		switch (c) {
		case 'd':
			debug++;
			break;
		case 'v':
			verbose++;
			break;
		case 'p':
			(void) sscanf(optarg, "%d", &tmp);
			if (tmp < 1 || tmp > UINT16_MAX) {
				(void) fprintf(stderr,
				    "testd: -P port invalid.\n");
				return (1);
			}
			testd_port = tmp;
			break;
		default:
			fprintf(stderr, "usage: testd [-v] [-r]\n");
			exit(1);
		}
	}

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Prevent our non-priv udp and tcp ports bound w/wildcard addr
	 * from being hijacked by a bind to a more specific addr.
	 */
	if (!rpc_control(__RPC_SVC_EXCLBIND_SET, &exclbind)) {
		fprintf(stderr, "warning: unable to set udp/tcp EXCLBIND\n");
	}

	if (testd_port < 0 || testd_port > UINT16_MAX) {
		fprintf(stderr, "unable to use specified port\n");
		exit(1);
	}

	/*
	 * Make sure to unregister any previous versions in case the
	 * user is reconfiguring the server in interesting ways.
	 */
	test_svc_unreg();

	/*
	 * Enumerate network transports and create service listeners
	 * as appropriate for each.
	 */
	if ((nc = setnetconfig()) == NULL) {
		perror("setnetconfig failed");
		return (-1);
	}
	while ((nconf = getnetconfig(nc)) != NULL) {
		/*
		 * Skip things like tpi_raw, invisible...
		 */
		if ((nconf->nc_flag & NC_VISIBLE) == 0)
			continue;
		if (nconf->nc_semantics != NC_TPI_CLTS &&
		    nconf->nc_semantics != NC_TPI_COTS &&
		    nconf->nc_semantics != NC_TPI_COTS_ORD)
			continue;

		test_svc_tp_create(nconf);
	}
	(void) endnetconfig(nc);

	/*
	 * XXX: Normally would call svc_run() here, but
	 * we just want to check our IP bindings.
	 */
	if (testd_port != 0)
		bind2();

	if (debug) {
		char sysbuf[100];

		snprintf(sysbuf, sizeof (sysbuf),
		    "rpcinfo -p |grep %u", TESTPROG);
		printf("x %s\n", sysbuf);
		fflush(stdout);
		system(sysbuf);

		if (testd_port) {
			snprintf(sysbuf, sizeof (sysbuf),
			    "netstat -a -f inet -P udp |grep %u", testd_port);
			printf("x %s\n", sysbuf);
			fflush(stdout);
			system(sysbuf);

			snprintf(sysbuf, sizeof (sysbuf),
			    "netstat -a -f inet -P tcp |grep %u", testd_port);
			printf("x %s\n", sysbuf);
			fflush(stdout);
			system(sysbuf);
		}
	}

	/* cleanup */
	test_svc_unreg();

	printf("%s complete\n", argv[0]);
	return (0);
}

/*
 * Server procedure switch routine
 */
static void
mysvc(struct svc_req *rq, SVCXPRT *xprt)
{

	switch (rq->rq_proc) {
	case NULLPROC:
		errno = 0;
		(void) svc_sendreply(xprt, xdr_void, (char *)0);
		return;

	default:
		svcerr_noproc(xprt);
		return;
	}
}

struct sockaddr_in addr;

/*
 * The actual test: Try doing a 2nd bind with a specific IP.
 * The exclusive wildcard bind should prvent this.
 */
static void
bind2(void)
{
	int ret;
	int sock;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(testd_port);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		fprintf(stderr, "bind2 socket fail %s\n",
		    strerror(errno));
		exit(1);
	}

	ret = bind(sock, (struct sockaddr *)&addr, sizeof (addr));
	if (ret == -1) {
		fprintf(stderr, "bind2 bind fail %s (expected) PASS\n",
		    strerror(errno));
		close(sock);
		return;
	}

	printf("Oh no, bind2 worked! test FAILED\n");
	close(sock);
}
