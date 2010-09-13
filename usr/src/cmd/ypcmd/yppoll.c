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
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley
 * under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This is a user command which asks a particular ypserv which version of a
 * map it is using.  Usage is:
 *
 * yppoll [-h <host>] [-d <domainname>] mapname
 *
 * If the host is ommitted, the local host will be used.  If host is specified
 * as an internet address, no yp services need to be locally available.
 *
 */
#include <stdio.h>
#include <ctype.h>
#include <rpc/rpc.h>
#include <rpcsvc/ypclnt.h>
#include <rpcsvc/yp_prot.h>
#include <netdir.h>
#include <arpa/inet.h>
#include "yp_b.h"

#ifdef NULL
#undef NULL
#endif
#define	NULL 0

#define	TIMEOUT 30			/* Total seconds for timeout */

static int status = 0;				/* exit status */
static char *domain = NULL;
static char default_domain_name[YPMAXDOMAIN];
static char *map = NULL;
static char *host = NULL;
static char default_host_name[256];

static char err_usage[] =
"Usage:\n\
	yppoll [ -h host ] [ -d domainname ] mapname\n\n";
static char err_bad_args[] =
	"Bad %s argument.\n";
static char err_cant_get_kname[] =
	"Can't get %s back from system call.\n";
static char err_null_kname[] =
	"%s hasn't been set on this machine.\n";
static char err_bad_hostname[] = "hostname";
static char err_bad_mapname[] = "mapname";
static char err_bad_domainname[] = "domainname";
static char err_bad_resp[] =
	"Ill-formed response returned from ypserv on host %s.\n";

static void get_command_line_args();
static void getdomain();
static void getlochost();
static void getmapparms();
static void newresults();
static void getypserv();

extern void exit();
extern int getdomainname();
extern int gethostname();
extern unsigned int strlen();
extern int strcmp();

/*
 * This is the mainline for the yppoll process.
 */

int
main(argc, argv)
	int argc;
	char **argv;

{
	get_command_line_args(argc, argv);

	if (!domain) {
		getdomain();
	}

	if (!host) {
		getypserv();
	}

	getmapparms();
	return (status);
}

/*
 * This does the command line argument processing.
 */
static void
get_command_line_args(argc, argv)
	int argc;
	char **argv;

{
	argv++;

	while (--argc) {

		if ((*argv)[0] == '-') {

			switch ((*argv)[1]) {

			case 'h':

				if (argc > 1) {
					argv++;
					argc--;
					host = *argv;
					argv++;

					if ((int)strlen(host) > 256) {
						(void) fprintf(stderr,
						    err_bad_args,
						    err_bad_hostname);
						exit(1);
					}

				} else {
					(void) fprintf(stderr, err_usage);
					exit(1);
				}

				break;

			case 'd':

				if (argc > 1) {
					argv++;
					argc--;
					domain = *argv;
					argv++;

					if ((int)strlen(domain) > YPMAXDOMAIN) {
						(void) fprintf(stderr,
						    err_bad_args,
						    err_bad_domainname);
						exit(1);
					}

				} else {
					(void) fprintf(stderr, err_usage);
					exit(1);
				}

				break;

			default:
				(void) fprintf(stderr, err_usage);
				exit(1);

			}

		} else {
			if (!map) {
				map = *argv;

				if ((int)strlen(map) > YPMAXMAP) {
					(void) fprintf(stderr, err_bad_args,
					    err_bad_mapname);
					exit(1);
				}

			} else {
				(void) fprintf(stderr, err_usage);
				exit(1);
			}
		}
	}

	if (!map) {
		(void) fprintf(stderr, err_usage);
		exit(1);
	}
}

/*
 * This gets the local default domainname, and makes sure that it's set
 * to something reasonable.  domain is set here.
 */
static void
getdomain()
{
	if (!getdomainname(default_domain_name, YPMAXDOMAIN)) {
		domain = default_domain_name;
	} else {
		(void) fprintf(stderr, err_cant_get_kname, err_bad_domainname);
		exit(1);
	}

	if ((int)strlen(domain) == 0) {
		(void) fprintf(stderr, err_null_kname, err_bad_domainname);
		exit(1);
	}
}

/*
 * This gets the local hostname back from the kernel
 */
static void
getlochost()
{

	if (! gethostname(default_host_name, 256)) {
		host = default_host_name;
	} else {
		(void) fprintf(stderr, err_cant_get_kname, err_bad_hostname);
		exit(1);
	}
}

static void
getmapparms()
{
	CLIENT * map_clnt;
	struct ypresp_order oresp;
	struct ypreq_nokey req;
	struct ypresp_master mresp;
	struct ypresp_master *mresults = (struct ypresp_master *)NULL;
	struct ypresp_order *oresults = (struct ypresp_order *)NULL;

	struct timeval timeout;
	enum clnt_stat s;

	if ((map_clnt = clnt_create(host, YPPROG, YPVERS,
	    "netpath"))  == NULL) {
		(void) fprintf(stderr,
		    "Can't create connection to %s.\n", host);
		clnt_pcreateerror("Reason");
		exit(1);
	}

	timeout.tv_sec = TIMEOUT;
	timeout.tv_usec = 0;
	req.domain = domain;
	req.map = map;
	mresp.master = NULL;

	if (clnt_call(map_clnt, YPPROC_MASTER,  (xdrproc_t)xdr_ypreq_nokey,
		    (caddr_t)&req, (xdrproc_t)xdr_ypresp_master,
		    (caddr_t)&mresp, timeout) == RPC_SUCCESS) {
		mresults = &mresp;
		s = (enum clnt_stat) clnt_call(map_clnt, YPPROC_ORDER,
		    (xdrproc_t)xdr_ypreq_nokey, (char *)&req,
			(xdrproc_t)xdr_ypresp_order, (char *)&oresp, timeout);

		if (s == RPC_SUCCESS) {
			oresults = &oresp;
			newresults(mresults, oresults);
		} else {
			(void) fprintf(stderr,
		"Can't make YPPROC_ORDER call to ypserv at %s.\n	",
				host);
			clnt_perror(map_clnt, "Reason");
			exit(1);
		}

	} else {
		clnt_destroy(map_clnt);
	}
}

static void
newresults(m, o)
	struct ypresp_master *m;
	struct ypresp_order *o;
{
	char *s_domok = "Domain %s is supported.\n";
	char *s_ook = "Map %s has order number %d.\n";
	char *s_mok = "The master server is %s.\n";
	char *s_mbad = "Can't get master for map %s.\n	Reason:  %s\n";
	char *s_obad = "Can't get order number for map %s.\n	Reason:  %s\n";

	if (m->status == YP_TRUE && o->status == YP_TRUE) {
		(void) printf(s_domok, domain);
		(void) printf(s_ook, map, o->ordernum);
		(void) printf(s_mok, m->master);
	} else if (o->status == YP_TRUE)  {
		(void) printf(s_domok, domain);
		(void) printf(s_ook, map, o->ordernum);
		(void) fprintf(stderr, s_mbad, map,
		    yperr_string(ypprot_err(m->status)));
		status = 1;
	} else if (m->status == YP_TRUE)  {
		(void) printf(s_domok, domain);
		(void) fprintf(stderr, s_obad, map,
		    yperr_string(ypprot_err(o->status)));
		(void) printf(s_mok, m->master);
		status = 1;
	} else {
		(void) fprintf(stderr,
			"Can't get any map parameter information.\n");
		(void) fprintf(stderr, s_obad, map,
		    yperr_string(ypprot_err(o->status)));
		(void) fprintf(stderr, s_mbad, map,
		    yperr_string(ypprot_err(m->status)));
		status = 1;
	}
}

static void
getypserv()
{
	struct ypbind_resp response;
	struct ypbind_domain ypdomain;
	struct ypbind_binding *binding;
	static char hostbuf[256];

	getlochost();

	(void) memset((char *)&response, 0, sizeof (response));
	ypdomain.ypbind_domainname = domain;
	ypdomain.ypbind_vers = YPBINDVERS;
	(void) rpc_call(host, YPBINDPROG, YPBINDVERS, YPBINDPROC_DOMAIN,
	    xdr_ypbind_domain, (char *)&ypdomain, xdr_ypbind_resp,
	    (char *)&response, "netpath");
	if (response.ypbind_status != YPBIND_SUCC_VAL) {
		(void) fprintf(stderr, "couldn't get yp server - status %u\n",
		    response.ypbind_status);
		exit(1);
	}
	binding = response.ypbind_resp_u.ypbind_bindinfo;
	host = binding->ypbind_servername;

	/*
	 *  When ypbind is running in broadcast mode, it sets the
	 *  servername to "".  To get the real name of the server,
	 *  we need to do a host lookup on the svcaddr.  This code
	 *  is similar to code in ypwhich.
	 */
	if (strcmp(host, "") == 0) {
		struct nd_hostservlist *nhs;
		struct netconfig *nconf = binding->ypbind_nconf;
		struct netbuf *svcaddr = binding->ypbind_svcaddr;

		if (netdir_getbyaddr(nconf, &nhs, svcaddr) != ND_OK) {
			struct sockaddr_in *sa;

			sa = (struct sockaddr_in *)svcaddr->buf;

			strcpy(hostbuf, inet_ntoa(sa->sin_addr));
		} else {
			sprintf(hostbuf, "%s", nhs->h_hostservs->h_host);
		}
		host = hostbuf;
		netdir_free((char *)nhs, ND_HOSTSERVLIST);
	}
}
