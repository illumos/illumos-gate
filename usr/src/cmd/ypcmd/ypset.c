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
 * This is a user command which issues a "Set domain binding" command to a
 * YP binder (ypbind) process
 *
 *	ypset [-h <host>] [-d <domainname>] server_to_use
 *
 * where host and server_to_use may be either names or internet addresses.
 */
#include <stdio.h>
#include <ctype.h>
#include <rpc/rpc.h>
#include <rpcsvc/ypclnt.h>
#include <rpcsvc/yp_prot.h>
#include "yp_b.h"
#include <sys/utsname.h>
extern CLIENT *__clnt_create_loopback();

#ifdef NULL
#undef NULL
#endif
#define	NULL 0

#define	TIMEOUT 30			/* Total seconds for timeout */

static char *pusage;
static char *domain = NULL;
static char default_domain_name[YPMAXDOMAIN];
static char default_host_name[256];
static char *host = NULL;
static char *server_to_use;
static struct timeval timeout = {
	TIMEOUT,			/* Seconds */
	0				/* Microseconds */
	};

static char err_usage_set[] =
"Usage:\n\
	ypset [ -h host ] [ -d domainname ] server_to_use\n\n";
static char err_bad_args[] =
	"Sorry, the %s argument is bad.\n";
static char err_cant_get_kname[] =
	"Sorry, can't get %s back from system call.\n";
static char err_null_kname[] =
	"Sorry, the %s hasn't been set on this machine.\n";
static char err_bad_hostname[] = "hostname";
static char err_bad_domainname[] = "domainname";
static char err_bad_server[] = "server_to_use";
static char err_tp_failure[] =
	"Sorry, I can't set up a connection to host %s.\n";
static char err_rpc_failure[] =
	"Sorry, I couldn't send my rpc message to ypbind on host %s.\n";
static char err_access_failure[] =
	"ypset: Sorry, ypbind on host %s has rejected your request.\n";

static void get_command_line_args();
static void send_message();

extern void exit();
extern int getdomainname();
extern int gethostname();
extern struct netconfig *getnetconfigent();
extern unsigned int strlen();

/*
 * This is the mainline for the ypset process.  It pulls whatever arguments
 * have been passed from the command line, and uses defaults for the rest.
 */

int
main(argc, argv)
	int argc;
	char **argv;

{
	get_command_line_args(argc, argv);

	if (!domain) {

		if (!getdomainname(default_domain_name, YPMAXDOMAIN)) {
			domain = default_domain_name;
		} else {
			(void) fprintf(stderr,
				err_cant_get_kname,
				err_bad_domainname);
			exit(1);
		}

		if ((int)strlen(domain) == 0) {
			(void) fprintf(stderr,
				err_null_kname,
				err_bad_domainname);
			exit(1);
		}
	}
	send_message();
	return (0);
}

/*
 * This does the command line argument processing.
 */
static void
get_command_line_args(argc, argv)
	int argc;
	char **argv;
{
	pusage = err_usage_set;
	argv++;

	while (--argc > 1) {

		if ((*argv)[0] == '-') {

			switch ((*argv)[1]) {

			case 'h': {

				if (argc > 1) {
					struct utsname utsname;

					argv++;
					argc--;
					(void) uname(&utsname);
					if (strcasecmp(utsname.nodename,
						*argv) != 0) {
						host = *argv;

						if ((int)strlen(host) > 256) {
							(void) fprintf(stderr,
	err_bad_args,
	err_bad_hostname);
							exit(1);
						}
					}
					argv++;

				} else {
					(void) fprintf(stderr, pusage);
					exit(1);
				}

				break;
			}

			case 'd': {

				if (argc > 1) {
					argv++;
					argc--;
					domain = *argv;
					argv++;

					if (strlen(domain) > YPMAXDOMAIN) {
						(void) fprintf(stderr,
	err_bad_args,
	err_bad_domainname);
						exit(1);
					}

				} else {
					(void) fprintf(stderr, pusage);
					exit(1);
				}

				break;
			}

			default: {
				(void) fprintf(stderr, pusage);
				exit(1);
			}

			}

		} else {
			(void) fprintf(stderr, pusage);
			exit(1);
		}
	}

	if (argc == 1) {

		if ((*argv)[0] == '-') {
			(void) fprintf(stderr, pusage);
			exit(1);
		}

		server_to_use = *argv;

		if ((int)strlen(server_to_use) > 256) {
			(void) fprintf(stderr, err_bad_args,
			    err_bad_server);
			exit(1);
		}

	} else {
		(void) fprintf(stderr, pusage);
		exit(1);
	}
}

/*
 * This takes the name of the YP host of interest, and fires off
 * the "set domain binding" message to the ypbind process.
 */

static void
send_message()
{
	CLIENT *server, *client;
	struct ypbind_setdom req;
	struct ypbind_binding ypbind_info;
	enum clnt_stat clnt_stat;
	struct netconfig *nconf;
	struct netbuf nbuf;
	int err;

	/*
	 * Open up a path to the server
	 */

	if ((server = clnt_create(server_to_use, YPPROG, YPVERS,
	    "datagram_n")) == NULL) {
		(void) fprintf(stderr, err_tp_failure, server_to_use);
		exit(1);
	}

	/* get nconf, netbuf structures */
	nconf = getnetconfigent(server->cl_netid);
	clnt_control(server, CLGET_SVC_ADDR, (char *)&nbuf);

	/*
	 * Open a path to host
	 */

	if (!host) {
		client = __clnt_create_loopback(YPBINDPROG, YPBINDVERS, &err);
		if (client == (CLIENT *)NULL) {
			clnt_pcreateerror("ypset: clnt_create");
			exit(1);
		}
		client->cl_auth = authsys_create("", geteuid(), 0, 0, NULL);
		if (client->cl_auth == NULL) {
			clnt_pcreateerror("ypset: clnt_create");
			exit(1);
		}
	} else {
		client = clnt_create(host, YPBINDPROG,
			YPBINDVERS, "datagram_n");
		if (client == (CLIENT *)NULL) {
			clnt_pcreateerror("ypset: clnt_create");
			exit(1);
		}
	}

	/*
	 * Load up the message structure and fire it off.
	 */
	ypbind_info.ypbind_nconf = nconf;
	ypbind_info.ypbind_svcaddr = (struct netbuf *)(&nbuf);
	ypbind_info.ypbind_servername = server_to_use;
	ypbind_info.ypbind_hi_vers = YPVERS;
	ypbind_info.ypbind_lo_vers = YPVERS;
	req.ypsetdom_bindinfo = &ypbind_info;
	req.ypsetdom_domain =  domain;

	clnt_stat = (enum clnt_stat) clnt_call(client,
	    YPBINDPROC_SETDOM, xdr_ypbind_setdom, (char *)&req, xdr_void, 0,
	    timeout);
	if (clnt_stat != RPC_SUCCESS) {
		if (clnt_stat == RPC_PROGUNAVAIL)
			(void) fprintf(stderr,
	err_access_failure, host ? host : "localhost");
		else
			(void) fprintf(stderr,
	err_rpc_failure, host ? host : "localhost");
		exit(1);
	}
	if (!host)
		auth_destroy((client)->cl_auth);
	(void) clnt_destroy(server);
	(void) clnt_destroy(client);
}
