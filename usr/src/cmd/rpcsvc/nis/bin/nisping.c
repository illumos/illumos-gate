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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	nisping.c
 *
 * This program will ping a server in an attempt to get it to resynchronize
 * with the master NIS+ server.  It also performs database checkpoints.
 */

#include <stdio.h>
#include <sys/types.h>
#include <rpc/types.h>
#include <rpc/rpc.h>
#include <rpc/clnt.h>
#include <rpcsvc/nis.h>
#include <sys/time.h>

extern void __nis_pingproc(nis_server *, nis_name, ulong_t);
extern bool_t xdr_nis_name();
extern bool_t xdr_cp_result();

#define	ROOT_OBJ "root.object"
extern nis_name __nis_local_root();

#define	NIS_PROG 100300
#define	NIS_VERSION 3
#define	NIS_CPTIME 18
#define	NIS_CHECKPOINT 19

/*
 * Return values (from the man page):
 *  -1		    No servers were  contacted,  or  the  server
 *		    specified  by the -H switch could not be con-
 *		    tacted.
 *
 *   0		    Success.
 *
 *   1		    Some, but not all, servers were  successfully
 *		    contacted.
 */
#define	PING_SUCCESS 0
#define	PING_SOME 1
#define	PING_NONE -1

/*
 * nis_checkpoint()
 *
 * This function will ask the indicated replicate to checkpoint itself
 */
static nis_error
nis_checkpnt(srv, name)
	nis_server	*srv;
	nis_name	name;
{
	CLIENT		*clnt;
	enum clnt_stat 	status;
	cp_result	res;
	struct timeval	tv;

	clnt = nis_make_rpchandle(srv, 0, NIS_PROG, NIS_VERSION,
				ZMH_DG|ZMH_AUTH|ZMH_NOFALLBACK, 1024, 512);
	/* If we can't contact it, return the safe answer */
	if (! clnt) {
		return (NIS_NAMEUNREACHABLE);
	}

	tv.tv_sec = 10;
	tv.tv_usec = 0;
	status = clnt_call(clnt, NIS_CHECKPOINT, xdr_nis_name, (char *)&name,
				xdr_cp_result, (char *)&res, tv);
	if (status != RPC_SUCCESS) {
		printf("nisping: RPC error on server %s, error %s\n",
					srv->name, clnt_sperrno(status));
		res.cp_status = NIS_RPCERROR;
	}
	clnt_destroy(clnt);
	return (res.cp_status);
}

/*
 * nis_cptime()
 *
 * This function will ask the indicated replicate for the last
 * update it has seen to the given directory.
 */
static nis_error
nis_cptime(srv, name, utime)
	nis_server	*srv;
	nis_name	name;
	ulong_t		*utime;
{
	CLIENT		*clnt;
	enum clnt_stat 	status;
	struct timeval	tv;
	nis_error	res;

	clnt = nis_make_rpchandle(srv, 0, NIS_PROG, NIS_VERSION,
				ZMH_DG|ZMH_AUTH|ZMH_NOFALLBACK, 1024, 512);

	/* If we can't contact it, return the safe answer */
	if (! clnt) {
		*utime = 0;
		return (NIS_RPCERROR);
	}
	/* Only wait 10 seconds */
	tv.tv_sec = 10;
	tv.tv_usec = 0;
	status = clnt_call(clnt, NIS_CPTIME, xdr_nis_name, (char *)&name,
					xdr_u_long, (char *)utime, tv);
	res = (status != RPC_SUCCESS) ? NIS_RPCERROR : NIS_SUCCESS;
	clnt_destroy(clnt);
	return (res);
}

static void
usage(s)
	char	*s;
{
	fprintf(stderr, "usage: %s [-uf] [-H hostname] [-r|directory]\n", s);
	fprintf(stderr, "       %s -C [-a] [-H hostname] [directory]\n", s);

	exit(PING_NONE);
}

static
int
match_host(char *host, char *target)
{
	int len = strlen(host);

	if (strncasecmp(host, target, len) == 0 &&
	    (target[len] == '.' || target[len] == '\0'))
		return (1);

	return (0);
}

extern int optind;
extern char *optarg;

int
main(int argc, char *argv[])
{
	nis_server 	*srvs;
	nis_object	*obj;
	int		c;
	int		i, ns, force = 0, uponly = 0;
	int		checkpoint_all = 0;
	int		chkpnt = 0;
	ulong_t		updtm, reptm;
	nis_error	status;
	nis_name	domain;
	char		dname[1024], obj_desc[1024];
	char		*host = NULL;
	nis_result	*res;
	int		root_object = 0;
	int		flag = EXPAND_NAME|USE_DGRAM;
	int		tries = 0;
	int		successes = 0;

	while ((c = getopt(argc, argv, "CH:ufra")) != -1) {
		switch (c) {
			case 'f':
				force = 1;
				break;
			case 'u':
				uponly = 1;
				break;
			case 'C' :
				chkpnt = 1;
				break;
			case 'H' :
				host = optarg;
				break;
			case 'r' :
				root_object = 1;
				break;
			case 'a' :
				checkpoint_all = 1;
				break;
			default :
				usage(argv[0]);
		}
	}

	if (optind < argc) {
		if (root_object)
			usage(argv[0]);
		domain = argv[optind];
	} else
		domain = nis_local_directory();

	if (chkpnt == 0 && checkpoint_all)
		usage(argv[0]);

	if (root_object) {
		if (chkpnt) {
			fprintf(stderr,
				"%s: no need to checkpoint root object.\n",
				argv[0]);
			usage(argv[0]);
		}
		domain = __nis_local_root();
		if (domain == 0) {
			fprintf(stderr,
				"%s: cannot get name of root directory.\n",
				argv[0]);
			exit(PING_NONE);
		}
	}

	if (!uponly)
		flag += MASTER_ONLY;
	res = nis_lookup(domain, flag);
	if (res->status != NIS_SUCCESS) {
		fprintf(stderr, "%s: %s\n", domain, nis_sperrno(res->status));
		exit(PING_NONE);
	}
	obj = res->objects.objects_val;
	sprintf(dname, "%s.%s", obj->zo_name, obj->zo_domain);
	if (__type_of(obj) != NIS_DIRECTORY_OBJ) {
		fprintf(stderr, "\"%s\" : not a directory.\n", dname);
		exit(PING_NONE);
	}
	srvs = obj->DI_data.do_servers.do_servers_val;
	ns = obj->DI_data.do_servers.do_servers_len;

	if (root_object)
		strcpy(obj_desc, "root object");
	else
		sprintf(obj_desc,  "directory %s", dname);

	if (host) { /* if a specific host has been specified */
		for (i = 0; i < ns; ++i) {
			if (match_host(host, srvs[i].name))
				break;
		}
		if (i == ns) {
			fprintf(stderr, "Host %s does not serve \"%s\".\n",
				    host, obj_desc);
			exit(PING_NONE);
		}
	}

	/* set real target name for root object. */
	if (root_object)
		strcpy(dname, ROOT_OBJ);

	if (! chkpnt && (ns == 1) && ! uponly) {
		printf("\"%s\" : no replicas\n", root_object? obj_desc : dname);
		exit(PING_NONE);
	}

	if (chkpnt)
		printf("Checkpointing %s serving directory \"%s\" :\n",
			(host) ? "host" : "replicas", dname);
	else if (uponly)
		printf("Last updates for \"%s\" : \n", obj_desc);
	else
		printf("Pinging %s serving \"%s\" :\n",
			(host) ? "host" : "replicas", obj_desc);

	printf("Master server is \"%s\"\n", srvs[0].name);
	status = nis_cptime(&srvs[0], dname, &updtm);
	if (status != NIS_SUCCESS)
		printf("\tUnable to fetch update time from master server.\n");
	else if (!updtm)
		printf("\tNo last update time available for \"%s\".\n",
		obj_desc);
	else
		printf("\tLast update occurred at %s\n",
						ctime((time_t *)&updtm));
	/*
	 * Need to increment success count if -H <master> or only 1 server.
	 */
	if ((!host || match_host(host, srvs[0].name)) &&
		(status == NIS_SUCCESS)) {
		tries++;
		successes++;
	}
	for (i = 0; i < ns; i++) {
		if (host && !match_host(host, srvs[i].name))
			continue;
		if ((i == 0) && ! chkpnt)
			continue;
		printf("%s server is \"%s\"\n", (i) ? "Replica" : "Master",
							srvs[i].name);
		if (chkpnt) {
			if (checkpoint_all)
				status = nis_checkpnt(&srvs[i], "");
			else
				status = nis_checkpnt(&srvs[i], dname);

			if (status != NIS_SUCCESS) {
				printf("checkpoint failed : %s\n",
					nis_sperrno(status));
			} else
				printf("checkpoint scheduled on \"%s\".\n",
					srvs[i].name);
		} else {
			status = nis_cptime(&srvs[i], dname, &reptm);
			if (status == NIS_SUCCESS) {
				if (!reptm)
				    printf(
				    "\tNo last update available for \"%s\".\n",
							    obj_desc);
				else
				    printf("\tLast Update seen was %s\n",
					    ctime((time_t *)&reptm));
				if (! uponly && updtm &&
				    ((reptm < updtm) || force)) {
					printf("\tPinging ...  \"%s\"\n",
							srvs[i].name);
					__nis_pingproc(&srvs[i], dname, updtm);
				}
			} else
				printf("\tUnavailable.\n\n");
		}
		tries++;
		if (status == NIS_SUCCESS) successes++;
	}
	if (successes == 0)
		exit(PING_NONE);
	if (successes < tries)
		exit(PING_SOME);
	return (PING_SUCCESS);
}
