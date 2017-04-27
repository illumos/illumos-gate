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
 * Copyright 2017 Joyent Inc
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * YP update service
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <rpc/rpc.h>
#include <rpc/nettype.h>
#include <rpcsvc/ypupd.h>
#include <rpcsvc/ypclnt.h>
#include <sys/debug.h>
#include <netdir.h>
#include <stropts.h>
#ifdef SYSLOG
#include <syslog.h>
#else
#define	LOG_ERR 1
#define	openlog(a, b, c)
#endif

#ifdef DEBUG
#define	RPC_SVC_FG
#define	debug(msg)	fprintf(stderr, "%s\n", msg);
#else
#define	debug(msg)	/* turn off debugging */
#endif

static char YPDIR[] = "/var/yp";
static char UPDATEFILE[] = "/var/yp/updaters";
#define	_RPCSVC_CLOSEDOWN 120

static int addr2netname();
static void closedown();
static void ypupdate_prog();
static void msgout();
static int update();
static int insecure;
static int _rpcpmstart;		/* Started by a port monitor ? */
static int _rpcsvcdirty;	/* Still serving ? */

extern unsigned int alarm();
extern void exit();
extern int close();
extern long fork();
extern int free();
extern struct netconfig *getnetconfigent();
extern int strcmp();
extern int strcpy();
extern int syslog();
extern void *signal();
extern int setsid();
extern int t_getinfo();
extern int user2netname();
extern int _openchild();

main(argc, argv)
	int argc;
	char *argv[];
{
	pid_t	pid;
	char *cmd;
	char mname[FMNAMESZ + 1];

	if (geteuid() != 0) {
		(void) fprintf(stderr, "must be root to run %s\n", argv[0]);
		exit(1);
	}

	cmd = argv[0];
	switch (argc) {
	case 0:
		cmd = "ypupdated";
		break;
	case 1:
		break;
	case 2:
		if (strcmp(argv[1], "-i") == 0) {
			insecure++;
			break;
		}
	default:
		fprintf(stderr, "%s: warning -- options ignored\n", cmd);
		break;
	}

	if (chdir(YPDIR) < 0) {
		fprintf(stderr, "%s: can't chdir to ", cmd);
		perror(YPDIR);
		exit(1);
	}

	if (!ioctl(0, I_LOOK, mname) &&
		(strcmp(mname, "sockmod") == 0 ||
				strcmp(mname, "timod") == 0)) {
		/*
		 * Started from port monitor: use 0 as fd
		 */
		char *netid;
		struct netconfig *nconf = NULL;
		SVCXPRT *transp;
		int pmclose;
		extern char *getenv();

		_rpcpmstart = 1;
		if ((netid = getenv("NLSPROVIDER")) == NULL) {
			msgout("cannot get transport name");
		}
		if ((nconf = getnetconfigent(netid)) == NULL) {
			msgout("cannot get transport info");
		}
		if (strcmp(mname, "sockmod") == 0) {
			if (ioctl(0, I_POP, 0) || ioctl(0, I_PUSH, "timod")) {
				msgout("could not get the right module");
				exit(1);
			}
		}
		pmclose = (t_getstate(0) != T_DATAXFER);
		if ((transp = svc_tli_create(0, nconf, NULL, 0, 0)) == NULL) {
			msgout("cannot create update server handle");
			exit(1);
		}
		if (!svc_reg(transp, YPU_PROG, YPU_VERS, ypupdate_prog, 0)) {
			msgout("unable to register (YPBINDPROG, YPBINDVERS).");
			exit(1);
		}
		if (nconf)
			freenetconfigent(nconf);

		if (pmclose) {
			(void) signal(SIGALRM, closedown);
			(void) alarm(_RPCSVC_CLOSEDOWN);
		}
		svc_run();
		exit(1);
	}
#ifndef RPC_SVC_FG
	/*
	 * Started from shell; background thyself and run
	 */
	pid = fork();

	if (pid < 0) {
		perror("cannot fork");
		exit(1);
	}
	if (pid)
		exit(0);
	closefrom(0);
	(void) setsid();
	openlog("ypupdated", LOG_PID, LOG_DAEMON);
#endif
	if (!svc_create(ypupdate_prog, YPU_PROG, YPU_VERS, "netpath")) {
		msgout("unable to create (YPU_PROG, YPU_VERS) for netpath.");
		exit(1);
	}

	svc_run();
	msgout("svc_run returned");
	exit(1);
	/* NOTREACHED */
}

static void
ypupdate_prog(rqstp, transp)
	struct svc_req *rqstp;
	SVCXPRT *transp;
{
	struct ypupdate_args args;
	uint_t rslt;
	uint_t op;
	char *netname;
	char namebuf[MAXNETNAMELEN+1];
	struct authunix_parms *aup;

	switch (rqstp->rq_proc) {
	case NULLPROC:
		svc_sendreply(transp, xdr_void, NULL);
		return;
	case YPU_CHANGE:
		op = YPOP_CHANGE;
		break;
	case YPU_DELETE:
		op = YPOP_DELETE;
		break;
	case YPU_INSERT:
		op = YPOP_INSERT;
		break;
	case YPU_STORE:
		op = YPOP_STORE;
		break;
	default:
		svcerr_noproc(transp);
		return;
	}
#ifdef DEBUG
	fprintf(stderr, "ypupdated: request received\n");
#endif
	switch (rqstp->rq_cred.oa_flavor) {
	case AUTH_DES:
		CTASSERT(sizeof (struct authdes_cred) <= RQCRED_SIZE);
		netname = ((struct authdes_cred *)
			rqstp->rq_clntcred)->adc_fullname.name;
		break;
	case AUTH_UNIX:
		if (insecure) {
			CTASSERT(sizeof (struct authunix_parms) <= RQCRED_SIZE);
			aup = (struct authunix_parms *)rqstp->rq_clntcred;
			if (aup->aup_uid == 0) {
				if (addr2netname(namebuf, transp) != 0) {
					fprintf(stderr,
						"addr2netname failing for %d\n",
						aup->aup_uid);
					svcerr_systemerr(transp);
					return;
				}
			} else {
				if (user2netname(namebuf, aup->aup_uid, NULL)
				    != 0) {
					fprintf(stderr,
						"user2netname failing for %d\n",
						aup->aup_uid);
					svcerr_systemerr(transp);
					return;
				}
			}
			netname = namebuf;
			break;
		}
	default:
		svcerr_weakauth(transp);
		return;
	}
	memset(&args, 0, sizeof (args));
	if (!svc_getargs(transp, xdr_ypupdate_args, (char *)&args)) {
		svcerr_decode(transp);
		return;
	}
#ifdef DEBUG
	fprintf(stderr, "netname = %s\n, map=%s\n key=%s\n",
		netname, args.mapname, args.key.yp_buf_val);
#endif
	rslt = update(netname, args.mapname, op,
		args.key.yp_buf_len, args.key.yp_buf_val,
		args.datum.yp_buf_len, args.datum.yp_buf_val);
	if (!svc_sendreply(transp, xdr_u_int, (char *)&rslt)) {
		debug("svc_sendreply failed");
	}
	if (!svc_freeargs(transp, xdr_ypupdate_args, (char *)&args)) {
		debug("svc_freeargs failed");
	}
}

/*
 * Determine if requester is allowed to update the given map,
 * and update it if so. Returns the yp status, which is zero
 * if there is no access violation.
 */
static
update(requester, mapname, op, keylen, key, datalen, data)
	char *requester;
	char *mapname;
	uint_t op;
	uint_t keylen;
	char *key;
	uint_t datalen;
	char *data;
{
	char updater[MAXMAPNAMELEN + 40];
	FILE *childargs;
	FILE *childrslt;
	int status;
	int yperrno = 0;
	int pid;

	sprintf(updater, "/usr/ccs/bin/make -s -f %s %s", UPDATEFILE, mapname);
#ifdef DEBUG
	fprintf(stderr, "updater: %s\n", updater);
	fprintf(stderr, "requestor = %s, op = %d, key = %s\n",
		requester, op, key);
	fprintf(stderr, "data = %s\n", data);
#endif
	pid = _openchild(updater, &childargs, &childrslt);
	if (pid < 0) {
		debug("openpipes failed");
		return (YPERR_YPERR);
	}

	/*
	 * Write to child
	 */
	fprintf(childargs, "%s\n", requester);
	fprintf(childargs, "%u\n", op);
	fprintf(childargs, "%u\n", keylen);
	fwrite(key, keylen, 1, childargs);
	fprintf(childargs, "\n");
	fprintf(childargs, "%u\n", datalen);
	fwrite(data, datalen, 1, childargs);
	fprintf(childargs, "\n");
	fclose(childargs);

	/*
	 * Read from child
	 */
	fscanf(childrslt, "%d", &yperrno);
	fclose(childrslt);

	wait(&status);
	if (!WIFEXITED(status)) {
		return (YPERR_YPERR);
	}
	return (yperrno);
}

static void
msgout(msg)
	char *msg;
{
	if (_rpcpmstart)
		syslog(LOG_ERR, msg);
	else
		(void) fprintf(stderr, "%s\n", msg);
}

void
closedown()
{
	if (_rpcsvcdirty == 0) {
		int i, openfd;
		struct t_info tinfo;

		if (t_getinfo(0, tinfo) || (tinfo.servtype == T_CLTS))
			exit(0);

		for (i = 0, openfd = 0; i < svc_max_pollfd && openfd < 2; i++)
			if (svc_pollfd[i].fd >= 0)
				openfd++;

		if (openfd <= 1)
			exit(0);
	}
	(void) alarm(_RPCSVC_CLOSEDOWN);
}

static int
addr2netname(namebuf, transp)
	char *namebuf;
	SVCXPRT *transp;
{
	struct nd_hostservlist *hostservs = NULL;
	struct netconfig *nconf;
	struct netbuf *who;

	who = svc_getrpccaller(transp);
	if ((who == NULL) || (who->len == 0))
		return (-1);
	if ((nconf = getnetconfigent(transp->xp_netid))
		== (struct netconfig *)NULL)
		return (-1);
	if (netdir_getbyaddr(nconf, &hostservs, who) != 0) {
		(void) freenetconfigent(nconf);
		return (-1);
	}
	if (hostservs == NULL) {
		msgout("ypupdated: netdir_getbyaddr failed\n");
	} else {
		strcpy(namebuf, hostservs->h_hostservs->h_host);
	}
	(void) freenetconfigent(nconf);
	netdir_free((char *)hostservs, ND_HOSTSERVLIST);
	return (0);
}
