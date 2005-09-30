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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <signal.h>
#include <sys/stat.h>
#include <rpc/rpc.h>
#include <memory.h>
#include <netconfig.h>
#include <stropts.h>
#include <syslog.h>
#include <utmpx.h>
#include <rpcsvc/rusers.h>
#include <sys/resource.h>
#include <limits.h>

#ifdef	DEBUG
#define	RPC_SVC_FG
#endif

#define	_RPCSVC_CLOSEDOWN 120

static void rusers_service();
static void closedown();
static void msgout();
static unsigned min();

static int _rpcpmstart;		/* Started by a port monitor ? */
static int _rpcfdtype;		/* Whether Stream or Datagram ? */
static int _rpcsvcdirty;	/* Still serving ? */
static int _rpcsvcrecent;	/* set when we serivce a request; tested */
				/* and cleared by closedown() routine */

#define	DIV60(t)	((t+30)/60)	/* x/60 rounded */

#define	ALL_ENTRIES	1
#define	REAL_USERS	0

utmp_array utmp_array_res;
int used_array_len = 0;
struct utmpidlearr utmpidlearr;

static void free_ua_entry(rusers_utmp *uap);
static int findidle(char *name, int ln, time_t	now);
static void usys5to_ru(struct utmpx *s5, struct ru_utmp *bss);

int
main(int argc, char *argv[])
{
	pid_t pid;
	int i;
	int connmaxrec = RPC_MAXDATASIZE;

	/*
	 * Set non-blocking mode and maximum record size for
	 * connection oriented RPC transports.
	 */
	if (!rpc_control(RPC_SVC_CONNMAXREC_SET, &connmaxrec)) {
		msgout("unable to set maximum RPC record size");
	}

	/*
	 * If stdin looks like a TLI endpoint, we assume
	 * that we were started by a port monitor. If
	 * t_getstate fails with TBADF, this is not a
	 * TLI endpoint.
	 */
	if (t_getstate(0) != -1 || t_errno != TBADF) {
		char *netid;
		struct netconfig *nconf = NULL;
		SVCXPRT *transp;
		int pmclose;
		extern char *getenv();

		_rpcpmstart = 1;
		openlog("rusers", LOG_PID, LOG_DAEMON);
		if ((netid = getenv("NLSPROVIDER")) == NULL) {
#ifdef DEBUG
			msgout("cannot get transport name");
#endif
		} else if ((nconf = getnetconfigent(netid)) == NULL) {
#ifdef DEBUG
			msgout("cannot get transport info");
#endif
		}
		if ((transp = svc_tli_create(0, nconf, NULL, 0, 0)) == NULL) {
			msgout("cannot create server handle");
			exit(1);
		}
		if (nconf)
			freenetconfigent(nconf);
		if (!svc_reg(transp, RUSERSPROG, RUSERSVERS_3, rusers_service,
				0)) {
	msgout("unable to register (RUSERSPROG, RUSERSVERS_3).");
			exit(1);
		}
		if (!svc_reg(transp, RUSERSPROG, RUSERSVERS_IDLE,
				rusers_service, 0)) {
	msgout("unable to register (RUSERSPROG, RUSERSVERS_IDLE).");
			exit(1);
		}
		(void) signal(SIGALRM, closedown);
		(void) alarm(_RPCSVC_CLOSEDOWN);
		svc_run();
		msgout("svc_run returned");
		exit(1);
		/* NOTREACHED */
	}
#ifndef RPC_SVC_FG
	pid = fork();
	if (pid < 0) {
		perror("rpc.rusersd: cannot fork");
		exit(1);
	}
	if (pid)
		exit(0);
	for (i = 0; i < 20; i++)
		(void) close(i);
	setsid();
	openlog("rusers", LOG_PID, LOG_DAEMON);
#endif
	if (!svc_create(rusers_service, RUSERSPROG, RUSERSVERS_3, "netpath")) {
	    msgout("unable to create (RUSERSPROG, RUSERSVERS_3) for netpath");
		exit(1);
	}
	if (!svc_create(rusers_service, RUSERSPROG, RUSERSVERS_IDLE,
			"netpath")) {
	    msgout(
		"unable to create (RUSERSPROG, RUSERSVERS_IDLE) for netpath");
		exit(1);
	}

	svc_run();
	msgout("svc_run returned");
	return (1);
}


/*
 * This routine gets the user information.
 * "all" specifies whether all listings should be counted, or only those of
 *	type "USER_PROCESS".
 * "version" is either RUSERSVERS_IDLE or RUSERSVERS_3.  If anything else,
 *	just a count is returned.
 * "limit" specifies the maximum number of entries to be processed.
 *
 * For both versions, the results are placed into an external variable.
 * For RUSERSVERS_IDLE, this routine mallocs entries in a vector as it
 * processed each utmpx entry.  These malloc'd entries must be freed after the
 * results are returned.
 * For RUSERSVERS_3, this routine uses array entries that are malloc'd prior
 * to this routine being called. "limit" is the number of elements available.
 */
int
getutmpx_3(all, version, limit)
	int all;		/* give all listings? */
	int version;		/* version 2 or 3 */
	int limit;		/* limits users returned, 0 means no limit */
{
	struct utmpx *utent;
	struct utmpidle **q = utmpidlearr.uia_arr;
	int minidle;
	int cnt = 0;
	time_t now;
	extern char *s_malodup();

	time(&now);		/* only one call to time() for this rpc call */
	setutxent();		/* reset the utmpx file */
	while ((utent = getutxent()) != NULL && (limit == 0 || cnt < limit)) {
		if (utent->ut_line[0] == '\0' || utent->ut_user[0] == '\0')
			continue;
		/*
		 * List only user processes.
		 * XXX modified to exclude cmdtool style window entries.
		 */
		if ((all == REAL_USERS) && ((utent->ut_type != USER_PROCESS) ||
		    nonuserx(*utent)))
			continue;

		if (version == RUSERSVERS_IDLE) {
			/*
			 * need to free this; done after svc_sendreply.
			 */
			*q = (struct utmpidle *)
				malloc(sizeof (struct utmpidle));
			(*q)->ui_idle = findidle(utent->ut_line,
						sizeof (utent->ut_line), now);
			if (strncmp(utent->ut_line, "console",
				strlen("console")) == 0) {
				(*q)->ui_idle = min((*q)->ui_idle,
					console_idle(now));
			}
			usys5to_ru(utent, &((*q)->ui_utmp));
#ifdef DEBUG
			printf("%-*s %-*s  %s; idle %d",
			    sizeof (utent->ut_line),
			    utent->ut_line,
			    sizeof (utent->ut_name),
			    utent->ut_name,
			    ctime(&utent->ut_xtime),
			    (*q)->ui_idle);
#endif
			q++;
		} else if (version == RUSERSVERS_3) {
#define	uav	utmp_array_res.utmp_array_val

			uav[cnt].ut_host =
				s_malodup(utent->ut_host, utent->ut_syslen);
			uav[cnt].ut_user = s_malodup(utent->ut_user,
				sizeof (utent->ut_user));
			uav[cnt].ut_line = s_malodup(utent->ut_line,
				sizeof (utent->ut_line));
			uav[cnt].ut_type = utent->ut_type;
			uav[cnt].ut_time = utent->ut_xtime;
			uav[cnt].ut_idle = findidle(utent->ut_line,
						sizeof (utent->ut_line), now);
			if (strncmp(utent->ut_line, "console",
				strlen("console")) == 0) {
				uav[cnt].ut_idle =
					min(uav[cnt].ut_idle,
							console_idle(now));
			}
#ifdef DEBUG
			printf("user: %-10s line: %-10s  %s; idle %d (%s)\n",
					uav[cnt].ut_line, uav[cnt].ut_user,
					ctime((time_t *)&uav[cnt].ut_time),
					uav[cnt].ut_idle, uav[cnt].ut_host);
#endif
#undef	uav
		}
		cnt++;
	}
	return (cnt);
}

/*
 * "string" is a character array with maximum size "size".  Return a
 * malloc'd string that's a duplicate of the string.
 */
char *
s_malodup(string, size)
char *string;
int size;
{
	char *tmp;

	tmp = (char *)malloc(size+1);
	if (tmp == NULL) {
		msgout("rpc.rusersd: malloc failed (2)");
		return (NULL);
	}
	strncpy(tmp, string, size);
	tmp[size] = '\0';
	return (tmp);
}


int
console_idle(now)
	time_t now;
{
	/*
	 * On the console, the user may be running a window system; if so,
	 * their activity will show up in the last-access times of
	 * "/dev/kbd" and "/dev/mouse", so take the minimum of the idle
	 * times on those two devices and "/dev/console" and treat that as
	 * the idle time.
	 */
	return (min((unsigned)findidle("kbd", strlen("kbd"), now),
		(unsigned)findidle("mouse", strlen("mouse"), now)));
}

static void
rusers_service(rqstp, transp)
	register struct svc_req *rqstp;
	register SVCXPRT *transp;
{
	int i;
	int cnt;
	char *replyerr = "rpc.rusersd: error replying to request";

	_rpcsvcrecent = _rpcsvcdirty = 1;
	switch (rqstp->rq_proc) {
	case 0:
		if (svc_sendreply(transp, xdr_void, 0) == FALSE) {
			msgout(replyerr);
		}
		break;
	case RUSERSPROC_NUM:
		cnt = getutmpx_3(REAL_USERS, 0, 0);
		if (!svc_sendreply(transp, xdr_u_long, (caddr_t)&cnt))
			msgout(replyerr);
		break;
	case RUSERSPROC_NAMES:
	case RUSERSPROC_ALLNAMES:
		if (rqstp->rq_vers == RUSERSVERS_IDLE) {
			utmpidlearr.uia_arr = (struct utmpidle **)
				malloc(MAXUSERS*sizeof (struct utmpidle *));
			utmpidlearr.uia_cnt = getutmpx_3(rqstp->rq_proc ==
				RUSERSPROC_ALLNAMES,
				RUSERSVERS_IDLE, MAXUSERS);
			if (!svc_sendreply(transp, xdr_utmpidlearr,
					(caddr_t)&utmpidlearr))
				msgout(replyerr);
			for (i = 0; i < utmpidlearr.uia_cnt; i++) {
				free(utmpidlearr.uia_arr[i]);
			}
			free(utmpidlearr.uia_arr);
		} else if (rqstp->rq_vers == RUSERSVERS_3) {
			int entries, alloc_array_len;

			/*
			 * Always free strings from previous results array
			 */
			for (i = 0; i < used_array_len; i++) {
			free_ua_entry(&utmp_array_res.utmp_array_val[i]);
			}
			entries = (rqstp->rq_proc == RUSERSPROC_ALLNAMES);
			cnt = getutmpx_3(entries, 0, 0);	/* get cnt */
			if (cnt > utmp_array_res.utmp_array_len) {
				free(utmp_array_res.utmp_array_val);
				utmp_array_res.utmp_array_len = 0;
				utmp_array_res.utmp_array_val = (rusers_utmp *)
					malloc(cnt * sizeof (rusers_utmp));
				if (utmp_array_res.utmp_array_val == NULL) {
				    msgout("rpc.rusersd: malloc failed (1)");
				    break;
				}
				alloc_array_len = cnt;
			} else {
				alloc_array_len = utmp_array_res.utmp_array_len;
			}
			cnt = getutmpx_3(entries, RUSERSVERS_3, cnt);
			utmp_array_res.utmp_array_len = used_array_len = cnt;
			if (!svc_sendreply(transp, xdr_utmp_array,
					(caddr_t)&utmp_array_res))
				msgout(replyerr);
			utmp_array_res.utmp_array_len = alloc_array_len;
		}
		break;
	default:
		svcerr_noproc(transp);
		break;
	}
	_rpcsvcdirty = 0;

}

static void
free_ua_entry(rusers_utmp *uap)
{
	if (uap == NULL)
		return;
	if (uap->ut_user)
		free(uap->ut_user);
	if (uap->ut_line)
		free(uap->ut_line);
	if (uap->ut_host)
		free(uap->ut_host);
}



/* find & return number of minutes current tty has been idle */
static int
findidle(char *name, int ln, time_t	now)
{
	struct stat stbuf;
	long lastaction, diff;
	char ttyname[32];

	strcpy(ttyname, "/dev/");
	strncat(ttyname, name, ln);
	if (stat(ttyname, &stbuf) < 0)
		return (INT_MAX);
	lastaction = stbuf.st_atime;
	diff = now - lastaction;
	diff = DIV60(diff);
	if (diff < 0) diff = 0;
	return (diff);
}

static void
usys5to_ru(struct utmpx *s5, struct ru_utmp *bss)
{
	int i;

#ifdef DEBUG
	printf("sizeof (bss->ut_host) == %d\n", sizeof (bss->ut_host));
#endif
	strncpy(bss->ut_name, s5->ut_name, sizeof (bss->ut_name));
	strncpy(bss->ut_line, s5->ut_line, sizeof (bss->ut_line));
	strncpy(bss->ut_host, s5->ut_host, sizeof (bss->ut_host));
	bss->ut_time = s5->ut_xtime;
}

static void
msgout(msg)
	char *msg;
{
#ifdef RPC_SVC_FG
	if (_rpcpmstart)
		syslog(LOG_ERR, msg);
	else
		(void) fprintf(stderr, "%s\n", msg);
#else
	syslog(LOG_ERR, msg);
#endif
}

static void
closedown(sig)
int sig;
{
	if (_rpcsvcrecent) {
		_rpcsvcrecent = 0;
	} else {
		if (_rpcsvcdirty == 0) {
			int i, openfd;
			struct t_info tinfo;

			if (t_getinfo(0, &tinfo) || (tinfo.servtype == T_CLTS))
				exit(0);

			for (i = 0, openfd = 0;
					i < svc_max_pollfd && openfd < 2;
					i++) {
				if (svc_pollfd[i].fd >= 0)
					openfd++;
			}

			if (openfd <= 1)
				exit(0);
		}
	}
	(void) signal(SIGALRM, closedown);
	(void) alarm(_RPCSVC_CLOSEDOWN);
}

unsigned
min(a, b)
unsigned a;
unsigned b;
{
	if (a < b)
		return (a);
	else
		return (b);
}
