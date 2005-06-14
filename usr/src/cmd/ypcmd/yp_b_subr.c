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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
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

#include "ypsym.h"
#include <stdlib.h>
#include "yp_b.h"
#include <string.h>
#include <limits.h>
#include <netconfig.h>
#include <netdir.h>
#include <rpc/clnt.h>
#include <syslog.h>
#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/statvfs.h>
#include <rpcsvc/nis.h>
#include <sys/systeminfo.h>

#ifndef NULL
#define	NULL	0
#endif

#define	YPSERVERS	"ypservers"

void ypbind_init_default();
static int ypbind_pipe_setdom();

static bool firsttime = TRUE;
static struct domain *known_domains;

extern struct netconfig *__rpc_getconf();
extern void *__rpc_setconf(), *__rpc_endconf();
extern CLIENT *__clnt_tp_create_bootstrap();
extern char *inet_ntoa();
extern int __rpc_get_local_uid();

extern listofnames *names();
extern void free_listofnames();

#define	PINGTIME	10	/* Timeout for the ypservers list */
#define	PINGTOTTIM 5	/* Total seconds for ping timeout */

static void broadcast_setup();
static void sigcld_handler();
static struct ypbind_binding *dup_ypbind_binding();
static struct netbuf *dup_netbuf();
static void free_ypbind_binding();
static void enable_exit();
static void ypbind_ping();
static struct domain *ypbind_point_to_domain();
static bool ypbind_broadcast_ack();
static int pong_servers();
void cache_binding();
void uncache_binding();

extern int setok;
extern int broadcast;
extern int cache_okay;

/*
 * Need to differentiate between RPC_UNKNOWNHOST returned by the RPC
 * library, and the same error caused by a local lookup failure in
 * /etc/hosts and/or /etc/inet/ipnodes.
 */
int hostNotKnownLocally;

/*ARGSUSED*/
void	*
ypbindproc_null_3(argp, clnt)
void	*argp;
CLIENT *clnt;
{
	static char	res;

	return ((void *) & res);
}

static void
enable_exit()
{
	static bool	done = FALSE;

	if (!done) {
		done = TRUE;
		sigset(SIGCHLD, (void (*)())sigcld_handler);
	}
}

int sigcld_event = 0;

static void
sigcld_handler()
{
	sigcld_event++;
#ifdef DEBUG
	fprintf(stderr, "ypbind sighandler: got SIGCLD signal (event=%d)\n",
		sigcld_event);
#endif
}


/*
 * This is a Unix SIGCHILD handler that notices when a broadcaster child
 * process has exited, and retrieves the exit status.  The broadcaster pid
 * is set to 0.  If the broadcaster succeeded, dom_report_success will be
 * be set to -1.
 */

void
broadcast_proc_exit()
{
	int pid, ret;
	siginfo_t infop;
	register struct domain *pdom;
	bool	succeeded = FALSE;

	sigcld_event = 0;
					/* ==== Why WEXITED? */
	while ((ret = waitid(P_ALL, 0, &infop, WNOHANG | WEXITED)) != -1) {
		switch (infop.si_code) {
		case CLD_EXITED:
			succeeded = infop.si_status == 0;
			break;
		case CLD_KILLED:
		case CLD_DUMPED:
			succeeded = FALSE;
			break;
		case CLD_TRAPPED:
		case CLD_STOPPED:
		case CLD_CONTINUED:
			enable_exit();
			return;
		}
		pid = infop.si_pid;

#ifdef DEBUG
		fprintf(stderr,
			"ypbind event_handler: got wait from %d status = %d\n",
			pid, infop.si_status);
#endif

	/* to aid the progeny print the infamous "not responding" message */
		firsttime = FALSE;

		for (pdom = known_domains; pdom != (struct domain *)NULL;
				pdom = pdom->dom_pnext) {

			if (pdom->dom_broadcaster_pid == pid) {
#ifdef DEBUG
			fprintf(stderr,
			"ypbind event_handler: got match %s\n", pdom->dom_name);
#endif
				if (succeeded) {
					broadcast_setup(pdom);
				}
				if (pdom->broadcaster_pipe != 0) {
					xdr_destroy(&(pdom->broadcaster_xdr));
					fclose(pdom->broadcaster_pipe);
					pdom->broadcaster_pipe = 0;
					pdom->broadcaster_fd = -1;
				}
				pdom->dom_broadcaster_pid = 0;

				break;
			}
		}
	}	/* while loop */
	enable_exit();
}

static void
broadcast_setup(pdom)
struct domain *pdom;
{
	ypbind_setdom req;

	memset(&req, 0, sizeof (req));
	if (pdom->broadcaster_pipe) {
		pdom->dom_report_success = -1;
		if (xdr_ypbind_setdom(&(pdom->broadcaster_xdr), &req)) {
#ifdef DEBUG
	fprintf(stderr, "parent: broadcast_setup: got xdr ok \n");
#endif
			ypbindproc_setdom_3(&req, (struct svc_req *)NULL,
			    (SVCXPRT *)NULL);
			xdr_free(xdr_ypbind_setdom, (char *)&req);
			gettimeofday(&(pdom->lastping), NULL);
		}
#ifdef DEBUG
		    else {
	fprintf(stderr, "ypbind parent: xdr_ypbind_setdom failed\n");
		}
#endif
	}
#ifdef DEBUG
	    else {
	fprintf(stderr, "ypbind: internal error -- no broadcaster pipe\n");
	}
#endif
}

#define	YPBIND_PINGHOLD_DOWN 5
/* Same as the ypbind_get_binding() routine in SunOS */
/*ARGSUSED*/
ypbind_resp *
ypbindproc_domain_3(argp, clnt)
ypbind_domain *argp;
CLIENT *clnt;
{
	static ypbind_resp resp;
	struct domain *cur_domain;
	int bpid;
	int fildes[2];

	memset((char *)&resp, 0, sizeof (resp));

#ifdef DEBUG
	fprintf(stderr, "\nypbindproc_domain_3: domain: %s\n",
		argp->ypbind_domainname);
#endif

	if ((int)strlen(argp->ypbind_domainname) > YPMAXDOMAIN) {

		resp.ypbind_status = YPBIND_FAIL_VAL;
		resp.ypbind_resp_u.ypbind_error = YPBIND_ERR_NOSERV;
		return (&resp);
	}

	if ((cur_domain = ypbind_point_to_domain(argp->ypbind_domainname)) !=
	    (struct domain *)NULL) {
		if (cur_domain->dom_boundp) {

			struct timeval tp;

			(void) gettimeofday(&tp, NULL);
			if ((tp.tv_sec - cur_domain->lastping.tv_sec) >
					YPBIND_PINGHOLD_DOWN) {
#ifdef DEBUG
	fprintf(stderr, "domain is bound pinging: %s\n",
		argp->ypbind_domainname);
#endif
				(void) ypbind_ping(cur_domain);
			}
		}

		/*
		 * Bound or not, return the current state of the binding.
		 */

		if (cur_domain->dom_boundp) {
#ifdef DEBUG
	fprintf(stderr, "server is up for domain: %s\n",
		argp->ypbind_domainname);
#endif
			resp.ypbind_status = YPBIND_SUCC_VAL;
			resp.ypbind_resp_u.ypbind_bindinfo =
			    cur_domain->dom_binding;
		} else {
#ifdef DEBUG
	fprintf(stderr, "domain is NOT bound returning: %s %d\n",
		argp->ypbind_domainname, cur_domain->dom_error);
#endif
			resp.ypbind_status = YPBIND_FAIL_VAL;
			resp.ypbind_resp_u.ypbind_error =
			    cur_domain->dom_error;
		}

	} else {
		resp.ypbind_status = YPBIND_FAIL_VAL;
		resp.ypbind_resp_u.ypbind_error = YPBIND_ERR_RESC;
	}
	/*
	 * RETURN NOW: if successful, otherwise
	 * RETURN LATER: after spawning off a child to do the "broadcast" work.
	 */
	if (resp.ypbind_status == YPBIND_SUCC_VAL) {
#ifdef DEBUG
	fprintf(stderr, "yp_b_subr: returning success to yp_b_svc %d\n",
		resp.ypbind_status);
#endif
		return (&resp);
	}

	/* Go about the broadcast (really, pinging here) business */

	if ((cur_domain) && (!cur_domain->dom_boundp) &&
	    (!cur_domain->dom_broadcaster_pid)) {
#ifdef DEBUG
	fprintf(stderr, "yp_b_subr: fork: boundp=%d broadcast_pid=%d\n",
		cur_domain->dom_boundp, cur_domain->dom_broadcaster_pid);
#endif
		/*
		 * The current domain is unbound, and there is no child
		 * process active now.  Fork off a child who will beg to the
		 * ypservers list one by one or broadcast and accept whoever
		 * commands the right domain.
		 */
		if (pipe(fildes) < 0) {
#ifdef DEBUG
	fprintf(stderr, "yp_b_subr: returning pipe failure to yp_b_svc %d\n",
		resp.ypbind_status);
#endif
			return (&resp);
		}

		enable_exit();
		sighold(SIGCLD); /* add it to ypbind's signal mask */
		cur_domain->dom_report_success++;
		bpid = fork();
		if (bpid != 0) { /* parent */
			if (bpid > 0) { /* parent started */
				close(fildes[1]);
				cur_domain->dom_broadcaster_pid = bpid;
				cur_domain->broadcaster_fd = fildes[0];
				cur_domain->broadcaster_pipe =
						fdopen(fildes[0], "r");
				if (cur_domain->broadcaster_pipe)
			xdrstdio_create(&(cur_domain->broadcaster_xdr),
			(cur_domain->broadcaster_pipe), XDR_DECODE);

#ifdef DEBUG
	fprintf(stderr, "ypbindproc_domain_3: %s starting pid = %d try = %d\n",
	    cur_domain->dom_name, bpid,
	    cur_domain->dom_report_success);
	fprintf(stderr, "yp_b_subr: returning after spawning, to yp_b_svc %d\n",
		resp.ypbind_status);
#endif
				sigrelse(SIGCLD);
				/* remove it from ypbind's signal mask */
				return (&resp);
			} else { /* fork failed */
				perror("fork");
				close(fildes[0]);
				close(fildes[1]);
#ifdef DEBUG
	fprintf(stderr, "yp_b_subr: returning fork failure to yp_b_svc %d\n",
		resp.ypbind_status);
#endif
				sigrelse(SIGCLD);
				return (&resp);
			}
		} /* end parent */
		/* child only code */
		sigrelse(SIGCLD);
		close(fildes[0]);
		cur_domain->broadcaster_fd = fildes[1];
		cur_domain->broadcaster_pipe = fdopen(fildes[1], "w");
		if (cur_domain->broadcaster_pipe)
			xdrstdio_create(&(cur_domain->broadcaster_xdr),
				(cur_domain->broadcaster_pipe), XDR_ENCODE);
		else {
			perror("fdopen-pipe");
			exit(-1);
		}
		exit(pong_servers(cur_domain));
	}
#ifdef DEBUG
	fprintf(stderr, "yp_b_subr: lazy returns failure status yp_b_svc %d\n",
			resp.ypbind_status);
#endif
	return (&resp);
}


/*
 * call ypbindproc_domain_3 and convert results
 *
 * This adds support for YP clients that send requests on
 * ypbind version 1 & 2 (i.e. clients before we started
 * using universal addresses and netbufs). This is supported
 * for binary compatibility for static 4.x programs. The
 * assumption used to be that clients coming in with ypbind vers 1
 * should be given the address of a server serving ypserv version 1.
 * However, since yp_bind routines in 4.x YP library try
 * to connect with ypserv version 2, even if they requested
 * binding using ypbind version 1, the ypbind process will
 * "always" look for only ypserv version 2 servers for all
 * (ypbind vers 1, 2, & 3) clients.
 */
ypbind_resp_2 *
ypbindproc_domain_2(argp, clnt)
domainname_2 *argp;
CLIENT *clnt;
{
	ypbind_domain arg_3;
	ypbind_resp *resp_3;
	static ypbind_resp_2 resp;

	arg_3.ypbind_domainname = *argp;
	resp_3 = ypbindproc_domain_3(&arg_3, clnt);
	if (resp_3 == NULL)
		return (NULL);
	resp.ypbind_status = resp_3->ypbind_status;
	if (resp_3->ypbind_status == YPBIND_SUCC_VAL) {
		struct sockaddr_in *sin;
		struct ypbind_binding_2 *bi;

		sin = (struct sockaddr_in *)
		    resp_3->ypbind_resp_u.ypbind_bindinfo->ypbind_svcaddr->buf;
		if (sin->sin_family == AF_INET) {
			bi = &resp.ypbind_respbody_2.ypbind_bindinfo;
			memcpy(&(bi->ypbind_binding_port), &sin->sin_port, 2);
			memcpy(&(bi->ypbind_binding_addr), &sin->sin_addr, 4);
		} else {
			resp.ypbind_respbody_2.ypbind_error = YPBIND_ERR_NOSERV;
		}
	} else {
		resp.ypbind_respbody_2.ypbind_error =
		    resp_3->ypbind_resp_u.ypbind_error;
	}
	return (&resp);
}

/* used to exchange information between pong_servers and ypbind_broadcast_ack */
struct domain *process_current_domain;

int
pong_servers(domain_struct)
struct domain *domain_struct; /* to pass back */
{
	char *domain = domain_struct->dom_name;
	CLIENT *clnt2;
	char *servername;
	listofnames *list, *lin;
	char serverfile[MAXNAMLEN];
	struct timeval timeout;
	int isok = 0, res = -1;
	struct netconfig *nconf;
	void *handle;
	int nconf_count;
	char rpcdomain[YPMAXDOMAIN+1];
	long inforet;

	/*
	 * If the ``domain'' name passed in is not the same as the RPC
	 * domain set from /etc/defaultdomain.  Then we set ``firsttime''
	 * to TRUE so no error messages are ever syslog()-ed this
	 * prevents a possible Denial of Service attack.
	 */
	inforet = sysinfo(SI_SRPC_DOMAIN, &(rpcdomain[0]), YPMAXDOMAIN);
	if ((inforet > 0) && (strcmp(domain, rpcdomain) != 0))
		firsttime = TRUE;

	if (broadcast) {
		enum clnt_stat stat = RPC_SUCCESS;
#ifdef DEBUG
	fprintf(stderr, "pong_servers: doing an rpc_broadcast\n");
#endif
		/*
		 * Here we do the real SunOS thing that users love. Do a
		 * broadcast on the network and find out the ypserv. No need
		 * to do "ypinit -c", no setting up /etc/hosts file, and no
		 * recursion looking up the server's IP address.
		 */
		process_current_domain = domain_struct;
		stat = rpc_broadcast(YPPROG, YPVERS, YPPROC_DOMAIN_NONACK,
			(xdrproc_t)xdr_ypdomain_wrap_string, (caddr_t)&domain,
			xdr_int,  (caddr_t)&isok,
			(resultproc_t)ypbind_broadcast_ack, "udp");
		if (stat == RPC_SYSTEMERROR || stat == RPC_UNKNOWNPROTO ||
			stat == RPC_CANTRECV || stat == RPC_CANTSEND ||
			stat == RPC_NOBROADCAST ||
			stat == RPC_N2AXLATEFAILURE) {
			syslog(LOG_ERR, "RPC/Transport subsystem failure %s\n",
				clnt_sperrno(stat));
			exit(-1);
		}
		if (domain_struct->broadcaster_pipe == 0)
			/* init binding case */
			return (domain_struct->dom_boundp - 1);
		if (domain_struct->dom_boundp) {
			res = ypbind_pipe_setdom(NULL, domain,
					NULL, domain_struct);
			if (domain_struct->dom_report_success > 0)
				syslog(LOG_ERR,
			"NIS server for domain \"%s\" OK", domain);
		} else if (firsttime == FALSE)
			syslog(LOG_ERR,
	"NIS server not responding for domain \"%s\"; still trying", domain);
		return (res);
	}
#ifdef DEBUG
	fprintf(stderr, "pong_servers: ponging servers one by one\n");
#endif
	/*
	 * Do the politically correct thing.. transport independent and
	 * secure (trusts only listed servers).
	 */

	/*
	 * get list of possible servers for this domain
	 */

	/*
	 * get alias for domain: Things of the past..
	 * sysvconfig();
	 * (void) yp_getalias(domain, domain_alias, NAME_MAX);
	 */
	sprintf(serverfile, "%s/%s/%s", BINDING, domain, YPSERVERS);
#ifdef DEBUG
	fprintf(stderr, "pong_servers: serverfile %s\n", serverfile);
#endif
	list = names(serverfile);
	if (list == NULL) {
		if (firsttime == FALSE)
		    syslog(LOG_ERR,
			"service not installed, use /usr/sbin/ypinit -c");
		return (-1);
	}
	lin = list;
	for (list = lin; list; list = list->nextname) {
		servername = strtok(list->name, " \t\n");
		if (servername == NULL) continue;

		/* Check all datagram_v transports for this server */
		if ((handle = __rpc_setconf("datagram_v")) == NULL) {
			syslog(LOG_ERR,
			"ypbind: RPC operation on /etc/netconfig failed");
			free_listofnames(lin);
			return (-1);
		}

		nconf_count = 0;
		clnt2 = 0;
		while (clnt2 == 0 && (nconf = __rpc_getconf(handle)) != 0) {
			nconf_count++;
			/*
			 * We use only datagram here. It is expected to be udp.
			 * VERY IMPORTANT: __clnt_tp_create_bootstrap is a
			 * hacked up version that does not do netdir_getbyname.
			 */
			hostNotKnownLocally = 0;
			clnt2 =
	__clnt_tp_create_bootstrap(servername, YPPROG, YPVERS, nconf);
		}
		if (nconf_count == 0) {
			syslog(LOG_ERR,
			"ypbind: RPC operation on /etc/netconfig failed");
			free_listofnames(lin);
			return (-1);
		}

		if (clnt2 == 0) {
			if (rpc_createerr.cf_stat == RPC_UNKNOWNHOST &&
				hostNotKnownLocally) {
				syslog(LOG_ERR,
		"NIS server %s is not in local host files !", servername);
			}
			perror(servername);
			clnt_pcreateerror("ypbind");
			continue;
		}

		timeout.tv_sec = PINGTIME;
		timeout.tv_usec = 0;
		if ((enum clnt_stat) clnt_call(clnt2,
		    YPPROC_DOMAIN, (xdrproc_t)xdr_ypdomain_wrap_string,
		    (char *)&domain, xdr_int,
		    (char *)&isok, timeout) == RPC_SUCCESS) {
			if (isok) {
				if (domain_struct->dom_report_success > 0) {
					syslog(LOG_ERR,
				"NIS server for domain \"%s\" OK", domain);
				}
				if (domain_struct->broadcaster_pipe == 0) {
					/* init binding case --parent */
					struct netconfig *setnc;
					struct netbuf setua;
					struct ypbind_binding *b =
						domain_struct->dom_binding;

					setnc =
				getnetconfigent(clnt2->cl_netid);
					if (b == NULL) {
					/* ASSERT: This shouldn't happen ! */
						b =
				(struct ypbind_binding *)calloc(1, sizeof (*b));
						domain_struct->dom_binding = b;
						if (b == NULL) {
							__rpc_endconf(handle);
							clnt_destroy(clnt2);
							free_listofnames(lin);
							return (-2);
						}
					}


					b->ypbind_nconf = setnc;
					clnt_control(clnt2, CLGET_SVC_ADDR,
						(char *)&setua);
					if (b->ypbind_svcaddr) {
						if (b->ypbind_svcaddr->buf)
				free(b->ypbind_svcaddr->buf);
						free(b->ypbind_svcaddr);
					}
					b->ypbind_svcaddr = dup_netbuf(&setua);
					if (b->ypbind_servername)
						free(b->ypbind_servername);
					b->ypbind_servername =
						strdup(servername);
					b->ypbind_hi_vers = YPVERS;
					b->ypbind_lo_vers = YPVERS;
					__rpc_endconf(handle);
					domain_struct->dom_boundp = TRUE;
					clnt_destroy(clnt2);
					free_listofnames(lin);
					return (0);
				}
				res = ypbind_pipe_setdom(clnt2, domain,
					servername, domain_struct);
				__rpc_endconf(handle);
				clnt_destroy(clnt2);
				free_listofnames(lin);
				return (res);
			} else {
				syslog(LOG_ERR,
				    "server %s doesn't serve domain %s\n",
				    servername, domain);
			}
		} else {
			clnt_perror(clnt2, servername);
		}
		clnt_destroy(clnt2);
	}
	/*
	 * We tried all servers, none obliged !
	 * After ypbind is started up it will not be bound
	 * immediately.  This is normal, no error message
	 * is needed. Although, with the ypbind_init_default
	 * it will be bound immediately.
	 */
	if (firsttime == FALSE) {
		syslog(LOG_ERR,
"NIS server not responding for domain \"%s\"; still trying", domain);
	}
	free_listofnames(lin);
	__rpc_endconf(handle);
	return (-2);
}

struct netbuf *
dup_netbuf(inbuf)
	struct netbuf *inbuf;
{
	struct netbuf *outbuf;

	if (inbuf == NULL)
		return (NULL);
	if ((outbuf =
		(struct netbuf *)calloc(1, sizeof (struct netbuf))) == NULL)
		return (NULL);
	if ((outbuf->buf = malloc(inbuf->len)) == NULL) {
		free(outbuf);
		return (NULL);
	}
	outbuf->len = inbuf->len;
	outbuf->maxlen = inbuf->len;
	(void) memcpy(outbuf->buf, inbuf->buf, inbuf->len);
	return (outbuf);
}

/*
 * This is called by the broadcast rpc routines to process the responses
 * coming back from the broadcast request. Since the form of the request
 * which is used in ypbind_broadcast_bind is "respond only in the positive
 * case", we know that we have a server.
 * The internet address of the responding server will be picked up from
 * the saddr parameter, and stuffed into the domain.  The domain's boundp
 * field will be set TRUE.  The first responding server (or the first one
 * which is on a reserved port) will be the bound server for the domain.
 */
bool
ypbind_broadcast_ack(ptrue, nbuf, nconf)
	bool *ptrue;
	struct netbuf *nbuf;
	struct netconfig *nconf;
{
	struct ypbind_binding b;

	process_current_domain->dom_boundp = TRUE;
	b.ypbind_nconf = nconf;
	b.ypbind_svcaddr = nbuf;
	b.ypbind_servername = "\000";
	b.ypbind_hi_vers = YPVERS;
	b.ypbind_lo_vers = YPVERS;
	free_ypbind_binding(process_current_domain->dom_binding);
	process_current_domain->dom_binding = dup_ypbind_binding(&b);
	return (TRUE);
}

/*
 * WARNING: This routine is entered only by the child process.
 * Called if it pongs/broadcasts okay.
 */
static int
ypbind_pipe_setdom(client, domain, servername, opaque_domain)
CLIENT *client;
char *servername;
char *domain;
struct domain *opaque_domain;
{
	struct netconfig *setnc;
	struct netbuf setua;
	ypbind_binding setb;
	ypbind_setdom setd;
	int retval;

	setd.ypsetdom_domain = domain;
	if (client == NULL && opaque_domain->dom_binding) {
#ifdef DEBUG
	fprintf(stderr, "ypbind_pipe_setdom: child broadcast case ");
#endif
		/* ypbind_broadcast_ack already setup dom_binding for us */
		setd.ypsetdom_bindinfo = opaque_domain->dom_binding;
	} else if (client) {
#ifdef DEBUG
	fprintf(stderr, "ypbind_pipe_setdom: child unicast case ");
#endif
		setnc = getnetconfigent(client->cl_netid);
		if (setnc == NULL) {
#ifdef DEBUG
	fprintf(stderr, "PANIC: shouldn't happen\n");
#endif
			fclose(opaque_domain->broadcaster_pipe);
			close(opaque_domain->broadcaster_fd);
			return (-2);
		}
		clnt_control(client, CLGET_SVC_ADDR, (char *)&setua);
		setb.ypbind_nconf = setnc;
		setb.ypbind_svcaddr = &setua;
		setb.ypbind_servername = servername;
		setb.ypbind_hi_vers = YPVERS;
		setb.ypbind_lo_vers = YPVERS;
		setd.ypsetdom_bindinfo = &setb;
	/*
	 * Let's hardcode versions, that is the only ypserv we support anyway.
	 * Avoid the song and dance of recursively calling ypbind_ping
	 * for no reason. Consistent with the 4.1 policy, that if ypbind gets
	 * a request on new binder protocol, the requestor is looking for the
	 * new ypserv. And, we have even higher binder protocol version i.e. 3.
	 */
	} else
		return (-1);
#ifdef DEBUG
	fprintf(stderr,
		" saving server settings, \nsupports versions %d thru %d\n",
		setd.ypsetdom_bindinfo->ypbind_lo_vers,
		setd.ypsetdom_bindinfo->ypbind_hi_vers);
#endif

	if (opaque_domain->broadcaster_pipe == 0) {
#ifdef DEBUG
	fprintf(stderr, "PANIC: shouldn't be in this function\n");
#endif
		return (-2);
	}
#ifdef DEBUG
	fprintf(stderr, "child: doing xdr_ypbind_setdom\n");
#endif
	retval = xdr_ypbind_setdom(&(opaque_domain->broadcaster_xdr), &setd);
	xdr_destroy(&(opaque_domain->broadcaster_xdr));
	fclose(opaque_domain->broadcaster_pipe);
	close(opaque_domain->broadcaster_fd);
	/*
	 * This child process is about to exit. Don't bother freeing memory.
	 */
	if (!retval) {
#ifdef DEBUG
	fprintf(stderr,
		"YPBIND pipe_setdom failed \n(xdr failure) to server %s\n",
		servername ? servername : "");
#endif
		return (-3);
	}
#ifdef DEBUG
	fprintf(stderr, "ypbind_pipe_setdom: YPBIND OK-set to server %s\n",
		servername ? servername : "");
#endif
	return (0);
}

/* Same as ypbind_set_binding in SunOS */
/*
 *  We use a trick from SunOS to return an error to the ypset command
 *  when we are not allowing the domain to be set.  We do a svcerr_noprog()
 *  to send RPC_PROGUNAVAIL to ypset.  We also return NULL so that
 *  our caller (ypbindprog_3) won't try to return a result.  This
 *  hack is necessary because the YPBINDPROC_SETDOM procedure is defined
 *  in the protocol to return xdr_void, so we don't have a direct way to
 *  return an error to the client.
 */
/*ARGSUSED*/
void	*
ypbindproc_setdom_3(argp, rqstp, transp)
ypbind_setdom *argp;
struct svc_req *rqstp;
SVCXPRT *transp;
{
	struct domain *a_domain;
	struct netbuf *who;
	static char res; /* dummy for void * return */
	uid_t caller_uid;

	if ((int)strlen(argp->ypsetdom_domain) > YPMAXDOMAIN) {

		if (transp) {
			svcerr_systemerr(transp);
			return (0);
		}
		return (&res);
	}

	if (transp != NULL) {
		/* find out who originated the request */
		char *uaddr;
		struct netconfig *nconf;

		who = svc_getrpccaller(transp);
		if ((nconf = getnetconfigent(transp->xp_netid))
			== (struct netconfig *)NULL) {
			svcerr_systemerr(transp);
			return (0);
		}
		if (strcmp(nconf->nc_protofmly, NC_LOOPBACK) == 0) {
			uaddr = strdup("local host");
		} else {
			uaddr = taddr2uaddr(nconf, who);
		}
		if (setok != YPSETALL) {
		/* for -ypset, it falls through and let anybody do a setdom ! */
			if (strcmp(nconf->nc_protofmly, NC_LOOPBACK) != 0) {
				syslog(LOG_ERR,
"ypset request from %s not on loopback, \
cannot set ypbind to %s", uaddr ? uaddr : "unknown source",
argp->ypsetdom_bindinfo->ypbind_servername);
				if (uaddr)
					free(uaddr);
				freenetconfigent(nconf);
				svcerr_noprog(transp);
				return (0);
			}
			switch (setok) {
			case YPSETNONE:
				if (strcmp(nconf->nc_protofmly,
					NC_LOOPBACK) == 0)
					syslog(LOG_ERR,
"ypset request to %s from %s failed - ypset not allowed",
argp->ypsetdom_bindinfo->ypbind_servername, uaddr);
				if (uaddr)
					free(uaddr);
				freenetconfigent(nconf);
				svcerr_noprog(transp);
				return (0);
			case YPSETLOCAL:
				if (__rpc_get_local_uid(transp,
					&caller_uid) < 0) {
					syslog(LOG_ERR, "ypset request from \
unidentified local user on %s - ypset not allowed",
transp->xp_netid);
					if (uaddr)
						free(uaddr);
					freenetconfigent(nconf);
					svcerr_noprog(transp);
					return (0);
				}
				if (caller_uid != 0) {
					syslog(LOG_ERR,
"Set domain request to host %s \
from local non-root user %ld failed - ypset not allowed",
argp->ypsetdom_bindinfo->ypbind_servername, caller_uid);
					if (uaddr)
						free(uaddr);
					freenetconfigent(nconf);
					svcerr_noprog(transp);
					return (0);
				}
			}
		}
		syslog(LOG_ERR, "Set domain request from %s : \
setting server for domain %s to %s", uaddr ? uaddr : "UNKNOWN SOURCE",
argp->ypsetdom_domain, argp->ypsetdom_bindinfo->ypbind_servername);
		if (uaddr)
			free(uaddr);
		freenetconfigent(nconf);
	}

	if ((a_domain = ypbind_point_to_domain(argp->ypsetdom_domain))
	    != (struct domain *)NULL) {
		/* setting binding; old may be invalid */
		uncache_binding(a_domain);

		/* this does the set -- should copy the structure */
		free_ypbind_binding(a_domain->dom_binding);
		if ((a_domain->dom_binding =
		    dup_ypbind_binding(argp->ypsetdom_bindinfo)) == NULL) {
			syslog(LOG_ERR, "ypbindproc_setdom_3: out of memory, ",
				"dup_ypbind_binding failed\n");
			if (transp) {
				svcerr_noprog(transp);
				return (0);
			}
			return (&res);
		}
		gettimeofday(&(a_domain->lastping), NULL);
		a_domain->dom_boundp = TRUE;
		cache_binding(a_domain);
#ifdef DEBUG
	fprintf(stderr, "ypbindproc_setdom_3: setting domain %s to server %s\n",
		argp->ypsetdom_domain,
		argp->ypsetdom_bindinfo->ypbind_servername);
#endif
	}

	return (&res);
}

/*
 * This returns a pointer to a domain entry.  If no such domain existed on
 * the list previously, an entry will be allocated, initialized, and linked
 * to the list.  Note:  If no memory can be malloc-ed for the domain structure,
 * the functional value will be (struct domain *) NULL.
 */
static struct domain *
ypbind_point_to_domain(pname)
register char	*pname;
{
	register struct domain *pdom;
	char buf[300];

	for (pdom = known_domains; pdom != (struct domain *)NULL;
	    pdom = pdom->dom_pnext) {
		if (strcmp(pname, pdom->dom_name) == 0)
			return (pdom);
	}

	/* Not found.  Add it to the list */

	if (pdom = (struct domain *)calloc(1, sizeof (struct domain))) {
		pdom->dom_name = strdup(pname);
		if (pdom->dom_name == NULL) {
			free((char *)pdom);
			syslog(LOG_ERR,
				"ypbind_point_to_domain: strdup failed\n");
			return (NULL);
		}
		pdom->dom_pnext = known_domains;
		known_domains = pdom;
		pdom->dom_boundp = FALSE;
		pdom->dom_vers = YPVERS; /* This doesn't talk to old ypserv */
		pdom->dom_binding = NULL;
		pdom->dom_error = YPBIND_ERR_NOSERV;
		pdom->ping_clnt = (CLIENT *)NULL;
		pdom->dom_report_success = -1;
		pdom->dom_broadcaster_pid = 0;
		pdom->broadcaster_pipe = 0;
		pdom->bindfile = -1;
		pdom->lastping.tv_sec = 0;
		pdom->lastping.tv_usec = 0; /* require ping */
		pdom->cache_fp = 0;
		sprintf(buf, "%s/%s/cache_binding", BINDING, pdom->dom_name);
		pdom->cache_file = strdup(buf);
		/*
		 *  We don't give an error if pdom->cache_file is not set.
		 *  If we got null (out of memory), then we just won't use
		 *  the cache file in cache_binding() (assuming the
		 *  application gets that far.
		 */
	}
	else
		syslog(LOG_ERR, "ypbind_point_to_domain: malloc failed\n");

	return (pdom);
}

static void
ypbind_ping(pdom)
struct domain *pdom;
{
	struct timeval timeout;
	int	vers;
	int	isok;

	if (pdom->dom_boundp == FALSE)
		return;
	vers = pdom->dom_vers;

	if (pdom->ping_clnt == (CLIENT *) NULL) {
		pdom->ping_clnt = __nis_clnt_create(RPC_ANYFD,
					pdom->dom_binding->ypbind_nconf, 0,
					pdom->dom_binding->ypbind_svcaddr, 0,
					YPPROG, vers, 0, 0);
	}

	if (pdom->ping_clnt == (CLIENT *) NULL) {
		perror("clnt_tli_create");
		clnt_pcreateerror("ypbind_ping()");
		pdom->dom_boundp = FALSE;
		pdom->dom_error = YPBIND_ERR_NOSERV;
		return;
	}


#ifdef DEBUG
	fprintf(stderr, "ypbind: ypbind_ping()\n");
#endif
	timeout.tv_sec = PINGTOTTIM;
	timeout.tv_usec =  0;
	if (clnt_call(pdom->ping_clnt,
	    YPPROC_DOMAIN, (xdrproc_t)xdr_ypdomain_wrap_string,
		(char *)&pdom->dom_name, xdr_int, (char *)&isok,
		timeout) == RPC_SUCCESS) {
			pdom->dom_boundp = isok;
			pdom->dom_binding->ypbind_lo_vers = vers;
			pdom->dom_binding->ypbind_hi_vers = vers;
#ifdef DEBUG
	fprintf(stderr,
		"Server pinged successfully, supports versions %d thru %d\n",
		pdom->dom_binding->ypbind_lo_vers,
		pdom->dom_binding->ypbind_hi_vers);
#endif
	} else {
		clnt_perror(pdom->ping_clnt, "ping");
		pdom->dom_boundp = FALSE;
		pdom->dom_error = YPBIND_ERR_NOSERV;
	}
	(void) gettimeofday(&(pdom->lastping), NULL);
	if (pdom->ping_clnt)
		clnt_destroy(pdom->ping_clnt);
	pdom->ping_clnt = (CLIENT *)NULL;
	if (pdom->dom_boundp)
		cache_binding(pdom);
}

static struct ypbind_binding *
dup_ypbind_binding(a)
struct ypbind_binding *a;
{
	struct ypbind_binding *b;
	struct netconfig *nca, *ncb;
	struct netbuf *nxa, *nxb;
	int i;

	b = (struct ypbind_binding *)calloc(1, sizeof (*b));
	if (b == NULL)
		return (b);
	b->ypbind_hi_vers = a->ypbind_hi_vers;
	b->ypbind_lo_vers = a->ypbind_lo_vers;
	b->ypbind_servername =
		a->ypbind_servername ? strdup(a->ypbind_servername) : NULL;
	ncb = (b->ypbind_nconf =
		(struct netconfig *)calloc(1, sizeof (struct netconfig)));
	nxb = (b->ypbind_svcaddr =
		(struct netbuf *)calloc(1, sizeof (struct netbuf)));
	nca = a->ypbind_nconf;
	nxa = a->ypbind_svcaddr;
	ncb->nc_flag = nca->nc_flag;
	ncb->nc_protofmly =
		nca->nc_protofmly ? strdup(nca->nc_protofmly) : NULL;
	ncb->nc_proto =
		nca->nc_proto ? strdup(nca->nc_proto) : NULL;
	ncb->nc_semantics = nca->nc_semantics;
	ncb->nc_netid =
		nca->nc_netid ? strdup(nca->nc_netid) : NULL;
	ncb->nc_device =
		nca->nc_device ? strdup(nca->nc_device) : NULL;
	ncb->nc_nlookups = nca->nc_nlookups;
	ncb->nc_lookups = (char **)calloc(nca->nc_nlookups, sizeof (char *));
	if (ncb->nc_lookups == NULL) {
		if (ncb->nc_device)
			free(ncb->nc_device);
		if (ncb->nc_netid)
			free(ncb->nc_netid);
		if (ncb->nc_proto)
			free(ncb->nc_proto);
		if (ncb->nc_protofmly)
			free(ncb->nc_protofmly);
		if (nxb)
			free(nxb);
		if (ncb)
			free(ncb);
		if (b->ypbind_servername)
			free(b->ypbind_servername);
		if (b)
			free(b);
		return (NULL);
	}
	for (i = 0; i < nca->nc_nlookups; i++)
		ncb->nc_lookups[i] =
			nca->nc_lookups[i] ? strdup(nca->nc_lookups[i]) : NULL;
	for (i = 0; i < 8; i++)
		ncb->nc_unused[i] = nca->nc_unused[i];
	nxb->maxlen = nxa->maxlen;
	nxb->len = nxa->len;
	nxb->buf = malloc(nxa->maxlen);
	if (nxb->buf == NULL) {
		for (i = 0; i < nca->nc_nlookups; i++)
			if (ncb->nc_lookups[i])
				free(ncb->nc_lookups[i]);
		free(ncb->nc_lookups);
		if (ncb->nc_device)
			free(ncb->nc_device);
		if (ncb->nc_netid)
			free(ncb->nc_netid);
		if (ncb->nc_proto)
			free(ncb->nc_proto);
		if (ncb->nc_protofmly)
			free(ncb->nc_protofmly);
		if (nxb)
			free(nxb);
		if (ncb)
			free(ncb);
		if (b->ypbind_servername)
			free(b->ypbind_servername);
		if (b)
			free(b);
		return (NULL);
	}
	memcpy(nxb->buf, nxa->buf, nxb->len);
	return (b);
}

static void
free_ypbind_binding(b)
struct ypbind_binding *b;
{
	if (b == NULL)
		return;
	netdir_free((char *)b->ypbind_svcaddr, ND_ADDR);
	free(b->ypbind_servername);
	freenetconfigent(b->ypbind_nconf);
	free(b);
}

/*
 * Preloads teh default domain's domain binding. Domain binding for the
 * local node's default domain for ypserv version 2 (YPVERS) will be
 * set up. This may make it a little slower to start ypbind during
 * boot time, but would make it easy on other domains that rely on
 * this binding.
 */
void
ypbind_init_default()
{
	char domain[256];
	struct domain *cur_domain;

	if (getdomainname(domain, 256) == 0) {
		cur_domain = ypbind_point_to_domain(domain);

		if (cur_domain == (struct domain *)NULL) {
			abort();
		}
		(void) pong_servers(cur_domain);
	}
}

bool_t
xdr_ypbind_binding_2(xdrs, objp)
	register XDR *xdrs;
	ypbind_binding_2 *objp;
{
	if (!xdr_opaque(xdrs, (char *)&(objp->ypbind_binding_addr), 4))
		return (FALSE);
	if (!xdr_opaque(xdrs, (char *)&(objp->ypbind_binding_port), 2))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_ypbind_resp_2(xdrs, objp)
	register XDR *xdrs;
	ypbind_resp_2 *objp;
{
	if (!xdr_ypbind_resptype(xdrs, &objp->ypbind_status))
		return (FALSE);
	switch (objp->ypbind_status) {
	case YPBIND_FAIL_VAL:
		if (!xdr_u_long(xdrs, &objp->ypbind_respbody_2.ypbind_error))
			return (FALSE);
		break;
	case YPBIND_SUCC_VAL:
		if (!xdr_ypbind_binding_2(xdrs,
		    &objp->ypbind_respbody_2.ypbind_bindinfo))
			return (FALSE);
		break;
	default:
		return (FALSE);
	}
	return (TRUE);
}

/*
 *  The following is some caching code to improve the performance of
 *  yp clients.  In the days of yore, a client would talk to rpcbind
 *  to get the address for ypbind, then talk to ypbind to get the
 *  address of the server.  If a lot of clients are doing this at
 *  the same time, then rpcbind and ypbind get bogged down and clients
 *  start to time out.
 *
 *  We cache two things:  the current address for ypserv, and the
 *  transport addresses for talking to ypbind.  These are saved in
 *  files in /var/yp.  To get the address of ypserv, the client opens
 *  a file and reads the address.  It does not have to talk to rpcbind
 *  or ypbind.  If this file is not available, then it can read the
 *  the transport address for talking to ypbind without bothering
 *  rpcbind.  If this also fails, then it uses the old method of
 *  talking to rpcbind and then ypbind.
 *
 *  We lock the first byte of the cache files after writing to them.
 *  This indicates to the client that they contents are valid.  The
 *  client should test the lock.  If the lock is held, then it can
 *  use the contents.  If the lock test fails, then the contents should
 *  be ignored.
 */

/*
 *  Cache new binding information for a domain in a file.  If the
 *  new binding is the same as the old, then we skip it.  We xdr
 *  a 'ypbind_resp', which is what would be returned by a call to
 *  the YBINDPROCP_DOMAIN service.  We xdr the data because it is
 *  easier than writing the data out field by field.  It would be
 *  nice if there were an xdrfd_create() that was similar to
 *  xdrstdio_create().  Instead, we do an fdopen and use xdrstdio_create().
 */
void
cache_binding(pdom)
	struct domain *pdom;
{
	int st;
	int fd;
	XDR xdrs;
	struct ypbind_resp resp;

	if (!cache_okay)
		return;

	/* if the domain doesn't have a cache file, then skip it */
	if (pdom->cache_file == 0)
		return;

	/*
	 *  If we already had a cache file for this domain, remove it.  If
	 *  a client just started accessing it, then it will either find
	 *  it unlocked (and not use it), or continue to use it with
	 *  old information.  This is not a problem, the client will
	 *  either fail to talk to ypserv and try to bind again, or
	 *  will continue to use the old server.
	 */
	if (pdom->cache_fp) {
		fclose(pdom->cache_fp);    /* automatically unlocks */
		unlink(pdom->cache_file);
		pdom->cache_fp = 0;
	}

	fd = open(pdom->cache_file, O_CREAT|O_WRONLY, 0444);
	if (fd == -1)
		return;

	pdom->cache_fp = fdopen(fd, "w");
	if (pdom->cache_fp == 0) {
		close(fd);
		return;
	}

	xdrstdio_create(&xdrs, pdom->cache_fp, XDR_ENCODE);
	resp.ypbind_status = YPBIND_SUCC_VAL;
	resp.ypbind_resp_u.ypbind_bindinfo = pdom->dom_binding;

	if (!xdr_ypbind_resp(&xdrs, &resp)) {
		xdr_destroy(&xdrs);
		unlink(pdom->cache_file);
		fclose(pdom->cache_fp);
		pdom->cache_fp = 0;
		return;
	}
	xdr_destroy(&xdrs);    /* flushes xdr but leaves fp open */

	/* we lock the first byte to indicate that the file is valid */
	lseek(fd, 0L, SEEK_SET);
	st = lockf(fd, F_LOCK, 1);
	if (st == -1) {
		unlink(pdom->cache_file);
		fclose(pdom->cache_fp);
		pdom->cache_fp = 0;
	}
}

void
uncache_binding(pdom)
	struct domain *pdom;
{
	if (!cache_okay)
		return;

	if (pdom->cache_fp != 0) {
		unlink(pdom->cache_file);
		fclose(pdom->cache_fp);
		pdom->cache_fp = 0;
	}
}

/*
 *  Cache a transport address for talking to ypbind.  We convert the
 *  transport address to a universal address and save that in a file.
 *  The file lives in the binding directory because it does not depend
 *  on the domain.
 */
void
cache_transport(nconf, xprt, vers)
	struct netconfig *nconf;
	SVCXPRT *xprt;
	int vers;
{
	char filename[300];
	char *uaddr;
	int fd;
	int st;
	int len;

	if (!cache_okay)
		return;

	sprintf(filename, "%s/xprt.%s.%d",
		BINDING, nconf->nc_netid, vers);

	unlink(filename);    /* remove any old version */

	uaddr = taddr2uaddr(nconf, &xprt->xp_ltaddr);
	if (uaddr == 0)
		return;

	fd = open(filename, O_CREAT|O_WRONLY, 0444);    /* readable by all */
	if (fd == -1) {
		free(uaddr);
		return;
	}

	len = strlen(uaddr) + 1;    /* include terminating null */
	st = write(fd, uaddr, len);
	if (st != len) {
		close(fd);
		unlink(filename);
		free(uaddr);
		return;
	}

	free(uaddr);

	/* we lock the first byte to indicate that the file is valid */
	lseek(fd, 0L, SEEK_SET);
	st = lockf(fd, F_LOCK, 1);
	if (st == -1) {
		close(fd);
		unlink(filename);
	}
}

/*
 *  Create a file that clients can check to see if we are running.
 */
void
cache_pid()
{
	char filename[300];
	char spid[15];
	int fd;
	int st;
	int len;

	if (!cache_okay)
		return;

	sprintf(filename, "%s/ypbind.pid", BINDING);

	unlink(filename);    /* remove any old version */

	fd = open(filename, O_CREAT|O_WRONLY, 0444);    /* readable by all */
	if (fd == -1) {
		return;
	}

	sprintf(spid, "%d\n", getpid());

	len = strlen(spid);
	st = write(fd, spid, len);
	if (st != len) {
		close(fd);
		unlink(filename);
		return;
	}

	/* we lock the first byte to indicate that the file is valid */
	lseek(fd, 0L, SEEK_SET);
	st = lockf(fd, F_LOCK, 1);
	if (st == -1) {
		close(fd);
		unlink(filename);
	}

	/* we keep 'fd' open so that the lock will continue to be held */
}

/*
 *  We are called once at startup (when the known_domains list is empty)
 *  to clean up left-over files.  We are also called right before
 *  exiting.  In the latter case case we don't bother closing descriptors
 *  in the entries in the domain list because they will be closed
 *  automatically (and unlocked) when we exit.
 *
 *  We ignore the cache_okay flag because it is important that we remove
 *  all cache files (left-over files can temporarily confuse clients).
 */
void
clean_cache()
{
	struct domain *pdom;
	DIR *dir;
	struct dirent *dirent;
	char filename[300];

	/* close and unlink cache files for each domain */
	for (pdom = known_domains; pdom != (struct domain *)NULL;
	    pdom = pdom->dom_pnext) {
		if (pdom->cache_file)
			unlink(pdom->cache_file);
	}

	sprintf(filename, "%s/ypbind.pid", BINDING);
	unlink(filename);

	dir = opendir(BINDING);

	if (dir == NULL) {
		/* Directory could not be opened. */
		syslog(LOG_ERR, "opendir failed with [%s]", strerror(errno));
		return;
	}

	while ((dirent = readdir(dir)) != 0) {
		if (strncmp(dirent->d_name, "xprt.", 5) == 0) {
			sprintf(filename, "%s/%s", BINDING, dirent->d_name);
			unlink(filename);
			rewinddir(dir);  /* removing file may harm iteration */
		}
	}
	closedir(dir);
}

/*
 *  We only want to use the cache stuff on local file systems.
 *  For remote file systems (e.g., NFS, the locking overhead is
 *  worse than the overhead of loopback RPC, so the caching
 *  wouldn't buy us anything.  In addition, if the remote locking
 *  software isn't configured before we start, then we would
 *  block when we try to lock.
 *
 *  We don't have a direct way to tell if a file system is local
 *  or remote, so we assume it is local unless it is NFS.
 */
int
cache_check()
{
	int st;
	struct statvfs stbuf;

	st = statvfs(BINDING, &stbuf);
	if (st == -1) {
		syslog(LOG_ERR, "statvfs failed with [%s]", strerror(errno));
		return (0);
	}

	/* we use strncasecmp to get NFS, NFS3, nfs, nfs3, etc. */
	if (strncasecmp(stbuf.f_basetype, "NFS", 3) == 0)
		return (0);
	return (1);
}
