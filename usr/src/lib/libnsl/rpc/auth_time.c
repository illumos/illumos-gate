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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This module contains the private function __rpc_get_time_offset()
 * which will return the difference in seconds between the local system's
 * notion of time and a remote server's notion of time. This must be
 * possible without calling any functions that may invoke the name
 * service. (netdir_getbyxxx, getXbyY, etc). The function is used in the
 * synchronize call of the authdes code to synchronize clocks between
 * NIS+ clients and their servers.
 *
 * Note to minimize the amount of duplicate code, portions of the
 * synchronize() function were folded into this code, and the synchronize
 * call becomes simply a wrapper around this function. Further, if this
 * function is called with a timehost it *DOES* recurse to the name
 * server so don't use it in that mode if you are doing name service code.
 *
 * Side effects :
 *	When called a client handle to a RPCBIND process is created
 *	and destroyed. Two strings "netid" and "uaddr" are malloc'd
 *	and returned. The SIGALRM processing is modified only if
 *	needed to deal with TCP connections.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <netdir.h>
#include <string.h>
#include <strings.h>
#include <netconfig.h>
#include <netdb.h>
#include <signal.h>
#include <sys/errno.h>
#include <sys/poll.h>
#include <rpc/rpc.h>
#include <rpc/nettype.h>
#undef NIS
#include <rpcsvc/nis.h>


extern void	__nis_netconfig2ep(struct netconfig *, endpoint *);
extern bool_t	__nis_netconfig_matches_ep(struct netconfig *, endpoint *);

#ifdef TESTING
#define	msg(x)	printf("ERROR: %s\n", x)
/* #define msg(x) syslog(LOG_ERR, "%s", x) */
#else
#define	msg(x)
#endif

static int saw_alarm = 0;

/* ARGSUSED */
static void
alarm_hndler(int s)
{
	saw_alarm = 1;
}

/*
 * The internet time server defines the epoch to be Jan 1, 1900
 * whereas UNIX defines it to be Jan 1, 1970. To adjust the result
 * from internet time-service time, into UNIX time we subtract the
 * following offset :
 */
#define	NYEARS	(1970 - 1900)
#define	TOFFSET ((uint_t)60*60*24*(365*NYEARS + (NYEARS/4)))

/*
 * free_eps()
 *
 * Free the strings that were strduped into the eps structure.
 */
static void
free_eps(endpoint eps[], int num)
{
	int		i;

	for (i = 0; i < num; i++) {
		free(eps[i].uaddr);
		free(eps[i].proto);
		free(eps[i].family);
	}
}

/*
 * get_server()
 *
 * This function constructs a nis_server structure description for the
 * indicated hostname.
 */
static nis_server *
get_server(char *host, nis_server *srv, endpoint eps[], int  maxep)
{
	int			num_ep = 0, i;
	struct netconfig	*nc;
	void			*nch;
	struct nd_hostserv	hs;
	struct nd_addrlist	*addrs;

	if (! host)
		return (NULL);
	hs.h_host = host;
	hs.h_serv = "rpcbind";
	nch = setnetconfig();
	while (nc = getnetconfig(nch)) {
		if ((nc->nc_flag & NC_VISIBLE) == 0)
			continue;
		if (! netdir_getbyname(nc, &hs, &addrs)) {
			for (i = 0; (i < (addrs->n_cnt)) && (num_ep < maxep);
								i++, num_ep++) {
				eps[num_ep].uaddr =
					taddr2uaddr(nc, &(addrs->n_addrs[i]));
				__nis_netconfig2ep(nc, &(eps[num_ep]));
			}
			netdir_free((char *)addrs, ND_ADDRLIST);
		}
	}
	(void) endnetconfig(nch);

	srv->name = (nis_name) host;
	srv->ep.ep_len = num_ep;
	srv->ep.ep_val = eps;
	srv->key_type = NIS_PK_NONE;
	srv->pkey.n_bytes = NULL;
	srv->pkey.n_len = 0;
	return (srv);
}

#define	MEP(ep, prot)	(strcasecmp(ep.proto, prot) == 0)
#define	MAX_ENDPOINTS	32

/*
 * __rpc_get_time_offset()
 *
 * This function uses a nis_server structure to contact the a remote
 * machine (as named in that structure) and returns the offset in time
 * between that machine and this one. This offset is returned in seconds
 * and may be positive or negative.
 *
 * The first time through, a lot of fiddling is done with the netconfig
 * stuff to find a suitable transport. The function is very aggressive
 * about choosing UDP or at worst TCP if it can. This is because
 * those transports support both the RCPBIND call and the internet
 * time service.
 *
 * Once through, *uaddr is set to the universal address of
 * the machine and *netid is set to the local netid for the transport
 * that uaddr goes with. On the second call, the netconfig stuff
 * is skipped and the uaddr/netid pair are used to fetch the netconfig
 * structure and to then contact the machine for the time.
 *
 * td = "server" - "client"
 */
int
__rpc_get_time_offset(struct timeval *td, nis_server *srv,
	char *thost, char **uaddr, char **netid)
{
	CLIENT			*clnt; 		/* Client handle 	*/
	struct netbuf		*addr = 0;	/* address 		*/
	void			*nc_handle;	/* Netconfig "state"	*/
	struct netconfig	*nc;		/* Various handles	*/
	endpoint		*ep;		/* useful endpoints	*/
	char			*useua = NULL,	/* uaddr of selected xp	*/
				*useid = NULL;	/* netid of selected xp	*/
	int			epl, i;		/* counters		*/
	enum clnt_stat		status;		/* result of clnt_call	*/
	uint_t			thetime;
	ulong_t			delta;
	int			needfree = 0;
	struct timeval		tv;
	int			rtime_fd = -1, time_valid, flag = 0;
	int			a1, a2, a3, a4;
	char			ut[INET6_ADDRSTRLEN];
	char			ipuaddr[INET6_ADDRSTRLEN];
	endpoint		teps[MAX_ENDPOINTS],
				*epcand[MAX_ENDPOINTS],
				*nonipcand[MAX_ENDPOINTS],
				supplied;
	uint32_t		epc, nonip;
	nis_server		tsrv;
	void			(*oldsig)() = NULL; /* old alarm handler */
	char 			*dot = NULL; /* tmp pointer */



	nc = NULL;
	td->tv_sec = 0;
	td->tv_usec = 0;

	/*
	 * First check to see if we need to find and address for this
	 * server.
	 */
	if (*uaddr == NULL) {
		if ((srv != NULL) && (thost != NULL)) {
			msg("both timehost and srv pointer used!");
			return (0);
		}
		if (! srv) {
			srv = get_server(thost, &tsrv, teps, 32);
			if (! srv) {
				msg("unable to contruct server data.");
				return (0);
			}
			needfree = 1;	/* need to free data in endpoints */
		}

		nc_handle = (void *) setnetconfig();
		if (! nc_handle) {
			msg("unable to get netconfig info.");
			if (needfree)
				free_eps(teps, tsrv.ep.ep_len);
			return (0);
		}

		ep = srv->ep.ep_val;
		epl = srv->ep.ep_len;
		for (i = 0; i < sizeof (epcand)/sizeof (epcand[0]); i++) {
			epcand[i] = 0;
			nonipcand[i] = 0;
		}
		epc = 0;
		nonip = 0;

		/*
		 * Build the list of endpoint candidates. We prefer transports
		 * that we know are IP, but let /etc/netconfig determine the
		 * ordering among the IP transports.
		 *
		 * Note: We assume that the endpoint 'proto' field contains
		 *	 the netid of the transport.
		 */
		while ((nc = getnetconfig(nc_handle)) != NULL) {

			/* Is it a visible transport ? */
			if ((nc->nc_flag & NC_VISIBLE) == 0)
				continue;

			/* Check against the end points */
			for (i = 0; i < epl; i++) {
				if (__nis_netconfig_matches_ep(nc, &(ep[i]))) {
					if (MEP(ep[i], "udp") ||
							MEP(ep[i], "udp6") ||
							MEP(ep[i], "tcp") ||
							MEP(ep[i], "tcp6")) {
						epcand[epc++] = &(ep[i]);
					} else {
						nonipcand[nonip++] = &ep[i];
					}
					break;
				}
			}
		}

		(void) endnetconfig(nc_handle);

		/*
		 * epcand[] now contains the candidate transports. If there
		 * were non-IP transports as well, add them to the end of the
		 * candidate list.
		 */
		for (i = 0; i < nonip; i++) {
			epcand[epc++] = nonipcand[i];
		}

		if (epc == 0) {
			msg("no acceptable transport endpoints.");
			if (needfree)
				free_eps(teps, tsrv.ep.ep_len);
			return (0);
		}
	} else {
		/* Caller supplied a uaddr. Fake an endpoint. */
		if (*netid != 0) {
			supplied.proto = *netid;
			/* Is it one of the known IP transports ? */
			if (strcmp("udp", supplied.proto) &&
				strcmp("udp6", supplied.proto) &&
				strcmp("tcp", supplied.proto) &&
				strcmp("tcp6", supplied.proto)) {
				/* No, it's not */
				nonip = 1;
			} else {
				nonip = 0;
			}
		} else {
			supplied.proto = (strchr(*uaddr, ':') != 0) ?
						"udp6" : "udp";
			nonip = 0;
		}
		supplied.uaddr = *uaddr;
		supplied.family = (strchr(*uaddr, ':') != 0) ?
						"inet6" : "inet";
		epcand[0] = &supplied;
		epc = 1;
		nonip = 0;
	}

	nc = 0;
	clnt = 0;
	status = RPC_FAILED;	/* Anything except RPC_SUCCESS */

	/*
	 * Loop over the endpoint candidates. Defer error reporting (except
	 * for the netconfig entry) until we've looked at all candidates.
	 */
	for (i = 0; i < epc; i++) {

		if (nc != 0)
			freenetconfigent(nc);
		nc = getnetconfigent(epcand[i]->proto);

		if (nc == 0) {
			msg("unable to locate netconfig info for netid.");
			if (needfree)
				free_eps(teps, tsrv.ep.ep_len);
			return (0);
		}

		/*
		 * Add the appropriate port number to the uaddr
		 */
		useua = epcand[i]->uaddr;
		useid = epcand[i]->proto;
		if (strcasecmp(nc->nc_protofmly, NC_INET) == 0) {
			(void) sscanf(useua,
					"%d.%d.%d.%d.", &a1, &a2, &a3, &a4);
			(void) sprintf(ipuaddr, "%d.%d.%d.%d.0.111",
					a1, a2, a3, a4);
			useua = &ipuaddr[0];
		} else if (strcasecmp(nc->nc_protofmly, NC_INET6) == 0) {
			size_t	len;
			char	*port = ".0.111";

			if (strlen(useua) >= sizeof (ipuaddr)) {
				freenetconfigent(nc);
				if (needfree)
					free_eps(teps, tsrv.ep.ep_len);
				return (0);
			}

			(void) strcpy(ipuaddr, useua);

			/* get the IPv6 address out of the uaddr */
			if ((dot = strrchr(ipuaddr, '.')) != 0) {
				*dot = '\0';
				if ((dot = strrchr(ipuaddr, '.')) != 0)
					*dot = '\0';
			}

			if (dot == 0 ||
				(len = strlen(ipuaddr))+strlen(port) >=
						sizeof (ipuaddr)) {
				freenetconfigent(nc);
				if (needfree)
					free_eps(teps, tsrv.ep.ep_len);
				return (0);
			}

			/* now put in 0.111 */
			(void) strcat(ipuaddr + len, port);
			useua = ipuaddr;
		}

		/*
		 * Create the client handle to rpcbind. Note we always try
		 * version 3 since that is the earliest version that supports
		 * the RPCB_GETTIME call. Also it is the version that comes
		 * standard with SVR4. Since most everyone supports TCP/IP
		 * we could consider trying the rtime call first.
		 */
		if (clnt != 0)
			clnt_destroy(clnt);
		clnt = __nis_clnt_create(RPC_ANYFD, nc, useua, 0, 0, RPCBPROG,
					RPCBVERS, 0, 0);
		if (! clnt)
			continue;

		tv.tv_sec = 5;
		tv.tv_usec = 0;
		time_valid = 0;

		status = clnt_call(clnt, RPCBPROC_GETTIME, xdr_void, NULL,
					xdr_u_int, (char *)&thetime, tv);
		/*
		 * The only error we check for is anything but success. In
		 * fact we could have seen PROGMISMATCH if talking to a 4.1
		 * machine (pmap v2) or TIMEDOUT if the net was busy.
		 */
		if (status == RPC_SUCCESS)
			break;

	}

	if (status == RPC_SUCCESS) {
		time_valid = 1;
	} else if (clnt == 0) {
		msg("unable to create client handle to rpcbind.");
		freenetconfigent(nc);
		if (needfree)
			free_eps(teps, tsrv.ep.ep_len);
		return (0);
	} else {

		/*
		 * Try the timeservice port. This presumably only exists
		 * for IP transports, so we ignore the non-IP ones.
		 */

		for (i = 0; i < epc-nonip; i++) {

			/*
			 * Convert PMAP address into timeservice address
			 * We take advantage of the fact that we "know" what
			 * a universal address looks like for inet transports.
			 *
			 * We also know that the internet timeservice is always
			 * listening on port 37.
			 */

			if (nc != 0)
				freenetconfigent(nc);
			nc = getnetconfigent(epcand[i]->proto);

			if (nc == 0) {
				msg("no netconfig info for netid.");
				if (needfree)
					free_eps(teps, tsrv.ep.ep_len);
				return (0);
			}

			useua = epcand[i]->uaddr;
			useid = epcand[i]->proto;

			if (strcasecmp(nc->nc_protofmly, NC_INET) == 0)  {
				(void) sscanf(useua,
					"%d.%d.%d.%d.", &a1, &a2, &a3, &a4);
				(void) sprintf(ut, "%d.%d.%d.%d.0.37",
							a1, a2, a3, a4);
			} else if (strcasecmp(nc->nc_protofmly, NC_INET6) ==
					0) {
				size_t	len;
				char	*port = ".0.37";

				if (strlen(useua) >= sizeof (ut)) {
					goto error;
				}

				(void) strcpy(ut, useua);

				/* get the IPv6 address out of the uaddr */
				if ((dot = strrchr(ut, '.')) != 0) {
					*dot = '\0';
					if ((dot = strrchr(ut, '.')) != 0)
						*dot = '\0';
				}

				if (dot == 0) {
					goto error;
				}

				if ((len = strlen(ut))+strlen(port) >=
						sizeof (ut)) {
					goto error;
				}

				(void) strcat(ut + len, port);

			}

			addr = uaddr2taddr(nc, ut);
			if (! addr) {
				msg("timeservice uaddr to taddr failed.");
				goto error;
			}

			rtime_fd = t_open(nc->nc_device, O_RDWR, NULL);
			if (rtime_fd == -1) {
				msg("unable to open fd to network.");
				goto error;
			}

			if (t_bind(rtime_fd, NULL, NULL) < 0) {
				msg("unable to bind an endpoint to fd.");
				goto error;
			}

			/*
			 * Now depending on whether or not we're talking to
			 * UDP we set a timeout or not.
			 */
			if (nc->nc_semantics == NC_TPI_CLTS) {
				struct t_unitdata tu_data;
				struct pollfd pfd;
				int res;

				tu_data.addr = *addr;
				tu_data.udata.buf = (char *)&thetime;
				tu_data.udata.len = (uint_t)sizeof (thetime);
				tu_data.udata.maxlen = tu_data.udata.len;
				tu_data.opt.len = 0;
				tu_data.opt.maxlen = 0;
				if (t_sndudata(rtime_fd, &tu_data) == -1) {
					msg("udp : t_sndudata failed.");
					goto error;
				}
				pfd.fd = rtime_fd;
				pfd.events =
				POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND;

				do {
					res = poll(&pfd, 1, 10000);
				} while (res < 0);
				if ((res <= 0) || (pfd.revents & POLLNVAL))
					goto error;
				if (t_rcvudata(rtime_fd, &tu_data, &flag) <
						0) {
					msg("t_rvcdata failed on udp trpt.");
					goto error;
				}
				time_valid = 1;
			} else {
				struct t_call sndcall;

				sndcall.addr = *addr;
				sndcall.opt.len = sndcall.opt.maxlen = 0;
				sndcall.udata.len = sndcall.udata.maxlen = 0;

				oldsig = (void (*)())signal(SIGALRM,
							alarm_hndler);
				saw_alarm = 0; /* global tracking the alarm */
				(void) alarm(20); /* only wait 20 seconds */
				if (t_connect(rtime_fd, &sndcall, NULL) ==
						-1) {
					msg("connect tcp endpoint failedd.");
					goto error;
				}
				if (saw_alarm) {
					msg("alarm caught it; unreachable.");
					goto error;
				}
				if (t_rcv(rtime_fd, (char *)&thetime,
				    (uint_t)sizeof (thetime), &flag) !=
						(uint_t)sizeof (thetime)) {
					if (saw_alarm) {
						/*EMPTY*/
						msg("timed out TCP call.");
					} else {
						/*EMPTY*/
						msg("wrong size results");
					}
					goto error;
				}
				time_valid = 1;
			}
			if (time_valid) {
				thetime = ntohl(thetime);
				/* adjust to UNIX time */
				thetime = thetime - TOFFSET;
			} else
				thetime = 0;
		}
	}

error:
	/*
	 * clean up our allocated data structures.
	 */
	if (addr)
		netdir_free((char *)(addr), ND_ADDR);

	if (rtime_fd != -1)
		(void) t_close(rtime_fd);

	if (clnt)
		clnt_destroy(clnt);

	if (nc)
		freenetconfigent(nc);

	if (oldsig) {
		(void) alarm(0); /* reset that alarm if its outstanding */
		(void) signal(SIGALRM, oldsig);
	}

	/*
	 * note, don't free uaddr strings until after we've made a
	 * copy of them.
	 */
	if (time_valid) {
		if (! *netid) {
			*netid = strdup(useid);
			if (! *netid) {
				msg("__rpc_get_time_offset: strdup failed.");
				if (needfree)
					free_eps(teps, tsrv.ep.ep_len);
				return (0);
			}

			*uaddr = strdup(useua);
			if (! *uaddr) {
				msg("__rpc_get_time_offset: strdup failed.");
				if (*netid)
					free(*netid);
				if (needfree)
					free_eps(teps, tsrv.ep.ep_len);
				return (0);
			}
		}

		(void) gettimeofday(&tv, 0);

		/* Round to the nearest second */
		tv.tv_sec += (tv.tv_sec > 500000) ? 1 : 0;
		delta = (thetime > tv.tv_sec) ? thetime - tv.tv_sec :
						tv.tv_sec - thetime;
		td->tv_sec = (thetime < tv.tv_sec) ? - delta : delta;
		td->tv_usec = 0;
	} else {
		/*EMPTY*/
		msg("unable to get the server's time.");
	}

	if (needfree)
		free_eps(teps, tsrv.ep.ep_len);

	return (time_valid);
}
