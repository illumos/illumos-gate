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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#include "mt.h"
#include "rpc_mt.h"
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <rpc/rpc.h>
#include <rpc/nettype.h>
#include <netdir.h>
#include <string.h>
#include <syslog.h>

extern int __td_setnodelay(int);
extern bool_t __rpc_is_local_host(const char *);
extern bool_t __rpc_try_doors(const char *, bool_t *);
extern CLIENT *_clnt_vc_create_timed(int, struct netbuf *, rpcprog_t,
			rpcvers_t, uint_t, uint_t, const struct timeval *);

CLIENT *_clnt_tli_create_timed(int, const struct netconfig *, struct netbuf *,
		rpcprog_t, rpcvers_t, uint_t, uint_t, const struct timeval *);

#ifndef NETIDLEN
#define	NETIDLEN 32
#endif

/*
 * Generic client creation with version checking the value of
 * vers_out is set to the highest server supported value
 * vers_low <= vers_out <= vers_high  AND an error results
 * if this can not be done.
 *
 * It calls clnt_create_vers_timed() with a NULL value for the timeout
 * pointer, which indicates that the default timeout should be used.
 */
CLIENT *
clnt_create_vers(const char *hostname, const rpcprog_t prog,
	rpcvers_t *vers_out, const rpcvers_t vers_low,
	const rpcvers_t vers_high, const char *nettype)
{
	return (clnt_create_vers_timed(hostname, prog, vers_out, vers_low,
				vers_high, nettype, NULL));
}

/*
 * This routine has the same definition as clnt_create_vers(),
 * except it takes an additional timeout parameter - a pointer to
 * a timeval structure.  A NULL value for the pointer indicates
 * that the default timeout value should be used.
 */
CLIENT *
clnt_create_vers_timed(const char *hostname, const rpcprog_t prog,
    rpcvers_t *vers_out, const rpcvers_t vers_low, const rpcvers_t vers_high,
    const char *nettype, const struct timeval *tp)
{
	CLIENT *clnt;
	struct timeval to;
	enum clnt_stat rpc_stat;
	struct rpc_err rpcerr;
	rpcvers_t v_low, v_high;

	clnt = clnt_create_timed(hostname, prog, vers_high, nettype, tp);
	if (clnt == NULL)
		return (NULL);
	if (tp == NULL) {
		to.tv_sec = 10;
		to.tv_usec = 0;
	} else
		to = *tp;

	rpc_stat = clnt_call(clnt, NULLPROC, (xdrproc_t)xdr_void,
			NULL, (xdrproc_t)xdr_void, NULL, to);
	if (rpc_stat == RPC_SUCCESS) {
		*vers_out = vers_high;
		return (clnt);
	}
	v_low = vers_low;
	v_high = vers_high;
	while (rpc_stat == RPC_PROGVERSMISMATCH && v_high > v_low) {
		unsigned int minvers, maxvers;

		clnt_geterr(clnt, &rpcerr);
		minvers = rpcerr.re_vers.low;
		maxvers = rpcerr.re_vers.high;
		if (maxvers < v_high)
			v_high = maxvers;
		else
			v_high--;
		if (minvers > v_low)
			v_low = minvers;
		if (v_low > v_high) {
			goto error;
		}
		CLNT_CONTROL(clnt, CLSET_VERS, (char *)&v_high);
		rpc_stat = clnt_call(clnt, NULLPROC, (xdrproc_t)xdr_void,
				NULL, (xdrproc_t)xdr_void,
				NULL, to);
		if (rpc_stat == RPC_SUCCESS) {
			*vers_out = v_high;
			return (clnt);
		}
	}
	clnt_geterr(clnt, &rpcerr);

error:
	rpc_createerr.cf_stat = rpc_stat;
	rpc_createerr.cf_error = rpcerr;
	clnt_destroy(clnt);
	return (NULL);
}

/*
 * Top level client creation routine.
 * Generic client creation: takes (servers name, program-number, nettype) and
 * returns client handle. Default options are set, which the user can
 * change using the rpc equivalent of ioctl()'s.
 *
 * It tries for all the netids in that particular class of netid until
 * it succeeds.
 * XXX The error message in the case of failure will be the one
 * pertaining to the last create error.
 *
 * It calls clnt_create_timed() with the default timeout.
 */
CLIENT *
clnt_create(const char *hostname, const rpcprog_t prog, const rpcvers_t vers,
    const char *nettype)
{
	return (clnt_create_timed(hostname, prog, vers, nettype, NULL));
}

/*
 * This the routine has the same definition as clnt_create(),
 * except it takes an additional timeout parameter - a pointer to
 * a timeval structure.  A NULL value for the pointer indicates
 * that the default timeout value should be used.
 *
 * This function calls clnt_tp_create_timed().
 */
CLIENT *
clnt_create_timed(const char *hostname, const rpcprog_t prog,
    const rpcvers_t vers, const char *netclass, const struct timeval *tp)
{
	struct netconfig *nconf;
	CLIENT *clnt = NULL;
	void *handle;
	enum clnt_stat	save_cf_stat = RPC_SUCCESS;
	struct rpc_err	save_cf_error;
	char nettype_array[NETIDLEN];
	char *nettype = &nettype_array[0];
	bool_t try_others;

	if (netclass == NULL)
		nettype = NULL;
	else {
		size_t len = strlen(netclass);
		if (len >= sizeof (nettype_array)) {
			rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
			return (NULL);
		}
		(void) strcpy(nettype, netclass);
	}

	/*
	 * Check to see if a rendezvous over doors should be attempted.
	 */
	if (__rpc_try_doors(nettype, &try_others)) {
		/*
		 * Make sure this is the local host.
		 */
		if (__rpc_is_local_host(hostname)) {
			if ((clnt = clnt_door_create(prog, vers, 0)) != NULL)
				return (clnt);
			else {
				if (rpc_createerr.cf_stat == RPC_SYSTEMERROR)
					return (NULL);
				save_cf_stat = rpc_createerr.cf_stat;
				save_cf_error = rpc_createerr.cf_error;
			}
		} else {
			save_cf_stat = rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
		}
	}
	if (!try_others)
		return (NULL);

	if ((handle = __rpc_setconf((char *)nettype)) == NULL) {
		rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
		return (NULL);
	}
	rpc_createerr.cf_stat = RPC_SUCCESS;
	while (clnt == NULL) {
		if ((nconf = __rpc_getconf(handle)) == NULL) {
			if (rpc_createerr.cf_stat == RPC_SUCCESS)
				rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
			break;
		}
		clnt = clnt_tp_create_timed(hostname, prog, vers, nconf, tp);
		if (clnt)
			break;
		else {
			/*
			 *	Since we didn't get a name-to-address
			 *	translation failure here, we remember
			 *	this particular error.  The object of
			 *	this is to enable us to return to the
			 *	caller a more-specific error than the
			 *	unhelpful ``Name to address translation
			 *	failed'' which might well occur if we
			 *	merely returned the last error (because
			 *	the local loopbacks are typically the
			 *	last ones in /etc/netconfig and the most
			 *	likely to be unable to translate a host
			 *	name).  We also check for a more
			 *	meaningful error than ``unknown host
			 *	name'' for the same reasons.
			 */
			if (rpc_createerr.cf_stat == RPC_SYSTEMERROR) {
				syslog(LOG_ERR, "clnt_create_timed: "
					"RPC_SYSTEMERROR.");
				break;
			}

			if (rpc_createerr.cf_stat != RPC_N2AXLATEFAILURE &&
			    rpc_createerr.cf_stat != RPC_UNKNOWNHOST) {
				save_cf_stat = rpc_createerr.cf_stat;
				save_cf_error = rpc_createerr.cf_error;
			}
		}
	}

	/*
	 *	Attempt to return an error more specific than ``Name to address
	 *	translation failed'' or ``unknown host name''
	 */
	if ((rpc_createerr.cf_stat == RPC_N2AXLATEFAILURE ||
				rpc_createerr.cf_stat == RPC_UNKNOWNHOST) &&
					(save_cf_stat != RPC_SUCCESS)) {
		rpc_createerr.cf_stat = save_cf_stat;
		rpc_createerr.cf_error = save_cf_error;
	}
	__rpc_endconf(handle);
	return (clnt);
}

/*
 * Create a client handle for a well known service or a specific port on
 * host. This routine bypasses rpcbind and can be use to construct a client
 * handle to services that are not registered with rpcbind or where the remote
 * rpcbind is not available, e.g., the remote rpcbind port is blocked by a
 * firewall. We construct a client handle and then ping the service's NULL
 * proc to see that the service is really available. If the caller supplies
 * a non zero port number, the service name is ignored and the port will be
 * used. A non-zero port number limits the protocol family to inet or inet6.
 */

CLIENT *
clnt_create_service_timed(const char *host, const char *service,
			const rpcprog_t prog, const rpcvers_t vers,
			const ushort_t port, const char *netclass,
			const struct timeval *tmout)
{
	int fd;
	void *handle;
	CLIENT *clnt = NULL;
	struct netconfig *nconf;
	struct nd_hostserv hs;
	struct nd_addrlist *raddrs;
	struct t_bind *tbind = NULL;
	struct timeval to;
	char nettype_array[NETIDLEN];
	char *nettype = &nettype_array[0];
	char *hostname, *serv;
	bool_t try_others;

	/*
	 * handle const of netclass
	 */
	if (netclass == NULL)
		nettype = NULL;
	else {
		size_t len = strlen(netclass);
		if (len >= sizeof (nettype_array)) {
			rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
			return (NULL);
		}
		(void) strcpy(nettype, netclass);
	}

	if (tmout == NULL) {
		to.tv_sec = 10;
		to.tv_usec = 0;
	} else
		to = *tmout;

	if ((handle = __rpc_setconf(nettype)) == NULL) {
		rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
		return (NULL);
	}

	/*
	 * Sinct host, and service are const
	 */
	if (host == NULL || (hostname = strdup(host)) == NULL) {
		rpc_createerr.cf_stat = RPC_SYSTEMERROR;
		rpc_createerr.cf_error.re_errno = (host ? errno : EINVAL);
		rpc_createerr.cf_error.re_terrno = 0;
		return (NULL);
	}

	if (service == NULL)
		serv = NULL;
	else if ((serv = strdup(service ? service : "")) == NULL) {
		free(hostname);
		rpc_createerr.cf_stat = RPC_SYSTEMERROR;
		rpc_createerr.cf_error.re_errno = errno;
		rpc_createerr.cf_error.re_terrno = 0;
		return (NULL);
	}

	hs.h_host = hostname;
	hs.h_serv = port ? NULL : serv;

	/*
	 * Check to see if a rendezvous over doors should be attempted.
	 */
	if (__rpc_try_doors(nettype, &try_others)) {
		/*
		 * Make sure this is the local host.
		 */
		if (__rpc_is_local_host(hostname)) {
			if ((clnt = clnt_door_create(prog, vers, 0)) != NULL)
				goto done;
			else if (rpc_createerr.cf_stat == RPC_SYSTEMERROR)
				goto done;
		} else {
			rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
		}
	}
	if (!try_others)
		goto done;

	rpc_createerr.cf_stat = RPC_SUCCESS;
	while (clnt == NULL) {
		tbind = NULL;
		if ((nconf = __rpc_getconf(handle)) == NULL) {
			if (rpc_createerr.cf_stat == RPC_SUCCESS)
				rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
			break;
		}

		if (port) {
			if (strcmp(nconf->nc_protofmly, NC_INET) != 0 &&
			    strcmp(nconf->nc_protofmly, NC_INET6) != 0)
				continue;
		}

		if ((fd = t_open(nconf->nc_device, O_RDWR, NULL)) < 0) {
			rpc_createerr.cf_stat = RPC_TLIERROR;
			rpc_createerr.cf_error.re_errno = errno;
			rpc_createerr.cf_error.re_terrno = t_errno;
			continue;
		}

		RPC_RAISEFD(fd);

		__rpc_set_mac_options(fd, nconf, prog);

		/* LINTED pointer cast */
		if ((tbind = (struct t_bind *)t_alloc(fd, T_BIND, T_ADDR))
		    == NULL) {
			(void) t_close(fd);
			rpc_createerr.cf_stat = RPC_TLIERROR;
			rpc_createerr.cf_error.re_errno = errno;
			rpc_createerr.cf_error.re_terrno = t_errno;
			continue;
		}

		if (netdir_getbyname(nconf, &hs, &raddrs) != ND_OK) {
			if (rpc_createerr.cf_stat == RPC_SUCCESS)
				rpc_createerr.cf_stat = RPC_UNKNOWNHOST;
			if (tbind)
				(void) t_free((char *)tbind, T_BIND);
			(void) t_close(fd);
			continue;
		}
		(void) memcpy(tbind->addr.buf, raddrs->n_addrs->buf,
		    raddrs->n_addrs->len);
		tbind->addr.len = raddrs->n_addrs->len;
		netdir_free((void *)raddrs, ND_ADDRLIST);

		if (port) {
			if (strcmp(nconf->nc_protofmly, NC_INET) == 0)
				/* LINTED pointer alignment */
				((struct sockaddr_in *)
				tbind->addr.buf)->sin_port = htons(port);
			else if (strcmp(nconf->nc_protofmly, NC_INET6) == 0)
				/* LINTED pointer alignment */
				((struct sockaddr_in6 *)
				tbind->addr.buf)->sin6_port = htons(port);
		}

		clnt = _clnt_tli_create_timed(fd, nconf, &tbind->addr,
					    prog, vers, 0, 0, &to);

		if (clnt == NULL) {
			if (tbind)
				(void) t_free((char *)tbind, T_BIND);
			(void) t_close(fd);
			continue;
		}

		(void) CLNT_CONTROL(clnt, CLSET_FD_CLOSE, NULL);

		/*
		 * Check if we can reach the server with this clnt handle
		 * Other clnt_create calls do a ping by contacting the
		 * remote rpcbind, here will just try to execute the service's
		 * NULL proc.
		 */

		rpc_createerr.cf_stat = clnt_call(clnt, NULLPROC,
						xdr_void, 0, xdr_void, 0, to);

		rpc_createerr.cf_error.re_errno = rpc_callerr.re_status;
		rpc_createerr.cf_error.re_terrno = 0;

		if (rpc_createerr.cf_stat != RPC_SUCCESS) {
			clnt_destroy(clnt);
			clnt = NULL;
			if (tbind)
				(void) t_free((char *)tbind, T_BIND);
			continue;
		} else
			break;
	}

	__rpc_endconf(handle);
	if (tbind)
		(void) t_free((char *)tbind, T_BIND);

done:
	if (hostname)
		free(hostname);
	if (serv)
		free(serv);

	return (clnt);
}

/*
 * Generic client creation: takes (servers name, program-number, netconf) and
 * returns client handle. Default options are set, which the user can
 * change using the rpc equivalent of ioctl()'s : clnt_control()
 * It finds out the server address from rpcbind and calls clnt_tli_create().
 *
 * It calls clnt_tp_create_timed() with the default timeout.
 */
CLIENT *
clnt_tp_create(const char *hostname, const rpcprog_t prog, const rpcvers_t vers,
    const struct netconfig *nconf)
{
	return (clnt_tp_create_timed(hostname, prog, vers, nconf, NULL));
}

/*
 * This has the same definition as clnt_tp_create(), except it
 * takes an additional parameter - a pointer to a timeval structure.
 * A NULL value for the timeout pointer indicates that the default
 * value for the timeout should be used.
 */
CLIENT *
clnt_tp_create_timed(const char *hostname, const rpcprog_t prog,
    const rpcvers_t vers, const struct netconfig *nconf,
    const struct timeval *tp)
{
	struct netbuf *svcaddr;			/* servers address */
	CLIENT *cl = NULL;			/* client handle */
	extern struct netbuf *__rpcb_findaddr_timed(rpcprog_t, rpcvers_t,
	    struct netconfig *, char *, CLIENT **, struct timeval *);

	if (nconf == NULL) {
		rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
		return (NULL);
	}

	/*
	 * Get the address of the server
	 */
	if ((svcaddr = __rpcb_findaddr_timed(prog, vers,
			(struct netconfig *)nconf, (char *)hostname,
			&cl, (struct timeval *)tp)) == NULL) {
		/* appropriate error number is set by rpcbind libraries */
		return (NULL);
	}
	if (cl == NULL) {
		cl = _clnt_tli_create_timed(RPC_ANYFD, nconf, svcaddr,
					prog, vers, 0, 0, tp);
	} else {
		/* Reuse the CLIENT handle and change the appropriate fields */
		if (CLNT_CONTROL(cl, CLSET_SVC_ADDR, (void *)svcaddr) == TRUE) {
			if (cl->cl_netid == NULL) {
				cl->cl_netid = strdup(nconf->nc_netid);
				if (cl->cl_netid == NULL) {
					netdir_free((char *)svcaddr, ND_ADDR);
					rpc_createerr.cf_stat = RPC_SYSTEMERROR;
					syslog(LOG_ERR,
						"clnt_tp_create_timed: "
						"strdup failed.");
					return (NULL);
				}
			}
			if (cl->cl_tp == NULL) {
				cl->cl_tp = strdup(nconf->nc_device);
				if (cl->cl_tp == NULL) {
					netdir_free((char *)svcaddr, ND_ADDR);
					if (cl->cl_netid)
						free(cl->cl_netid);
					rpc_createerr.cf_stat = RPC_SYSTEMERROR;
					syslog(LOG_ERR,
						"clnt_tp_create_timed: "
						"strdup failed.");
					return (NULL);
				}
			}
			(void) CLNT_CONTROL(cl, CLSET_PROG, (void *)&prog);
			(void) CLNT_CONTROL(cl, CLSET_VERS, (void *)&vers);
		} else {
			CLNT_DESTROY(cl);
			cl = _clnt_tli_create_timed(RPC_ANYFD, nconf, svcaddr,
					prog, vers, 0, 0, tp);
		}
	}
	netdir_free((char *)svcaddr, ND_ADDR);
	return (cl);
}

/*
 * Generic client creation:  returns client handle.
 * Default options are set, which the user can
 * change using the rpc equivalent of ioctl()'s : clnt_control().
 * If fd is RPC_ANYFD, it will be opened using nconf.
 * It will be bound if not so.
 * If sizes are 0; appropriate defaults will be chosen.
 */
CLIENT *
clnt_tli_create(const int fd, const struct netconfig *nconf,
    struct netbuf *svcaddr, const rpcprog_t prog, const rpcvers_t vers,
    const uint_t sendsz, const uint_t recvsz)
{
	return (_clnt_tli_create_timed(fd, nconf, svcaddr, prog, vers, sendsz,
		recvsz, NULL));
}

/*
 * This has the same definition as clnt_tli_create(), except it
 * takes an additional parameter - a pointer to a timeval structure.
 *
 * Not a public interface. This is for clnt_create_timed,
 * clnt_create_vers_times, clnt_tp_create_timed to pass down  the
 * timeout value to COTS creation routine.
 * (for bug 4049792: clnt_create_timed does not time out)
 */
CLIENT *
_clnt_tli_create_timed(int fd, const struct netconfig *nconf,
	struct netbuf *svcaddr, rpcprog_t prog, rpcvers_t vers, uint_t sendsz,
	uint_t recvsz, const struct timeval *tp)
{
	CLIENT *cl;			/* client handle */
	struct t_info tinfo;		/* transport info */
	bool_t madefd;			/* whether fd opened here */
	t_scalar_t servtype;
	int retval;

	if (fd == RPC_ANYFD) {
		if (nconf == NULL) {
			rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
			return (NULL);
		}

		fd = t_open(nconf->nc_device, O_RDWR, NULL);
		if (fd == -1)
			goto err;
		RPC_RAISEFD(fd);
		madefd = TRUE;
		__rpc_set_mac_options(fd, nconf, prog);
		if (t_bind(fd, NULL, NULL) == -1)
			goto err;
		switch (nconf->nc_semantics) {
		case NC_TPI_CLTS:
			servtype = T_CLTS;
			break;
		case NC_TPI_COTS:
			servtype = T_COTS;
			break;
		case NC_TPI_COTS_ORD:
			servtype = T_COTS_ORD;
			break;
		default:
			if (t_getinfo(fd, &tinfo) == -1)
				goto err;
			servtype = tinfo.servtype;
			break;
		}
	} else {
		int state;		/* Current state of provider */

		/*
		 * Sync the opened fd.
		 * Check whether bound or not, else bind it
		 */
		if (((state = t_sync(fd)) == -1) ||
		    ((state == T_UNBND) && (t_bind(fd, NULL, NULL) == -1)) ||
		    (t_getinfo(fd, &tinfo) == -1))
			goto err;
		servtype = tinfo.servtype;
		madefd = FALSE;
	}

	switch (servtype) {
	case T_COTS:
		cl = _clnt_vc_create_timed(fd, svcaddr, prog, vers, sendsz,
				recvsz, tp);
		break;
	case T_COTS_ORD:
		if (nconf && ((strcmp(nconf->nc_protofmly, NC_INET) == 0) ||
		    (strcmp(nconf->nc_protofmly, NC_INET6) == 0))) {
			retval =  __td_setnodelay(fd);
			if (retval == -1)
				goto err;
		}
		cl = _clnt_vc_create_timed(fd, svcaddr, prog, vers, sendsz,
			recvsz, tp);
		break;
	case T_CLTS:
		cl = clnt_dg_create(fd, svcaddr, prog, vers, sendsz, recvsz);
		break;
	default:
		goto err;
	}

	if (cl == NULL)
		goto err1; /* borrow errors from clnt_dg/vc creates */
	if (nconf) {
		cl->cl_netid = strdup(nconf->nc_netid);
		if (cl->cl_netid == NULL) {
			rpc_createerr.cf_stat = RPC_SYSTEMERROR;
			rpc_createerr.cf_error.re_errno = errno;
			rpc_createerr.cf_error.re_terrno = 0;
			syslog(LOG_ERR,
				"clnt_tli_create: strdup failed");
			goto err1;
		}
		cl->cl_tp = strdup(nconf->nc_device);
		if (cl->cl_tp == NULL) {
			if (cl->cl_netid)
				free(cl->cl_netid);
			rpc_createerr.cf_stat = RPC_SYSTEMERROR;
			rpc_createerr.cf_error.re_errno = errno;
			rpc_createerr.cf_error.re_terrno = 0;
			syslog(LOG_ERR,
				"clnt_tli_create: strdup failed");
			goto err1;
		}
	} else {
		struct netconfig *nc;

		if ((nc = __rpcfd_to_nconf(fd, servtype)) != NULL) {
			if (nc->nc_netid) {
				cl->cl_netid = strdup(nc->nc_netid);
				if (cl->cl_netid == NULL) {
					rpc_createerr.cf_stat = RPC_SYSTEMERROR;
					rpc_createerr.cf_error.re_errno = errno;
					rpc_createerr.cf_error.re_terrno = 0;
					syslog(LOG_ERR,
						"clnt_tli_create: "
						"strdup failed");
					goto err1;
				}
			}
			if (nc->nc_device) {
				cl->cl_tp = strdup(nc->nc_device);
				if (cl->cl_tp == NULL) {
					if (cl->cl_netid)
						free(cl->cl_netid);
					rpc_createerr.cf_stat = RPC_SYSTEMERROR;
					rpc_createerr.cf_error.re_errno = errno;
					rpc_createerr.cf_error.re_terrno = 0;
					syslog(LOG_ERR,
						"clnt_tli_create: "
						"strdup failed");
					goto err1;
				}
			}
			freenetconfigent(nc);
		}
		if (cl->cl_netid == NULL)
			cl->cl_netid = "";
		if (cl->cl_tp == NULL)
			cl->cl_tp = "";
	}
	if (madefd) {
		(void) CLNT_CONTROL(cl, CLSET_FD_CLOSE, NULL);
/*		(void) CLNT_CONTROL(cl, CLSET_POP_TIMOD, NULL);  */
	};

	return (cl);

err:
	rpc_createerr.cf_stat = RPC_TLIERROR;
	rpc_createerr.cf_error.re_errno = errno;
	rpc_createerr.cf_error.re_terrno = t_errno;
err1:	if (madefd)
		(void) t_close(fd);
	return (NULL);
}

/*
 *  To avoid conflicts with the "magic" file descriptors (0, 1, and 2),
 *  we try to not use them.  The __rpc_raise_fd() routine will dup
 *  a descriptor to a higher value.  If we fail to do it, we continue
 *  to use the old one (and hope for the best).
 */
int
__rpc_raise_fd(int fd)
{
	int nfd;

	if ((nfd = fcntl(fd, F_DUPFD, RPC_MINFD)) == -1)
		return (fd);

	if (t_sync(nfd) == -1) {
		(void) close(nfd);
		return (fd);
	}

	if (t_close(fd) == -1) {
		/* this is okay, we will syslog an error, then use the new fd */
		(void) syslog(LOG_ERR,
			"could not t_close() fd %d; mem & fd leak", fd);
	}

	return (nfd);
}
