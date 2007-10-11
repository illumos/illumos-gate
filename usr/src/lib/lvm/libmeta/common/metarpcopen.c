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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

#include <meta.h>
#include <metad.h>
#include <sdssc.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define	CC_TTL_MAX	20

typedef struct {
	char		*cc_node;
	struct timeval	cc_ttl;
	CLIENT		*cc_clp;
} client_cache_t;

typedef struct client_header {
	client_cache_t	**ch_cache;	/* array of clients. */
	mutex_t		ch_mutex;	/* lock access to ch_cache */
} client_header_t;

/*
 * This structure is used to pass data from meta_client_create to
 * client_create_helper via meta_client_create_retry.
 */
typedef struct clnt_data {
	rpcprog_t	cd_prognum;	/* RPC program number */
	rpcvers_t	cd_version;	/* Desired interface version */
	char		*cd_nettype;	/* Type of network to use */
} clnt_data_t;

#define	MALLOC_BLK_SIZE	10
static client_header_t	client_header = {(client_cache_t **)NULL, DEFAULTMUTEX};

static void
cc_add(
	client_header_t *header,
	char *node,
	CLIENT *clntp,
	md_error_t *ep
)
{
	client_cache_t ***cachep = &header->ch_cache;
	struct timeval	now;
	int		i;
	int		j = 0;

	if (gettimeofday(&now, NULL) == -1) {
		(void) mdsyserror(ep, errno, "gettimeofday()");
		return;
	}

	(void) mutex_lock(&header->ch_mutex);
	if (*cachep) {
		for (i = 0; (*cachep)[i] != NULL; i++)
			if (strcmp((*cachep)[i]->cc_node, node) == 0 &&
			    (*cachep)[i]->cc_clp == NULL) {
				(*cachep)[i]->cc_clp = clntp;
				(*cachep)[i]->cc_ttl = now;
				(void) mutex_unlock(&header->ch_mutex);
				return;
			}
	} else {
		*cachep = Calloc(MALLOC_BLK_SIZE, sizeof (**cachep));
		i = 0;
	}

	(*cachep)[i] = Zalloc(sizeof (***cachep));
	(*cachep)[i]->cc_node = Strdup(node);
	(*cachep)[i]->cc_clp = clntp;
	(*cachep)[i]->cc_ttl = now;

	if ((++i % MALLOC_BLK_SIZE) == 0) {
		*cachep = Realloc(*cachep,
		    (i + MALLOC_BLK_SIZE) * sizeof (**cachep));
		for (j = i; j < (i + MALLOC_BLK_SIZE); j++)
			(*cachep)[j] = NULL;
	}
	(void) mutex_unlock(&header->ch_mutex);
}

static void
rel_clntp(client_cache_t *cachep)
{
	CLIENT		*clntp = cachep->cc_clp;

	if (clntp != NULL) {
		auth_destroy(clntp->cl_auth);
		clnt_destroy(clntp);
	}
	cachep->cc_clp = NULL;
}

static void
cc_destroy(client_header_t *header)
{
	client_cache_t ***cachep = &header->ch_cache;
	int	i;

	(void) mutex_lock(&header->ch_mutex);
	if (*cachep) {
		for (i = 0; ((*cachep)[i] != NULL); i++) {
			client_cache_t	*p = (*cachep)[i];

			Free(p->cc_node);
			rel_clntp(p);
			Free(p);
		}
		Free(*cachep);
		*cachep = NULL;
	}
	(void) mutex_unlock(&header->ch_mutex);
}

/*
 * Set the timeout value for this client handle.
 */
int
cl_sto(
	CLIENT		*clntp,
	char		*hostname,
	long		time_out,
	md_error_t	*ep
)
{
	struct timeval	nto;

	(void) memset(&nto, '\0', sizeof (nto));

	nto.tv_sec = time_out;

	if (clnt_control(clntp, CLSET_TIMEOUT, (char *)&nto) != TRUE)
		return (mdrpcerror(ep, clntp, hostname,
		    dgettext(TEXT_DOMAIN, "metad client set timeout")));

	return (0);
}

/*
 * client_create_vers_retry is the helper function to be passed to
 * meta_client_create_retry to do the actual work of creating the client
 * when version selection is necessary.
 */

/* ARGSUSED */
static CLIENT *
client_create_vers_retry(char *hostname,
	void *ignore,
	struct timeval *tout
)
{
	rpcvers_t	vers;		/* Version # not needed. */

	return (clnt_create_vers_timed(hostname, METAD, &vers,
	    METAD_VERSION, METAD_VERSION_DEVID, "tcp", tout));
}

/*
 * client_create_helper is the helper function to be passed to
 * meta_client_create_retry when plain vanilla client create is desired.
 */
static CLIENT *
client_create_helper(char *hostname, void *private, struct timeval *time_out)
{
	clnt_data_t	*cd = (clnt_data_t *)private;

	return (clnt_create_timed(hostname, cd->cd_prognum, cd->cd_version,
	    cd->cd_nettype, time_out));
}

/*
 * meta_client_create_retry is a general function to assist in creating RPC
 * clients.  This function handles retrying if the attempt to create a
 * client fails.  meta_client_create_retry itself does not actually create
 * the client.  Instead it calls the helper function, func, to do that job.
 *
 * With the help of func, meta_client_create_retry will create an RPC
 * connection allowing up to tout seconds to complete the task.  If the
 * connection creation fails for RPC_RPCBFAILURE, RPC_CANTRECV or
 * RPC_PROGNOTREGISTERED and tout seconds have not passed,
 * meta_client_create_retry will try again.  The reason retries are
 * important is that when the inet daemon is being refreshed, it can take
 * 15-20 seconds for it to start responding again.
 *
 * Arguments:
 *
 *	hostname	- Name of remote host
 *
 *	func		- Pointer to the helper function, that will
 *			  actually try to create the client.
 *
 *	data		- Private data to be passed on to func.
 *			  meta_client_create_retry treats this as an opaque
 *			  pointer.
 *
 *	tout		- Number of seconds to allow for the connection
 *			  attempt.
 *
 *	ep		- Standard SVM error pointer.  May be NULL.
 */
CLIENT *
meta_client_create_retry(
	char			*hostname,
	clnt_create_func_t	func,
	void			*data,
	time_t			tout,
	md_error_t		*ep
)
{
	static int		debug;		/* print debugging info */
	static int		debug_set = 0;

	CLIENT			*clnt = (CLIENT *) NULL;
	struct timeval		curtime;
	char			*d;
	struct timeval		start;
	struct timeval		timeout;

	if (debug_set == 0) {
		d = getenv("MD_DEBUG");
		if (d == NULL) {
			debug = 0;
		} else {
			debug = (strstr(d, "RPC") == NULL) ? 0 : 1;
		}
		debug_set = 1;
	}
	timeout.tv_usec = 0;
	if (gettimeofday(&start, NULL) == -1) {
		if (ep != (md_error_t *)NULL) {
			(void) mdsyserror(ep, errno, "gettimeofday()");
		}
		return (clnt);
	}
	curtime = start;
	while ((curtime.tv_sec - start.tv_sec) < tout) {
		/* Use remaining time as the timeout value. */
		timeout.tv_sec = tout - (curtime.tv_sec - start.tv_sec);
		clnt = (*func)(hostname, data, &timeout);
		if (clnt != (CLIENT *) NULL)
			break;
		if ((rpc_createerr.cf_stat == RPC_RPCBFAILURE) ||
		    (rpc_createerr.cf_stat == RPC_PROGNOTREGISTERED) ||
		    (rpc_createerr.cf_stat == RPC_CANTRECV)) {
			if (debug) {
				clnt_pcreateerror("meta_client_create_retry");
			}
			/* If error might be fixed in time, sleep & try again */
			(void) sleep(2);
			if (gettimeofday(&curtime, NULL) == -1) {
				if (ep != (md_error_t *)NULL) {
					(void) mdsyserror(ep, errno,
					    "gettimeofday()");
				}
				return (clnt);
			}
		} else {
			/* Not a recoverable error. */
			break;
		}
	}
	if ((clnt == (CLIENT *) NULL) && (ep != (md_error_t *)NULL)) {
		(void) mdrpccreateerror(ep, hostname,
		    "meta_client_create_retry");
	}
	return (clnt);
}

/*
 * meta_client_create is intended to be used within SVM as a replacement
 * for calls to clnt_create.  meta_client_create invokes the retry
 * mechanism of meta_client_create_retry.
 */
CLIENT *
meta_client_create(char *host, rpcprog_t prognum, rpcvers_t version,
	char *nettype)
{
	clnt_data_t		cd;

	cd.cd_prognum = prognum;
	cd.cd_version = version;
	cd.cd_nettype = nettype;
	return (meta_client_create_retry(host, client_create_helper,
	    (void *)&cd, MD_CLNT_CREATE_TOUT, (md_error_t *)NULL));
}

/*
 * create and return RPC connection
 */
CLIENT *
metarpcopen(
	char		*hostname,
	long		time_out,
	md_error_t	*ep
)
{
	CLIENT		*clntp = NULL;
	client_cache_t	***cachep = &client_header.ch_cache;
	int		i;
	long		delta;
	struct timeval	now;
	struct in_addr	p_ip;
	char		*host_sc = NULL;
	char		host_priv[18];

	/*
	 * If we are in cluster mode, lets use the private interconnect
	 * hostnames to establish the rpc connections.
	 */
	if (sdssc_bind_library() != SDSSC_NOT_BOUND)
		if (sdssc_get_priv_ipaddr(hostname, &p_ip) == SDSSC_OKAY) {
			/*
			 * inet_ntoa() returns pointer to a string in the
			 * base 256 notation d.d.d.d (IPv4) and so
			 * host_priv[18] should be sufficient enough to
			 * hold it.
			 */
			host_sc = inet_ntoa(p_ip);
			if (host_sc != NULL) {
				int size = sizeof (host_priv);
				if (strlcpy(host_priv, host_sc, size) < size)
					hostname = host_priv;
			}
		}

	if (gettimeofday(&now, NULL) == -1) {
		(void) mdsyserror(ep, errno, "gettimeofday()");
		return (NULL);
	}

	/*
	 * Before trying to create the client, make sure that the core SVM
	 * services are enabled by the Service Management Facility.  We
	 * don't want to suffer the 60 second timeout if the services are
	 * not even enabled.  This call actually only verifies that they
	 * are enabled on this host no matter which host the caller wants
	 * to connect to.  Nonetheless, if the services are not enabled on
	 * the local host, our RPC stuff is not going to work as expected.
	 */
	if (meta_smf_isonline(META_SMF_CORE, ep) == 0) {
		return (NULL);
	}

	(void) mutex_lock(&client_header.ch_mutex);
	if (client_header.ch_cache) {
		for (i = 0; (*cachep)[i] != NULL; i++) {
			if (strcmp((*cachep)[i]->cc_node, hostname) == 0) {
				clntp = (*cachep)[i]->cc_clp;
				if (clntp == NULL)
					continue;
				delta = now.tv_sec -
				    (*cachep)[i]->cc_ttl.tv_sec;
				if (delta > CC_TTL_MAX) {
					rel_clntp((*cachep)[i]);
					continue;
				}
				if (cl_sto(clntp, hostname, time_out,
				    ep) != 0) {
					(void) mutex_unlock(
					    &client_header.ch_mutex);
					return (NULL);
				}
				(void) mutex_unlock(&client_header.ch_mutex);
				return (clntp);
			}
		}
	}
	(void) mutex_unlock(&client_header.ch_mutex);

	/*
	 * Try to create a version 2 client handle by default.
	 * If this fails (i.e. client is version 1), try to
	 * create a version 1 client handle.
	 */
	clntp = meta_client_create_retry(hostname, client_create_vers_retry,
	    (void *)NULL, MD_CLNT_CREATE_TOUT, ep);

	/* open connection */
	if (clntp == NULL) {
		(void) mdrpccreateerror(ep, hostname,
		    dgettext(TEXT_DOMAIN, "metad client create"));
		cc_add(&client_header, hostname, NULL, ep);
		return (NULL);
	} else {
		auth_destroy(clntp->cl_auth);
		clntp->cl_auth = authsys_create_default();
		assert(clntp->cl_auth != NULL);
	}

	cc_add(&client_header, hostname, clntp, ep);

	if (cl_sto(clntp, hostname, time_out, ep) != 0)
		return (NULL);

	return (clntp);
}

/*
 * metarpcclose - is a place holder so that when using
 *		  metarpcopen, it does not appear that
 *		  we have dangling opens.  We can at some
 *		  later decrement open counts here too, if needed.
 */
/*ARGSUSED*/
void
metarpcclose(CLIENT *clntp)
{
}

void
metarpccloseall(void)
{
	cc_destroy(&client_header);
}
