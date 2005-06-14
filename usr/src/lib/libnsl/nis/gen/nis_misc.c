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
 * nis_misc.c
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * nis_misc.c
 *
 * This module contains miscellaneous library functions.
 */

#include "mt.h"
#include <string.h>
#include <syslog.h>
#include <malloc.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <tiuser.h>
#include <netdir.h>
#include <netinet/in.h>
#include <strings.h>
#include "nis_clnt.h"
#include "nis_local.h"

static void nis_sort_server_endpoints_inet(nis_server *);
extern char *handle_to_server_name(CLIENT *);
extern void *__inet_get_local_interfaces();
extern FILE *__nis_debug_file;


/* ARGSUSED */
int
__clear_directory_local(nis_name n)
{
	return (1);
}

int (*__clear_directory_ptr)(nis_name) = __clear_directory_local;

/*
 * __nis_pingproc()
 *
 * This function will send a  ping "message" to a remote server.
 * It doesn't bother to see if there are any results since the ping
 * is defined to be unreliable.
 */
void
__nis_pingproc(
	nis_server	*srv,	/* Server to talk to 		*/
	nis_name	name,	/* Directory that changed 	*/
	uint32_t	mtime)	/* When it changed		*/
{
	CLIENT		*clnt;
	ping_args	args;
	struct timeval	tv;

	clnt = nis_make_rpchandle(srv, 0, NIS_PROG, NIS_VERSION,
				ZMH_DG|ZMH_AUTH, 0, 0);
	if (! clnt)
		return;

	tv.tv_sec = 0;
	tv.tv_usec = 0;
	args.dir = name;
	args.stamp = mtime;
	(void) clnt_call(clnt, NIS_PING, xdr_ping_args, (char *)&args,
			xdr_void, 0, tv);
	clnt_destroy(clnt);
}

/*
 * nis_ping()
 *
 * This function is used to ping all of the servers that serve a given
 * directory. The point of the ping is to inform them that something
 * has changed in the directory and they should go off and find what it
 * is. Note that we avoid pinging ourselves for optimisation. During a
 * replica/master switch the location of the master object in the array
 * will briefly change from server[0] to the offset corresponding to
 * the new master (the old replica). When everything has settled down
 * after the switch, the master will once again be in server[0] of the
 * directory object. The object parameter is optional for clients
 * (REQUIRED FOR SERVERS) this is the object describing the directory.
 */

void
nis_ping(nis_name name, uint32_t mtime, nis_object *obj)
{
	nis_server	**srvs;
	nis_server	*s, *list;
	int		i, ns;
	nis_name	thishost = nis_local_host();

	if (obj) {
		if (name == 0)
			name = obj->DI_data.do_name;
		list = obj->DI_data.do_servers.do_servers_val;
		ns = obj->DI_data.do_servers.do_servers_len;

		for (i = 0, s = &(list[0]); i < ns; i++, s = &(list[i])) {

			if (nis_dir_cmp(s->name, thishost) == SAME_NAME) {
				continue;
			}

			__nis_pingproc(s, name, mtime);
		}
	} else {
		srvs = nis_getservlist(name);
		if (! srvs)
			return;

		for (i = 0, s = srvs[0]; s; i++, s = srvs[i]) {

			if (nis_dir_cmp(s->name, thishost) == SAME_NAME) {
				continue;
			}
			__nis_pingproc(s, name, mtime);

		}
		nis_freeservlist(srvs);
	}
}


/*
 * nis_dumplog(host, name, time)
 *
 * This function will dump log entries from the indicated host to the
 * caller. It is used by the replica servers to get the updates that have
 * occurred on a directory since the indicated time.
 */

log_result *
nis_dumplog(
	nis_server	*host,	/* Server to talk to		*/
	nis_name	name,	/* Directory name to dump.	*/
	uint32_t	dtime)	/* Last _valid_ timestamp.	*/
{
	CLIENT			*clnt;
	dump_args		da;
	struct timeval		tv;
	enum clnt_stat		stat;
	log_result	*result_ptr;

	result_ptr = (log_result *)calloc(1, sizeof (log_result));
	if (result_ptr == NULL) {
		syslog(LOG_ERR, "nis_dumplog: Client out of memory.");
		return (NULL);
	}

	clnt = nis_make_rpchandle(host, 0, NIS_PROG, NIS_VERSION,
				ZMH_VC+ZMH_AUTH, 0, 0);
	if (! clnt) {
		result_ptr->lr_status = NIS_NAMEUNREACHABLE;
		return (result_ptr);
	}
	(void) memset((char *)&da, 0, sizeof (da));
	da.da_dir = name;
	da.da_time = dtime;
	tv.tv_sec = NIS_DUMP_TIMEOUT;
	tv.tv_usec = 0;
	stat = clnt_call(clnt, NIS_DUMPLOG,
			xdr_dump_args, (char *)&da,
			xdr_log_result, (char *)result_ptr, tv);
	auth_destroy(clnt->cl_auth);
	clnt_destroy(clnt);

	/*
	 * Now see if the RPC succeeded. Note that we have
	 * to check for local vs. remote errors in order to
	 * know whether the contents of the log_result record
	 * (result_ptr) are meaningful.
	 */
	switch (stat) {
	case RPC_CANTENCODEARGS:
	case RPC_CANTDECODERES:
	case RPC_CANTSEND:
	case RPC_CANTRECV:
	case RPC_TIMEDOUT:
	case RPC_INTR:
		syslog(LOG_WARNING, "nis_dumplog: RPC error %d", stat);
		/*
		 * This is a local error, so just return a
		 * generic RPC error.
		 */
		result_ptr->lr_status = NIS_RPCERROR;
		break;

	default:
		/*
		 * All other return values mean that result_ptr
		 * already has a valid status code.
		 */
		break;
	}

	return (result_ptr);
}

/*
 * nis_dump(host, name, cback)
 *
 * This function will dump an entire directory from the indicated host.
 * It uses a callback function to minimize the memory requirements on
 * the client and server.
 */

log_result *
nis_dump(
	nis_server	*host,	/* Server to talk to		*/
	nis_name	name,	/* Directory name to dump.	*/
	int		(*cback)()) /* Callback function	*/
{
	CLIENT			*clnt;
	dump_args		da;
	struct timeval		tv;
	enum clnt_stat		stat;
	int			err;
	log_result		*result_ptr;

	result_ptr = (log_result *)calloc(1, sizeof (log_result));
	if (result_ptr == NULL) {
		syslog(LOG_ERR, "nis_dump: Client out of memory.");
		return (NULL);
	}

	clnt = nis_make_rpchandle(host, 0, NIS_PROG, NIS_VERSION,
				ZMH_VC+ZMH_AUTH, 0, 0);
	if (!clnt) {
		result_ptr->lr_status = NIS_NAMEUNREACHABLE;
		return (result_ptr);
	}
	(void) mutex_lock(&__nis_callback_lock);
	(void) memset((char *)&da, 0, sizeof (da));
	da.da_dir = name;
	da.da_time = 0;
	da.da_cbhost.da_cbhost_len = 1;
	da.da_cbhost.da_cbhost_val = __nis_init_dump_callback(clnt, cback,
								NULL);
	if (! da.da_cbhost.da_cbhost_val) {
		(void) mutex_unlock(&__nis_callback_lock);
		result_ptr->lr_status = NIS_CBERROR;
		auth_destroy(clnt->cl_auth);
		clnt_destroy(clnt);
		return (result_ptr);
	}

	/*
	 * The value of the NIS_DUMP_TIMEOUT is applicable only for the
	 * dump to get initiated.
	 */
	tv.tv_sec = NIS_DUMP_TIMEOUT;
	tv.tv_usec = 0;
	stat = clnt_call(clnt, NIS_DUMP, xdr_dump_args, (char *)&da,
			xdr_log_result, (char *)result_ptr, tv);
	if (stat != RPC_SUCCESS) {
		result_ptr->lr_status = NIS_RPCERROR;
	} else if (result_ptr->lr_status == NIS_CBRESULTS) {
		(*__clear_directory_ptr)(name);
		err = __nis_run_dump_callback(&(result_ptr->lr_cookie),
					NIS_CALLBACK, 0, clnt);
		if (err < 0)
			result_ptr->lr_status = NIS_CBERROR;
	}
	(void) mutex_unlock(&__nis_callback_lock);
	auth_destroy(clnt->cl_auth);
	clnt_destroy(clnt);
	return (result_ptr);
}

/*
 *  Sort server endpoints so that local addresses appear
 *  before remote addresses.
 */
void
nis_sort_directory_servers(directory_obj *slist)
{
	int i;

	int nsvrs = slist->do_servers.do_servers_len;
	nis_server *svrs = slist->do_servers.do_servers_val;

	for (i = 0; i < nsvrs; i++) {
		nis_sort_server_endpoints_inet(&svrs[i]);
	}
}

static
int
is_local(void *local_interfaces, struct netconfig *ncp, char *uaddr)
{
	return (__inet_uaddr_is_local(local_interfaces, ncp, uaddr));
}

static
int
is_remote(void *local_interfaces, struct netconfig *ncp, char *uaddr)
{
	return (!is_local(local_interfaces, ncp, uaddr));
}

void
__nis_swap_endpoints(endpoint *e1, endpoint *e2)
{
	char *t;

	t = e1->uaddr;
	e1->uaddr = e2->uaddr;
	e2->uaddr = t;

	t = e1->family;
	e1->family = e2->family;
	e2->family = t;

	t = e1->proto;
	e1->proto = e2->proto;
	e2->proto = t;
}

/*
 *  Sort a list of server endpoints so that address for local interfaces
 *  occur before remote interfaces.  If an error occurs (e.g., no memory),
 *  we just clean up and return; we end up not sorting the endpoints, but
 *  this is just for optimization anyway.
 *
 *  There is a lot of work in this routine, so it should not be called
 *  frequently.
 */
static
void
nis_sort_server_endpoints_inet(nis_server *svr)
{
	int i;
	int j;
	int neps = svr->ep.ep_len;
	endpoint *eps = svr->ep.ep_val;
	struct netconfig *ncp, *ncp_inet = 0, *ncp_inet6 = 0;
	void *local_interfaces;
	void *nch;

	nch = setnetconfig();
	if (nch == 0)
		return;

	/* find any inet entry so we can do uaddr2taddr */
	while ((ncp = getnetconfig(nch)) != 0 &&
		ncp_inet == 0 && ncp_inet6 == 0) {
		if (strcmp(ncp->nc_protofmly, NC_INET) == 0)
			ncp_inet = ncp;
		else if (strcmp(ncp->nc_protofmly, NC_INET6))
			ncp_inet6 = ncp;
	}
	if (ncp_inet == 0 && ncp_inet6 == 0) {
		endnetconfig(nch);
		return;
	}

	local_interfaces = __inet_get_local_interfaces();
	if (local_interfaces == 0) {
		endnetconfig(nch);
		return;
	}

	/*
	 *  Sort endpoints so local inet addresses are first.  The
	 *  variable 'i' points to the beginning of the array,
	 *  and 'j' points to the end.  We advance 'i' as long
	 *  as it indexes a non-inet endpoint or a local endpoint.
	 *  We retract 'j' as long as it indexes a non-inet endpoint
	 *  or a remote endpoint.  If either of these cases fail,
	 *  then 'i' is pointing at a remote endpoint and 'j' is
	 *  pointing at a local endpoint.  We swap them, adjust
	 *  the indexes, and continue.  When the indexes cross
	 *  we are done.
	 */
	i = 0;
	j = neps - 1;
	while (i < j) {
		if ((strcmp(eps[i].family, NC_INET) != 0 &&
			strcmp(eps[i].family, NC_INET6) != 0) ||
		    is_local(local_interfaces, ncp, eps[i].uaddr)) {
			i++;
			continue;
		}

		if ((strcmp(eps[j].family, NC_INET) != 0 &&
			strcmp(eps[j].family, NC_INET6) != 0) ||
		    is_remote(local_interfaces, ncp, eps[j].uaddr)) {
			--j;
			continue;
		}

		__nis_swap_endpoints(&eps[i], &eps[j]);
		i++;
		--j;
	}

	/* clean up */
	__inet_free_local_interfaces(local_interfaces);
	endnetconfig(nch);
}

/*
 * In the pre-IPv6 code, secure RPC has a bug such that it doesn't look
 * at the endpoint 'family' field when selecting an endpoint to use for
 * time synchronization. In order to protect that broken code from itself,
 * we set the endpoint 'proto' to 'nc_netid' (i.e., "udp6" or "tcp6")
 * rather than 'nc_proto' ("udp"/"tcp") if 'nc_family' is "inet6".
 *
 * The __nis_netconfig2ep() and __nis_netconfig_matches_ep() service
 * functions below simplify endpoint manipulation by implementing the
 * rules above.
 */

void
__nis_netconfig2ep(struct netconfig *nc, endpoint *ep) {

	if (nc == 0 || ep == 0)
		return;

	ep->family = strdup(nc->nc_protofmly);

	if (strcmp(ep->family, "inet6") == 0) {
		ep->proto = strdup(nc->nc_netid);
	} else {
		ep->proto = strdup(nc->nc_proto);
	}
}

bool_t
__nis_netconfig_matches_ep(struct netconfig *nc, endpoint *ep) {

	if (nc == 0 || ep == 0)
		return (FALSE);

	if (strcmp(nc->nc_protofmly, ep->family) != 0)
		return (FALSE);

	if (strcmp(ep->family, "inet6") == 0)
		return (strcmp(nc->nc_netid, ep->proto) == 0 ||
			strcmp(nc->nc_proto, ep->proto) == 0);
	else
		return (strcmp(nc->nc_proto, ep->proto) == 0);

}

struct netconfig_list {
	struct netconfig *nc;
	struct netconfig_list *next;
};

static struct netconfig_list *ncl;

struct netconfig *
__nis_get_netconfig(endpoint *ep)
{
	void *nch;
	struct netconfig *nc;
	struct netconfig_list *p;

	for (p = ncl; p; p = p->next) {
		if (__nis_netconfig_matches_ep(p->nc, ep)) {
			return (p->nc);
		}
	}

	nch = setnetconfig();
	if (nch == 0)
		return (0);

	while ((nc = getnetconfig(nch)) != 0) {
		if (__nis_netconfig_matches_ep(nc, ep))
			break;
	}
	/*
	 *  We call getnetconfigent to allocate a copy of the
	 *  netconfig entry.
	 */
	if (nc) {
		p = (struct netconfig_list *)malloc(sizeof (*p));
		if (p == 0)
			return (0);
		p->nc = getnetconfigent(nc->nc_netid);
		p->next = ncl;
		ncl = p;
	}
	endnetconfig(nch);

	return (nc);
}

void
nis_free_binding(nis_bound_directory *binding)
{
	xdr_free((xdrproc_t)xdr_nis_bound_directory, (char *)binding);
	free(binding);
}

void
__free_fdresult(fd_result *res)
{
	xdr_free((xdrproc_t)xdr_fd_result, (char *)res);
	free(res);
}

endpoint *
__endpoint_dup(endpoint *src, endpoint *dst)
{
	if (dst == NULL) {
		dst = (endpoint *)malloc(sizeof (endpoint));
		if (dst == NULL)
			return (NULL);
	}

	dst->family = src->family?strdup(src->family):0;
	dst->proto = src->proto?strdup(src->proto):0;
	dst->uaddr = src->uaddr?strdup(src->uaddr):0;

	return (dst);
}

void
__endpoint_free(endpoint *ep)
{
	if (ep) {
		free(ep->family);
		free(ep->proto);
		free(ep->uaddr);
		free(ep);
	}
}

endpoint *
__get_bound_endpoint(nis_bound_directory *binding, int n)
{
	endpoint *ep;
	nis_server *srv;
	nis_bound_endpoint *bep;

	bep = &binding->bep_val[n];
	srv = binding->dobj.do_servers.do_servers_val;
	ep = &srv[bep->hostnum].ep.ep_val[bep->epnum];
	return (ep);
}

nis_server *
__nis_server_dup(nis_server *src, nis_server *dst)
{
	if (dst == NULL) {
		dst = (nis_server *)malloc(sizeof (nis_server));
		if (dst == NULL)
			return (NULL);
	}
	(void) memset((char *)dst, 0, sizeof (nis_server));
	return ((nis_server *)
		__nis_xdr_dup(xdr_nis_server, (char *)src, (char *)dst));
}


char *
__nis_xdr_dup(xdrproc_t proc, char *src, char *dst)
{
	uint_t size;
	char *data;
	XDR xdrs;

	size = xdr_sizeof(proc, src);
	data = (char *)malloc(size);
	if (data == NULL)
		return (NULL);

	xdrmem_create(&xdrs, data, size, XDR_ENCODE);
	if (!proc(&xdrs, src)) {
		free(data);
		return (NULL);
	}

	xdrmem_create(&xdrs, data, size, XDR_DECODE);
	if (!proc(&xdrs, dst)) {
		free(data);
		return (NULL);
	}

	free(data);
	return (dst);
}

void
__nis_path_free(char **names, int len)
{
	int i;

	for (i = 0; i < len; i++)
		free((void *)names[i]);
	free((void *)names);
}

/*
 * __nis_path
 *
 * Given two path strings, *from and *to, work out the list of names
 * between them. The length of that path and the pointer to the list
 * of pointers to the name strings are returned to the caller using
 * path_length and namesp. As the names list is a pointer to a list of
 * pointers, the caller must pass the address of the pointer to the
 * pointer to the list of pointers, hence the unusual "char ***"
 * type. It is the callers responsibility to free **namesp.
 */
nis_error
__nis_path(char *from, char *to, int *path_length, char ***namesp)
{
	int i;
	int n;
	int start;
	int end;
	int st, dircmp, lastdircmp;
	char *tfrom = from;
	char *tto = to;
	char **names;

	dircmp = st = nis_dir_cmp(from, to);
	if (st == BAD_NAME)
		return (NIS_BADNAME);

	/* figure out how long path is */
	n = 0;
	if (st == HIGHER_NAME) {
		while ((dircmp = nis_dir_cmp(from, to)) == HIGHER_NAME) {
			n++;
			to = nis_domain_of(to);
		}
		if (dircmp != SAME_NAME) {
			/* Unrecoverable error */
			dircmp = BAD_NAME;
		}
	} else if (st == LOWER_NAME) {
		from = nis_domain_of(from);
		while ((dircmp = nis_dir_cmp(from, to)) == LOWER_NAME) {
			n++;
			from = nis_domain_of(from);
		}
		if (dircmp != SAME_NAME) {
			/* Unrecoverable error */
			dircmp = BAD_NAME;
		}
		n++;	/* include actual target */
	} else if (st == NOT_SEQUENTIAL) {
		/* names are not sequential */
		from = nis_domain_of(from);
		while ((dircmp = nis_dir_cmp(from, to)) == NOT_SEQUENTIAL) {
			n++;
			from = nis_domain_of(from);
		}
		n++;	/* include common parent */
		lastdircmp = dircmp; /* Handle HIGHER or LOWER */
		while ((dircmp = nis_dir_cmp(from, to)) == lastdircmp) {
			n++;
			lastdircmp = dircmp;
			to = nis_domain_of(to);
		}
		if (dircmp != SAME_NAME) {
			/* Unrecoverable error */
			dircmp = BAD_NAME;
		}
	}

	if (dircmp == BAD_NAME) {
		syslog(LOG_WARNING, "__nis_path: Unable to walk "
		    "from %s to %s", tfrom, tto);
		return (NIS_BADNAME);
	}

	names = malloc(n * sizeof (char *));
	if (names == NULL)
		return (NIS_NOMEMORY);

	start = 0;
	end = n;
	from = tfrom;
	to = tto;

	/*
	 * Go through again, this time storing names.
	 * We shouldn't need to check the loops will terminate
	 * on the SAME_NAME condition as we've already checked for
	 * errors in the previous loop.
	 */
	if (st == HIGHER_NAME) {
		while (nis_dir_cmp(from, to) != SAME_NAME) {
			names[--end] = strdup(to);
			to = nis_domain_of(to);
		}
	} else if (st == LOWER_NAME) {
		from = nis_domain_of(from);
		while (nis_dir_cmp(from, to) != SAME_NAME) {
			names[start++] = strdup(from);
			from = nis_domain_of(from);
		}
		names[start++] = strdup(to);	/* include actual target */
	} else if (st == NOT_SEQUENTIAL) {
		/* names are not sequential */
		from = nis_domain_of(from);
		while (nis_dir_cmp(from, to) == NOT_SEQUENTIAL) {
			names[start++] = strdup(from);
			from = nis_domain_of(from);
		}
		names[start++] = strdup(from);	/* include common parent */
		while (nis_dir_cmp(from, to) != SAME_NAME) {
			names[--end] = strdup(to);
			to = nis_domain_of(to);
		}
	}

	/* make sure all of the allocations were successful */
	for (i = 0; i < n; i++) {
		if (names[i] == NULL) {
			__nis_path_free(names, n);
			names = NULL;
			break;
		}
	}

	/* Set the return values */

	*path_length = n;
	*namesp = names;

	return (NIS_SUCCESS);
}

/*
 *  This is a stub function for clients.  There is a version of
 *  it in rpc.nisd that checks to see if the host is listed in
 *  the server list.
 */
int
__nis_host_is_server(nis_server *srv, int nsrv)
{
#ifdef lint
	srv = srv;
	nsrv = nsrv;
#endif /* lint */
	return (0);
}

char *call_names[] = {
	"NULL",
	"NIS_LOOKUP",
	"NIS_ADD",
	"NIS_MODIFY",
	"NIS_REMOVE",
	"NIS_IBLIST",
	"NIS_IBADD",
	"NIS_IBMODIFY",
	"NIS_IBREMOVE",
	"NIS_IBFIRST",
	"NIS_IBNEXT",
	"13",
	"NIS_FINDDIRECTORY",
	"NIS_STATUS",
	"NIS_DUMPLOG",
	"NIS_DUMP",
	"NIS_CALLBACK",
	"NIS_CPTIME",
	"NIS_CHECKPOINT",
	"NIS_PING",
	"NIS_SERVSTATE",
	"NIS_MKDIR",
	"NIS_RMDIR",
	"NIS_UPDKEYS",
};

void
__nis_print_call(CLIENT *clnt, int proc)
{
	char *name;
	char *pname;
	char lbuf[10];

	name = handle_to_server_name(clnt);
	if (proc > NIS_UPDKEYS)
		(void) sprintf(lbuf, "%d", proc);
	else
		pname = call_names[proc];
	(void) fprintf(__nis_debug_file, "calling server %s for %s\n",
	    name, pname);
}

void
__nis_print_rpc_result(enum clnt_stat status)
{
	(void) fprintf(__nis_debug_file, "result:  %s\n", clnt_sperrno(status));
}

void
__nis_print_req(ib_request *req)
{
	int i;
	int nattr = req->ibr_srch.ibr_srch_len;
	nis_attr *attr = req->ibr_srch.ibr_srch_val;

	(void) fprintf(__nis_debug_file, "[");
	for (i = 0; i < nattr; i++) {
		if (i != 0)
			(void) fprintf(__nis_debug_file, ",");
		(void) fprintf(__nis_debug_file, "%s=%s",
			attr[i].zattr_ndx,
			attr[i].zattr_val.zattr_val_val);
	}
	(void) fprintf(__nis_debug_file, "],%s\n", req->ibr_name);
}

void
__nis_print_nsreq(ns_request *req)
{
	(void) fprintf(__nis_debug_file, "%s\n", req->ns_name);
}

void
__nis_print_result(nis_result *res)
{
	(void) fprintf(__nis_debug_file,
		"status=%s, %d object%s, [z=%d, d=%d, a=%d, c=%d]\n",
		nis_sperrno(res->status),
		res->objects.objects_len,
		res->objects.objects_len == 1 ? "" : "s",
		res->zticks,
		res->dticks,
		res->aticks,
		res->cticks);
}

void
__nis_print_fdreq(fd_args *arg)
{
	(void) fprintf(__nis_debug_file, "%s (from %s)\n",
		arg->dir_name, arg->requester);
}
