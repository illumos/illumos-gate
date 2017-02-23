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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 * This contains YP server code which supplies the set of functions
 * requested using rpc.   The top level functions in this module
 * are those which have symbols of the form YPPROC_xxxx defined in
 * yp_prot.h, and symbols of the form YPOLDPROC_xxxx defined in ypsym.h.
 * The latter exist to provide compatibility to the old version of the yp
 * protocol/server, and may emulate the behavior of the previous software
 * by invoking some other program.
 *
 * This module also contains functions which are used by (and only by) the
 * top-level functions here.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <limits.h>
#include <sys/systeminfo.h>
#include <rpc/rpc.h>
#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "ypsym.h"
#include "ypdefs.h"
#include <ctype.h>

/* Use shim version of DBM calls */
#include "shim.h"
#include "shim_hooks.h"

USE_YP_PREFIX
USE_YP_SECURE
USE_YP_INTERDOMAIN

#ifndef	YPXFR_PROC
#define	YPXFR_PROC "/usr/lib/netsvc/yp/ypxfr"
#endif
static char ypxfr_proc[] = YPXFR_PROC;
#ifndef	YPPUSH_PROC
#define	YPPUSH_PROC "/usr/lib/netsvc/yp/yppush"
#endif
static char yppush_proc[] = YPPUSH_PROC;
struct yppriv_sym {
    char *sym;
    unsigned len;
};
static	char err_fork[] = "ypserv:  %s fork failure.\n";
#define	FORK_ERR logprintf(err_fork, fun)
static char err_execl[] = "ypserv:  %s execl failure.\n";
#define	EXEC_ERR logprintf(err_execl, fun)
static char err_respond[] = "ypserv: %s can't respond to rpc request.\n";
#define	RESPOND_ERR logprintf(err_respond, fun)
static char err_free[] = "ypserv: %s can't free args.\n";
#define	FREE_ERR logprintf(err_free, fun)
static char err_map[] = "ypserv: %s no such map or access denied.\n";
#define	MAP_ERR logprintf(err_map, fun)
static char err_vers[] = "ypserv: %s version not supported.\n";
#define	VERS_ERR logprintf(err_vers, fun)

static void ypfilter(DBM *fdb, datum *inkey, datum *outkey, datum *val,
			uint_t *status, bool_t update);
static bool isypsym(datum *key);
static bool xdrypserv_ypall(XDR *xdrs, struct ypreq_nokey *req);
static int multihomed(struct ypreq_key req, struct ypresp_val *resp,
			SVCXPRT *xprt, DBM *fdb);
static int omultihomed(struct yprequest req, struct ypresponse *resp,
			SVCXPRT *xprt, DBM *fdb);


/* For DNS forwarding */
extern bool dnsforward;
extern bool client_setup_failure;
extern int resolv_pid;
extern CLIENT *resolv_client;
extern char *resolv_tp;

/*
 * This determines whether or not a passed domain is served by this
 * server, and returns a boolean.  Used by both old and new protocol
 * versions.
 */
void
ypdomain(SVCXPRT *transp, bool always_respond)
{
	char domain_name[YPMAXDOMAIN + 1];
	char *pdomain_name = domain_name;
	bool isserved;
	char *fun = "ypdomain";
	struct netbuf *nbuf;
	sa_family_t af;

	memset(domain_name, 0, sizeof (domain_name));

	if (!svc_getargs(transp, (xdrproc_t)xdr_ypdomain_wrap_string,
				(caddr_t)&pdomain_name)) {
		svcerr_decode(transp);
		return;
	}

	/*
	 * If the file /var/yp/securenets is present on the server, and if
	 * the hostname is present in the file, then let the client bind to
	 * the server.
	 */
	nbuf = svc_getrpccaller(transp);
	af = ((struct sockaddr_storage *)nbuf->buf)->ss_family;
	if (af != AF_INET && af != AF_INET6) {
		logprintf("Protocol incorrect\n");
		return;
	}

	if (!(check_secure_net_ti(nbuf, fun))) {
		MAP_ERR;
		return;
	}

	isserved = ypcheck_domain(domain_name);

	if (isserved || always_respond) {

		if (!svc_sendreply(transp, xdr_bool, (char *)&isserved)) {
		    RESPOND_ERR;
		}
		if (!isserved)
			logprintf("Domain %s not supported\n",
					domain_name);

	} else {
		/*
		 * This case is the one in which the domain is not
		 * supported, and in which we are not to respond in the
		 * unsupported case.  We are going to make an error happen
		 * to allow the portmapper to end its wait without the
		 * normal timeout period.  The assumption here is that
		 * the only process in the world which is using the function
		 * in its no-answer-if-nack form is the portmapper, which is
		 * doing the krock for pseudo-broadcast.  If some poor fool
		 * calls this function as a single-cast message, the nack
		 * case will look like an incomprehensible error.  Sigh...
		 * (The traditional Unix disclaimer)
		 */

		svcerr_decode(transp);
		logprintf("Domain %s not supported (broadcast)\n",
				domain_name);
	}
}

/*
 * This implements the yp "match" function.
 */
void
ypmatch(SVCXPRT *transp, struct svc_req *rqstp)
{
	struct ypreq_key req;
	struct ypresp_val resp;
	char *fun = "ypmatch";
	DBM *fdb;

	memset(&req, 0, sizeof (req));
	memset(&resp, 0, sizeof (resp));
	resp.status = (unsigned)YP_NOKEY;

	if (!svc_getargs(transp, (xdrproc_t)xdr_ypreq_key, (char *)&req)) {
		svcerr_decode(transp);
		return;
	}

	/*
	 * sanity check the map name and to a DBM lookup
	 * also perform an access check...
	 */
	if ((fdb = ypset_current_map(req.map, req.domain,
					&resp.status)) != NULL &&
		yp_map_access(transp, &resp.status, fdb)) {

		/* Check with the DBM database */
		resp.valdat = dbm_fetch(fdb, req.keydat);
		if (resp.valdat.dptr != NULL) {
			resp.status = YP_TRUE;
			if (!silent)
				printf("%s: dbm: %40.40s\n",
					fun, resp.valdat.dptr);
			goto send_reply;
		}

		/*
		 * If we're being asked to match YP_SECURE or YP_INTERDOMAIN
		 * and we haven't found it in the dbm file, then we don't
		 * really want to waste any more time.  Specifically, we don't
		 * want to ask DNS
		 */
		if (req.keydat.dsize == 0 ||
		    req.keydat.dptr == NULL ||
		    req.keydat.dptr[0] == '\0' ||
	strncmp(req.keydat.dptr, yp_secure, req.keydat.dsize) == 0 ||
	strncmp(req.keydat.dptr, yp_interdomain, req.keydat.dsize) == 0) {
			goto send_reply;
		}

		/* Let's try the YP_MULTI_ hack... */
#ifdef MINUS_C_OPTION
		if (multiflag == TRUE && multihomed(req, &resp, transp, fdb))
			goto send_reply;
#else
		if (multihomed(req, &resp, transp, fdb))
			goto send_reply;
#endif

		/*
		 * Let's try DNS, but if client_setup_failure is set,
		 * we have tried DNS in the past and failed, there is
		 * no reason in forcing an infinite loop by turning
		 * off DNS in setup_resolv() only to turn it back on
		 * again here.
		 */
		if (!dnsforward && !client_setup_failure) {
			datum idkey, idval;
			idkey.dptr = yp_interdomain;
			idkey.dsize = yp_interdomain_sz;
			idval = dbm_fetch(fdb, idkey);
			if (idval.dptr)
				dnsforward = TRUE;
		}

		if (dnsforward) {
			if (!resolv_pid || !resolv_client) {
				setup_resolv(&dnsforward, &resolv_pid,
						&resolv_client, resolv_tp, 0);
				if (resolv_client == NULL)
					client_setup_failure = TRUE;
			}

			if (resolv_req(&dnsforward, &resolv_client,
						&resolv_pid, resolv_tp,
						rqstp->rq_xprt, &req,
						req.map) == TRUE)
				goto free_args;
		}
	}
	send_reply:

	if (!svc_sendreply(transp, (xdrproc_t)xdr_ypresp_val,
				(caddr_t)&resp)) {
		RESPOND_ERR;
	}

	free_args:

	if (!svc_freeargs(transp, (xdrproc_t)xdr_ypreq_key,
				(char *)&req)) {
		FREE_ERR;
	}
}


/*
 * This implements the yp "get first" function.
 */
void
ypfirst(SVCXPRT *transp)
{
	struct ypreq_nokey req;
	struct ypresp_key_val resp;
	char *fun = "ypfirst";
	DBM *fdb;

	memset(&req, 0, sizeof (req));
	memset(&resp, 0, sizeof (resp));

	if (!svc_getargs(transp,
				(xdrproc_t)xdr_ypreq_nokey,
				(char *)&req)) {
		svcerr_decode(transp);
		return;
	}

	if ((fdb = ypset_current_map(req.map, req.domain,
					&resp.status)) != NULL &&
		yp_map_access(transp, &resp.status, fdb)) {
		ypfilter(fdb, NULL,
			&resp.keydat, &resp.valdat, &resp.status, FALSE);
	}

	if (!svc_sendreply(transp,
				(xdrproc_t)xdr_ypresp_key_val,
				(char *)&resp)) {
		RESPOND_ERR;
	}

	if (!svc_freeargs(transp, (xdrproc_t)xdr_ypreq_nokey,
				(char *)&req)) {
		FREE_ERR;
	}
}

/*
 * This implements the yp "get next" function.
 */
void
ypnext(SVCXPRT *transp)
{
	struct ypreq_key req;
	struct ypresp_key_val resp;
	char *fun = "ypnext";
	DBM *fdb;

	memset(&req, 0, sizeof (req));
	memset(&resp, 0, sizeof (resp));

	if (!svc_getargs(transp, (xdrproc_t)xdr_ypreq_key, (char *)&req)) {
		svcerr_decode(transp);
		return;
	}

	if ((fdb = ypset_current_map(req.map, req.domain,
					&resp.status)) != NULL &&
		yp_map_access(transp, &resp.status, fdb)) {
		ypfilter(fdb, &req.keydat,
			&resp.keydat, &resp.valdat, &resp.status, FALSE);
	}

	if (!svc_sendreply(transp,
				(xdrproc_t)xdr_ypresp_key_val,
				(char *)&resp)) {
		RESPOND_ERR;
	}

	if (!svc_freeargs(transp,
				(xdrproc_t)xdr_ypreq_key,
				(char *)&req)) {
		FREE_ERR;
	}
}

/*
 * This implements the "transfer map" function.  It takes the domain
 * and map names and the callback information provided by the
 * requester (yppush on some node), and execs a ypxfr process to do
 * the actual transfer.
 */
void
ypxfr(SVCXPRT *transp, int prog)
{
	struct ypreq_newxfr newreq;
	struct ypreq_xfr oldreq;
	struct ypresp_val resp;  /* not returned to the caller */
	char transid[32];
	char proto[32];
	char name[256];
	char *pdomain, *pmap;
	pid_t pid = -1;
	char *fun = "ypxfr";
	DBM *fdb;

	if (prog == YPPROC_NEWXFR) {
		memset(&newreq, 0, sizeof (newreq));
		if (!svc_getargs(transp, (xdrproc_t)xdr_ypreq_newxfr,
				(char *)&newreq)) {
			svcerr_decode(transp);
			return;
		}

#ifdef OPCOM_DEBUG
		fprintf(stderr, "newreq:\n"
			"\tmap_parms:\n"
			"\t\tdomain:    %s\n"
			"\t\tmap:       %s\n"
			"\t\tordernum:  %u\n"
			"\t\towner:     %s\n"
			"\ttransid:    %u\n"
			"\tproto:      %u\n"
			"\tname:       %s\n\n",
			newreq.map_parms.domain,
			newreq.map_parms.map,
			newreq.map_parms.ordernum,
			newreq.map_parms.owner,
			newreq.transid,
			newreq.proto,
			newreq.name);
#endif
		sprintf(transid, "%u", newreq.transid);
		sprintf(proto, "%u", newreq.proto);
		sprintf(name, "%s", newreq.ypxfr_owner);
		pdomain = newreq.ypxfr_domain;
		pmap = newreq.ypxfr_map;
	} else if (prog == YPPROC_XFR) {
		memset(&oldreq, 0, sizeof (oldreq));
		if (!svc_getargs(transp,
					(xdrproc_t)xdr_ypreq_xfr,
					(char *)&oldreq)) {
		    svcerr_decode(transp);
		    return;
		}

#ifdef OPCOM_DEBUG
		fprintf(stderr, "oldreq:\n"
			"\tmap_parms:\n"
			"\t\tdomain:    %s\n"
			"\t\tmap:       %s\n"
			"\t\tordernum:  %u\n"
			"\t\towner:     %s\n"
			"\ttransid:    %u\n"
			"\tproto:      %u\n"
			"\tport:       %u\n\n",
			oldreq.map_parms.domain,
			oldreq.map_parms.map,
			oldreq.map_parms.ordernum,
			oldreq.map_parms.owner,
			oldreq.transid,
			oldreq.proto,
			oldreq.port);
#endif

		sprintf(transid, "%u", oldreq.transid);
		sprintf(proto, "%u", oldreq.proto);
		sprintf(name, "%s", oldreq.ypxfr_owner);
		pdomain = oldreq.ypxfr_domain;
		pmap = oldreq.ypxfr_map;
	} else {
		VERS_ERR;
	}

	/* Check that the map exists and is accessible */
	if ((fdb = ypset_current_map(pmap, pdomain, &resp.status)) != NULL &&
		yp_map_access(transp, &resp.status, fdb)) {

		pid = vfork();
		if (pid == -1) {
			FORK_ERR;
		} else if (pid == 0) {
		    if (prog == YPPROC_NEWXFR || prog == YPPROC_XFR) {
#ifdef OPCOM_DEBUG
			fprintf(stderr,
				"EXECL: %s, -d, %s, -C, %s, %s, %s, %s\n",
				ypxfr_proc, pdomain,
				transid, proto, name, pmap);
#endif
			if (execl(ypxfr_proc, "ypxfr", "-d",
					pdomain, "-C", transid, proto,
					name, pmap, NULL))
			    EXEC_ERR;
		    } else {
			VERS_ERR;
		    }
		    _exit(1);
		}

	} else {
		MAP_ERR;
	}
	if (!svc_sendreply(transp, xdr_void, 0)) {
		RESPOND_ERR;
	}

	if (prog == YPPROC_NEWXFR) {
		if (!svc_freeargs(transp,
					(xdrproc_t)xdr_ypreq_newxfr,
					(char *)&newreq)) {
		    FREE_ERR;
		}
	}
}

/*
 * This implements the "get all" function.
 */
void
ypall(SVCXPRT *transp)
{
	struct ypreq_nokey req;
	struct ypresp_val resp;  /* not returned to the caller */
	pid_t pid;
	char *fun = "ypall";
	DBM *fdb;

	req.domain = req.map = NULL;

	memset((char *)&req, 0, sizeof (req));

	if (!svc_getargs(transp,
				(xdrproc_t)xdr_ypreq_nokey,
				(char *)&req)) {
		svcerr_decode(transp);
		return;
	}

	pid = fork1();

	if (pid) {

		if (pid == -1) {
			FORK_ERR;
		}

		if (!svc_freeargs(transp,
					(xdrproc_t)xdr_ypreq_nokey,
					(char *)&req)) {
			FREE_ERR;
		}

		return;
	}

	/*
	 * access control hack:  If denied then invalidate the map name.
	 */
	ypclr_current_map();
	if ((fdb = ypset_current_map(req.map,
		req.domain, &resp.status)) != NULL &&
		!yp_map_access(transp, &resp.status, fdb)) {

		req.map[0] = '-';
	}

	/*
	 * This is the child process.  The work gets done by xdrypserv_ypall/
	 * we must clear the "current map" first so that we do not
	 * share a seek pointer with the parent server.
	 */

	if (!svc_sendreply(transp,
				(xdrproc_t)xdrypserv_ypall,
				(char *)&req)) {
		RESPOND_ERR;
	}

	if (!svc_freeargs(transp,
				(xdrproc_t)xdr_ypreq_nokey,
				(char *)&req)) {
		FREE_ERR;
	}

	/*
	 * In yptol mode we may start a cache update thread within a child
	 * process. It is thus important that child processes do not exit,
	 * killing any such threads, before the thread has completed.
	 */
	if (yptol_mode) {
		thr_join(0, NULL, NULL);
	}

	exit(0);
}

/*
 * This implements the "get master name" function.
 */
void
ypmaster(SVCXPRT *transp)
{
	struct ypreq_nokey req;
	struct ypresp_master resp;
	char *nullstring = "";
	char *fun = "ypmaster";
	DBM *fdb;

	memset((char *)&req, 0, sizeof (req));
	resp.master = nullstring;
	resp.status = YP_TRUE;

	if (!svc_getargs(transp,
				(xdrproc_t)xdr_ypreq_nokey,
				(char *)&req)) {
		svcerr_decode(transp);
		return;
	}

	if ((fdb = ypset_current_map(req.map,
		req.domain, &resp.status)) != NULL &&
		yp_map_access(transp, &resp.status, fdb)) {

		if (!ypget_map_master(&resp.master, fdb)) {
			resp.status = (unsigned)YP_BADDB;
		}
	}

	if (!svc_sendreply(transp,
				(xdrproc_t)xdr_ypresp_master,
				(char *)&resp)) {
		RESPOND_ERR;
	}

	if (!svc_freeargs(transp,
				(xdrproc_t)xdr_ypreq_nokey,
				(char *)&req)) {
		FREE_ERR;
	}
}

/*
 * This implements the "get order number" function.
 */
void
yporder(SVCXPRT *transp)
{
	struct ypreq_nokey req;
	struct ypresp_order resp;
	char *fun = "yporder";
	DBM *fdb;

	req.domain = req.map = NULL;
	resp.status  = YP_TRUE;
	resp.ordernum  = 0;

	memset((char *)&req, 0, sizeof (req));

	if (!svc_getargs(transp,
				(xdrproc_t)xdr_ypreq_nokey,
				(char *)&req)) {
		svcerr_decode(transp);
		return;
	}

	resp.ordernum = 0;

	if ((fdb = ypset_current_map(req.map,
					req.domain,
					&resp.status)) != NULL &&
		yp_map_access(transp, &resp.status, fdb)) {

		if (!ypget_map_order(req.map, req.domain, &resp.ordernum)) {
			resp.status = (unsigned)YP_BADDB;
		}
	}

	if (!svc_sendreply(transp,
				(xdrproc_t)xdr_ypresp_order,
				(char *)&resp)) {
		RESPOND_ERR;
	}

	if (!svc_freeargs(transp,
				(xdrproc_t)xdr_ypreq_nokey,
				(char *)&req)) {
		FREE_ERR;
	}
}

void
ypmaplist(SVCXPRT *transp)
{
	char domain_name[YPMAXDOMAIN + 1];
	char *pdomain = domain_name;
	char *fun = "ypmaplist";
	struct ypresp_maplist maplist;
	struct ypmaplist *tmp;

	maplist.list = (struct ypmaplist *)NULL;

	memset(domain_name, 0, sizeof (domain_name));

	if (!svc_getargs(transp,
				(xdrproc_t)xdr_ypdomain_wrap_string,
				(caddr_t)&pdomain)) {
		svcerr_decode(transp);
		return;
	}

	maplist.status = yplist_maps(domain_name, &maplist.list);

	if (!svc_sendreply(transp,
				(xdrproc_t)xdr_ypresp_maplist,
				(char *)&maplist)) {
		RESPOND_ERR;
	}

	while (maplist.list) {
		tmp = maplist.list->ypml_next;
		free((char *)maplist.list);
		maplist.list = tmp;
	}
}

/*
 * Ancillary functions used by the top-level functions within this
 * module
 */

/*
 * This returns TRUE if a given key is a yp-private symbol, otherwise
 * FALSE
 */
static bool
isypsym(datum *key)
{
	if ((key->dptr == NULL) ||
		(key->dsize < yp_prefix_sz) ||
		memcmp(yp_prefix, key->dptr, yp_prefix_sz) ||
		(!memcmp(key->dptr, "YP_MULTI_", 9))) {
		return (FALSE);
	}
	return (TRUE);
}

/*
 * This provides private-symbol filtration for the enumeration functions.
 */
static void
ypfilter(DBM *fdb, datum *inkey, datum *outkey, datum *val, uint_t *status,
							bool_t update)
{
	datum k;

	if (inkey) {

		if (isypsym(inkey)) {
			*status = (unsigned)YP_BADARGS;
			return;
		}

		k = dbm_do_nextkey(fdb, *inkey);
	} else {
		k = dbm_firstkey(fdb);
	}

	while (k.dptr && isypsym(&k)) {
		k = dbm_nextkey(fdb);
	}

	if (k.dptr == NULL) {
		*status = YP_NOMORE;
		return;
	}

	*outkey = k;

	/*
	 * In N2L mode we must call a version of dbm_fetch() that either does
	 * or does not check for entry updates. In non N2L mode both of these
	 * will end up doing a normal dbm_fetch().
	 */
	if (update)
		*val = shim_dbm_fetch(fdb, k);
	else
		*val = shim_dbm_fetch_noupdate(fdb, k);

	if (val->dptr != NULL) {
		*status = YP_TRUE;
	} else {
		*status = (unsigned)YP_BADDB;
	}
}

/*
 * Serializes a stream of struct ypresp_key_val's.  This is used
 * only by the ypserv side of the transaction.
 */
static bool
xdrypserv_ypall(XDR *xdrs, struct ypreq_nokey *req)
{
	bool_t more = TRUE;
	struct ypresp_key_val resp;
	DBM *fdb;

	resp.keydat.dptr = resp.valdat.dptr = (char *)NULL;
	resp.keydat.dsize = resp.valdat.dsize = 0;

	if ((fdb = ypset_current_map(req->map, req->domain,
					&resp.status)) != NULL) {
		ypfilter(fdb, (datum *) NULL, &resp.keydat, &resp.valdat,
				&resp.status, FALSE);

		while (resp.status == YP_TRUE) {
			if (!xdr_bool(xdrs, &more)) {
				return (FALSE);
			}

			if (!xdr_ypresp_key_val(xdrs, &resp)) {
				return (FALSE);
			}

			ypfilter(fdb, &resp.keydat, &resp.keydat, &resp.valdat,
					&resp.status, FALSE);
		}
	}

	if (!xdr_bool(xdrs, &more)) {
		return (FALSE);
	}

	if (!xdr_ypresp_key_val(xdrs, &resp)) {
		return (FALSE);
	}

	more = FALSE;

	if (!xdr_bool(xdrs, &more)) {
		return (FALSE);
	}

	return (TRUE);
}

/*
 * Additions for sparc cluster support
 */

/*
 * Check for special multihomed host cookie in the key.  If there,
 * collect the addresses from the comma separated list and return
 * the one that's nearest the client.
 */
static int
multihomed(struct ypreq_key req, struct ypresp_val *resp,
		SVCXPRT *xprt, DBM *fdb)
{
	char *cp, *bp;
	ulong_t bestaddr, call_addr;
	struct netbuf *nbuf;
	char name[PATH_MAX];
	static char localbuf[_PBLKSIZ];	/* buffer for multihomed IPv6 addr */

	if (strcmp(req.map, "hosts.byname") &&
			strcmp(req.map, "ipnodes.byname"))
		/* default status is YP_NOKEY */
		return (0);

	if (strncmp(req.keydat.dptr, "YP_MULTI_", 9)) {
		datum tmpname;

		strncpy(name, "YP_MULTI_", 9);
		strncpy(name + 9, req.keydat.dptr, req.keydat.dsize);
		tmpname.dsize = req.keydat.dsize + 9;
		tmpname.dptr = name;
		resp->valdat = dbm_fetch(fdb, tmpname);
	} else {
		/*
		 * Return whole line (for debugging) if YP_MULTI_hostnam
		 * is specified.
		 */
		resp->valdat = dbm_fetch(fdb, req.keydat);
		if (resp->valdat.dptr != NULL)
			return (1);
	}

	if (resp->valdat.dptr == NULL)
		return (0);

	strncpy(name, req.keydat.dptr, req.keydat.dsize);
	name[req.keydat.dsize] = NULL;

	if (strcmp(req.map, "ipnodes.byname") == 0) {
		/*
		 * This section handles multihomed IPv6 addresses.
		 * It returns all the IPv6 addresses one per line and only
		 * the requested hostname is returned.  NO aliases will be
		 * returned.  This is done exactly the same way DNS forwarding
		 * daemon handles multihomed hosts.
		 * New IPv6 enabled clients should be able to handle this
		 * information returned.  The sorting is also the client's
		 * responsibility.
		 */

		char *buf, *endbuf;

		if ((buf = strdup(resp->valdat.dptr)) == NULL) /* no memory */
			return (0);
		if ((bp = strtok(buf, " \t")) == NULL) { /* no address field */
			free(buf);
			return (0);
		}
		if ((cp = strtok(NULL, "")) == NULL) { /* no host field */
			free(buf);
			return (0);
		}
		if ((cp = strtok(bp, ",")) != NULL) { /* multihomed host */
			int bsize;

			localbuf[0] = '\0';
			bsize = sizeof (localbuf);
			endbuf = localbuf;

			while (cp) {
				if ((strlen(cp) + strlen(name)) >= bsize) {
					/* out of range */
					break;
				}
				sprintf(endbuf, "%s %s\n", cp, name);
				cp = strtok(NULL, ",");
				endbuf = &endbuf[strlen(endbuf)];
				bsize = &localbuf[sizeof (localbuf)] - endbuf;
			}
			resp->valdat.dptr = localbuf;
			resp->valdat.dsize = strlen(localbuf);
		}

		free(buf);
		/* remove trailing newline */
		if (resp->valdat.dsize &&
			resp->valdat.dptr[resp->valdat.dsize-1] == '\n') {
			resp->valdat.dptr[resp->valdat.dsize-1] = '\0';
			resp->valdat.dsize -= 1;
		}

		resp->status = YP_TRUE;
		return (1);
	}
	nbuf = svc_getrpccaller(xprt);
	/*
	 * OK, now I have a netbuf structure which I'm supposed to
	 * treat as opaque...  I hate transport independance!
	 * So, we're just gonna doit wrong...  By wrong I mean that
	 * we assume that the buf part of the netbuf structure is going
	 * to be a sockaddr_in.  We'll then check the assumed family
	 * member and hope that we find AF_INET in there...  if not
	 * then we can't continue.
	 */
	if (((struct sockaddr_in *)(nbuf->buf))->sin_family != AF_INET)
		return (0);

	call_addr = ((struct sockaddr_in *)(nbuf->buf))->sin_addr.s_addr;

	cp = resp->valdat.dptr;
	if ((bp = strtok(cp, " \t")) == NULL) /* no address field */
		return (0);
	if ((cp = strtok(NULL, "")) == NULL)  /* no host field */
		return (0);
	bp = strtok(bp, ",");

	bestaddr = inet_addr(bp);
	while (cp = strtok(NULL, ",")) {
		ulong_t taddr;

		taddr = inet_addr(cp);
		if (ntohl(call_addr ^ taddr) < ntohl(call_addr ^ bestaddr))
			bestaddr = taddr;
	}
	cp = resp->valdat.dptr;
	sprintf(cp, "%s %s", inet_ntoa(*(struct in_addr *)&bestaddr), name);
	resp->valdat.dsize = strlen(cp);

	resp->status = YP_TRUE;

	return (1);
}

/* V1 dispatch routines */
void
ypoldmatch(SVCXPRT *transp, struct svc_req *rqstp)
{
	bool dbmop_ok = TRUE;
	struct yprequest req;
	struct ypreq_key nrq;
	struct ypresponse resp;
	char *fun = "ypoldmatch";
	DBM *fdb;

	memset((void *) &req, 0, sizeof (req));
	memset((void *) &resp, 0, sizeof (resp));

	if (!svc_getargs(transp,
				(xdrproc_t)_xdr_yprequest,
				(caddr_t)&req)) {
		svcerr_decode(transp);
		return;
	}

	if (req.yp_reqtype != YPMATCH_REQTYPE) {
		resp.ypmatch_resp_status = (unsigned)YP_BADARGS;
		dbmop_ok = FALSE;
	}

	if (dbmop_ok &&
		(((fdb = ypset_current_map(req.ypmatch_req_map,
						req.ypmatch_req_domain,
						&resp.ypmatch_resp_status))
						!= NULL) &&
						yp_map_access(transp,
						&resp.ypmatch_resp_status,
						fdb))) {

		/* Check with the DBM database */
		resp.ypmatch_resp_valdat = dbm_fetch(fdb,
						req.ypmatch_req_keydat);

		if (resp.ypmatch_resp_valptr != NULL) {
			resp.ypmatch_resp_status = YP_TRUE;
			if (!silent)
				printf("%s: dbm: %s\n",
					fun, resp.ypmatch_resp_valptr);
			goto send_oldreply;
		}

		/*
		 * If we're being asked to match YP_SECURE or YP_INTERDOMAIN
		 * and we haven't found it in the dbm file, then we don't
		 * really want to waste any more time.  Specifically, we don't
		 * want to ask DNS
		 */
		if (req.ypmatch_req_keysize == 0 ||
		    req.ypmatch_req_keyptr == NULL ||
		    req.ypmatch_req_keyptr[0] == '\0' ||
		    strncmp(req.ypmatch_req_keyptr, "YP_SECURE", 9) == 0 ||
		    strncmp(req.ypmatch_req_keyptr, "YP_INTERDOMAIN", 14) == 0)

		    goto send_oldreply;

		/* Let's try the YP_MULTI_ hack... */
#ifdef MINUS_C_OPTION
		if (multiflag == TRUE && omultihomed(req, &resp, transp, fdb))
			goto send_oldreply;
#else
		if (omultihomed(req, &resp, transp, fdb))
			goto send_oldreply;
#endif

		/* Let's try DNS */
		if (!dnsforward) {
			USE_YP_INTERDOMAIN
			datum idkey, idval;
			idkey.dptr = yp_interdomain;
			idkey.dsize = yp_interdomain_sz;
			idval = dbm_fetch(fdb, idkey);
			if (idval.dptr)
				dnsforward = TRUE;
		}

		if (dnsforward) {
		    if (!resolv_pid)
			setup_resolv(&dnsforward, &resolv_pid, &resolv_client,
					resolv_tp, 0);

		    if (req.yp_reqtype == YPREQ_KEY) {
			nrq = req.yp_reqbody.yp_req_keytype;

			resolv_req(&dnsforward, &resolv_client, &resolv_pid,
					resolv_tp, rqstp->rq_xprt,
					&nrq, nrq.map);
		    }
		    return;
		}
	}

	send_oldreply:

	if (!svc_sendreply(transp,
				(xdrproc_t)_xdr_ypresponse,
				(caddr_t)&resp)) {
		RESPOND_ERR;
	}

	if (!svc_freeargs(transp,
				(xdrproc_t)_xdr_yprequest,
				(char *)&req)) {
		FREE_ERR;
	}
}

void
ypoldfirst(SVCXPRT *transp)
{
	bool dbmop_ok = TRUE;
	struct yprequest req;
	struct ypresponse resp;
	char *fun = "ypoldfirst";
	DBM *fdb;

	memset((void *) &req, 0, sizeof (req));
	memset((void *) &resp, 0, sizeof (resp));

	if (!svc_getargs(transp,
				(xdrproc_t)_xdr_yprequest,
				(caddr_t)&req)) {
		svcerr_decode(transp);
		return;
	}

	if (req.yp_reqtype != YPFIRST_REQTYPE) {
		resp.ypfirst_resp_status = (unsigned)YP_BADARGS;
		dbmop_ok = FALSE;
	}

	if (dbmop_ok &&
		((fdb = ypset_current_map(req.ypfirst_req_map,
						req.ypfirst_req_domain,
						&resp.ypfirst_resp_status))
						!= NULL) &&
						yp_map_access(transp,
						&resp.ypfirst_resp_status,
						fdb)) {

		resp.ypfirst_resp_keydat = dbm_firstkey(fdb);

		if (resp.ypfirst_resp_keyptr != NULL) {
			resp.ypfirst_resp_valdat =
				dbm_fetch(fdb, resp.ypfirst_resp_keydat);

			if (resp.ypfirst_resp_valptr != NULL) {
				resp.ypfirst_resp_status = YP_TRUE;
			} else {
				resp.ypfirst_resp_status = (unsigned)YP_BADDB;
			}
		} else {
			resp.ypfirst_resp_status = (unsigned)YP_NOKEY;
		}
	}

	resp.yp_resptype = YPFIRST_RESPTYPE;

	if (!svc_sendreply(transp,
				(xdrproc_t)_xdr_ypresponse,
				(caddr_t)&resp)) {
		RESPOND_ERR;
	}

	if (!svc_freeargs(transp,
				(xdrproc_t)_xdr_yprequest,
				(caddr_t)&req)) {
		FREE_ERR;
	}
}

void
ypoldnext(SVCXPRT *transp)
{
	bool dbmop_ok = TRUE;
	struct yprequest req;
	struct ypresponse resp;
	char *fun = "ypoldnext";
	DBM *fdb;

	memset((void *) &req, 0, sizeof (req));
	memset((void *) &resp, 0, sizeof (resp));

	if (!svc_getargs(transp,
				(xdrproc_t)_xdr_yprequest,
				(caddr_t)&req)) {
		svcerr_decode(transp);
		return;
	}

	if (req.yp_reqtype != YPNEXT_REQTYPE) {
		resp.ypnext_resp_status = (unsigned)YP_BADARGS;
		dbmop_ok = FALSE;
	}

	if (dbmop_ok &&
		((fdb = ypset_current_map(req.ypnext_req_map,
					req.ypnext_req_domain,
					&resp.ypnext_resp_status)) != NULL &&
		yp_map_access(transp, &resp.ypnext_resp_status, fdb))) {

		resp.ypnext_resp_keydat = dbm_nextkey(fdb);

		if (resp.ypnext_resp_keyptr != NULL) {
			resp.ypnext_resp_valdat =
			dbm_fetch(fdb, resp.ypnext_resp_keydat);

			if (resp.ypnext_resp_valptr != NULL) {
				resp.ypnext_resp_status = YP_TRUE;
			} else {
				resp.ypnext_resp_status = (unsigned)YP_BADDB;
			}
		} else {
			resp.ypnext_resp_status = (unsigned)YP_NOMORE;
		}
	}

	resp.yp_resptype = YPNEXT_RESPTYPE;

	if (!svc_sendreply(transp,
				(xdrproc_t)_xdr_ypresponse,
				(caddr_t)&resp)) {
		RESPOND_ERR;
	}

	if (!svc_freeargs(transp,
				(xdrproc_t)_xdr_yprequest,
				(caddr_t)&req)) {
		FREE_ERR;
	}
}

/*
 * This retrieves the order number and master peer name from the map.
 * The conditions for the various message fields are: domain is filled
 * in iff the domain exists.  map is filled in iff the map exists.
 * order number is filled in iff it's in the map.  owner is filled in
 * iff the master peer is in the map.
 */
void
ypoldpoll(SVCXPRT *transp)
{
	struct yprequest req;
	struct ypresponse resp;
	char *map = "";
	char *domain = "";
	char *owner = "";
	uint_t error;
	char *fun = "ypoldpoll";
	DBM *fdb;

	memset((void *) &req, 0, sizeof (req));
	memset((void *) &resp, 0, sizeof (resp));

	if (!svc_getargs(transp,
				(xdrproc_t)_xdr_yprequest,
				(caddr_t)&req)) {
		svcerr_decode(transp);
		return;
	}

	if (req.yp_reqtype == YPPOLL_REQTYPE) {
		if (strcmp(req.yppoll_req_domain, "yp_private") == 0 ||
			strcmp(req.yppoll_req_map, "ypdomains") == 0 ||
			strcmp(req.yppoll_req_map, "ypmaps") == 0) {

			/*
			 * Backward comatibility for 2.0 NIS servers
			 */
			domain = req.yppoll_req_domain;
			map = req.yppoll_req_map;
		} else if ((fdb = ypset_current_map(req.yppoll_req_map,
				req.yppoll_req_domain,
				&error)) != NULL) {
			domain = req.yppoll_req_domain;
			map = req.yppoll_req_map;
			ypget_map_order(map, domain,
					&resp.yppoll_resp_ordernum);
			ypget_map_master(&owner, fdb);
		} else {
			switch ((int)error) {
			case YP_BADDB:
				map = req.yppoll_req_map;
				/* Fall through to set the domain too. */

			case YP_NOMAP:
				domain = req.yppoll_req_domain;
				break;
			}
		}
	}

	resp.yp_resptype = YPPOLL_RESPTYPE;
	resp.yppoll_resp_domain = domain;
	resp.yppoll_resp_map = map;
	resp.yppoll_resp_owner = owner;

	if (!svc_sendreply(transp,
				(xdrproc_t)_xdr_ypresponse,
				(caddr_t)&resp)) {
		RESPOND_ERR;
	}

	if (!svc_freeargs(transp,
				(xdrproc_t)_xdr_yprequest,
				(caddr_t)&req)) {
		FREE_ERR;
	}
}

void
ypoldpush(SVCXPRT *transp)
{
	struct yprequest req;
	struct ypresp_val resp;
	pid_t pid = -1;
	char *fun = "ypoldpush";
	DBM *fdb;

	memset((void *) &req, 0, sizeof (req));

	if (!svc_getargs(transp,
				(xdrproc_t)_xdr_yprequest,
				(caddr_t)&req)) {
		svcerr_decode(transp);
		return;
	}

	if (((fdb = ypset_current_map(req.yppush_req_map,
					req.yppush_req_domain,
					&resp.status)) != NULL) &&
		(yp_map_access(transp, &resp.status, fdb))) {

		pid = vfork();
	}

	if (pid == -1) {
		FORK_ERR;
	} else if (pid == 0) {
		ypclr_current_map();

		if (execl(yppush_proc, "yppush", "-d", req.yppush_req_domain,
				req.yppush_req_map, NULL)) {
			EXEC_ERR;
		}
		_exit(1);
	}

	if (!svc_sendreply(transp,
				(xdrproc_t)xdr_void,
				(caddr_t)NULL)) {
		RESPOND_ERR;
	}

	if (!svc_freeargs(transp,
				(xdrproc_t)_xdr_yprequest,
				(caddr_t)&req)) {
		FREE_ERR;
	}
}

void
ypoldpull(SVCXPRT *transp)
{
	struct yprequest req;
	struct ypresp_val resp;
	pid_t pid = -1;
	char *fun = "ypoldpull";
	DBM *fdb;

	memset((void *) &req, 0, sizeof (req));

	if (!svc_getargs(transp,
				(xdrproc_t)_xdr_yprequest,
				(caddr_t)&req)) {
		svcerr_decode(transp);
		return;
	}

	if (req.yp_reqtype == YPPULL_REQTYPE) {

		if (((fdb = ypset_current_map(req.yppull_req_map,
						req.yppull_req_domain,
						&resp.status)) == NULL) ||
			(yp_map_access(transp, &resp.status, fdb))) {
			pid = vfork();
		}

		if (pid == -1) {
			FORK_ERR;
		} else if (pid == 0) {
			ypclr_current_map();

			if (execl(ypxfr_proc, "ypxfr", "-d",
					req.yppull_req_domain,
					req.yppull_req_map, NULL)) {
				EXEC_ERR;
			}
			_exit(1);
		}
	}

	if (!svc_freeargs(transp,
				(xdrproc_t)_xdr_yprequest,
				(caddr_t)&req)) {
		FREE_ERR;
	}
}

void
ypoldget(SVCXPRT *transp)
{
	struct yprequest req;
	struct ypresp_val resp;
	pid_t pid = -1;
	char *fun = "ypoldget";
	DBM *fdb;

	memset((void *) &req, 0, sizeof (req));

	if (!svc_getargs(transp,
				(xdrproc_t)_xdr_yprequest,
				(caddr_t)&req)) {
		svcerr_decode(transp);
		return;
	}

	if (!svc_sendreply(transp, xdr_void, 0)) {
		RESPOND_ERR;
	}

	if (req.yp_reqtype == YPGET_REQTYPE) {

		if (((fdb = ypset_current_map(req.ypget_req_map,
						req.ypget_req_domain,
						&resp.status)) == NULL) ||
			(yp_map_access(transp, &resp.status, fdb))) {

			pid = vfork();
		}

		if (pid == -1) {
			FORK_ERR;
		} else if (pid == 0) {

			ypclr_current_map();

			if (execl(ypxfr_proc, "ypxfr", "-d",
					req.ypget_req_domain, "-h",
					req.ypget_req_owner,
					req.ypget_req_map, NULL)) {

				EXEC_ERR;
			}
			_exit(1);
		}
	}

	if (!svc_freeargs(transp,
				(xdrproc_t)_xdr_yprequest,
				(caddr_t)&req)) {
		RESPOND_ERR;
	}
}

static int
omultihomed(struct yprequest req,
	    struct ypresponse *resp, SVCXPRT *xprt, DBM *fdb)
{
	char *cp, *bp;
	char name[PATH_MAX];
	struct netbuf *nbuf;
	ulong_t bestaddr, call_addr;

	if (strcmp(req.ypmatch_req_map, "hosts.byname"))
		return (0);

	if (strncmp(req.ypmatch_req_keyptr, "YP_MULTI_", 9)) {
		datum tmpname;

		strncpy(name, "YP_MULTI_", 9);
		strncpy(name + 9, req.ypmatch_req_keyptr,
			req.ypmatch_req_keysize);
		tmpname.dsize = req.ypmatch_req_keysize + 9;
		tmpname.dptr = name;
		resp->ypmatch_resp_valdat = dbm_fetch(fdb, tmpname);
	} else {
		resp->ypmatch_resp_valdat =
			dbm_fetch(fdb, req.ypmatch_req_keydat);
		if (resp->ypmatch_resp_valptr != NULL)
			return (1);
	}

	if (resp->ypmatch_resp_valptr == NULL)
		return (0);

	strncpy(name, req.ypmatch_req_keyptr, req.ypmatch_req_keysize);
	name[req.ypmatch_req_keysize] = NULL;

	nbuf = svc_getrpccaller(xprt);

	/*
	 * OK, now I have a netbuf structure which I'm supposed to treat
	 * as opaque...  I hate transport independance!  So, we're just
	 * gonna doit wrong...  By wrong I mean that we assume that the
	 * buf part of the netbuf structure is going to be a sockaddr_in.
	 * We'll then check the assumed family member and hope that we
	 * find AF_INET in there...  if not then we can't continue.
	 */
	if (((struct sockaddr_in *)(nbuf->buf))->sin_family != AF_INET)
		return (0);

	call_addr = ((struct sockaddr_in *)(nbuf->buf))->sin_addr.s_addr;

	cp = resp->ypmatch_resp_valptr;
	if ((bp = strtok(cp, "\t")) == NULL)	/* No address field */
		return (0);
	if ((cp = strtok(NULL, "")) == NULL)	/* No host field */
		return (0);
	bp = strtok(bp, ",");

	bestaddr = inet_addr(bp);
	while (cp = strtok(NULL, ",")) {
		ulong_t taddr;

		taddr = inet_addr(cp);
		if (ntohl(call_addr ^ taddr) < ntohl(call_addr ^ bestaddr))
			bestaddr = taddr;
	}

	cp = resp->ypmatch_resp_valptr;
	sprintf(cp, "%s %s", inet_ntoa(*(struct in_addr *)&bestaddr), name);
	resp->ypmatch_resp_valsize = strlen(cp);

	resp->ypmatch_resp_status = YP_TRUE;

	return (1);
}
