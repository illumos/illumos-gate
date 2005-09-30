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
 *	yp_ns_proc.c
 *
 * This module contains the implementation for backward compatibility
 * with NIS version 2 (aka YP), so that a version 3 server (aka NIS+) can
 * serve a version 2 client requests [only for Sun standard maps].
 * It provides the routines that the dispatch function yp_prog_svc in
 * yp_svc.c calls. That file, yp_svc.c, reflects
 * the interface definition that is described in the nis.x/yp.x files.
 *
 * This module contains the Namespace manipulation procedures and is
 * not supposed to access the database directly.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <rpc/rpc.h>
#include <netinet/in.h>
#include <netconfig.h>
#include <netdir.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/yp_prot.h>
/* "nis_proc.h" includes "nis_mt.h" */
#include "nis_proc.h"
#undef master

#include <netdb.h>
#include <ctype.h>

#define	ORGDIR ".org_dir."
#define	ORGDIR1 org_dir
#define	ORGDIR2 "org_dir."
#define	ORGLEN 10 /* len(ORGDIR + null char) */
#define	DEFAULTKEY "key" /* search column name for the non-standard maps */
#define	BY "by"
#define	CNAME "cname"
#define	CNAMELEN 5
#define	MAILNAME "alias"	/* name of the first column in mail_aliases */
#define	MAILADDR "expansion"	/* name of the second column in mail_aliases */
#define	NGROUPNAME "name"	/* column name of netgroup name in netgroup */
#define	COLVAL(n) (e->en_cols.en_cols_val[n].ENVAL && COLLEN(n) > 0) ? \
		e->en_cols.en_cols_val[n].ENVAL : ""
#define	COLLEN(n) e->en_cols.en_cols_val[n].ENLEN
#define	COLGETVAL(n) e->en_cols.en_cols_val[n].ENVAL
#define	ENCOLVAL(e, n) e->en_cols.en_cols_val[n].ENVAL ? \
		e->en_cols.en_cols_val[n].ENVAL : ""

extern nis_object *nis_return_list(nis_object *,
	obj_list *, int, nis_name, int *, int, int, nis_attr *);
extern nis_object *nis_censor_object(nis_object *,
	table_col *, nis_name);

static void cook_err_resp(struct ypresp_val *resp, long stat);
static void cook_err_keyresp(struct ypresp_key_val *keyresp, long stat);
static int get_keyndx(table_obj *t_obj, char *col_val);

extern int resolv_flag;
extern int resolv_pid;
extern CLIENT *resolv_client;
extern char *resolv_tp;

long err_conv_nistoyp();
nis_error getzobj_orgdir();
int ypcheck_nisdir();
struct ypresp_maplist *ypproc_maplist_svc();
void map2table();
bool_t xdr_ypresp_all();

int serv_wart = 0;
/* to help the two key lookup on port/proto or service/proto in services */

int mail_wart_byaddr = 0;
/* to pass the column name info from map2table to cook_record */

int netid_wart = 0;
/* the request on cred table/auth_name is for netid */

int mult_lines_wart = 0;
/* the client can handle mulitple lines of reply from ypproc_match_svc */

static nis_error
cook_record_from_entry(entry_obj *, char **, int *, char *, nis_object *);
static void
cook_an_ngroup(entry_obj *, char **, int *);
static nis_error
cook_host_record(nis_object *, int, char **, int *, struct svc_req *);
static char *getcaller_inet();

#define	record		(__nis_get_tsd()->yp_ns_proc_record)
#define	keyval		(__nis_get_tsd()->yp_ns_proc_keyval)


static
int
check_map(map)
	char *map;
{
	int n;

	if (map == 0 || (n = strlen(map)) == 0 || n >= YPMAXMAP)
		return (0);
	return (1);
}

static
char *
check_domain(domain)
	char *domain;
{
	int n;

	if (domain == 0 || *domain == 0 || strlen(domain) >= YPMAXDOMAIN)
		return (0);
	while (*domain && *domain == '.')
		domain++;
	if (*domain == 0)
		return (0);
	return (domain);
}

static
int
check_key(keydat)
	datum *keydat;
{
	if (keydat->dsize == 0 || keydat->dptr == 0)
		return (0);
	return (1);
}

/*
 * This determines whether or not the domain passed is served by this server,
 * and returns a boolean.
 */
int *
ypproc_domain_svc(dname, rqstp)
	string_t	*dname;
	struct svc_req *rqstp;
{
	char *domain;
#define	isserved	(__nis_get_tsd()->ypproc_domain_svc_isserved)

	if ((domain = check_domain(*dname)) == 0)
		return (&isserved);

	if (verbose)
		syslog(LOG_INFO, "ypserv: bind request from %s",
			getcaller_inet(rqstp));
	isserved = ypcheck_nisdir(domain);
	if (!isserved)
		syslog(LOG_ERR, "ypserv: Domain %s not supported", *dname);
	return (&isserved);
}

#undef	isserved

/*
 *  We keep a list of the domains that have been broadcasted, but that
 *  we don't serve so that we will only syslog a message about it
 *  once.
 */
struct domain_list {
	char *domain;
	struct domain_list *next;
};
struct domain_list *domains;
DECLMUTEXLOCK(domains);

/*
 *  Check to see if dname is in the list of domains.  As a side-effect
 *  we add it to the list.
 */
static
int
domain_list_check(char *dname)
{
	struct domain_list *dl;

	MUTEXLOCK(domains, "domain_list_check(domains)");
	for (dl = domains; dl; dl = dl->next) {
		if (strcmp(dname, dl->domain) == 0) {
			MUTEXUNLOCK(domains, "domain_list_check(domains)");
			return (1);
		}
	}

	if ((dl = malloc(sizeof (*dl))) != 0 &&
		(dl->domain  = strdup(dname)) != 0) {
		dl->next = domains;
		domains = dl;
	} else if (dl != 0) {
		free(dl);
	}

	MUTEXUNLOCK(domains, "domain_list_check(domains)");
	return (0);
}

int *
ypproc_domain_nonack_svc(dname, rqstp)
	string_t *dname;
	struct svc_req *rqstp;
{
	char *domain;
#define	isserved	(__nis_get_tsd()->ypproc_domain_nonack_svc_isserved)

	if ((domain = check_domain(*dname)) == 0)
		return (&isserved);

	if (verbose)
		syslog(LOG_INFO, "ypserv: (broadcast) request from %s",
			getcaller_inet(rqstp));
	isserved = ypcheck_nisdir(domain);
	if (isserved)
		return (&isserved);
	else {

		/*
		 * This case is the one in which the domain is not supported,
		 * and in which we are not to respond in the unsupported
		 * case.  We are going to make an error happen to allow the
		 * portmapper to end his wait without the normal udp timeout
		 * period.  The assumption here is that the only process in
		 * the world which is using the function in its
		 * no-answer-if-nack form is the portmapper, which is doing
		 * the krock for pseudo-broadcast.  If some poor fool calls
		 * this function as a single-cast message, the nack case will
		 * look like an incomprehensible error.  Sigh... (The
		 * traditional Unix disclaimer)
		 */

		svcerr_decode(rqstp->rq_xprt);
		if (!domain_list_check(domain)) {
			syslog(LOG_ERR,
			    "ypserv: Domain %s not supported (broadcast)",
			    *dname);
		}
		return (0);
	}
}

#undef	isserved

/*
 * This implements the "get master name" function.
 */
struct ypresp_master *
ypproc_master_svc(req, rqstp)
	struct ypreq_nokey *req;
	struct svc_req *rqstp;
{
#define	resp		(__nis_get_tsd()->ypproc_master_svc_resp)
#define	masterbuf	(__nis_get_tsd()->ypproc_master_svc_masterbuf)
	nis_object *org_zobj = NULL;
	nis_error status;
	char *domain;
	char *table, *column, *full_tblnm;
	nis_db_result	*dbres;
	int i;

	if ((domain = check_domain(req->domain)) == 0 ||
	    !check_map(req->map)) {
		resp.status = YP_BADARGS;
		return (&resp);
	}

	resp.status = YP_TRUE;
	resp.master = masterbuf;
	if (verbose)
		syslog(LOG_INFO, "ypserv: yp_master MAP = %s from %s",
			req->map, getcaller_inet(rqstp));
	status = getzobj_orgdir(domain, &org_zobj);
	if (status != NIS_SUCCESS || org_zobj == NULL) {
		syslog(LOG_INFO, "ypserv: yp_master failed for %s%s.",
						ORGDIR2, domain);
		resp.status = err_conv_nistoyp(NIS_NAMEUNREACHABLE);
		return (&resp);
	}
	strcpy(resp.master,
	(nis_leaf_of((org_zobj)->DI_data.do_servers.do_servers_val[0].name)));
	map2table(req->map, &table, &column);

	if ((full_tblnm = (char *)XCALLOC(1, strlen(table) + ORGLEN
					+ strlen(domain) + 1)) == NULL) {
		resp.status = err_conv_nistoyp(NIS_NOMEMORY);
		return (&resp);
	}
	strcpy(full_tblnm, table);
	strcat(full_tblnm, ORGDIR);
	strcat(full_tblnm, domain);
	if (*(domain + strlen(domain) - 1) != '.')
		strcat(full_tblnm, ".");

	/* Get the information base (table) object from the database */
	dbres = db_lookup(full_tblnm);
	/*
	 * MEMORY POLICY: db_lookup adds dbres to the cleanup list.
	 * We use it and forget it.
	 */
	if (dbres->status != NIS_SUCCESS || (!dbres->obj)) {
		if (dbres->status == NIS_NOTFOUND)
			resp.status = err_conv_nistoyp(NIS_NOSUCHTABLE);
		else
			resp.status = err_conv_nistoyp(dbres->status);
		XFREE(full_tblnm);
		return (&resp);
	}
	if ((__type_of(dbres->obj) != NIS_TABLE_OBJ) ||
					(column &&
			((i = get_keyndx(&(dbres->obj->TA_data), column)) < 0 ||
		(!((dbres->obj->TA_data.ta_cols.ta_cols_val + i)->tc_flags &
							TA_SEARCHABLE))))) {
		resp.status = err_conv_nistoyp(NIS_NOSUCHTABLE);
	}
	XFREE(full_tblnm);
	return (&resp);
}

#undef	resp
#undef	masterbuf

entry_obj *
get_netid_entry(tobj, e, table_name, princp, err)
	nis_object	*tobj; /* cred table object */
	entry_obj *e; /* correspoding DES entry in cred table */
	char *table_name; /* fully qualified cred table name */
	nis_name princp;
	long *err;
{
	ib_request	table_req;
	nis_attr	inkey[2];
	nis_db_list_result	*entry_obj_list;
	nis_object *ret_en_objs;
	int num_ntrees;
	int all_read;
	char *val;

	val = COLVAL(2);	/* netname */
	if (((int)strlen(val) > 5) && (! isdigit(val[5]))) {
		/*
		 * this section handles netid for root.
		 * Just return the corresponding DES entry, leave up to
		 * cook_record_from_entry() to format the return value.
		 */
		return (e);
	}
	memset((char *)inkey, 0, 2*sizeof (nis_attr));
	inkey[0].zattr_ndx	= CNAME;
	inkey[0].ZAVAL = (char *)XMALLOC(COLLEN(0));
	add_cleanup((void (*)())XFREE,
		(char *)inkey[0].ZAVAL, "get_netid_entry zaval");
	memcpy(inkey[0].ZAVAL, COLVAL(0), COLLEN(0));
	inkey[0].ZALEN = COLLEN(0);

	inkey[1].zattr_ndx = "auth_type";
	inkey[1].ZAVAL = "LOCAL";
	inkey[1].ZALEN = 6;

	table_req.ibr_srch.ibr_srch_len	= 2;
	table_req.ibr_srch.ibr_srch_val	= inkey;
	table_req.ibr_name = table_name;

	entry_obj_list = db_list(table_req.ibr_name,
			table_req.ibr_srch.ibr_srch_len,
			table_req.ibr_srch.ibr_srch_val);
	if (entry_obj_list->status != NIS_SUCCESS) {
		if (entry_obj_list->status == NIS_NOTFOUND)
			*err = YP_NOKEY;
		else
			*err = YP_NOMAP; /* bad column, attr etc. */
		return (NULL);
	}

	/*
	 * Now, process the list of objects we've got to return.
	 * We know, we gonna return only one entry. The real reason for
	 * going through this is to enforce nis_return_list's censorship.
	 */
	all_read = __can_do(NIS_READ_ACC, tobj->zo_access, tobj, princp);
	ret_en_objs = nis_return_list(tobj, entry_obj_list->objs,
			entry_obj_list->numo, princp, &num_ntrees, all_read,
					2, inkey);

	if ((ret_en_objs == NULL) || !(num_ntrees) ||
				(__type_of(ret_en_objs) != NIS_ENTRY_OBJ)) {
		*err = YP_NOKEY;
		return (NULL);
	}
	return (&(ret_en_objs->EN_data));
}

struct ypresp_val *
ypproc_match_svc(req, rqstp)
	struct ypreq_key *req;
	struct svc_req *rqstp;
{
#define	resp	(__nis_get_tsd()->ypproc_match_svc_resp)
	char *table, *column;
	int len;
	entry_obj *e, *netid_e;
	char	 princp[1024];
	char	 map[YPMAXMAP];
	int	num_ntrees;
	nis_error status;

	ib_request	table_req;
	char		*t, *proto;
	char	 *col_proto = "proto";
	nis_attr	inkey[2];
	char *domain;
	nis_db_list_result	*entry_obj_list;
	nis_object *ret_en_objs;
	nis_db_result	*dbres;
	int		i, j, all_read;

	if ((domain = check_domain(req->domain)) == 0 ||
	    !check_map(req->map) ||
	    !check_key(&req->keydat)) {
		resp.status = YP_BADARGS;
		return (&resp);
	}

	resp.status = YP_TRUE;

	if (verbose) {
		syslog(LOG_INFO, "ypserv: yp_match MAP = %s from %s",
			req->map, getcaller_inet(rqstp));
	}

	/*
	 * All YP requests are unauthenticated and are successful
	 * only if the database has nobody-read access.
	 */

	if (resolv_flag) { /* save real map name */
		strncpy(map, req->map, sizeof (map)-1);
		map[sizeof (map)-1] = '\0';
	}

	map2table(req->map, &table, &column);

	if ((strcmp(table, "netgroup") == 0) &&
		(strcmp(column, NGROUPNAME) != 0)) {
		/* We only support one netgroup YP map, "netgroup". */
		cook_err_resp(&resp, YP_NOMAP);
		return (&resp);
	}

	/* Cook the ib_request */
	if ((table_req.ibr_name = (char *)XCALLOC(1, \
			(strlen(table) + ORGLEN + strlen(domain) + 1))) ==
									NULL) {
		cook_err_resp(&resp, err_conv_nistoyp(NIS_NOMEMORY));
		return (&resp);
	}
	strcpy(table_req.ibr_name, table);
	strcat(table_req.ibr_name, ORGDIR);
	strcat(table_req.ibr_name, domain);
	if (*(domain + strlen(domain) - 1) != '.')
		strcat(table_req.ibr_name, ".");

	/* Get the information base (table) object from the database */
	dbres = db_lookup(table_req.ibr_name);
	/*
	 * MEMORY POLICY: db_lookup adds dbres to the cleanup list.
	 * We use it and forget it.
	 */
	if (dbres->status != NIS_SUCCESS || (!dbres->obj)) {
		if (dbres->status == NIS_NOTFOUND)
			cook_err_resp(&resp, err_conv_nistoyp(NIS_NOSUCHTABLE));
		else
			cook_err_resp(&resp, err_conv_nistoyp(dbres->status));
		XFREE(table_req.ibr_name);
		return (&resp);
	}
	if (__type_of(dbres->obj) != NIS_TABLE_OBJ) {
		/* there goes yp's limited knowledge of the NIS+ universe ! */
		cook_err_resp(&resp, err_conv_nistoyp(NIS_NOSUCHTABLE));
		XFREE(table_req.ibr_name);
		return (&resp);
	}

	/*
	 * If we are using the default key check that the the map actually
	 * contains this column. If not the log an informational error instead
	 * of proceeding to the lookup where a more serious error would be
	 * produced.
	 */
	if (strcmp(column, DEFAULTKEY) == 0) {
		if (get_keyndx(&(dbres->obj->TA_data), column) < 0) {
			syslog(LOG_INFO,
				"%s is not explicitly supported in YP "
				"compatibility mode. Unsupported NIS+ tables "
				"must have column named \'%s\'.",
				table, DEFAULTKEY);
			cook_err_resp(&resp, err_conv_nistoyp(NIS_NOSUCHTABLE));
			XFREE(table_req.ibr_name);
			return (&resp);
		}
	}

	/* Cook the nis_attr key */
	memset((char *)inkey, 0, 2*sizeof (nis_attr));
	inkey[0].zattr_ndx	= column;
	/*
	 * ASSERT: column is never NULL,
	 *		could be client supplied or DEFAULTKEY
	 */

	/*
	 * Do the jugglery to conform to the NIS+ convention of null
	 * terminated data in the database. Cannot rely on YP
	 * that it will always pass a null terminated key.
	 */
	i = req->keydat.dsize;
	if (req->keydat.dptr[i-1] != '\0')
		i++;
	inkey[0].ZAVAL = (char *)XMALLOC(i);
	inkey[0].ZALEN = i;
	if (inkey[0].ZAVAL == NULL) {
		cook_err_resp(&resp, err_conv_nistoyp(NIS_NOMEMORY));
		XFREE(table_req.ibr_name);
		return (&resp);
	}
	strncpy(inkey[0].ZAVAL, req->keydat.dptr, req->keydat.dsize);
	inkey[0].ZAVAL[i-1] = '\0';

	cook_err_resp(&resp, err_conv_nistoyp(NIS_SUCCESS));

	/* Now, do the actual lookup for an entry we want */
	table_req.ibr_srch.ibr_srch_len	= 1;
	table_req.ibr_srch.ibr_srch_val	= inkey;

	if (serv_wart && (strcmp(table, "services") == 0) &&
		((proto = strchr(inkey[0].ZAVAL, '/')) != NULL)) {
		*proto++ = '\0';
		inkey[1].zattr_ndx = col_proto;
		inkey[1].ZALEN = (strlen(proto) + 1);
		inkey[1].ZAVAL = proto;
		inkey[0].ZALEN = i - inkey[1].ZALEN;
		table_req.ibr_srch.ibr_srch_len++;
	}

	if (strcmp(table, "cred") == 0) {
		/* only make the publickey.byname type of information visible */
		inkey[1].zattr_ndx = "auth_type";
		table_req.ibr_srch.ibr_srch_len++;
		inkey[1].ZAVAL = "DES";
		inkey[1].ZALEN = 4;
	}

	entry_obj_list = db_list(table_req.ibr_name,
			table_req.ibr_srch.ibr_srch_len,
			table_req.ibr_srch.ibr_srch_val);
	if (entry_obj_list->status != NIS_SUCCESS) {
		if (entry_obj_list->status == NIS_NOTFOUND)
			if (resolv_flag &&
				resolv_req(&resolv_flag, &resolv_client,
						&resolv_pid, resolv_tp,
						rqstp->rq_xprt, req, map)) {
				XFREE(table_req.ibr_name);
				XFREE(inkey[0].ZAVAL);
				return (NULL);	/* fwd'ed req: skip reply */
			} else
				cook_err_resp(&resp, YP_NOKEY);
		else
			/* bad column, attr etc. */
			cook_err_resp(&resp, YP_NOMAP);
		XFREE(table_req.ibr_name);
		XFREE(inkey[0].ZAVAL);
		return (&resp);
	}

	/*
	 * Now, process the list of objects we've got to return.
	 * We know, we gonna return only one entry. The real reason for
	 * going through this is to enforce nis_return_list's censorship.
	 */
	nis_getprincipal(princp, rqstp);
	all_read = __can_do(NIS_READ_ACC, dbres->obj->zo_access,
		dbres->obj, princp);
	ret_en_objs = nis_return_list(dbres->obj, entry_obj_list->objs,
			entry_obj_list->numo, princp, &num_ntrees, all_read,
					2, inkey);

	if ((ret_en_objs == NULL) || !(num_ntrees) ||
				(__type_of(ret_en_objs) != NIS_ENTRY_OBJ)) {
		cook_err_resp(&resp, YP_NOKEY);
		XFREE(table_req.ibr_name);
		XFREE(inkey[0].ZAVAL);
		return (&resp);
	}
	if (strcmp(table, "netgroup") == 0) {
		/*
		 * This is as grungy as any code can get. The
		 * netgroup format of the NIS+ table is quite
		 * different from that in YP; for instance, we
		 * do not have "reverse" lookup support. We write
		 * the complete code here.
		 */
		if (strcmp(column, NGROUPNAME) == 0) {
			int i = 0, len;
			char *ngrp;

			ngrp = XMALLOC(YPMAXRECORD);
			add_cleanup((void (*)())XFREE,
				(char *)ngrp, "yp (match) mem");
			memset(record, 0, YPMAXRECORD);
			resp.valdat.dptr = record;
			while ((ret_en_objs + i) && (i < num_ntrees)) {
				e = &((ret_en_objs + i)->EN_data);
				len = 0;
				cook_an_ngroup(e, &ngrp, &len);
				/*
				 * len returned here includes the
				 * NULL character '\0'
				 */
				if ((strlen(record) + len) > YPMAXRECORD)
					break;
				strcat(record, ngrp);
				strcat(record, " ");
				i++;
			}
			if ((num_ntrees == 1) &&
					(strcmp(COLVAL(5), "") != 0) &&
					((strlen(record) + COLLEN(5) + 3) <=
								YPMAXRECORD)) {
				/*
				 * the special case of leaf netgroup,
				 * print comments
				 */
				strcat(record, "\t#");
				strcat(record, COLVAL(5));
			}
			resp.valdat.dsize = strlen(record);
		} else
			cook_err_resp(&resp, YP_NOMAP);
		XFREE(table_req.ibr_name);
		XFREE(inkey[0].ZAVAL);
		return (&resp);
	}

	e = &(ret_en_objs->EN_data);
	if (netid_wart) {
		long yperr = YP_TRUE;

		netid_e = e;
		e = get_netid_entry(dbres->obj, netid_e,
				table_req.ibr_name, princp, &yperr);
		if (! e) {
			cook_err_resp(&resp, yperr);
			XFREE(table_req.ibr_name);
			XFREE(inkey[0].ZAVAL);
			return (&resp);
		}
	}

	/* construct a complete entry from all columns */
	memset(record, 0, YPMAXRECORD);
	t = record;
	if (strcmp(table, "hosts") == 0) {
		status = cook_host_record(ret_en_objs, num_ntrees,
			&t, &len, rqstp);
	} else {
		status = cook_record_from_entry(e, &t, &len, table, dbres->obj);
	}
	if (status != NIS_SUCCESS) {
		cook_err_resp(&resp, err_conv_nistoyp(status));
		XFREE(table_req.ibr_name);
		XFREE(inkey[0].ZAVAL);
		return (&resp);
	}

	resp.valdat.dptr = record;
	resp.valdat.dsize = len;

	XFREE(table_req.ibr_name);
	XFREE(inkey[0].ZAVAL);
	return (&resp);
}

#undef	resp

struct ypresp_key_val *
ypproc_first_svc(req, rqstp)
	struct ypreq_nokey *req;
	struct svc_req *rqstp;
{
#define	resp	(__nis_get_tsd()->ypproc_first_svc_resp)
	char *table, *column, *full_tblnm, *t;
	int len, key_ndx;
	entry_obj *e, *netid_e = NULL;
	nis_error status;
	char *domain;
	nis_object *ret_en_objs;
	nis_db_result	*dbres;
	nis_fn_result *fnr;
	char	 princp[1024];
	netobj cookie;
	int all_readable = 0;

	if ((domain = check_domain(req->domain)) == 0 ||
	    !check_map(req->map)) {
		resp.status = YP_BADARGS;
		return (&resp);
	}

	resp.status = YP_TRUE;
	if (verbose)
		syslog(LOG_INFO, "ypserv: yp_first MAP = %s from %s",
			req->map, getcaller_inet(rqstp));

	/*
	 * All YP requests are unauthenticated and are successful
	 * only if the database has nobody-read access.
	 */

	map2table(req->map, &table, &column);
	if (strcmp(table, "netgroup") == 0) {
		cook_err_keyresp(&resp, YP_NOMORE);
		return (&resp);
	}

	if ((full_tblnm = (char *)XCALLOC(1, strlen(table) + ORGLEN
						+ strlen(domain) + 1)) ==
									NULL) {
		cook_err_keyresp(&resp, err_conv_nistoyp(NIS_NOMEMORY));
		return (&resp);
	}
	strcpy(full_tblnm, table);
	strcat(full_tblnm, ORGDIR);
	strcat(full_tblnm, domain);
	if (*(domain + strlen(domain) - 1) != '.')
		strcat(full_tblnm, ".");

	/* Get the information base (table) object from the database */
	dbres = db_lookup(full_tblnm);
	/*
	 * MEMORY POLICY: db_lookup adds dbres to the cleanup list.
	 * We use it and forget it.
	 */
	if (dbres->status != NIS_SUCCESS || (!dbres->obj)) {
		if (dbres->status == NIS_NOTFOUND)
			cook_err_keyresp(&resp,
					err_conv_nistoyp(NIS_NOSUCHTABLE));
		else
			cook_err_keyresp(&resp,
					err_conv_nistoyp(dbres->status));
		XFREE(full_tblnm);
		return (&resp);
	}
	if (__type_of(dbres->obj) != NIS_TABLE_OBJ) {
		cook_err_keyresp(&resp, err_conv_nistoyp(NIS_NOSUCHTABLE));
		XFREE(full_tblnm);
		return (&resp);
	}

	nis_getprincipal(princp, rqstp);
	all_readable = __can_do(NIS_READ_ACC, dbres->obj->zo_access,
					dbres->obj, princp);
	/*
	 * MEMORY POLICY on db_firstib/nextib: always call it with
	 * !(flags & 2), the db_*ib routines will add fnr and fnr->obj
	 * to the cleanup list. We never free cookie.n_bytes if the
	 * cookie is to be passwd to db_nextib(). db_nextib() always
	 * frees the cookie it is given.
	 */
	fnr = db_firstib(full_tblnm, 0, NULL, FN_NOMANGLE, NULL);
	if (fnr->status != NIS_SUCCESS) {
		cook_err_keyresp(&resp, YP_NOMORE);
		XFREE(full_tblnm);
		return (&resp);
	}
	cookie = fnr->cookie;
doagain:
	do {
		if (all_readable) {
			ret_en_objs = fnr->obj;
			break;
		} else {
			ret_en_objs = nis_censor_object(fnr->obj,
				dbres->obj->TA_data.ta_cols.ta_cols_val,
								princp);
		}
		if (! ret_en_objs) {
			fnr =  db_nextib(full_tblnm, &cookie, 0, NULL);
			if (fnr->status != NIS_SUCCESS) {
				cook_err_keyresp(&resp, YP_NOMORE);
				XFREE(full_tblnm);
				return (&resp);
			}
			cookie = fnr->cookie;
		}
	} while ((ret_en_objs == NULL) && (fnr->status == NIS_SUCCESS));

	if (fnr->status != NIS_SUCCESS) {
		cook_err_keyresp(&resp, YP_NOMORE);
		if (ret_en_objs && !all_readable)
			nis_destroy_object(ret_en_objs);
		XFREE(full_tblnm);
		return (&resp);
	}
	if (__type_of(ret_en_objs) != NIS_ENTRY_OBJ) {
		cook_err_keyresp(&resp, YP_NOKEY);
		if (ret_en_objs && !all_readable)
			nis_destroy_object(ret_en_objs);
		XFREE(full_tblnm);
		return (&resp);
	}
	e = &(ret_en_objs->EN_data);

	if ((strcmp(table, "cred") == 0) &&
		(strcmp(COLVAL(1), "DES") != 0)) {
		fnr =  db_nextib(full_tblnm, &cookie, 0, NULL);
		if (fnr->status != NIS_SUCCESS) {
			cook_err_keyresp(&resp, YP_NOMORE);
			if (ret_en_objs && !all_readable)
				nis_destroy_object(ret_en_objs);
			XFREE(full_tblnm);
			return (&resp);
		}
		cookie = fnr->cookie;
		if (ret_en_objs && !all_readable)
			nis_destroy_object(ret_en_objs);
		goto doagain;
	}

	if ((strcmp(table, "cred") == 0) &&
		(strcmp(COLVAL(1), "DES") == 0) &&
		netid_wart) {
		long yperr = YP_TRUE;

		netid_e = e;
		e = get_netid_entry(dbres->obj,
				netid_e, full_tblnm, princp, &yperr);
		if (! e) {
			fnr = db_nextib(full_tblnm, &cookie, 0, NULL);
			if (fnr->status != NIS_SUCCESS) {
				cook_err_keyresp(&resp, YP_NOMORE);
				if (ret_en_objs && !all_readable)
					nis_destroy_object(ret_en_objs);
				XFREE(full_tblnm);
				return (&resp);
			}
			cookie = fnr->cookie;
			if (ret_en_objs && !all_readable)
				nis_destroy_object(ret_en_objs);
			goto doagain;
		}
	}
	add_cleanup((void (*)())XFREE,
		(char *)cookie.n_bytes, "yp (first) cookie");
	XFREE(full_tblnm);

	/* construct a complete entry from all columns */
	memset(record, 0, YPMAXRECORD);
	t = &(record[0]);
	status = cook_record_from_entry(e, &t, &len, table, dbres->obj);
	if (status != NIS_SUCCESS) {
		if (ret_en_objs && !all_readable)
			nis_destroy_object(ret_en_objs);
		cook_err_keyresp(&resp, err_conv_nistoyp(status));
		return (&resp);
	}

	key_ndx = get_keyndx(&(dbres->obj->TA_data), column);
	if ((key_ndx < 0) || (key_ndx > (e->en_cols.en_cols_len - 1))) {
		if (ret_en_objs && !all_readable)
			nis_destroy_object(ret_en_objs);
		cook_err_keyresp(&resp, YP_NOKEY);
		return (&resp);
	} else {
	/*
	 * We are cheating the yp_first/next client by sending the pattern
	 * "<key>\n\0#<cookie><int>" as the key in resp.keydat. They loose
	 * if they don't send the same key back to us or send it back after
	 * str*cpy()'ing to a new place.
	 */
		int enlen;
		char *enval;
		char *pattern = "\n\0#";
		int patlen = 3;

		if (netid_wart && netid_e)
			e = netid_e;
		enlen = COLLEN(key_ndx);
		enval = COLVAL(key_ndx);
		resp.keydat.dptr =
			XMALLOC(enlen + patlen + cookie.n_len + sizeof (int));
		add_cleanup((void (*)())XFREE, (char *)resp.keydat.dptr,
						"yp (first) resp.keydat.dptr");
		resp.keydat.dsize = enlen + patlen + cookie.n_len +
								sizeof (int);
		memcpy(resp.keydat.dptr, enval, enlen);
		memcpy(resp.keydat.dptr + enlen, pattern, patlen);
		memcpy((resp.keydat.dptr + enlen + patlen), cookie.n_bytes,
			cookie.n_len);
		/* skip these many bytes before getting to the cookie */
		enlen += patlen;
		memcpy((resp.keydat.dptr + enlen + cookie.n_len),
			(char *)&enlen, sizeof (int));
	}

	if (ret_en_objs && !all_readable)
		nis_destroy_object(ret_en_objs);
	resp.valdat.dptr = record;
	resp.valdat.dsize = len;

	return (&resp);
}

#undef	resp

struct ypresp_key_val *
ypproc_next_svc(req, rqstp)
	struct ypreq_key *req;
	struct svc_req *rqstp;
{
#define	resp	(__nis_get_tsd()->ypproc_next_svc_resp)
	char *t, *table, *column, *full_tblnm;
	int len;
	entry_obj *e, *netid_e = NULL;
	nis_error status;
	char *domain;
	nis_object *ret_en_objs;
	nis_db_result	*dbres;
	char princp[1024];
	nis_fn_result *fnr;
	netobj cookie;
	int key_ndx;
	int all_readable = 0;

	if ((domain = check_domain(req->domain)) == 0 ||
	    !check_map(req->map) ||
	    !check_key(&req->keydat)) {
		resp.status = YP_BADARGS;
		return (&resp);
	}

	resp.status = YP_TRUE;
	if (verbose)
		syslog(LOG_INFO, "ypserv: yp_next MAP = %s from %s",
				req->map, getcaller_inet(rqstp));

	/*
	 * All YP requests are unauthenticated and are successful
	 * only if the database has nobody-read access.
	 */

	map2table(req->map, &table, &column);
	if (strcmp(table, "netgroup") == 0) {
		cook_err_keyresp(&resp, YP_NOMORE);
		return (&resp);
	}

	if ((full_tblnm = (char *)XCALLOC(1, strlen(table) + ORGLEN
					+ strlen(domain) + 1)) == NULL) {
		cook_err_keyresp(&resp, YP_YPERR);
		return (&resp);
	}
	strcpy(full_tblnm, table);
	strcat(full_tblnm, ORGDIR);
	strcat(full_tblnm, domain);
	if (*(domain + strlen(domain) - 1) != '.')
		strcat(full_tblnm, ".");

	/* Get the information base (table) object from the database */
	dbres = db_lookup(full_tblnm);
	/*
	 * MEMORY POLICY: db_lookup adds dbres to the cleanup list.
	 * We use it and forget it.
	 */
	if (dbres->status != NIS_SUCCESS || (!dbres->obj)) {
		if (dbres->status == NIS_NOTFOUND)
			cook_err_keyresp(&resp,
					err_conv_nistoyp(NIS_NOSUCHTABLE));
		else
			cook_err_keyresp(&resp,
					err_conv_nistoyp(dbres->status));
		XFREE(full_tblnm);
		return (&resp);
	}
	if (__type_of(dbres->obj) != NIS_TABLE_OBJ) {
		/* there goes yp's limited knowledge of the NIS+ universe ! */
		cook_err_keyresp(&resp, err_conv_nistoyp(NIS_NOSUCHTABLE));
		XFREE(full_tblnm);
		return (&resp);
	}

	/*
	 * We have cheated the yp_first/next client by sending the pattern
	 * "<key>\n\0#<cookie><int>" as the key in resp.keydat. They loose
	 * if they haven't sent the same key back to us or sent it back after
	 * str*cpy()'ing to a new place.
	 */
	memcpy((char *)&len,
		(req->keydat.dptr + req->keydat.dsize - sizeof (int)),
		sizeof (int));
	if ((len < 0) || (len > req->keydat.dsize)) {
		/* We got a cookie we can't understand */
		cook_err_keyresp(&resp, YP_NOMORE);
		XFREE(full_tblnm);
		return (&resp);
	}
	t = (req->keydat.dptr) + len;
	if ((*(t - 1) != '#') || (*(t -2) != '\0')) {
		/* We got a cookie we can't understand */
		cook_err_keyresp(&resp, YP_NOMORE);
		XFREE(full_tblnm);
		return (&resp);
	}
	cookie.n_len = req->keydat.dsize - len - sizeof (int);
	cookie.n_bytes = XMALLOC(cookie.n_len);
	memcpy(cookie.n_bytes, t, cookie.n_len);

	nis_getprincipal(princp, rqstp);
	all_readable = __can_do(NIS_READ_ACC, dbres->obj->zo_access,
					dbres->obj, princp);
	fnr = db_nextib(full_tblnm, &cookie, 0, NULL);
	if (fnr->status != NIS_SUCCESS) {
		cook_err_keyresp(&resp, YP_NOMORE);
		XFREE(full_tblnm);
		return (&resp);
	}
	cookie = fnr->cookie;
doagain:
	do {
		if (all_readable) {
			ret_en_objs = fnr->obj;
			break;
		} else {
			ret_en_objs = nis_censor_object(fnr->obj,
				dbres->obj->TA_data.ta_cols.ta_cols_val,
								princp);
		}
		if (! ret_en_objs) {
			fnr =  db_nextib(full_tblnm, &cookie, 0, NULL);
			if (fnr->status != NIS_SUCCESS) {
				cook_err_keyresp(&resp, YP_NOMORE);
				XFREE(full_tblnm);
				return (&resp);
			}
			cookie = fnr->cookie;
		}
	} while ((ret_en_objs == NULL) && (fnr->status == NIS_SUCCESS));

	if (fnr->status != NIS_SUCCESS) {
		cook_err_keyresp(&resp, YP_NOMORE);
		if (ret_en_objs && !all_readable)
			nis_destroy_object(ret_en_objs);
		XFREE(full_tblnm);
		return (&resp);
	}
	if (__type_of(ret_en_objs) != NIS_ENTRY_OBJ) {
		cook_err_keyresp(&resp, YP_NOKEY);
		if (ret_en_objs && !all_readable)
			nis_destroy_object(ret_en_objs);
		XFREE(full_tblnm);
		return (&resp);
	}
	e = &(ret_en_objs->EN_data);

	if ((strcmp(table, "cred") == 0) &&
		(strcmp(COLVAL(1), "DES") != 0)) {
		fnr =  db_nextib(full_tblnm, &cookie, 0, NULL);
		if (fnr->status != NIS_SUCCESS) {
			cook_err_keyresp(&resp, YP_NOMORE);
			if (ret_en_objs && !all_readable)
				nis_destroy_object(ret_en_objs);
			XFREE(full_tblnm);
			return (&resp);
		}
		cookie = fnr->cookie;
		if (ret_en_objs && !all_readable)
			nis_destroy_object(ret_en_objs);
		goto doagain;
	}

	if ((strcmp(table, "cred") == 0) &&
		(strcmp(COLVAL(1), "DES") == 0) &&
		netid_wart) {
		long yperr = YP_TRUE;

		netid_e = e;
		e = get_netid_entry(dbres->obj,
				netid_e, full_tblnm, princp, &yperr);
		if (! e) {
			fnr = db_nextib(full_tblnm, &cookie, 0, NULL);
			if (fnr->status != NIS_SUCCESS) {
				cook_err_keyresp(&resp, YP_NOMORE);
				if (ret_en_objs && !all_readable)
					nis_destroy_object(ret_en_objs);
				XFREE(full_tblnm);
				return (&resp);
			}
			cookie = fnr->cookie;
			if (ret_en_objs && !all_readable)
				nis_destroy_object(ret_en_objs);
			goto doagain;
		}
	}
	add_cleanup((void (*)())XFREE,
		(char *)cookie.n_bytes, "yp (next) cookie");
	XFREE(full_tblnm);

	/* construct a complete entry from all columns */
	memset(record, 0, YPMAXRECORD);
	t = &(record[0]);
	status = cook_record_from_entry(e, &t, &len, table, dbres->obj);
	if (status != NIS_SUCCESS) {
		cook_err_keyresp(&resp, err_conv_nistoyp(status));
		if (ret_en_objs && !all_readable)
			nis_destroy_object(ret_en_objs);
		return (&resp);
	}

	key_ndx = get_keyndx(&(dbres->obj->TA_data), column);
	if ((key_ndx < 0) || (key_ndx > (e->en_cols.en_cols_len - 1))) {
		if (ret_en_objs && !all_readable)
			nis_destroy_object(ret_en_objs);
		cook_err_keyresp(&resp, YP_NOMORE);
		return (&resp);
	} else {
	/*
	 * We are cheating the yp_first/next client by sending the pattern
	 * "<key>\n\0#<cookie><int>" as the key in resp.keydat. They loose
	 * if they don't send the same key back to us or send it back after
	 * str*cpy()'ing to a new place.
	 */
		int enlen;
		char *enval;
		char *pattern = "\n\0#";
		int patlen = 3;

		if (netid_wart && netid_e)
			e = netid_e;
		enlen = COLLEN(key_ndx);
		enval = COLVAL(key_ndx);
		resp.keydat.dptr = XMALLOC(enlen + patlen + cookie.n_len +
								sizeof (int));
		add_cleanup((void (*)())XFREE, (char *)resp.keydat.dptr,
						"yp (next) resp.keydat.dptr");
		resp.keydat.dsize = enlen + patlen + cookie.n_len +
								sizeof (int);
		memcpy(resp.keydat.dptr, enval, enlen);
		memcpy(resp.keydat.dptr + enlen, pattern, patlen);
		memcpy((resp.keydat.dptr + enlen + patlen), cookie.n_bytes,
			cookie.n_len);
		/* skip these many bytes before getting to the cookie */
		enlen += patlen;
		memcpy((resp.keydat.dptr + enlen + cookie.n_len),
			(char *)&enlen, sizeof (int));
	}

	if (ret_en_objs && !all_readable)
		nis_destroy_object(ret_en_objs);

	resp.valdat.dptr = record;
	resp.valdat.dsize = len;
	return (&resp);
}

#undef	resp

struct ypresp_all *
ypproc_all_svc(req, rqstp)
	struct ypreq_nokey *req;
	struct svc_req *rqstp;
{
#define	resp	(__nis_get_tsd()->ypproc_all_svc_resp)
	char *table, *column, *full_tblnm;
	nis_error status;
	char *domain;
	pid_t pid;
	SVCXPRT *transp = rqstp->rq_xprt;

	nis_db_result	*dbres;
	char princp[1024];

	if ((domain = check_domain(req->domain)) == 0 ||
	    !check_map(req->map)) {
		resp.status = YP_BADARGS;
		return (&resp);
	}

	memset((char *)&resp, 0, sizeof (struct ypresp_all));
	resp.status = YP_TRUE;
	if (verbose)
		syslog(LOG_INFO, "ypserv: yp_all MAP = %s from %s",
			req->map, getcaller_inet(rqstp));

	/*
	 * All YP requests are unauthenticated and are successful
	 * only if the database has nobody-read access.
	 */

	map2table(req->map, &table, &column);
	if (strcmp(table, "netgroup") == 0) {
		resp.status = YP_NOMORE;
		return (&resp);
	}

	if ((full_tblnm = (char *)XCALLOC(1, strlen(table) + ORGLEN
					+ strlen(domain) + 1)) == NULL) {
		resp.status = YP_YPERR;
		return (&resp);
	}
	add_cleanup((void (*)())XFREE,
		(char *)full_tblnm, "yp (all) full_tblnm");
	strcpy(full_tblnm, table);
	strcat(full_tblnm, ORGDIR);
	strcat(full_tblnm, domain);
	if (*(domain + strlen(domain) - 1) != '.')
		strcat(full_tblnm, ".");

	/* Get the information base (table) object from the database */
	dbres = db_lookup(full_tblnm);
	/*
	 * MEMORY POLICY: db_lookup adds dbres to the cleanup list.
	 * We use it and forget it.
	 */
	if (dbres->status != NIS_SUCCESS || (!dbres->obj)) {
		if (dbres->status == NIS_NOTFOUND)
			resp.status = err_conv_nistoyp(NIS_NOSUCHTABLE);
		else
			resp.status = err_conv_nistoyp(dbres->status);
		return (&resp);
	}
	if ((__type_of(dbres->obj) != NIS_TABLE_OBJ) ||
				(column && (strcmp(column, DEFAULTKEY) != 0) &&
((resp.key_column_ndx = get_keyndx(&(dbres->obj->TA_data), column)) < 0 ||
			(!((dbres->obj->TA_data.ta_cols.ta_cols_val +
			resp.key_column_ndx)->tc_flags & TA_SEARCHABLE))))) {
		resp.status = err_conv_nistoyp(NIS_NOSUCHTABLE);
		return (&resp);
	}

	nis_getprincipal(princp, rqstp);
	resp.table_name = full_tblnm;
	resp.princp = strdup(princp);
	add_cleanup((void (*)()) XFREE, (char *)resp.princp, "principal name");
	resp.status = YP_TRUE; /* so far, so good. */
	resp.table_zobj = dbres->obj;

	/*
	 * Send reply from this thread without forking. An alternative
	 * implementation would be to create a new thread to send the
	 * reply; both have their complementary advantages and disadvantages:
	 *
	 * Send reply from this thread:
	 *
	 *	Simpler to implement
	 *
	 *	No new thread created, so probably slightly quicker
	 *
	 *	No runaway resource usage (i.e., lots of threads) in
	 *	rpc.nisd
	 *
	 *	Don't have to worry about 'transp' (= rqstp->rq_xprt)
	 *	possibly becoming invalid while a child thread is running.
	 *
	 * Send reply from a new thread:
	 *
	 *	Less risk of denial-of-service if yp_all() calls use up
	 *	all of the auto RPC mode service threads
	 *
	 * We opt for simplicity.
	 */
	if (!svc_sendreply(transp,
			(xdrproc_t)xdr_ypresp_all, (char *)&resp)) {
		svcerr_systemerr(transp);
	}

	return (0);
}

#undef	resp

static void
free_ypmaplist(maplist)
	struct ypmaplist	*maplist;
{
	struct ypmaplist *tmp;
	while (maplist) {
		tmp = maplist->ypml_next;
		(void) XFREE(maplist);
		maplist = tmp;
	}
}

struct ypresp_maplist *
ypproc_maplist_svc(dname, rqstp)
	string_t *dname;
	struct svc_req *rqstp;
{
#define	maplist		(__nis_get_tsd()->ypproc_maplist_svc_maplist)
	struct ypmaplist *map, *mapnames;
	nis_object *z_obj = NULL;
	nis_error status;
	char *domain;
	int namesz, i;
	char orgdir[YPMAXDOMAIN + ORGLEN];
	nis_fn_result *fnr;
	netobj cookie;

	if ((domain = check_domain(*dname)) == 0) {
		maplist.status = YP_BADARGS;
		maplist.list = 0;
		return (&maplist);
	}

	maplist.status = YP_TRUE;
	maplist.list = NULL;
	if (verbose)
		syslog(LOG_INFO, "ypserv: yp_maplist from %s",
			getcaller_inet(rqstp));
	status = getzobj_orgdir(domain, &z_obj);
	if (status != NIS_SUCCESS || z_obj == NULL) {
		syslog(LOG_INFO, "ypserv: yp_maplist failed for ORGDIR1.%s.",
								domain);
		maplist.status = err_conv_nistoyp(NIS_NAMEUNREACHABLE);
		return (&maplist);
	}
	strcpy(orgdir, ORGDIR2);
	strcat(orgdir, domain);
	if (*(domain + strlen(domain) - 1) != '.')
		strcat(orgdir, ".");

	/*
	 * MEMORY POLICY on db_firstib/nextib: always call it with
	 * !(flags & 2), the db_*ib routines will add fnr and fnr->obj
	 * to the cleanup list. We never free cookie.n_bytes if the
	 * cookie is to be passwd to db_nextib(). db_nextib() always
	 * frees the cookie it is given.
	 */
	fnr = db_firstib(orgdir, 0, NULL, FN_NOMANGLE, NULL);
	while ((fnr->status == NIS_SUCCESS) &&
			(__type_of(fnr->obj) == NIS_TABLE_OBJ)) {
		char *tblname, mname[YPMAXMAP + 1];
		struct table_obj *t_obj;
		struct table_col *tcol;

		cookie = fnr->cookie;
		memset(mname, 0, YPMAXMAP+1);
		/*
		 * POLICY: For each table name, the corresponding map names
		 * are concocted by expanding <tablename>.by<approriate_column>,
		 * where appropriate_column is a searchable column in the
		 * table that does not have the names CNAME (ignore this) or
		 * DEFAULTKEY (expand only to <tablename>). Idea is that the
		 * client MUST be able to lookup EVERY such mapname returned,
		 * should not return too many mapnames and should not confuse
		 * users by renaming conventional NIS mapnames.
		 *
		 * HACKS: As a consequence of the above policy, we must do
		 * something special to rename all the "auto_*" tables to
		 * "auto.*", suppress printing "services.byproto", print
		 * a new map "services.byservicename" that really looks at the
		 * key "name" in the services table (look at map2table() for
		 * the explanation of this hack), and print "mail.aliases"
		 * and "mail.byaddr" as the only two maps for the mail_aliases
		 * table.
		 */
		tblname = fnr->obj->zo_name;
		t_obj = &(fnr->obj->TA_data);
		for (i = 0; i < t_obj->ta_cols.ta_cols_len; i++) {
			tcol = t_obj->ta_cols.ta_cols_val + i;
			if (!(tcol->tc_flags & TA_SEARCHABLE) ||
				(strcmp(CNAME, tcol->tc_name) == 0) ||
				(strlen(tblname) + strlen(tcol->tc_name) + 3) >
								YPMAXMAP) {
				continue;
			}

			if (strcmp(tblname, "mail_aliases") == 0) {
				if (strcmp(MAILNAME, tcol->tc_name) == 0)
					strcpy(mname, "mail.aliases");
				else if (strcmp(MAILADDR, tcol->tc_name) == 0)
					strcpy(mname, "mail.byaddr");
				else
					continue;
			} else if (strncmp(tblname, "auto_", 5) == 0) {
				char *ptr;
				strcpy(mname, tblname);
				ptr = strchr(mname, '_');
				if (ptr)
					*ptr = '.';
			} else if (strcmp(tblname, "services") == 0) {
				if (strcmp("name", tcol->tc_name) == 0)
					strcpy(mname, "services.byservicename");
				else if (strcmp("port", tcol->tc_name) == 0)
					strcpy(mname, "services.byname");
				else
					continue;
			} else if (strcmp(tblname, "cred") == 0) {
				if (strcmp("auth_type", tcol->tc_name) == 0)
					strcpy(mname, "publickey.byname");
				else if (strcmp("auth_name",
							tcol->tc_name) == 0)
					strcpy(mname, "netid.byname");
				else
					continue;
			} else if (strcmp(tblname, "netgroup") == 0) {
				if (strcmp(NGROUPNAME, tcol->tc_name) == 0)
					strcpy(mname, "netgroup");
				else
					continue;
			} else {
				strcpy(mname, tblname);
				if (strcmp(tcol->tc_name, DEFAULTKEY) != 0) {
					strcat(mname, ".");
					strcat(mname, BY);
					strcat(mname, tcol->tc_name);
				}
			}
			if ((map = (struct ypmaplist *)XMALLOC(
			    (unsigned)sizeof (struct ypmaplist))) == NULL) {
				maplist.status = YP_YPERR;
				break;
			}
			map->ypml_next = maplist.list;
			maplist.list = map;
			namesz = strlen(mname);
			if (namesz <= YPMAXMAP) {
				(void) strcpy(map->ypml_name, mname);
			} else {
				(void) strncpy(map->ypml_name, mname, YPMAXMAP);
				map->ypml_name[YPMAXMAP] = '\0';
			}
		}
		fnr = db_nextib(orgdir, &cookie, FN_NOMANGLE, NULL);
	}
	add_cleanup(free_ypmaplist, (void *)(maplist.list), "ypmaplist");
	return (&maplist);
}

#undef	maplist

/*
 * This one does most of the server side work for yp_all. Of course,
 * should not be generated by rpcgen. Fetches the whole database
 * for the map and serializes a stream of struct ypresp_key_val's.
 */
bool_t
xdr_ypresp_all(xdrs, resp)
	XDR *xdrs;
	struct ypresp_all *resp;
{
	struct ypresp_key_val respdat;
	nis_object *ret_en_objs;
	nis_fn_result *fnr;
	netobj cookie;
	entry_obj *e, *netid_e = NULL;
	int len;
	int nokey = 0; /* can we isolate the key part of the entry ? */
	bool_t more = TRUE;
	nis_error status;
#define	short_tblnm	(__nis_get_tsd()->xdr_ypresp_all_short_tblnm)
	char	*t, *p = short_tblnm;
	int all_readable = 0;

	respdat.keydat.dptr = respdat.valdat.dptr = (char *)NULL;
	respdat.keydat.dsize = respdat.valdat.dsize = 0;
	respdat.status = resp->status;

	if (!resp->table_name || !resp->princp || (resp->status != YP_TRUE)) {
		if (!xdr_bool(xdrs, &more))
			return (FALSE);
		if (!xdr_ypresp_key_val(xdrs, &respdat))
			return (FALSE);
		more = FALSE;
		if (!xdr_bool(xdrs, &more))
			return (FALSE);
		return (TRUE);
	}

	memset(p, 0, YPMAXMAP);
	strcpy(p, resp->table_name);
	t = strchr(p, '.');
	if (t)
		*t = '\0';

	all_readable = __can_do(NIS_READ_ACC, resp->table_zobj->zo_access,
					resp->table_zobj, resp->princp);
	/*
	 * MEMORY POLICY on db_firstib/nextib: always call it with
	 * !(flags & 2), the db_*ib routines will add fnr and fnr->obj
	 * to the cleanup list. We never free cookie.n_bytes if the
	 * cookie is to be passwd to db_nextib(). db_nextib() always
	 * frees the cookie it is given.
	 */
	fnr = db_firstib(resp->table_name, 0, NULL, FN_NOMANGLE, NULL);
	cookie = fnr->cookie;
	while (fnr->status == NIS_SUCCESS) {
		if (all_readable)
			ret_en_objs = fnr->obj;
		else
			ret_en_objs = nis_censor_object(fnr->obj,
				resp->table_zobj->TA_data.ta_cols.ta_cols_val,
								resp->princp);
		if (ret_en_objs == NULL) {
			fnr = db_nextib(resp->table_name,
					&cookie, FN_NOMANGLE, NULL);
			cookie = fnr->cookie;
			continue; /* avoid the song 'n dance below */
		}
		if (__type_of(ret_en_objs) != NIS_ENTRY_OBJ) {
			respdat.status = YP_NOKEY;
			if (!xdr_bool(xdrs, &more))
				return (FALSE);
			if (!xdr_ypresp_key_val(xdrs, &respdat))
				return (FALSE);
			if (ret_en_objs && !all_readable)
				nis_destroy_object(ret_en_objs);
			break;
		}
		e = &(ret_en_objs->EN_data);

		if ((strcmp(p, "cred") == 0) &&
			(strcmp(COLVAL(1), "DES") != 0)) {
			fnr = db_nextib(resp->table_name,
					&cookie, FN_NOMANGLE, NULL);
			cookie = fnr->cookie;
			if (ret_en_objs && !all_readable)
				nis_destroy_object(ret_en_objs);
			continue;
		}

		if ((strcmp(p, "cred") == 0) &&
			(strcmp(COLVAL(1), "DES") == 0) &&
			netid_wart) {
			long yperr = YP_TRUE;

			netid_e = e;
			e = get_netid_entry(resp->table_zobj, netid_e,
					resp->table_name, resp->princp, &yperr);
			if (! e) {
				fnr = db_nextib(resp->table_name, &cookie,
							FN_NOMANGLE, NULL);
				cookie = fnr->cookie;
				if (ret_en_objs && !all_readable)
					nis_destroy_object(ret_en_objs);
				continue;
			}
		}

		if ((resp->key_column_ndx < 0) ||
			(resp->key_column_ndx > (e->en_cols.en_cols_len - 1)))
			nokey = 1;

		/* construct a complete entry from all columns */
		memset(record, 0, YPMAXRECORD);
		t = &(record[0]);
		status = cook_record_from_entry(e, &t, &len, p,
						resp->table_zobj);
		if (status != NIS_SUCCESS) {
			respdat.status = err_conv_nistoyp(status);
			if (!xdr_bool(xdrs, &more))
				return (FALSE);
			if (!xdr_ypresp_key_val(xdrs, &respdat))
				return (FALSE);
			break;
		}
		memset(keyval, 0, YPMAXRECORD);
		if (! nokey) {
			if (netid_wart && netid_e)
				e = netid_e;
			strncpy(keyval,
				COLVAL(resp->key_column_ndx),
				COLLEN(resp->key_column_ndx));
			if (serv_wart &&
				(strcmp(p, "services") == 0)) {
				strcat(keyval, "/");
				strcat(keyval, COLVAL(2));
			}
		}
		respdat.keydat.dptr = keyval;
		respdat.keydat.dsize = strlen(keyval);
		respdat.valdat.dptr = record;
		respdat.valdat.dsize = len;
		if (!xdr_bool(xdrs, &more))
			return (FALSE);
		if (!xdr_ypresp_key_val(xdrs, &respdat))
			return (FALSE);
		fnr = db_nextib(resp->table_name, &cookie, FN_NOMANGLE, NULL);
		cookie = fnr->cookie;
		if (ret_en_objs && !all_readable)
			nis_destroy_object(ret_en_objs);
	}

	more = FALSE;
	if (!xdr_bool(xdrs, &more))
		return (FALSE);
	return (TRUE);
}

#undef	short_tblnm

static char *
upcase(s)
	char *s;
{
	char *t;

	for (t = s; *t; t++)
		*t = toupper(*t);
	return (s);
}

/*
 * Following cook_* routines are very flimsy, and should be kept static.
 */

static void
cook_err_resp(struct ypresp_val *resp, long stat)
{
	resp->status = stat;
	resp->valdat.dptr = NULL;
	resp->valdat.dsize = 0;
}

static void
cook_err_keyresp(struct ypresp_key_val *keyresp, long stat)
{
	keyresp->status = stat;
	keyresp->keydat.dptr = NULL;
	keyresp->keydat.dsize = 0;
	keyresp->valdat.dptr = NULL;
	keyresp->valdat.dsize = 0;
}

/*
 * Takes a NIS+ entry and the column separator and returns
 * a reasonable looking YP record and its length.
 */

static nis_error
cook_record_from_entry(e, record_dat, record_len, table, tobj)
	entry_obj *e;
	char **record_dat;
	int *record_len;
	char *table;
	nis_object *tobj;
{
	int i, len;
	char *entrydat = *record_dat, *last;
	char	minibuf[80];
	table_obj *tbl = &tobj->TA_data;
	table_col *cols = tbl->ta_cols.ta_cols_val;
	int num_cols = tbl->ta_cols.ta_cols_len;

	for (i = 0, len = 0; i < num_cols; i++, len++)
		len += e->en_cols.en_cols_val[i].ENLEN;

	/* a rare occasion, to safeguard against garbage in e */
	if (++len > YPMAXRECORD)
		return (NIS_NOMEMORY);

	if (strcmp(table, "hosts") == 0)
		sprintf(entrydat, "%s %s\t#%s", COLVAL(2), COLVAL(1),
								COLVAL(3));
	else if (strcmp(table, "passwd") == 0)
		sprintf(entrydat, "%s:%s:%s:%s:%s:%s:%s", COLVAL(0),
					    COLVAL(1), COLVAL(2), COLVAL(3),
					    COLVAL(4), COLVAL(5), COLVAL(6));
	else if (strcmp(table, "group") == 0)
		sprintf(entrydat, "%s:%s:%s:%s", COLVAL(0), COLVAL(1),
				COLVAL(2), COLVAL(3));
	else if (strcmp(table, "services") == 0)
		sprintf(entrydat, "%s %s/%s #%s", COLVAL(1), COLVAL(3),
				COLVAL(2), COLVAL(4));
	else if (strcmp(table, "ethers") == 0)
		sprintf(entrydat, "%s %s #%s", COLVAL(0), COLVAL(1), COLVAL(2));
	else if (strcmp(table, "networks") == 0)
		sprintf(entrydat, "%s %s #%s", COLVAL(1), COLVAL(2), COLVAL(3));
	else if (strcmp(table, "netmasks") == 0)
		sprintf(entrydat, "%s #%s", COLVAL(1), COLVAL(2));
	else if (strcmp(table, "rpc") == 0)
		sprintf(entrydat, "%s %s #%s", COLVAL(1), COLVAL(2), COLVAL(3));
	else if (strcmp(table, "timezone") == 0)
		sprintf(entrydat, "%s %s", COLVAL(1), COLVAL(0));
	else if (strcmp(table, "protocols") == 0) {
		minibuf[79] = '\0'; /* make sure its terminated */
		strncpy(minibuf, COLVAL(1), 79);
		sprintf(entrydat, "%s %s %s #%s", minibuf, COLVAL(2),
					upcase(COLVAL(1)), COLVAL(3));
	} else if (strcmp(table, "cred") == 0) {
		if (netid_wart) {
			if (strcmp(COLVAL(1), "DES") == 0) {
				/* netid for root */
				char *col, *p, *q;

				if ((col = strdup(COLVAL(2))) == NULL)
					return (NIS_NOMEMORY);
				p = strchr(col, '.');
				if ((p != NULL) &&
					((q = strchr(++p, '@')) != NULL)) {
					*q = '\0';
					sprintf(entrydat, "0:%s", p);
				} else {
					free(col);
					return (NIS_BADOBJECT);
				}
				free(col);
			} else {
				/* netid for user */
				sprintf(entrydat, "%s:%s", COLVAL(2),
					COLVAL(3));
			}
		} else {
			char *p;
			p = strchr(COLVAL(3), ':');
			if (p)
				*p = 0;
			/* weed out the uid/gid junk. why is it there ? */
			sprintf(entrydat, "%s:%s", COLVAL(3), COLVAL(4));
		}
	} else if (strcmp(table, "mail_aliases") == 0)
		if (mail_wart_byaddr)
			sprintf(entrydat, "%s", COLVAL(0));
		else
			sprintf(entrydat, "  %s", COLVAL(1));
	else if (strncmp(table, "auto_", 5) == 0)
		sprintf(entrydat, "%s", COLVAL(1));
	else {
		/*
		 * For 2-column key/value tables we build a value
		 * with whatever is in column 1.  For other tables
		 * we combine all of the columns with the table
		 * separator.
		 */
		if (num_cols == 2 &&
		    strcasecmp(cols[0].tc_name, "key") == 0 &&
		    strcasecmp(cols[1].tc_name, "value") == 0) {
			sprintf(entrydat, "%s", COLVAL(1));
		} else {
			entrydat[0] = 0;
			for (i = 0; i < num_cols; i++) {
				if (i) {
					strncat(entrydat,
						(char *)&tbl->ta_sep, 1);
				}
				strcat(entrydat, COLVAL(i));
			}
		}
	}
	if (verbose)
		syslog(LOG_INFO,
		"cook_record_from_entry: returns %s", entrydat);
	*record_len = strlen(entrydat);

	/* XXX Just a hack to workaround 1083096 ??? */
	if (strcmp(table, "mail_aliases") == 0)
		(*record_len)++;

	return (NIS_SUCCESS);
}

#define	best_address	(__nis_get_tsd()->best_host_address_best_address)

static
char *
best_host_address(nis_object *obj, int nobj, struct svc_req *rqstp)
{
	int i;
	SVCXPRT *xp;
	struct netconfig *nc;
	ulong_t addr;
	char *beststring;
	ulong_t bestaddr;
	char *tstring;
	ulong_t taddr;

	/* determine the address of the client and store in 'addr' */
	if (rqstp == NULL)
		return (NULL);
	xp = rqstp->rq_xprt;
	nc = getnetconfigent(xp->xp_netid);
	if (nc == NULL)
		return (NULL);
	if (strcmp(nc->nc_protofmly, "inet") != 0) {
		freenetconfigent(nc);
		return (NULL);
	}
	addr = ((struct sockaddr_in *)xp->xp_rtaddr.buf)->sin_addr.s_addr;

	/* start with first object as best address */
	beststring = ENTRY_VAL(&obj[0], 2);
	bestaddr = inet_addr(beststring);

	/* loop through other objects and see if there is a better address */
	for (i = 1; i < nobj; i++) {
		tstring = ENTRY_VAL(&obj[i], 2);
		taddr = inet_addr(tstring, 2);
		if (ntohl(addr ^ taddr) < ntohl(addr ^ bestaddr)) {
			bestaddr = taddr;
			beststring = tstring;
		}
	}

	/* set global variable to best address found */
	return (strdup(beststring));
}

/*
 *  This is a qsort comparison function for host objects.
 *  The objects are sorted by address.  For hosts with the
 *  same address, the canonical object (cname == name) is
 *  sorted before the other objects with the same address.
 */
static int
host_object_compar(p1, p2)
	const void *p1;
	const void *p2;
{
	int st;
	int iscanon1;
	int iscanon2;
	entry_obj *e1 = &((nis_object *)p1)->EN_data;
	entry_obj *e2 = &((nis_object *)p2)->EN_data;

	/* if addresses differ, return comparison */
	st = strcmp(ENCOLVAL(e1, 2), ENCOLVAL(e2, 2));
	if (st != 0) {
		/*
		 *  If either address matches the best host address for
		 *  the client, sort that before all others.
		 */
		if (best_address) {
			if (strcmp(ENCOLVAL(e1, 2), best_address) == 0)
				return (-1);
			else if (strcmp(ENCOLVAL(e2, 2), best_address) == 0)
				return (1);
		}
		return (st);
	}

	/* determine if any objects are canonical (cname == name) */
	iscanon1 = strcmp(ENCOLVAL(e1, 0), ENCOLVAL(e1, 1));
	iscanon2 = strcmp(ENCOLVAL(e2, 0), ENCOLVAL(e2, 1));

	if (iscanon1 == iscanon2)
		return (0);

	if (iscanon1)
		return (-1);
	else
		return (1);
}


#define	STRCAT_CHECK(ptr, s, space) {	\
	int len;			\
					\
	len = strlen(s);		\
	if (len + 1 > space) {		\
		nis_err = NIS_NOMEMORY;	\
		goto out_of_space;	\
	} else {			\
		strcat(ptr, s);		\
		ptr += len;		\
		space -= len;		\
	}				\
}

/*
 * Takes an NIS+ entry and returns a reasonable looking YP host record
 * and its length.  We sort the host objects by host address.  For
 * hosts with the same address, the canonical host object (cname == name)
 * is placed before the other objects with the same address.  For each
 * address, we print the entries for that address.  If a comment appears in
 * an entry, then we save it and print it after all of the host names for
 * the address have been printed.
 *
 * The fields in a host object are:
 *	COLVAL(0) - official host name (canonical name)
 *	COLVAL(1) - host name (alias name)
 *	COLVAL(2) - host address
 *	COLVAL(3) - comment
 *
 * We use COLGETVAL instead COLVAL for the comment field so that if it
 * is null we don't put an obnoxious "\t#" at the end.
 */
static nis_error
cook_host_record(objs, num_objs, record_dat, record_len, rqstp)
	nis_object *objs;
	int num_objs;
	char **record_dat;
	int *record_len;
	struct svc_req *rqstp;
{
	int i;
	entry_obj *e;
	char *comment;
	char *ptr;
	char *s;
	int space;
	int did_line;
	char *current_address;
	char *completed_entry;
	char *cname;
	char *name;
	char *addr;
	nis_error nis_err = NIS_SUCCESS;    /* assume success */

	*record_len = 0;

	if (num_objs == 0) {
		return (NIS_SUCCESS);
	} else if (num_objs > 1) {
		best_address = best_host_address(objs, num_objs, rqstp);
		qsort((void *)objs, num_objs, sizeof (nis_object),
			host_object_compar);
		if (best_address) {
			free(best_address);
			best_address = NULL;
		}
	}

	ptr = *record_dat;	/* this is where we write our data */
	space = YPMAXRECORD;	/* this is how much space we have */
	comment = 0;		/* we save the comment field here */
	did_line = 0;		/* if true, we have started an entry */
	completed_entry = ptr;	/* keeps track of last full entry */
	current_address = "";

	for (i = 0; i < num_objs; i++) {
		e = &objs[i].EN_data;
		cname = COLVAL(0);
		name = COLVAL(1);
		addr = COLVAL(2);

		if (strcmp(addr, current_address) != 0) {
			/* new address, finish off previous entry */
			current_address = addr;
			if (did_line) {
				if (comment) {
					STRCAT_CHECK(ptr, "\t# ", space);
					STRCAT_CHECK(ptr, comment, space);
					comment = 0;
				}
				STRCAT_CHECK(ptr, "\n", space);
			}
			STRCAT_CHECK(ptr, addr, space);
			STRCAT_CHECK(ptr, " ", space);
			STRCAT_CHECK(ptr, cname, space);
			did_line = 1;
		}
		if (strcmp(name, cname) != 0) {
			STRCAT_CHECK(ptr, " ", space);
			STRCAT_CHECK(ptr, name, space);
		}
		if (!comment) {
			s = COLGETVAL(3);
			if (s && *s)
				comment = s;
		}

		completed_entry = ptr;
	}
	if (did_line && comment) {
		STRCAT_CHECK(ptr, "\t# ", space);
		STRCAT_CHECK(ptr, comment, space);
	}
	completed_entry = ptr;

out_of_space:

	*completed_entry = 0;    /* in case failed on partial entry */
	*record_len = completed_entry - *record_dat;

	if (verbose) {
		syslog(LOG_INFO,
			"cook_host_record: returning \"%s\"", *record_dat);
	}

	return (nis_err);
}

/*
 * Given an entry in the netgroup table, constructs a string
 * consisting of either a member netgroup name, or a leaf
 * netgroup like "(host,name,domain)".
 */
static void
cook_an_ngroup(e, val, vallen)
	entry_obj *e;
	char **val;
	int *vallen;
{
	if (strcmp(COLVAL(1), "") == 0) {
		*vallen = COLLEN(2) + COLLEN(3) + COLLEN(4) + 5;
		if (*vallen > YPMAXRECORD) {
			sprintf(*val, "");
			*vallen = 1;
		} else
			sprintf(*val, "(%s,%s,%s)",
				COLVAL(2), COLVAL(3), COLVAL(4));
	} else {
		*vallen = COLLEN(1) + 1;
		if (*vallen > YPMAXRECORD) {
			sprintf(*val, "");
			*vallen = 1;
		} else
			sprintf(*val, COLVAL(1));
	}
}

/*
 * Goes through column names in table object and returns the
 * index for the one that matches with the col_val passed.
 * indexing is 0 thro n and returns -1 on failure.
 */
static int
get_keyndx(table_obj *t_obj, char *col_val)
{
	int i;

	for (i = 0; i < t_obj->ta_cols.ta_cols_len; i++)
		if (strcmp(col_val,
			(t_obj->ta_cols.ta_cols_val + i)->tc_name) == 0)
			return (i);
	return (-1);
}

static char *
getcaller_inet(rqstp)
	struct svc_req *rqstp;
{
#define	buf	(__nis_get_tsd()->getcaller_inet_buf)
	SVCXPRT			*xp;
	char			*uaddr;
	struct netconfig	*nc;

	if (rqstp == NULL)
		return ("");
	xp = rqstp->rq_xprt;
	nc = (struct netconfig *)getnetconfigent(xp->xp_netid);

	if (nc)
		uaddr = taddr2uaddr(nc, &(xp->xp_rtaddr));
	else
		uaddr = "<no netconfig ent>";

	sprintf(buf, "[tp=%s, netid=%d, uaddr=%s]",
		xp->xp_tp, xp->xp_netid, uaddr);

	if (nc) {
		freenetconfigent(nc);
		XFREE(uaddr);
	}
	return (buf);
}

#undef	buf

/*
 * Hacks here onwards may go into a library, potentially
 * to be inflicted on the users.
 */

long
err_conv_nistoyp(inerr)
	nis_error inerr;
{
	switch (inerr) {
		case NIS_SUCCESS:
		case NIS_S_SUCCESS: return (YP_TRUE);
		case NIS_NOTFOUND:
		case NIS_S_NOTFOUND: return (YP_FALSE);
		case NIS_NAMEUNREACHABLE:
		case NIS_NOTSEARCHABLE:
		case NIS_UNKNOWNOBJ: return (YP_NODOM);
		case NIS_NOSUCHTABLE: return (YP_NOMAP);
		case NIS_BADOBJECT:
		case NIS_NOMEMORY: return (YP_YPERR);
		default: return (YP_YPERR);
	}
}

/*
 * Takes the name of a domain/directory, fully qualifies it
 * the most naive way and finds out if the corresponding
 * NIS+ directory is served by this server.
 */

int
ypcheck_nisdir(dname)
	char	*dname;
{
	char name[YPMAXDOMAIN + 2];
	struct ticks    ticks;
	nis_object *z_obj = NULL;
	nis_error status;
	int len = strlen(dname);

	(void) strncpy(name, dname, len);
	if (name[len - 1] != '.')
		name[len++] = '.';
	name[len] = '\0';
	status = __directory_object(name, &ticks, FALSE, &z_obj);
	/*
	 * MEMORY POLICY: __directory_object maintains a cache and
	 * returns a pointer to an entry into it. We do not free
	 * anything here.
	 */
	return (status == NIS_SUCCESS);
}

/*
 * A little different from ypcheck_nisdir. This one attempts to
 * get the nis_object for the "ORGDIR.<domainname>[.]" directory.
 */
nis_error
getzobj_orgdir(dname, z_obj)
	char *dname;
	nis_object **z_obj;
{
	char    name[YPMAXDOMAIN + ORGLEN];
	struct	ticks ticks;
	nis_error status;
	int	len;

	(void) strcpy(name, ORGDIR2);
	(void) strncat(name, dname, strlen(dname));
	len = strlen(name);
	if (name[len - 1] != '.')
		name[len++] = '.';
	name[len] = '\0';
	/* don't bother who's master */
	status = __directory_object(name, &ticks, FALSE, z_obj);
	/*
	 * MEMORY POLICY: __directory_object maintains a cache and
	 * returns a pointer to an entry into it. We do not free
	 * anything here.
	 */
	return (status);
}


/*
 * Supply an NIS style mapname and get back pointers to the
 * names of corresponding table in NIS+ and the column to
 * search. Does not make any guarantees that the table
 * and/or column indeed exist in the NIS+ namespace.
 */
void
map2table(xx_mapname, xx_table, xx_column)
	char *xx_mapname;
	char **xx_table;
	char **xx_column;
{
#define	tbl	(__nis_get_tsd()->map2table_tbl)
#define	col	(__nis_get_tsd()->map2table_col)
	char *p, *t = tbl, *c = col;

	memset(t, 0, YPMAXMAP);
	memset(c, 0, NIS_MAXATTRNAME);
	*xx_table = t;
	*xx_column = c;

	serv_wart = 0;
	netid_wart = 0;
	mult_lines_wart = 0;

	if (verbose)
		syslog(LOG_INFO, "map2table: maps from %s", xx_mapname);
	if (strcmp(xx_mapname, "services.byname") == 0) {
		/*
		 * This is a special and weird case.
		 * We have to be compatible with past mistakes
		 * when some ??????? built the services.byname map
		 * with a key of the form "port/proto".
		 */
		strcpy(t, "services");
		strcpy(c, "port");
		serv_wart = 1;
		if (verbose)
			syslog(LOG_INFO, "map2table: maps to %s and %s", t, c);
		return;
	}
	if (strcmp(xx_mapname, "services.byservicename") == 0) {
		/*
		 * This is even more special and weird case.
		 * We are trying to be nice to the YP clients by
		 * giving a map they can match on using the key
		 * service/proto. It turns out, they can do
		 * the match only on "service" or "port" as
		 * the key too.
		 */
		strcpy(t, "services");
		strcpy(c, "name");
		serv_wart = 1;
		if (verbose)
			syslog(LOG_INFO, "map2table: maps to %s and %s", t, c);
		return;
	}

	if (strcmp(xx_mapname, "publickey.byname") == 0) {
		strcpy(t, "cred");
		strcpy(c, "auth_name");
		if (verbose)
			syslog(LOG_INFO, "map2table: maps to %s and %s", t, c);
		return;
	}

	if (strcmp(xx_mapname, "netid.byname") == 0) {
		strcpy(t, "cred");
		strcpy(c, "auth_name");
		netid_wart = 1;
		if (verbose)
			syslog(LOG_INFO, "map2table: maps to %s and %s", t, c);
		return;
	}

	if (strncmp(xx_mapname, "mail.", 5) == 0) {
		strcpy(t, "mail_aliases");
		if (strcmp(xx_mapname, "mail.byaddr") == 0) {
			mail_wart_byaddr = 1;
			strcpy(c, MAILADDR);
		} else /* if (strcmp(xx_mapname, "mail.aliases) == 0) */ {
			mail_wart_byaddr = 0;
			strcpy(c, MAILNAME);
		}
		if (verbose)
			syslog(LOG_INFO, "map2table: maps to %s and %s", t, c);
		return;
	}

	if ((p = strrchr(xx_mapname, '.')) != NULL) {
		/*
		 * First check for maps of type X.byY and then replace
		 * all dots by _
		 */
		char *tmp;

		tmp = p;
		if (strncmp(++p, BY, 2) == 0) {
			p += 2;
			if (*p == NULL) {
				/* BY was really a name */
				*tmp = '_';	/* replace _ back */
				p = NULL;
			} else {
				*tmp = '\0';
			}
		} else {
			p = NULL;
		}
		/* replace the other dots by _ */
		while ((tmp = strchr(xx_mapname, '.')) != NULL)
			*tmp = '_';
	}
	strcpy(t, xx_mapname);

	/* only the gethostbyYY client backends can handle multiple lines */
	if (strcmp(t, "hosts") == 0)
		mult_lines_wart = 1;

	if (p)
		strcpy(c, p);
	else if (strcmp(xx_mapname, "netgroup") == 0)
			strcpy(c, NGROUPNAME);
	else
		/*
		 * POLICY: The default column for all maps that want to
		 * use the backward compatibility and are not among the
		 * privileged 12 must be DEFAULTKEY. The 12 are: passwd,
		 * group, hosts, networks, services, rpc, mail_aliases,
		 * ethers, protocols, netmasks, publickey and bootparams.
		 */
		strcpy(c, DEFAULTKEY);

	if (verbose)
		syslog(LOG_INFO, "map2table: maps to %s and %s", t, c);
}

#undef	tbl
#undef	col
