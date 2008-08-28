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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



/*
 * Ported from
 * "@(#)nis_ib_proc.c 1.37 91/03/21 Copyr 1990 Sun Micro";
 *
 *	nis_ib_proc.c
 *
 * This module contains information base function of NIS Version 3
 * NB : It provides the routines that the dispatch function in nis_svc.c
 * call. That file, nis_svc.c, is automatically generated and reflects the
 * interface definition that is described in the nis.x file. When the
 * nis.x file changes, you must make sure that any parameters that change
 * get reflected in these routines.
 *
 */

#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <rpc/rpc.h>
#include <rpc/clnt.h>
#include <rpc/svc.h>
#include <rpc/auth.h>
#include <rpc/auth_des.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nis_callback.h>
#include "nis_proc.h"
#include "nisdb_mt.h"

#include <string.h>
#include <netdir.h>
#include <netconfig.h>
#include <shadow.h>

extern bool_t 	xdr_nis_result();
extern bool_t 	xdr_nis_error();
extern bool_t 	xdr_nis_object();
extern void	(*_svc_getreqset_proc)();

#define	NO_ENTRY_OBJS	96

/*
 * nis_censor_object[_attr]
 *
 * This function enforces the access rights policies for objects.
 * It is called with a candidate ENTRY object and a principal name.
 * The result is either NULL (object not readable) or a pointer to
 * an object that has been "censored" by this code to remove sensitive
 * columns or encrypt encrypted columns.
 * nis_censor_object_attr adds a fix which ensures that
 * users cannot infer information from the database by using special
 * search criteria.
 */
nis_object *
nis_censor_object_attr(o, tc, p, zn, za)
	nis_object	*o;	/* The object to censor 	*/
	table_col	*tc;	/* Table column descriptor 	*/
	nis_name	p;	/* The principal in question 	*/
	uint_t		zn;	/* Number of attributes 	*/
	nis_attr	*za;	/* The search attributes 	*/
{
	nis_object		zo;	/* our censored object */
	int			mc;	/* Number of columns */
	int			i, j,
				somedata;
#define	buf			__nis_get_tsd()->censor_object_buf
	entry_col		*oec,	/* The old columns pointer */
				*ec;	/* Some temporary buffer */


	/* copy the object */
	zo = *o;

	mc = o->EN_data.en_cols.en_cols_len;
	/* get some temporay space. */
	ec = (entry_col *)nis_get_static_storage(&buf, sizeof (entry_col), mc);
	if (! ec)
		return (NULL);

	/* Use our static version of the columns */
	zo.EN_data.en_cols.en_cols_val = ec;

	/* Get a pointer to the original columns */
	oec = o->EN_data.en_cols.en_cols_val;
	somedata = 0;
	for (j = 0; j < mc; j++) {
		ec[j] = oec[j]; /* copy the pointers */
		ec[j].ec_flags = 0;
		/* Transfer the flags values */
		if (tc[j].tc_flags & TA_BINARY)
			ec[j].ec_flags |= EN_BINARY;
		if (tc[j].tc_flags & TA_XDR)
			ec[j].ec_flags |= EN_XDR;
#ifdef NIS_CRYPT_SUPPORT
		if (tc[j].tc_flags & TA_CRYPT)
			ec[j].ec_flags |= EN_CRYPT;
#endif

		/* Check to see if we can read this column */
		if (! __can_do(NIS_READ_ACC, tc[j].tc_rights, o, p)) {
		    /* close inference holes */
		    for (i = 0; i < zn; i++)
			if (za[i].zattr_ndx &&
			    (strcasecmp(tc[j].tc_name, za[i].zattr_ndx) == 0))
			    return (NULL);
		    /* Replace with No Permission value */
		    ec[j].ENLEN = 5;
		    ec[j].ENVAL = NOPWDRTR;
		} else {
			somedata++;
#ifdef NIS_CRYPT_SUPPORT
			if (ec[j].ec_flags & EN_CRYPT) {
				/* Encrypt the data using the session key */
				/* XXX */
			}
#endif
		}
	}
	if (somedata == NULL)
		return (NULL);

	return (nis_clone_object(&zo, 0));
}

#undef	buf

/*
 * The original function (nis_censor_object) takes
 * the old arguments, and passes them on with new placeholder arguments to
 * the new function (nis_censor_object_attr).  Only YP compat functions
 * still call nis_censor_object.
 */
nis_object
*nis_censor_object(o, tc, p)
	nis_object	*o;	/* The object to censor 	*/
	table_col	*tc;	/* Table column descriptor 	*/
	nis_name	p;	/* The principal in question 	*/
{
	return (nis_censor_object_attr(o, tc, p, 0, NULL));
}

/*
 * This is the free function for the list results that are returned "enmasse"
 * without a callback.
 */
static void
free_rlist(entries)
	nis_object *entries;
{
	XFREE(entries);
}

/*
 * nis_return_list()
 *
 * This function converts a full list of entries returned by the database
 * into a list that can be returned to the user. It has two main functions,
 * 	#1) Remove those entries from the list which the client does not
 *	    have read access too.
 *	#2) If the client has read access to the entry, censor those
 *	    columns which the client does not have read access to.
 */

nis_object *
nis_return_list(obj, list, num, p, got, ar, zn, za)
	nis_object	*obj; 	/* Information base object */
	obj_list	*list;	/* Array of objects	   */
	int		num;	/* Size of the array	   */
	nis_name	p;	/* principal making reqst  */
	int		*got;	/* Number actually returned */
	int		ar;	/* All readable flag	    */
	uint_t		zn;	/* All readable flag	*/
	nis_attr	*za;	/* The search attributes    */
{
	register table_col	*tc;		/* Table column pointer    */
	nis_object		*eo;		/* Temporary object	   */
	nis_object		*entries;	/* our result pointer	   */
	int			i, 		/* Temporary counters	   */
				cur_entry;	/* The current entry	   */

	*got = 0;
	/* Get some parameters from the table object */
	if (__type_of(obj) == NIS_TABLE_OBJ)
		tc = obj->TA_data.ta_cols.ta_cols_val;
	else
		tc = tbl_prototype.ta_cols.ta_cols_val;

	/* This may allocate more than we need but it is faster this way */
	entries = (nis_object *)XCALLOC(num+1, sizeof (nis_object));
	if (! entries)
		return (NULL);

	add_cleanup(free_rlist, (char *)entries, "nis_return_list array.");

	if (entries == NULL)
		return (NULL);

	for (i = 0, cur_entry = 0; i < num; i++) {
		if (! list[i].o)
			continue;
		if (ar ||
		__can_do(NIS_READ_ACC, list[i].o->zo_access, list[i].o, p)) {
			entries[cur_entry] = *list[i].o;
			cur_entry++;
		} else {
			eo = nis_censor_object_attr(list[i].o, tc, p, zn, za);
			if (eo) {
				*(entries+cur_entry) = *eo;
				add_cleanup(nis_destroy_object, eo,
					"nis_censor_object_attr result");
				cur_entry++;
			}
		}
	}

	*got = cur_entry;
	return (entries);
}

/*
 * __search_ok()
 *
 * This function does a sanity check on the request (which has attribute
 * value pairs) and the table which defines the names of searchable columns.
 * if an attribute is passed that doesn't match up to a column the request
 * is rejected.
 */
static int
__search_ok(zn, za, tobj)
	uint_t		zn;	/* Number of attributes 	*/
	nis_attr	*za;	/* The search attributes 	*/
	nis_object	*tobj;	/* A Table object		*/
{
	register table_col	*tc;
	short			acm[256]; /* XXX HARD LIMIT on columns XXX */
	int			i, j, mc;

	if (__type_of(tobj) == NIS_TABLE_OBJ) {
		mc = tobj->TA_data.ta_maxcol;
		tc = tobj->TA_data.ta_cols.ta_cols_val;
	} else {
		/* Can't specify anything for directories */
		return (zn == 0);
	}
	for (i = 0; i < zn; i++) {
		acm[i] = -1; /* Entry column map */
		for (j = 0; j < mc; j++) {
			if ((tc[j].tc_flags & TA_SEARCHABLE) &&
			    (strcasecmp(tc[j].tc_name, za[i].zattr_ndx)
								    == 0)) {
				if (acm[i] == -1)
					acm[i] = j;
				else
					acm[i] = -2;
				break;
			}
		}

		/*
		 *  If we didn't find a searchable column with the name,
		 *  check to see if it is a multival column.  If it is,
		 *  then continue on to the other attributes.  We don't
		 *  update acm because multival columns can be specified
		 *  multiple times.
		 */
		if (acm[i] == -1) {
			if (multival_check(tobj, &za[i], tc, mc))
				continue;
		}

		/* Didn't match or matched twice */
		if (acm[i] < 0) {
			return (0);
		}

	}
	return (1);
}

/*
 * __nis_listinit()
 *
 * This function set's up either a list or first/next operation.
 * If it is successful, it returns a pointer to the object to be
 * listed (either a table or directory object), if it is unsuccessful
 * it returns NULL and fills in the result structure appropriately.
 */
static nis_object *
__nis_listinit(res, argp, princp)
	nis_result	*res;
	ib_request	*argp;
	nis_name	princp;
{
	nis_object	*d_obj, *ib_obj = NULL;
	struct ticks	t;
	nis_db_result	*dbres;
	nis_error	xx;
	enum name_pos	p;

	NIS_RES_NUMOBJ(res) = 0;
	p = nis_dir_cmp(argp->ibr_name, __nis_rpc_domain());
	if ((p != SAME_NAME) && (p != LOWER_NAME)) {
		res->status = NIS_BADNAME;
		return (NULL);
	}

	/* Make sure we serve this directory. */
	xx = __directory_object(nis_domain_of(argp->ibr_name), &t, 0, &d_obj);
	res->aticks = t.aticks;
	res->dticks = t.dticks;
	res->cticks = t.cticks;
	res->zticks = t.zticks;

	if ((xx != NIS_SUCCESS) && (xx != NIS_S_SUCCESS)) {
		/*
		 * Hmm, we didn't find it. Maybe it _is_ our directory
		 * object.
		 */
		xx = __directory_object(argp->ibr_name, &t, 0, &d_obj);
		res->aticks += t.aticks;
		res->dticks += t.dticks;
		res->cticks += t.cticks;
		res->zticks += t.zticks;
		if ((xx != NIS_SUCCESS) && (xx != NIS_S_SUCCESS)) {
			/* They really blew it */
			syslog(LOG_INFO, "Can't find directory for %s",
						argp->ibr_name);
			res->status = xx;
			return (NULL);
		} else {
			ib_obj = d_obj;
		}
	}

	/* Now get the information base object from the database */
	if (! ib_obj) {
		dbres = db_lookup(argp->ibr_name);
		res->dticks += dbres->ticks;
		if (dbres->status == NIS_NOSUCHTABLE) {
			/* This means table of directory does not exist. */
			dbres->status =	recover_from_no_table(d_obj,
						nis_domain_of(argp->ibr_name));
			/* for sure, argp->ibr_name will not be there */
			if (dbres->status == NIS_SUCCESS)
				dbres->status = NIS_NOTFOUND;
		}
		if (dbres->status != NIS_SUCCESS) {
			if (dbres->status == NIS_NOTFOUND)
				res->status = NIS_NOSUCHTABLE;
			else
				res->status = dbres->status;
			res->zticks += __stop_clock(0);
			return (NULL);
		}
		ib_obj = dbres->obj;
	} else {
		/*
		 * If its a directory, make sure we've got a database
		 * for it. (if not create one and synchronize)
		 */
		nis_error status = db_find_table(argp->ibr_name);
		switch (status) {
		case NIS_SUCCESS:
			break;
		case NIS_NOSUCHTABLE:
			res->status = recover_from_no_table(d_obj,
							    argp->ibr_name);
			if (res->status != NIS_SUCCESS) {
				return (NULL);
			}
			break;
		default:
			res->status = status;
			return (NULL);
		}
	}

	switch (__type_of(ib_obj)) {
	    case NIS_TABLE_OBJ:
	    case NIS_DIRECTORY_OBJ:
		break;

	    case NIS_LINK_OBJ:
		if (verbose)
			syslog(LOG_INFO, "__nis_listinit: Object is a link.");
		/*
		 * we return a partial result indicating that the LINK was
		 * found and the client can follow it if they choose to.
		 */
		res->status = NIS_PARTIAL;
		NIS_RES_NUMOBJ(res) = 1;
		NIS_RES_OBJECT(res) = ib_obj;
		return (NULL);

	    default:
		/*
		 * XXX this hard codes the "kinds" of objects that can be
		 * information bases. This is not nice if we want to support
		 * user designed objects.
		 */
		res->status = NIS_INVALIDOBJ;
		if (verbose)
			syslog(LOG_INFO,
			    "__nis_listinit: Nonsearchable object (type = %d).",
							__type_of(ib_obj));
		return (NULL);
	}

	/* Check to see is we have a valid search criteria */
	if (!__search_ok(argp->ibr_srch.ibr_srch_len,
			argp->ibr_srch.ibr_srch_val, ib_obj)) {
		res->status = NIS_BADATTRIBUTE;
		if (verbose)
			syslog(LOG_INFO,
			    "__nis_listinit: Unparsable attribute failure.");
		return (NULL);
	}

	res->status = NIS_SUCCESS;
	return (ib_obj);
}

/*
 * Does the callback part of iblist
 */
static nis_result *
nis_iblist_callback(argp, pname, ib_obj, all_read, res)
	ib_request	*argp;
	char		*pname;		/* caller's name */
	nis_object	*ib_obj;
	int		all_read;	/* all readable flag		*/
	nis_result	*res;
{
	nis_error	err;
	nis_object	*d_obj;
	int		pid = -1; /* Process ID of child making call back */
	int		i, queued;
	CLIENT		*cback = NULL;	/* Callback client handle 	*/
	cback_data	cbarg;		/* Callback arguments		*/
				/* An array of object pointers	*/
	struct timeval	tv;		/* Timeout for callback		*/
	nis_fn_result	*fnr;
	netobj		cookie;		/* Cookie storage for first/nxt	*/
	enum clnt_stat	status = RPC_SUCCESS;
	nis_error	result;
	table_col	*tc;
	ulong_t		flags;
	char		tblbuf[NIS_MAXNAMELEN * 2];
	char		*table;
	nis_attr	*a;
	int		na;	/* number of regular attributes */
	int		nm;	/* number of multival attributes */


	/*
	 * Used to create the callback handle here. We now delay
	 * until we know that we actually intend to perform the callback.
	 */

	table = internal_table_name(argp->ibr_name, tblbuf);
	if (! table) {
		res->status = NIS_BADNAME;
		return (res);
	}

	na = argp->ibr_srch.ibr_srch_len;
	a = argp->ibr_srch.ibr_srch_val;
	err = multival_attr(ib_obj, a, &na, &nm);
	if (err != NIS_SUCCESS) {
		res->status = err;
		return (res);
	}

	/*
	 * This will force the database to be loaded.
	 */
	fnr = db_firstib(argp->ibr_name, na, a, FN_MANGLE+FN_NORAGS, table);

	if (fnr->status != NIS_SUCCESS) {
		if (fnr->status == NIS_NOTFOUND) {
			res->status = NIS_PARTIAL;
			res->objects.objects_val = ib_obj;
			res->objects.objects_len = 1;
		} else {
			res->status = fnr->status;
			res->objects.objects_val = NULL;
			res->objects.objects_len = 0;
		}
		res->dticks += fnr->ticks;
		res->zticks += __stop_clock(0);
		XFREE(fnr);
		fnr = NULL;
		return (res);
	}

	if (verbose)
		syslog(LOG_INFO, "Making callback handle to : %s",
			argp->ibr_cbhost.ibr_cbhost_val[0].name);
	if ((strcmp(pname, "nobody") == 0) || (secure_level < 2))
		flags = ZMH_VC;
	else
		flags = ZMH_VC+ZMH_AUTH;

	cback = nis_make_rpchandle(argp->ibr_cbhost.ibr_cbhost_val, 1,
				CB_PROG, 1, flags, 16384, 16384);
	/* If we couldn't create a client handle we're hosed */
	if (! cback) {
		syslog(LOG_WARNING, "Unable to create callback.");
		res->status = NIS_NOCALLBACK;
		res->zticks = __stop_clock(0);
		XFREE(fnr);
		fnr = NULL;
		return (res);
	}

	/* Create a new thread to perform the callback */
	{
		pthread_t		tid;
		pthread_attr_t		attr;
		int			stat;
		callback_thread_arg_t	*cbtarg;
		int			attrsize = na * sizeof (cbtarg->a[0]);

		if ((cbtarg = calloc(1, sizeof (*cbtarg))) == 0) {
			syslog(LOG_WARNING,
		"nis_iblist_callback: memory allocation failed for %d bytes",
				sizeof (*cbtarg));
			auth_destroy(cback->cl_auth);
			clnt_destroy(cback);
			res->status = NIS_NOMEMORY;
			res->zticks = __stop_clock(0);
			XFREE(fnr);
			return (res);
		}
		cbtarg->fnr = fnr;
		cbtarg->ib_obj = nis_clone_object(ib_obj, 0);
		if (na <= (sizeof (cbtarg->a)/sizeof (cbtarg->a[0]))) {
			cbtarg->na = na;
		} else {
			syslog(LOG_WARNING,
	"nis_iblist_callback: too many attributes; max %d expected, %d found",
			(sizeof (cbtarg->a)/sizeof (cbtarg->a[0])), na);
			cbtarg->na = sizeof (cbtarg->a)/sizeof (cbtarg->a[0]);
#ifdef	NIS_MT_DEBUG
			abort();
#endif	/* NIS_MT_DEBUG */
		}
		memcpy(cbtarg->a, a, cbtarg->na * sizeof (cbtarg->a[0]));
		cbtarg->nm = nm;
		cbtarg->all_read = all_read;
		strncpy(cbtarg->pname, pname, sizeof (cbtarg->pname));
		cbtarg->pname[sizeof (cbtarg->pname) - 1] = '\0';
		cbtarg->cbarg = cbarg;
		cbtarg->cback = cback;
		strncpy(cbtarg->cbhostname,
			argp->ibr_cbhost.ibr_cbhost_val[0].name,
			sizeof (cbtarg->cbhostname));
		cbtarg->cbhostname[sizeof (cbtarg->cbhostname) - 1] = '\0';
		strncpy(cbtarg->ibr_name,
			argp->ibr_name, sizeof (cbtarg->ibr_name));
		cbtarg->ibr_name[sizeof (cbtarg->ibr_name) - 1] = '\0';

		(void) pthread_attr_init(&attr);
		(void) pthread_attr_setdetachstate(&attr,
						PTHREAD_CREATE_DETACHED);
		if ((stat = pthread_create(&tid, &attr, callback_thread,
			cbtarg)) == 0) {
			if (verbose)
				syslog(LOG_INFO,
		"nis_iblist_callback: created callback thread %d", tid);
			res->status = NIS_CBRESULTS;
		} else {
			if (verbose)
				syslog(LOG_WARNING,
		"nis_iblist_callback: callback thread create failed: %d",
					stat);
			res->status = NIS_TRYAGAIN;
		}
		res->zticks += __stop_clock(0);

		(void) pthread_attr_destroy(&attr);

		res->cookie.n_bytes = (char *)malloc(sizeof (anonid_t));
		if (res->cookie.n_bytes == NULL) {
			syslog(LOG_WARNING,
			"Couldn't allocate memory for callback id");
			/* what error to return in case of no memory */
			res->status = NIS_NOMEMORY;
		} else {
			anonid_t	anonid = tid;
			add_cleanup((void (*)())XFREE,
				(char *)res->cookie.n_bytes, "callback id");
			res->cookie.n_len = sizeof (anonid);
			memcpy(res->cookie.n_bytes, &anonid,
							sizeof (anonid));
			if (verbose)
				syslog(LOG_INFO,
			"returning, callback id = %d",
					*((anonid_t *)res->cookie.n_bytes));
		}
		return (res);
	}
}


/*
 * __nis_alt_callback_server()
 *
 * Return a pointer to a new chunk of memory containing a copy of the
 * org_endpoint argument, with the rpc_origin address substituted (merged,
 * since the port number is retained) for the first endpoint whose family
 * matches an NC_TPI_COTS netconfig entry.
 *
 * If (*uaddr != 0), it is assumed to point to a piece of memory of length
 * uaddrlen, where the caller wants a copy of the uaddr.
 *
 * It is the responsibility of the caller to free() the returned endpoint
 * structure, as well as the uaddr if (*uaddr == 0).
 */
endpoint *
__nis_alt_callback_server(endpoint	*org_endpoint,
			uint_t		count,
			struct netbuf	*rpc_origin,
			char		**uaddr,
			int		uaddrlen)
{
	endpoint		*alt_endpoint;
	uint_t			size, i, j, ei;
	struct netconfig	*nc, *match = 0;
	struct netbuf		*taddr;
	void			*newaddr;
	void			*rpcaddr;
	int			addrlen;
	sa_family_t		af, rpcaf;
	char			*tmpuaddr;

	/* Sanity check arguments */
	if (org_endpoint == 0 || count == 0 || rpc_origin == 0) {
		return (0);
	}

	/* We only know how to deal with IP */
	rpcaf = ((struct sockaddr *)rpc_origin->buf)->sa_family;
	if (rpcaf != AF_INET && rpcaf != AF_INET6) {
		return (0);
	}

	/* Retrieve a netconfig entry for "inet" that matches an endpoint */
	for (i = 0; i < count; i++) {
		if ((nc = __nis_get_netconfig(&org_endpoint[i])) != 0 &&
			nc->nc_semantics == NC_TPI_COTS_ORD) {
			if (strcasecmp(nc->nc_protofmly, NC_INET) == 0 &&
				rpcaf == AF_INET) {
				af = AF_INET;
			} else if (strcasecmp(
					nc->nc_protofmly, NC_INET6) == 0 &&
					rpcaf == AF_INET6) {
				af = AF_INET6;
			} else {
				continue;
			}
			match = nc;
			ei = i;
			break;
		}
	}

	/* Did we find one ? */
	if (match == 0) {
		return (0);
	}

	/*
	 * Allocate memory for the alternate endpoint array.
	 * Must be freed by caller, if we return successfully.
	 */
	size = count * sizeof (endpoint);
	if ((alt_endpoint = malloc(size)) == 0) {
		return (0);
	}

	for (j = 0; j < count; j++) {
		alt_endpoint[j] = org_endpoint[j];
	}

	/* Get the address suggested by the remote caller */
	if ((taddr = uaddr2taddr(match, alt_endpoint[ei].uaddr)) == 0) {
		free(alt_endpoint);
		return (0);
	}

	/*
	 * The ugly part: merge port number and RPC source address.
	 * This requires knowledge about the internals of a netbuf.
	 */

	if (af == AF_INET) {
		struct in_addr dummy;
		newaddr =
			&((struct sockaddr_in *)taddr->buf)->sin_addr.s_addr;
		rpcaddr =
		&((struct sockaddr_in *)rpc_origin->buf)->sin_addr.s_addr;
		addrlen = sizeof (dummy.s_addr);
	} else {
		struct in6_addr dummy;
		newaddr =
			&((struct sockaddr_in6 *)taddr->buf)->sin6_addr.s6_addr;
		rpcaddr =
		&((struct sockaddr_in6 *)rpc_origin->buf)->sin6_addr.s6_addr;
		addrlen = sizeof (dummy.s6_addr);
	}

	/*
	 * If addresses are the same, there is no need to try an alternate
	 * address, so just pretend that we failed.
	 */
	if (!memcmp(newaddr, rpcaddr, addrlen)) {
		free(alt_endpoint);
		netdir_free(taddr, ND_ADDR);
		return (0);
	}

	/* Alternate address differs; worth trying */
	memcpy(newaddr, rpcaddr, addrlen);
	if ((tmpuaddr = taddr2uaddr(match, taddr)) == 0) {
		free(alt_endpoint);
		netdir_free(taddr, ND_ADDR);
		return (0);
	}

	if (*uaddr == 0) {
		*uaddr = tmpuaddr;
	} else if (strlen(tmpuaddr) < uaddrlen) {
		(void) strcpy(*uaddr, tmpuaddr);
		free(tmpuaddr);
	} else {
		free(alt_endpoint);
		netdir_free(taddr, ND_ADDR);
		free(tmpuaddr);
		return (0);
	}

	/* Clean up */
	netdir_free(taddr, ND_ADDR);

	alt_endpoint[ei].uaddr = *uaddr;

	return (alt_endpoint);
}

/*
 * nis_iblist, this function will take the search criteria passed,
 * and pass it on to the database. If the callback structure is
 * null then the results are simply returned, otherwise the server
 * forks and and begins returning results one by one. In a multithreaded
 * environment this is handled by a thread. The library will check
 * a resource limit variable before forking.
 */
nis_result *
nis_iblist_svc(argp, reqstp)
	ib_request *argp;
	struct svc_req *reqstp;
{
	nis_result	*res = NULL;
	nis_object	*ib_obj,
			*list;
	int		got;
	char		*s;
	int		all_read;	/* all readable flag		*/
	char		pname[1024];
	nis_db_list_result	*ib_list;
	int		zn;
	nis_attr	*za;

	__start_clock(0);
	if (verbose)
		syslog(LOG_INFO, "LIST_SVC: Listing table %s",
							argp->ibr_name);

	res = (nis_result *)XCALLOC(1, sizeof (nis_result));
	add_cleanup((void (*)())XFREE, (char *)res, "iblist result");

	/* If reqstp == NULL then we're recursing */
	if (reqstp)
		nis_getprincipal(pname, reqstp);
	else
		pname[0] = '\0';

	ib_obj = __nis_listinit(res, argp, pname);

	if (res->status != NIS_SUCCESS) {
		res->zticks = __stop_clock(0);
		return (res);
	}
	/* If we have read access on the table, we can read all of it */
	all_read = __can_do(NIS_READ_ACC, ib_obj->zo_access, ib_obj, pname);

	/*
	 * Now we actually do the list operation. If there is a callback,
	 * then we use the first/next operations to send the objects back
	 * one at a time.
	 */
	if (argp->ibr_cbhost.ibr_cbhost_len) {
		/* Process the callback request. */
		/*
		 * The client supplied an address for the callback service.
		 * However, we may not be able to reach that address, so
		 * try the source address of the RPC request first.
		 *
		 * Note: The alt_endpoint array (which usually contains just
		 * a single element) is a copy of of org_endpoint, including
		 * pointers, except for the uaddr of one element. This uaddr
		 * contains a merged version of the RPC source address and the
		 * port number specified by the client in the callback data.
		 */
		{
			struct netbuf	*rpc_origin;
			endpoint	*org_endpoint, *alt_endpoint;
			char		*uaddr = 0;

			org_endpoint =
			    argp->ibr_cbhost.ibr_cbhost_val->ep.ep_val;
			rpc_origin = svc_getrpccaller(reqstp->rq_xprt);
			if ((alt_endpoint = __nis_alt_callback_server(
				org_endpoint,
				argp->ibr_cbhost.ibr_cbhost_val->ep.ep_len,
				rpc_origin,
				&uaddr, 0)) != 0) {
				argp->ibr_cbhost.ibr_cbhost_val->ep.ep_val =
				    alt_endpoint;
				res = nis_iblist_callback(argp, pname, ib_obj,
							all_read, res);
				argp->ibr_cbhost.ibr_cbhost_val->ep.ep_val =
				    org_endpoint;
				free(alt_endpoint);
				free(uaddr);
				if (res->status != NIS_NOCALLBACK) {
					return (res);
				}
			}
		}
		return (nis_iblist_callback(argp, pname, ib_obj,
					    all_read, res));
	}
	/*
	 * If the client didn't ask for a callback, we process the
	 * entire list at once and return it. (implicit else clause)
	 */
	ib_list = db_list(argp->ibr_name, argp->ibr_srch.ibr_srch_len,
				argp->ibr_srch.ibr_srch_val);

	res->dticks += ib_list->ticks;
	if (ib_list->status != NIS_SUCCESS) {
		if (ib_list->status == NIS_NOTFOUND) {
			res->status = NIS_PARTIAL;
			NIS_RES_OBJECT(res) = ib_obj;
			NIS_RES_NUMOBJ(res) = 1;
		} else {
			if (__type_of(ib_obj) == NIS_TABLE_OBJ) {
				s = "table";
			} else
				s = "directory";
			syslog(LOG_ERR, "Unable to list %s '%s' err=%d",
				    s, argp->ibr_name, ib_list->status);
			res->status = ib_list->status;
			NIS_RES_OBJECT(res) = NULL;
			NIS_RES_NUMOBJ(res) = 0;
		}
		res->zticks = __stop_clock(0);
		if (verbose)
			syslog(LOG_INFO, "nis_iblist_svc: return status %s",
						    nis_sperrno(res->status));
		return (res);
	}
	/* Now process the list of objects we've got to return */
	zn = argp->ibr_srch.ibr_srch_len;
	za = argp->ibr_srch.ibr_srch_val;
	list = nis_return_list(ib_obj, ib_list->objs, ib_list->numo, pname,
							&got, all_read,
							zn, za);

	/* Construct the result */
	if (got) {
		res->status = NIS_SUCCESS;
		NIS_RES_NUMOBJ(res) = got;
		NIS_RES_OBJECT(res) = list;
	} else {
		res->status = NIS_NOTFOUND;
		NIS_RES_NUMOBJ(res) = 0;
		NIS_RES_OBJECT(res) = NULL;
	}
	res->zticks = __stop_clock(0);
	return (res);
}

/*
 * This is an internal Information Base operations function. It is collected
 * here for clarity. It makes the actual database calls to manipulate the
 * namespace.
 */
static void
add_entry(name, zn, za, obj, tbl, flags, princp, xid, res)
	nis_name		name;	/* Table name		    */
	int			zn;	/* Number of attributes	    */
	nis_attr		*za;	/* NIS+ attribute list.	    */
	nis_object		*obj,	/* The entry we're adding   */
				*tbl;	/* Table we're adding to    */
	ulong_t			flags;	/* Semantic flags	    */
	nis_name		princp;	/* Principal making request */
	int			*xid;	/* XID for transaction	    */
	nis_result		*res;	/* Place for results.	    */
{
	nis_db_list_result 	*db;
	nis_db_result		*ars;
	int			add_ok, mod_ok;
	time_t			currtime;

	/*
	 * Check to see if we can actually create an entry in this
	 * table.
	 */
	add_ok = __can_do(NIS_CREATE_ACC, tbl->zo_access, tbl, princp);
	mod_ok = __can_do(NIS_MODIFY_ACC, tbl->zo_access, tbl, princp);
	if (auth_verbose) {
		syslog(LOG_INFO,
			"add_entry: creation is %s by the table.",
				(add_ok) ? "ALLOWED" : "DISALLOWED");

	}

	db = db_list(name, zn, za);

	*xid = begin_transaction(princp);
	if (*xid == 0) {
		res->status = NIS_TRYAGAIN;
		return;
	}

	currtime = time(0);	/* Make sure REMOVE/ADD has same time */
	obj->zo_oid.ctime = (ulong_t)currtime;
	obj->zo_oid.mtime = obj->zo_oid.ctime;
	if (db->status == NIS_SUCCESS) {
		if (db->numo != 1) {
			res->status = NIS_NOTUNIQUE;
		} else if ((flags & ADD_OVERWRITE) == 0) {
			res->status = NIS_NAMEEXISTS;
		} else if (! mod_ok &&
			    ! __can_do(NIS_MODIFY_ACC, db->objs[0].o->zo_access,
				    db->objs[0].o, princp)) {
			res->status = NIS_PERMISSION;
		} else {
			nisdb_tsd_t	*tsd;

			/* Act like a modify on the OID */
			obj->zo_oid.ctime = db->objs->o->zo_oid.ctime;

			/*
			 * Tell the DB that we're doing a modify, so that
			 * it can merge the remove/add to a single LDAP
			 * update.
			 */
			tsd = __nisdb_get_tsd();
			tsd->doingModify = 1;

			/* This updates the log */
			db_remib(name, zn, za, db->objs, db->numo, tbl,
							(ulong_t)currtime);
			/* As does this, a virtual modify operation */
			ars = db_addib(name, zn, za, obj, tbl);

			tsd->doingModify = 0;

			res->dticks += ars->ticks;
			res->status = ars->status;
		}
	} else if (db->status == NIS_NOTFOUND) {
		/* Ok, it doesn't exist so lets add it to the table */
		if (! add_ok) {
			res->status = NIS_PERMISSION;
			return;
		}

		ars = db_addib(name, zn, za, obj, tbl);
		if ((ars->status == NIS_SUCCESS) && (flags & RETURN_RESULT)) {
			res->objects.objects_val = nis_clone_object(obj, NULL);
			res->objects.objects_len = 1;
		}
		res->dticks += ars->ticks;
		res->status = ars->status;
	} else
		res->status = db->status;
}

/*
 * This is an internal Information Base operations function that implements
 * the remove operation. It is collected here for clarity.
 */
static void
remove_entry(name, zn, za, obj, tbl, flags, princp, xid, res)
	nis_name		name;	/* Table name		    */
	int			zn;	/* Number of attributes	    */
	nis_attr		*za;	/* NIS attribute list.	    */
	nis_object		*obj,	/* The entry we're removing */
				*tbl;	/* Table we're adding to    */
	ulong_t			flags;	/* Semantic flags	    */
	nis_name		princp;	/* Principal making request */
	int			*xid;	/* XID for transaction	    */
	nis_result		*res;	/* Place for results.	    */
{
	nis_db_list_result 	*db;
	nis_db_result		*rrs;
	int			i, rem_ok;

	/*
	 * Access control, if we have remove access granted at the
	 * table level then we can remove all entries.
	 */
	rem_ok =  __can_do(NIS_DESTROY_ACC, tbl->zo_access, tbl, princp);
	if (auth_verbose) {
		syslog(LOG_INFO,
			"remove_entry: removal is %s by the table.",
				(rem_ok) ? "ALLOWED" : "DISALLOWED");

	}


	db = db_list(name, zn, za);
	res->dticks += db->ticks;

	/*
	 * Check for errors, first to see if we actually found an
	 * object to remove.
	 */
	if (db->status != NIS_SUCCESS) {
		res->status = db->status;
		return;
	}

	/*
	 * next to see if more than one object may be removed.
	 */
	if ((db->numo > 1) && ((flags & REM_MULTIPLE) == 0)) {
		res->status = NIS_NOTUNIQUE;
		return;
	}

	/*
	 * Third to see if we need the same object to remove
	 */
	if (obj && (! same_oid(obj, db->objs->o))) {
		res->status = NIS_NOTSAMEOBJ;
		return;
	}

	/*
	 * Fourth check to see if we have the right to remove
	 * these entrie(s)
	 */
	if (! rem_ok) {
		for (i = 0; i < db->numo; i++)
			if (! __can_do(NIS_DESTROY_ACC,
					db->objs[i].o->zo_access,
					db->objs[i].o, princp))
				break;
		if (i < db->numo) {
			res->status = NIS_PERMISSION;
			return;
		}
	}

	*xid = begin_transaction(princp);
	if (*xid == 0) {
		res->status = NIS_TRYAGAIN;
		return;
	}

	/*
	 * Finally, remove the object in question.
	 */
	rrs = db_remib(name, zn, za, db->objs, db->numo, tbl,
							(ulong_t)(time(0)));
	res->dticks += rrs->ticks;
	res->status = rrs->status;
}

/*
 * This is the internal Information base function that implements the modify
 * operation. It is put here for clarity.
 */
static void
modify_entry(name, zn, za, obj, tbl, flags, princp, xid, res)
	nis_name		name;	/* Table name		    */
	int			zn;	/* Number of attributes	    */
	nis_attr		*za;	/* NIS attribute list.	    */
	nis_object		*obj,	/* The entry we're removing */
				*tbl;	/* Table we're adding to    */
	ulong_t			flags;	/* Semantic flags	    */
	nis_name		princp;	/* Principal making request */
	int			*xid;	/* XID for transaction	    */
	nis_result		*res;	/* Place for results.	    */
{
#define	buf			__nis_get_tsd()->modify_entry_buf
	nis_db_list_result 	*db;
	nis_db_result		*rrs;
	int			i, mc;
	entry_col		*o_ec,	/* Old entry columns */
				*n_ec;	/* New entry columns */
	nis_object		mobj; 	/* Modified object ...	*/
	int			clone;	/* True if new object is a clone */
	entry_col		*mec;	/* ... and it's columns	*/
	int			mod_ok;
	table_col		*tcol;
	nis_db_list_result	*o_db;
	nis_attr		*test_attr;
	int			na, mod_attrs = 0;
	time_t			currtime;
	nisdb_tsd_t		*tsd;

	/*
	 * Set the global modify access bit for the objects by checking
	 * the table's access rights.
	 */
	mod_ok = __can_do(NIS_MODIFY_ACC, tbl->zo_access, tbl, princp);

	if (auth_verbose) {
		syslog(LOG_INFO,
			"modify_entry: modification is %s by the table.",
				(mod_ok) ? "ALLOWED" : "DISALLOWED");

	}

	mc = tbl->TA_data.ta_maxcol;
	tcol = tbl->TA_data.ta_cols.ta_cols_val;
	mec = (entry_col *)nis_get_static_storage(&buf, sizeof (entry_col), mc);
	if (! mec) {
		res->status = NIS_NOMEMORY;
		return;
	}

	db = db_list(name, zn, za);

	/* If we didn't find the original just return the error */
	if (db->status != NIS_SUCCESS) {
		res->status = db->status;
		return;
	}

	/* If the object isn't unique we can't modify it. */
	if (db->numo > 1) {
		res->status = NIS_NOTUNIQUE;
		return;
	}

	clone = same_oid(obj, db->objs->o);

	if ((flags & MOD_SAMEOBJ) && (! clone)) {
		res->status = NIS_NOTSAMEOBJ;
		return;
	}

	/*
	 * Now check the permissions on the object itself.
	 * If we don't have modify access to the table we check
	 * to see if we have modify access  to the object itself,
	 * if that fails we check to see if we have modify access
	 * to the column we are modifying. If that fails we return
	 * a permission error.
	 */
	o_ec = db->objs->o->EN_data.en_cols.en_cols_val;
	n_ec = obj->EN_data.en_cols.en_cols_val;
	if (! mod_ok)
		mod_ok = __can_do(NIS_MODIFY_ACC, db->objs[0].o->zo_access,
					db->objs[0].o, princp);
	if (! mod_ok) {
		for (i = 0; i < mc; i++)
			if (((n_ec[i].ec_flags & EN_MODIFIED) != 0) &&
				! __can_do(NIS_MODIFY_ACC,
						tcol[i].tc_rights,
						db->objs[0].o, princp)) {
				res->status = NIS_PERMISSION;
				return;
			}
	}

	/*
	 * Check the MOD_EXCLUSIVE flag. If a searchable column has been
	 * modified, the key index will be changed, which may conflict with
	 * an existing entry.
	 */

	if (flags & MOD_EXCLUSIVE) {
		/* Check for a searchable column that has been modified */
		for (i = 0; i < mc; i++) {
			if (mod_attrs = ((tcol[i].tc_flags & TA_SEARCHABLE) &&
				(n_ec[i].ec_flags & EN_MODIFIED))) {
				break;
			}
		}
		/*
		 * If key modified, then create new attr list and see if
		 * it matches an existing entry
		 */
		if (mod_attrs) {
			test_attr = __get_attrs(mc);
			if (test_attr == NULL) {
				res->status = NIS_NOMEMORY;
				return;
			}
			for (i = 0, na = 0; i < mc; i++) {
				if (tcol[i].tc_flags & TA_SEARCHABLE) {
					test_attr[na].zattr_ndx =
								tcol[i].tc_name;
					if ((n_ec[i].ec_flags & EN_MODIFIED) ==
					    0) {
					test_attr[na].ZAVAL = o_ec[i].ENVAL;
					test_attr[na].ZALEN = o_ec[i].ENLEN;
					} else {
					test_attr[na].ZAVAL = n_ec[i].ENVAL;
					test_attr[na].ZALEN = n_ec[i].ENLEN;
					}
					na++;
				}
			}
			o_db = db_list(name, na, test_attr);
			if (o_db->status == NIS_SUCCESS) {
				res->status = NIS_NAMEEXISTS;
				return;
			}
		}
	}

	mobj = *(db->objs->o);
	currtime = time(0);	/* Make sure REMOVE/ADD has same time */
	mobj.zo_oid.mtime = (ulong_t)currtime;

	/* Now check to see if the attributes need to change */
	/*
	 * XXX this can fail silently when attributes change
	 * but mod_ok isn't set, we should figure out how to
	 * return a permission error. XXX
	 */
	if (clone && mod_ok) {
		mobj.zo_owner = obj->zo_owner;
		mobj.zo_group = obj->zo_group;
		mobj.zo_access = obj->zo_access;
		mobj.zo_ttl = obj->zo_ttl;
	}
	mobj.EN_data.en_cols.en_cols_val = mec;

	for (i = 0; i < mc; i++) {
		if ((n_ec[i].ec_flags & EN_MODIFIED) == 0)
			mec[i] = o_ec[i];
		else
			mec[i] = n_ec[i];
	}

	*xid = begin_transaction(princp);
	if (*xid == 0) {
		res->status = NIS_TRYAGAIN;
		return;
	}

	/*
	 * If changes are written through to LDAP, we want to make
	 * just one LDAP update, not one remove and one add, which
	 * causes problems when more than one NIS+ table maps to
	 * one and the same LDAP container. Hence, inform the DB
	 * that this removal is part of a modify operation.
	 */
	tsd = __nisdb_get_tsd();	/* Never returns NULL */
	tsd->doingModify = 1;

	/* Remove the old version of the entry */
	rrs = db_remib(name, zn, za, db->objs, db->numo, tbl,
						(ulong_t)currtime);
	res->dticks += rrs->ticks;

	if (res->status != NIS_SUCCESS)
		syslog(LOG_ERR, "modify_entry: Unable to remove object %s",
							name);
	/*
	 * Now do the modify by overwriting the existing
	 * object.
	 */
	rrs = db_addib(name, zn, za, &mobj, tbl);
	if ((rrs->status == NIS_SUCCESS) && (flags & RETURN_RESULT)) {
		res->objects.objects_val = nis_clone_object(&mobj, NULL);
		res->objects.objects_len = 1;
	}

	/* Reset modification indication to the DB */
	tsd->doingModify = 0;

	res->dticks += rrs->ticks;
	res->status = rrs->status;
}

#undef	buf

/*
 * __nis_ibops()
 * This is the common information base ops routine. It implements the
 * various operations that can be done on an information base. It is
 * analagous to the nameops() routine above.
 */
static nis_result *
__nis_ibops(op, argp, princp)
	int		op;
	ib_request	*argp;
	nis_name	princp;
{
	nis_result 	*res;
#define	buf		__nis_get_tsd()->__ibops_buf
	nis_object	*t_obj, *n_obj, *d_obj;
	nis_attr	*za;
	int		zn;
	table_col	*tc;
	ulong_t		ttime;
	int		i, mc, xid;
	entry_col	*ec;
	nis_db_result	*table;
	struct ticks	t;
	char		optxt[32];
	nis_error	xx;

	res = (nis_result *)XCALLOC(1, sizeof (nis_result));
	add_xdr_cleanup(xdr_nis_result, (char *)res, "ibops result");

	if (readonly) {
		res->status = NIS_TRYAGAIN;
		return (res);
	}

	if (auth_verbose) {
		switch (op) {
			case ADD_OP :
				strcpy(optxt, "ADD");
				break;
			case REM_OP :
				strcpy(optxt, "REMOVE");
				break;
			case MOD_OP :
				strcpy(optxt, "MODIFY");
				break;
		}
		syslog(LOG_INFO, "Entry operation '%s' for principal %s",
				optxt, princp);
	}

	/*
	 * Check to see if we serve the directory this table is in.
	 * NOTE: this could do a NIS+ lookup to the parent.
	 */
	xx = __directory_object(nis_domain_of(argp->ibr_name), &t, TRUE,
								&d_obj);
	res->aticks = t.aticks;
	res->zticks = t.zticks;
	res->cticks = t.cticks;
	res->dticks = t.dticks;
	if (d_obj == NULL) {
		syslog(LOG_ERR, "Couldn't locate directory object for %s",
				argp->ibr_name);
		res->status = NIS_NOT_ME;  /* XXX should we use 'xx'? */
		return (res);
	}

	/*
	 * Get the last update time. If the current time is earlier
	 * someone has set the clock back which is very bad as far
	 * as NIS+ is concerned. This will catch almost all possible
	 * situations except the single second when time has finally
	 * caught up with the last entry in the log. Fixing this
	 * would require more radical changes to the whole update
	 * mechanism which is potentially risky and may even require
	 * protocol changes.
	 */
	if (last_update(d_obj->DI_data.do_name) > time(0)) {
		syslog(LOG_ERR, "Update rejected because system time is "
		    "earlier than most recent log entry");
		res->status = NIS_SYSTEMERROR;
		return (res);
	}

	/*
	 * POLICY : Should we have to read the directory to
	 *	    read the table ?
	 * ANSWER : No, if we _know_ the name of the table we
	 *	    should be able to access it.
	 */

	/* quick pointer to the "new" object */
	if (argp->ibr_obj.ibr_obj_len)
		n_obj = argp->ibr_obj.ibr_obj_val;
	else
		n_obj = NULL;

	/* Get the table that we will be manipulating. */
	table = db_lookup(argp->ibr_name);
	res->dticks += table->ticks;
	if (table->status != NIS_SUCCESS) {
		res->status = table->status;
		return (res);
	}

	t_obj = table->obj;
	if (__type_of(t_obj) != NIS_TABLE_OBJ) {
		res->status = NIS_INVALIDOBJ;
		return (res);
	}

	if (! __search_ok(argp->ibr_srch.ibr_srch_len,
				argp->ibr_srch.ibr_srch_val, t_obj)) {
		res->status = NIS_BADATTRIBUTE;
		return (res);
	}

	/* For ADD/MODify Make sure the types are the same */
	if ((op == MOD_OP) || (op == ADD_OP)) {
		if (! n_obj) {
			res->status = NIS_BADOBJECT;
			return (res);
		}
	}

	/*
	 *  For all operations, if there is an object, check that
	 *  it matches the table.
	 */
	if (n_obj) {
		if (strcasecmp(n_obj->EN_data.en_type,
					t_obj->TA_data.ta_type) != 0) {
			res->status = NIS_TYPEMISMATCH;
			return (res);
		}

		/* Make sure the number of columns are the same */
		if (n_obj->EN_data.en_cols.en_cols_len !=
		    t_obj->TA_data.ta_maxcol) {
			res->status = NIS_TYPEMISMATCH;
			return (res);
		}
	}

	/*
	 * Now we check the attribute list, doing some sanity checking
	 * and then go to the database.
	 */

	tc = t_obj->TA_data.ta_cols.ta_cols_val; /* The Table columns */
	mc = t_obj->TA_data.ta_maxcol;		/* The total columns */
	if (n_obj)				/* The Entry columns */
		ec = n_obj->EN_data.en_cols.en_cols_val;
	else
		ec = NULL;

	if (argp->ibr_srch.ibr_srch_len) {
		za = argp->ibr_srch.ibr_srch_val;	/* The AVA list */
		zn = argp->ibr_srch.ibr_srch_len;	/* The current AVA */
	} else if (ec) {
		/* build a search criteria from the passed entry */
		za = (nis_attr *)nis_get_static_storage(&buf, sizeof (nis_attr),
									    mc);
		for (i = 0, zn = 0; i < mc; i++) {
			if ((tc[i].tc_flags & TA_SEARCHABLE) &&
			    (ec[i].ec_value.ec_value_val)) {
				za[zn].zattr_ndx = tc[i].tc_name;
				za[zn].ZAVAL = ec[i].ENVAL;
				za[zn].ZALEN = ec[i].ENLEN;
				zn++;
			}
		}
	} else {
		za = NULL;
		zn = 0;
	}

	xid = 0;

	switch (op) {

		case ADD_OP :
			add_entry(argp->ibr_name, zn, za, n_obj, t_obj,
						argp->ibr_flags, princp, &xid,
						res);
			break;
		case REM_OP :
			remove_entry(argp->ibr_name, zn, za, n_obj, t_obj,
						argp->ibr_flags, princp, &xid,
						res);
			break;
		case MOD_OP :
			modify_entry(argp->ibr_name, zn, za, n_obj, t_obj,
						argp->ibr_flags, princp, &xid,
						res);
			break;
	}

	if (verbose)
		syslog(LOG_INFO, "ibops: operation completed.");
	if (res->status == NIS_SUCCESS) {
		end_transaction(xid);
		ttime = last_update(d_obj->DI_data.do_name);
		if (d_obj->DI_data.do_servers.do_servers_len > 1) {
			RLOCK(ping_list);
			add_pingitem(d_obj, ttime, &ping_list);
			RULOCK(ping_list);
		}
	} else if (xid != 0)
		abort_transaction(xid);

	if (verbose)
		syslog(LOG_INFO, "ibops: returning...");
	return (res);
}

#undef	buf

/*
 * nis_fnops()
 * This is routine is common to the first and next functions below. Quite
 * a bit of code is shared so this cuts down on the chance for errors.
 * The first part is identical to the ibops function above but this
 * routine needs to return different data so I didn't want to overload
 * the return value of ibobs() above.
 */
static nis_result *
__nis_fnops(op, argp, princp)
	int		op;
	ib_request	*argp;
	nis_name	princp;
{
	nis_object		*r_obj, *t_obj, *ib_obj = NULL;
	nis_fn_result		*fnr;
	table_col		*tc;
	int			all_read = 0;
	nis_result		*res;
	int			zn;
	nis_attr		*za;

	res = (nis_result *)XCALLOC(1, sizeof (nis_result));
	if (! res) {
		syslog(LOG_ERR, "rpc.nisd: Out of memory");
		return (NULL);
	}
	add_cleanup((void (*)())XFREE, (char *)res, "fnops result");

	ib_obj = __nis_listinit(res, argp, princp);

	if (! ib_obj) {
		res->zticks = __stop_clock(0);
		return (res);
	}

	all_read = __can_do(NIS_READ_ACC, ib_obj->zo_access, ib_obj, princp);
	if (op == FIRST_OP)
		fnr = db_firstib(argp->ibr_name, argp->ibr_srch.ibr_srch_len,
			argp->ibr_srch.ibr_srch_val, FN_MANGLE+FN_NORAGS, NULL);
	else if (op == NEXT_OP) {
		res->cookie.n_len   = argp->ibr_cookie.n_len;
		res->cookie.n_bytes = (char *)malloc(res->cookie.n_len);
		memcpy(res->cookie.n_bytes,
			argp->ibr_cookie.n_bytes, res->cookie.n_len);
		fnr = db_nextib(argp->ibr_name, &(res->cookie),
						FN_MANGLE+FN_NORAGS, NULL);
	}

	res->dticks += fnr->ticks;
	if (fnr->status != NIS_SUCCESS) {
		res->status = fnr->status;
		XFREE(fnr);
		return (res);
	}

	res->cookie = fnr->cookie;
	res->status = fnr->status;
	/*
	 * If we have read access to everything or the object then we're done.
	 */
	if (all_read ||
	    __can_do(NIS_READ_ACC, fnr->obj->zo_access, fnr->obj, princp)) {
		res->objects.objects_val = fnr->obj;
		res->objects.objects_len = 1;
		add_cleanup(nis_destroy_object, (char *)fnr->obj, "fnops obj");
		add_cleanup((void (*)())XFREE, (char *)fnr->cookie.n_bytes,
							"fnops descript");
		XFREE(fnr);
		return (res);
	}

	r_obj = fnr->obj;
	XFREE(fnr); /* free the result structure */
	if (__type_of(ib_obj) == NIS_TABLE_OBJ)
		tc = ib_obj->TA_data.ta_cols.ta_cols_val;
	else
		tc = tbl_prototype.ta_cols.ta_cols_val;
	do {
		if (__can_do(NIS_READ_ACC, r_obj->zo_access, r_obj, princp))
			t_obj = r_obj;
		else {
			zn = argp->ibr_srch.ibr_srch_len;
			za = argp->ibr_srch.ibr_srch_val;
			t_obj = nis_censor_object_attr(r_obj, tc, princp,
							zn, za);
			nis_destroy_object(r_obj);
		}
		if (t_obj) {
			res->objects.objects_val = t_obj;
			res->objects.objects_len = 1;
			add_cleanup(nis_destroy_object, (char *)t_obj,
								"fnops obj");
			add_cleanup((void (*)())XFREE,
						(char *)res->cookie.n_bytes,
							"fnops descript");
			return (res);
		}

		fnr = db_nextib(argp->ibr_name, &(res->cookie),
						FN_MANGLE+FN_NORAGS, NULL);
		res->dticks += fnr->ticks;
		res->status = fnr->status;
		if (res->status == NIS_SUCCESS)
			res->cookie = fnr->cookie;
		r_obj = fnr->obj;
		XFREE(fnr);
	} while (res->status == NIS_SUCCESS);

	return (res);
}

/*
 * nis_addib, this function adds an entry into an Information Base.
 * the entry is not "visible" in the namespace, only as a component
 * of the information base that contains it.
 */
nis_result *
nis_ibadd_svc(argp, reqstp)
	ib_request *argp;
	struct svc_req *reqstp;
{
	nis_result 	*res;
	char		pname[1024];

	__start_clock(0);
	if (verbose)
		syslog(LOG_INFO, "Entry ADD_SVC: to table %s", argp->ibr_name);
	/* A quick and easy check... */
	if ((argp->ibr_obj.ibr_obj_len == 1) &&
	    (__type_of(argp->ibr_obj.ibr_obj_val) != NIS_ENTRY_OBJ)) {
		return (nis_make_error(NIS_INVALIDOBJ, 0, 0, 0,
							__stop_clock(0)));
	}
	nis_getprincipal(pname, reqstp);
	res = __nis_ibops(ADD_OP, argp, pname);
	if (verbose)
		syslog(LOG_INFO, "Done, exit status %s",
			nis_sperrno(res->status));
	res->zticks += __stop_clock(0);
	return (res);
}

/*
 * nis_ibmodify, this function modifys an entry in the information
 * base by changing the columns that are marked as modified in the
 * passed entry. Permission checking is done here as well.
 */
nis_result *
nis_ibmodify_svc(argp, reqstp)
	ib_request *argp;
	struct svc_req *reqstp;
{
	char		pname[1024];
	nis_result 	*res;

	__start_clock(0);
	if (verbose)
		syslog(LOG_INFO, "Entry MODIFY_SVC: to table %s",
							argp->ibr_name);
	/* A quick and easy check... */
	if ((argp->ibr_obj.ibr_obj_len == 1) &&
	    (__type_of(argp->ibr_obj.ibr_obj_val) != NIS_ENTRY_OBJ)) {
		return (nis_make_error(NIS_INVALIDOBJ, 0, 0, 0,
							__stop_clock(0)));
	}
	nis_getprincipal(pname, reqstp);
	res = __nis_ibops(MOD_OP, argp, pname);
	if (verbose)
		syslog(LOG_INFO, "Done, exit status %s",
			nis_sperrno(res->status));
	res->zticks += __stop_clock(0);
	return (res);
}

/*
 * nis_remove, delete an entry from the indicated information base.
 */
nis_result *
nis_ibremove_svc(argp, reqstp)
	ib_request *argp;
	struct svc_req *reqstp;
{
	char		pname[1024];
	nis_result 	*res;

	__start_clock(0);
	if (verbose)
		syslog(LOG_INFO, "Entry REMOVE_SVC: to table %s",
							argp->ibr_name);
	/* A quick and easy check... */
	if ((argp->ibr_obj.ibr_obj_len == 1) &&
	    (__type_of(argp->ibr_obj.ibr_obj_val) != NIS_ENTRY_OBJ)) {
		return (nis_make_error(NIS_INVALIDOBJ, 0, 0, 0,
							__stop_clock(0)));
	}
	nis_getprincipal(pname, reqstp);
	res = __nis_ibops(REM_OP, argp, pname);
	if (verbose)
		syslog(LOG_INFO, "Done, exit status %s",
			nis_sperrno(res->status));
	res->zticks += __stop_clock(0);
	return (res);
}

/*
 * nis_ibfirst()
 * This function will return the first entry in an information base.
 * It is provided primarily for backward compatibility with YP and its
 * use is not encouraged.
 */
nis_result *
nis_ibfirst_svc(argp, reqstp)
	ib_request *argp;
	struct svc_req *reqstp;
{
	char		pname[1024];
	nis_result 	*res;


	__start_clock(0);
	if (verbose)
		syslog(LOG_INFO, "Entry FIRST_SVC : Fetch from table %s",
			argp->ibr_name);
	nis_getprincipal(pname, reqstp);
	res = __nis_fnops(FIRST_OP, argp, pname);
	if (verbose)
		syslog(LOG_INFO, "Done, exit status %s",
			nis_sperrno(res->status));
	res->zticks += __stop_clock(0);
	return (res);
}

/*
 * nis_ibnext, return a subsequent entry in the information base.
 */
nis_result *
nis_ibnext_svc(argp, reqstp)
	ib_request *argp;
	struct svc_req *reqstp;
{
	char		pname[1024];
	nis_result 	*res;

	__start_clock(0);
	if (verbose)
		syslog(LOG_INFO, "Entry NEXT_SVC : Fetch from table %s",
			argp->ibr_name);
	nis_getprincipal(pname, reqstp);
	res = __nis_fnops(NEXT_OP, argp, pname);
	if (verbose)
		syslog(LOG_INFO, "Done, exit status %s",
			nis_sperrno(res->status));
	res->zticks += __stop_clock(0);
	return (res);
}
