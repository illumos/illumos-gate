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
 *	nislib.c
 *
 *	This module contains the user visible functions for lookup, and list,
 *	add name service calls add/remove/modify, all information base calls
 *	add_entry/remove_entry/modify_entry, and mkdir, rmdir, and checkpoint.
 * 	nis server. It should be broken up into at least three separate modules
 *
 */

#include "mt.h"
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <rpcsvc/nis.h>
#include <errno.h>
#include "nis_clnt.h"
#include "nis_local.h"

/*
 * This is *NOT* used in /usr/lib/libnsl.so.1, but has to be here so a program
 * like "sendmail" can access it BEFORE it makes ANY getXXbyYY calls.
 */

mutex_t __nis_force_lookup_policy_lock = DEFAULTMUTEX;
uint_t  __nis_force_hard_lookups = 0;

extern const nis_result	__nomem_nis_result;

/*
 * __nis_nss_lookup_policy: set's the __nis_force_hard_lookups flag
 * to HARD_LOOKUP or SOFT_LOOKUP depending upon the argument.  It will
 * be OR-ed into the nis_list() calls in the
 * NIS+ Name Service Switch backend /usr/lib/nss_nisplus.so.1
 */
unsigned int
__nis_nss_lookup_policy(unsigned int in)
{
	unsigned int old;

	sig_mutex_lock(&__nis_force_lookup_policy_lock);
	old = (__nis_force_hard_lookups & HARD_LOOKUP) ?
						HARD_LOOKUP : SOFT_LOOKUP;
	if (in == HARD_LOOKUP)
		__nis_force_hard_lookups = HARD_LOOKUP;
	else if (in == SOFT_LOOKUP)
		__nis_force_hard_lookups = 0;
	else {
		old = 0;
		errno = EINVAL;
	}
	sig_mutex_unlock(&__nis_force_lookup_policy_lock);
	return (old);
}

/* maximum number of times to loop on NIS_NOTMASTER error */
#define	MAX_NOTMASTER 5

/*
 * Prototypes for static functions.
 */
static nis_result *__nis_path_list(nis_object *, int, nis_result *,
				ib_request *, uint_t,
				int (*)(nis_name, nis_object *, void *),
				void *);
static nis_result * nis_ibops(ib_request *, rpcproc_t);
static nis_result * nis_nameops(nis_name, nis_object *, rpcproc_t);
static nis_result *nis_list_partial(nis_result *, ib_request *, uint_t,
				int (*)(), void *);

extern int __nis_debug_rpc;
extern int __nis_debug_calls;
extern FILE *__nis_debug_file;


/*
 * nis_freeresult()
 *
 * This function calls the XDR free function for the user to free up the
 * memory associated with a result structure. NB: It isn't a macro because
 * it needs to be exposed to the client. Internally the xdr routine should
 * be used to save a procedure call.
 */
void
nis_freeresult(nis_result *res)
{
	if (res == &__nomem_nis_result)
		return;
	xdr_free(xdr_nis_result, (char *)res);
	free(res);
}

void
__nis_freelogresult(log_result *lres)
{
	if (lres) {
		xdr_free((xdrproc_t)xdr_log_result, (char *)lres);
		free(lres);
	}
}

/*
 * nis_bind_dir()
 *
 * This function is used to return a binding to a candidate server.
 * It has two side effects :
 *	1) It keeps track of time in the cache code
 *	2) it optionally mallocs a NIS+ result structure.
 *
 * 'name' contains the name of the object that will be operated on.
 * If the operation is a lookup or a table search, then this code
 * returns a directory object that describes that objects directory
 * and thus a server that will have knowledge about the object.
 *
 * However, since the directory object, and the directory itself
 * can be on two different machines, when listing directories we
 * attempt to bind to the name passed. This only occurs when nis_list
 * is called and the search criteria is NULL (which is the only legal
 * search on a directory).
 *
 */
nis_error
nis_bind_dir(
	char *dname,
	int parent_first,
	nis_bound_directory **binding,
	uint_t flags)
{
	nis_error stat;

	if (parent_first) {
		stat = __nis_CacheBindDir(nis_domain_of(dname),
					binding, flags);
		if (stat != NIS_SUCCESS)
			stat = __nis_CacheBindDir(dname, binding, flags);
	} else {
		stat = __nis_CacheBindDir(dname, binding, flags);
		if (stat != NIS_SUCCESS)
			stat = __nis_CacheBindDir(nis_domain_of(dname),
					binding, flags);
	}
	return (stat);
}

nis_error
nis_bind_server(nis_server *srv, int nsrv, nis_bound_directory **binding)
{
	nis_error stat;

	stat = __nis_CacheBindServer(srv, nsrv, binding);
	return (stat);
}

/*
 * __nis_path_list()
 *
 * This internal function will list all of the tables in a path.
 * if the ALL_RESULTS flag is set, it keeps on going, and going.
 * otherwise it returns on the first match.
 *
 * NB: The nis_list() function initializes the request's search
 * criteria, we just swap in table names.
 *
 * All possible returns from call to NIS_IBLIST (all NIS_xxx)
 *
 * Successful returns
 *
 * CBRESULTS, SUCCESS, S_SUCCESS  - found something
 * NOTFOUND, PARTIAL,  - looked but no data.
 * PERMISSION - can't read the table
 *
 * Errors that generate syslog warnings
 * NOTMASTER, NOT_ME, BADNAME, NOSUCHTABLE, NOSUCHNAME
 * BADATTRIBUTE, INVALIDOBJ
 *
 * Errors that fail silently but change final result to "soft"
 * NOMEMORY, TRYAGAIN, SYSTEMERROR, BADOBJECT
 *
 * Fatal errors :
 * NOCALLBACK
 */
static nis_result *
__nis_path_list(
	nis_object	*tbl_obj,	/* Path of tables to search */
	int		sf,		/* search first object */
	nis_result	*res,		/* result structure to use */
	ib_request	*req,		/* Request structure */
	unsigned int	flags,		/* Flags to this function */
	int		(*cback)(nis_name, nis_object *, void *),
	void		*cbdata)
{
	nis_name	pathlist[NIS_MAXPATHDEPTH];	/* Parsed table path */
	char		pathbuf[NIS_MAXPATHLEN];
	char		firstpath[NIS_MAXNAMELEN];
	nis_result	*local_res;		/* local result */
	nis_name	table;			/* current table */
	int		tnum, 			/* # of tables to search */
			i, j, 			/* counters */
			cur_obj,		/* obj, link counters */
			soft_error = 0; 	/* error detected */
	unsigned int	aticks = 0, 		/* profiling vars */
			dticks = 0,
			cticks = 0,
			zticks = 0;
	nis_object	*obj_list;		/* list returned from call */
	int		num_objs,
			total_objs;		/* # of objects returned */
	struct obj_lists {			/* returned objects from each */
		nis_object	*objs;
		int		len;
	} 		ret_objs[NIS_MAXPATHDEPTH];

	/* construct a list of tables to search */
	(void) strncpy(pathbuf, tbl_obj->TA_data.ta_path, NIS_MAXPATHLEN);
	if (sf) {
		(void) snprintf(firstpath, sizeof (firstpath),
						"%s.%s", tbl_obj->zo_name,
						tbl_obj->zo_domain);
		pathlist[0] = firstpath;
		tnum = __nis_parse_path(pathbuf, &pathlist[1],
						NIS_MAXPATHDEPTH - 1);
		tnum++;
	} else
		tnum = __nis_parse_path(pathbuf, pathlist, NIS_MAXPATHDEPTH);

	/* Take any existing objects from the result passed in */
	ret_objs[0].objs = res->objects.objects_val;
	ret_objs[0].len = res->objects.objects_len;
	total_objs = ret_objs[0].len;
	res->objects.objects_val = NULL;
	res->objects.objects_len = 0;

	/*
	 * Either search until a match is found, or if ALL_RESULTS is
	 * set, search until path is exhausted.
	 */
	for (i = 0; i < tnum; i++) {
		table = pathlist[i];
		/* Ignore non-fully qualified names in path */
		if (table[strlen(table) - 1] != '.') {
			syslog(LOG_WARNING,
	"nis_list: non fully qualified name in table path, %s, ignored.\n",
									table);
			continue;
		}
		/* swap in the table name from the path */
		req->ibr_name = table;
		/* prepare to receive the objects returned */
		ret_objs[i+1].objs = NULL;
		ret_objs[i+1].len = 0;
		if (cback) {
			(void) mutex_lock(&__nis_callback_lock);
			local_res = __nis_core_lookup(req, flags, 1, cbdata,
			    cback);
			(void) mutex_unlock(&__nis_callback_lock);
		} else
			local_res = __nis_core_lookup(req, flags, 1, cbdata,
			    cback);
		aticks += local_res->aticks;
		dticks += local_res->dticks;
		cticks += local_res->cticks;
		zticks += local_res->zticks;
		obj_list = local_res->objects.objects_val;
		num_objs = local_res->objects.objects_len;

		switch (local_res->status) {
		case NIS_SUCCESS :
			/* put these into the array */
			ret_objs[i+1].objs = obj_list;
			ret_objs[i+1].len = num_objs;
			total_objs += num_objs;
			/* zero this so freeresult won't free them */
			local_res->objects.objects_val = NULL;
			local_res->objects.objects_len = 0;
			/* fall through to the CBRESULTS code */
			/*FALLTHROUGH*/
		case NIS_CBRESULTS :
		case NIS_CBERROR :
			break;
		case NIS_PARTIAL :
		case NIS_PERMISSION :
		case NIS_NOTMASTER :
			/* these errors, just break */
			break;
		case NIS_LINKNAMEERROR : /* message generated above */
			soft_error = TRUE;
			break;
		case NIS_NOT_ME :
		case NIS_RPCERROR :
		case NIS_NAMEUNREACHABLE :
		/* generate message and set soft_error */
			syslog(LOG_WARNING,
"nis_list: NIS+ error %s encountered on name %s in table %s.%s's path.",
				nis_sperrno(local_res->status),
				table, tbl_obj->zo_name, tbl_obj->zo_domain);
			soft_error = TRUE;
			break;
		case NIS_NOTFOUND :
		case NIS_BADNAME :
		case NIS_NOSUCHTABLE :
		case NIS_NOSUCHNAME :
		case NIS_BADATTRIBUTE :
		case NIS_INVALIDOBJ :
		/* generate message but don't set soft_error */
			syslog(LOG_WARNING,
"nis_list: NIS+ error %s encountered on name %s in table %s.%s's path.",
				nis_sperrno(local_res->status),
				table, tbl_obj->zo_name, tbl_obj->zo_domain);
			break;
		default :
			soft_error = TRUE;
			break;
		}
		/*
		 * POLICY : When one table in a path is unreachable,
		 * should we continue on or stop with an error?
		 * ANSWER : Continue on. Loss of a portion of the namespace
		 * should not cause disruptions in all of the namespace.
		 * NB: This can have interesting side effects such that a
		 * name may suddenly change "value" because it is being
		 * resolved from a different place.
		 *
		 * If we're not returning all results and we've had a
		 * successful call, we just return those results.
		 */
		if (((flags & ALL_RESULTS) == 0) &&
		    ((local_res->status == NIS_SUCCESS) ||
		    (local_res->status == NIS_CBRESULTS))) {
			res->status = local_res->status;
			res->aticks += aticks;
			res->dticks += dticks;
			res->zticks += zticks;
			res->objects.objects_val = obj_list;
			res->objects.objects_len = num_objs;
			/* reset so that caller does not free it */
			req->ibr_name = NULL;
			nis_freeresult(local_res);
			/* return same result structure back to them */
			return (res);
		}

		/* otherwise just free local result (we've got the objs) */
		nis_freeresult(local_res);
	}

	/* name is already freed so null this out */
	req->ibr_name = NULL;

	/*
	 * At this point, we've either exhausted the list of tables
	 * (total_objs == 0), or we've asked for all results so the
	 * ret_objs[] array has some data in it (total_objs > 0)
	 * if soft_error is set we will adjust our result status
	 * appropriately.
	 */
	if (total_objs) {
		/* now build a list of objects that should be returned */
		obj_list = calloc(total_objs, sizeof (nis_object));
		if (obj_list == NULL) {
			res->status = NIS_NOMEMORY;
			res->aticks += aticks;
			res->dticks += dticks;
			res->zticks += zticks;
			for (i = 0; i < (tnum+1); i++) {
				if (ret_objs[i].objs == NULL)
					continue;
				for (j = 0; j < ret_objs[i].len; j++)
					xdr_free(xdr_nis_object,
						(char *)&(ret_objs[i].objs[j]));
				free(ret_objs[i].objs);
			}
			return (res);
		}

		/* copyout all objects into this new array */
		cur_obj = 0;
		for (i = 0; i < (tnum+1); i++) {
			if (ret_objs[i].objs == NULL)
				continue;
			for (j = 0; j < ret_objs[i].len; j++)
				obj_list[cur_obj++] = ret_objs[i].objs[j];
			free(ret_objs[i].objs);
		}
		res->objects.objects_val = obj_list;
		res->objects.objects_len = cur_obj;
		if (cur_obj)
			res->status = NIS_SUCCESS;
		else
			res->status = NIS_NOTFOUND;
	} else {
		if (cback)
			res->status = NIS_CBRESULTS;
		else
			res->status = NIS_NOTFOUND;
	}

	if (soft_error && (res->status == NIS_SUCCESS))
		res->status = NIS_S_SUCCESS;
	else if (soft_error && (res->status == NIS_NOTFOUND))
		res->status = NIS_S_NOTFOUND;
	res->aticks += aticks;
	res->dticks += dticks;
	res->cticks += cticks;
	res->zticks += zticks;
	return (res);
}

/*
 * nis_lookup()
 *
 * This is the main lookup function of the name service. It will look
 * for the named object and return it. If the object was a link and
 * the flag FOLLOW_LINKS was set it will look up the item named by
 * the LINK, if that is an indexed name the lookup may return multiple
 * objects. If the name is not fully qualified and EXPAND_NAME is set
 * this function will expand the name into several candidate names.
 */
nis_result *
nis_lookup(nis_name name, uint_t flags)
{
	nis_error	nis_err = NIS_SUCCESS;
	nis_name	*namelist;
	nis_result	*res;
	ib_request	req;
	int		i;
	unsigned int	aticks = 0,
			cticks = 0,
			dticks = 0,
			zticks = 0;

	(void) __start_clock(CLOCK_CLIENT);
	__nis_CacheStart();
	if (__nis_debug_calls) {
		(void) fprintf(__nis_debug_file, "nis_lookup(%s, 0x%x)\n",
			name, flags);
	}
	(void) memset((char *)&req, 0, sizeof (ib_request));
	req.ibr_name = name;
	i = (int)strlen(name);
	if ((flags & EXPAND_NAME) == 0 || (i > 0 && name[i-1] == '.')) {
		res = __nis_core_lookup(&req, flags, 0, NULL, NULL);
		res->cticks = __stop_clock(CLOCK_CLIENT);
		if (__nis_debug_calls)
			__nis_print_result(res);
		return (res);
	}
	namelist = __nis_getnames(name, &nis_err);
	if (! namelist) {
		res = nis_make_error(nis_err, 0, 0, 0, 0);
		res->cticks = __stop_clock(CLOCK_CLIENT);
		if (__nis_debug_calls)
			__nis_print_result(res);
		return (res);
	}
	for (i = 0; namelist[i]; i++) {
		req.ibr_name = namelist[i];
		res = __nis_core_lookup(&req, flags, 0, NULL, NULL);
		switch (res->status) {
			/*
			 * All of the errors that indicate the name
			 * is bound.
			 * NB: We include the "nis_list" errors as well
			 * as the core_lookup call could have followed
			 * a link into a table operation.
			 */
			case NIS_SUCCESS :
			case NIS_PARTIAL :
			case NIS_CBRESULTS :
			case NIS_CBERROR :
			case NIS_CLNTAUTH :
			case NIS_SRVAUTH :
			case NIS_PERMISSION :
			case NIS_LINKNAMEERROR:
			case NIS_NOTMASTER :
				res->aticks += aticks;
				res->dticks += dticks;
				res->zticks += zticks;
				res->cticks += cticks;
				res->cticks += __stop_clock(CLOCK_CLIENT);
				nis_freenames(namelist);
				if (__nis_debug_calls)
					__nis_print_result(res);
				return (res);
			default :
				aticks += res->aticks;
				cticks += res->cticks;
				dticks += res->dticks;
				zticks += res->zticks;
				if (nis_err == NIS_SUCCESS)
					nis_err = res->status;
				nis_freeresult(res);
		}
	}
	nis_freenames(namelist);
	cticks += __stop_clock(CLOCK_CLIENT);
	if (nis_err == NIS_SUCCESS) {
		syslog(LOG_WARNING, "nis_lookup: empty namelist");
		nis_err = NIS_NOTFOUND;    /* fix up in case namelist empty */
	}
	res = nis_make_error(nis_err, aticks, cticks, dticks, zticks);
	if (__nis_debug_calls)
		__nis_print_result(res);
	return (res);
}

/*
 * nis_list()
 *
 * This function takes a "standard" NIS name with embedded search criteria
 * and does a list on the object.
 */
nis_result *
nis_list(
	nis_name	name,	/* list name like '[foo=bar].table.name' */
	uint_t		flags,		/* Flags for the search */
	int		(*cback)(),	/* Callback function. */
	void		*cbdata)	/* Callback private data */
{
	nis_error	nis_err = NIS_SUCCESS;
	nis_name	*namelist;
	nis_object	*obj;
	nis_result	*res;
	ib_request	req;
	nis_error	stat;
	uint32_t	zticks = 0,
			aticks = 0,
			dticks = 0,
			cticks = 0;
	int		i, done;

	/* start the client profiling clock */
	(void) __start_clock(CLOCK_CLIENT);

	__nis_CacheStart();
	if (__nis_debug_calls) {
		(void) fprintf(__nis_debug_file,
		    "nis_list(%s, 0x%x, 0x%p, 0x%p)\n", name, flags,
		    (void *)cback, (void *)cbdata);
	}

	/* Parse the request into a table name and attr/value pairs */
	stat = nis_get_request(name, NULL, NULL, &req);
	if (stat != NIS_SUCCESS) {
		res = nis_make_error(stat, 0, 0, 0, 0);
		res->cticks = __stop_clock(CLOCK_CLIENT);
		if (__nis_debug_calls)
			__nis_print_result(res);
		return (res);
	}

	/*
	 * process the ALL_RESULTS flag specially. First fetch
	 * the table object to get the path, then call path list
	 * to read all of the data. Note if we returned the object
	 * on a list we could save an RPC here.
	 */
	if (flags & ALL_RESULTS) {
		res = nis_lookup(req.ibr_name, flags);
		if (res->status != NIS_SUCCESS) {
			nis_free_request(&req);
			if (__nis_debug_calls)
				__nis_print_result(res);
			return (res);
		}
		aticks = res->aticks;
		cticks = res->cticks;
		dticks = res->dticks;
		zticks = res->zticks;
		obj = res->objects.objects_val;
		if ((res->objects.objects_len > 1) ||
		    (__type_of(obj) != NIS_TABLE_OBJ)) {
			/* Note : can't do all results on directory obj. */
			xdr_free(xdr_nis_result, (char *)res);
			nis_free_request(&req);
			(void) memset((char *)res, 0, sizeof (nis_result));
			res->status = NIS_BADOBJECT;
			res->aticks = aticks;
			res->dticks = dticks;
			res->cticks = cticks;
			res->zticks = zticks;
			if (__nis_debug_calls)
				__nis_print_result(res);
			return (res);
		}
		res->objects.objects_val = NULL;
		res->objects.objects_len = 0;
		free(req.ibr_name); /* won't be needing this */
		req.ibr_name = NULL;
		res = __nis_path_list(obj, 1, res, &req, flags, cback, cbdata);
		nis_free_request(&req);
		xdr_free(xdr_nis_object, (char *)obj);
		free(obj);
		res->aticks += aticks;
		res->dticks += dticks;
		res->cticks += cticks;
		res->zticks += zticks;
		if (__nis_debug_calls)
			__nis_print_result(res);
		return (res);
	}

	/*
	 * Normal requests.  The server will return NIS_PARTIAL
	 * if we specify a search criteria and the table exists
	 * but the entry does not exist within the table.  We
	 * need to handle this return value by checking for a
	 * table path in nis_list_partial().
	 */
	i = (int)strlen(name);
	if ((flags & EXPAND_NAME) == 0 || (i > 0 && name[i-1] == '.')) {
		if (cback) {
			(void) mutex_lock(&__nis_callback_lock);
			res = __nis_core_lookup(&req, flags, 1, cbdata, cback);
			(void) mutex_unlock(&__nis_callback_lock);
		} else
			res = __nis_core_lookup(&req, flags, 1, cbdata, cback);
		free(req.ibr_name);
		if (res->status == NIS_PARTIAL)
			res = nis_list_partial(res, &req, flags, cback, cbdata);
	} else {
		namelist = __nis_getnames(req.ibr_name, &stat);
		if (! namelist) {
			res = nis_make_error(stat, 0, 0, 0, 0);
			nis_free_request(&req);
			res->cticks = __stop_clock(CLOCK_CLIENT);
			if (__nis_debug_calls)
				__nis_print_result(res);
			return (res);
		}
		free(req.ibr_name); /* non fully qualified name */

		for (i = 0, done = 0; !done && namelist[i]; i++) {
			/* replace with the candidate name */
			req.ibr_name = namelist[i];
			if (cback) {
				(void) mutex_lock(&__nis_callback_lock);
				res = __nis_core_lookup(&req, flags, 1, cbdata,
				    cback);
				(void) mutex_unlock(&__nis_callback_lock);
			} else
				res = __nis_core_lookup(&req, flags, 1, cbdata,
				    cback);
			if (res->status == NIS_PARTIAL)
				res = nis_list_partial(res, &req,
							flags, cback, cbdata);
			switch (res->status) {
				/*
				 * All of the errors that indicate the name
				 * is bound.
				 */
				case NIS_SUCCESS :
				case NIS_CBRESULTS :
				case NIS_CBERROR :
				case NIS_CLNTAUTH :
				case NIS_SRVAUTH :
				case NIS_PERMISSION :
				case NIS_NOTMASTER :
					done = 1;
					break;
				default :
					aticks += res->aticks;
					cticks += res->cticks;
					dticks += res->dticks;
					zticks += res->zticks;
					if (nis_err == NIS_SUCCESS)
						nis_err = res->status;
					nis_freeresult(res);
					break;
			}
		}
		if (! done) {
			if (nis_err == NIS_SUCCESS) {
				syslog(LOG_WARNING, "nis_list: empty namelist");
				nis_err = NIS_NOTFOUND; /* if empty namelist */
			}
			res = nis_make_error(nis_err, aticks, cticks,
							    dticks, zticks);
		}
		nis_freenames(namelist); /* not needed any longer */
	}
	req.ibr_name = NULL; /* already freed */

	/*
	 * Returns from __nis_core_lookup :
	 *	NIS_SUCCESS,  	Table/Name found, search suceeded.
	 *	NIS_CBRESULTS,	Table/Name found, search suceeded to callback
	 *	NIS_PARTIAL,  	found the name but didn't match any entries.
	 *	NIS_CLNTAUTH,	Found table, couldn't authenticate callback
	 *	NIS_SRVAUTH	Found table, couldn't authenticate server
	 *	NIS_PERMISSION	Found table, couldn't read it.
	 *	NIS_NOTMASTER	Found table, wasn't master (master requested)
	 *	NIS_RPCERROR	unable to communicate with service.
	 *	NIS_XXX 	Error somewhere.
	 *
	 */
	res->aticks += aticks;
	res->cticks += cticks;
	res->dticks += dticks;
	res->zticks += zticks;
	res->cticks += __stop_clock(CLOCK_CLIENT);
	nis_free_request(&req);
	if (__nis_debug_calls)
		__nis_print_result(res);
	return (res);
}

/*
 * Deal with a "PARTIAL" result. Given a NIS name of
 * [search-criteria].table-name, this occurs when the
 * server found an object whose name was 'table-name' but
 * either the object couldn't be searched because it was the
 * wrong type or the search resulted in no results.
 *
 * If the object that matched 'table-name' was a LINK object
 * core lookup will have followed it for us.
 *
 * We increment a local copy of the statistics and then reset
 * them in 'res' before returning.
 */
static
nis_result *
nis_list_partial(
	nis_result	*res,
	ib_request	*req,
	uint_t		flags,		/* Flags for the search */
	int		(*cback)(),	/* Callback function. */
	void		*cbdata)	/* Callback private data */
{
	nis_object	*obj;
	table_obj	*tdata;
	unsigned int aticks = res->aticks;
	unsigned int cticks = res->cticks;
	unsigned int dticks = res->dticks;
	unsigned int zticks = res->zticks;

	obj = res->objects.objects_val;
	if (__type_of(obj) ==  NIS_DIRECTORY_OBJ) {
		/*
		 * POLICY : What is the error when you search a
		 * a DIRECTORY and the results are no entries ?
		 * ANSWER : A NOT FOUND error, assuming the server
		 * did not return a "bad attribute" error, AND
		 * we do _NOT_ return the directory object that the
		 * server returned.
		 */
		xdr_free(xdr_nis_result, (char *)res);
		(void) memset((char *)res, 0, sizeof (nis_result));
		res->status = NIS_NOTFOUND;
	} else if (__type_of(obj) == NIS_LINK_OBJ) {
		/* If the object that matched 'table-name' was a LINK object */
		/* core lookup will have followed it for us.  If it's not */
		/* found there and we somehow came to nis_list_partial() */
		/* we need to return NIS_NOTFOUND */

		xdr_free(xdr_nis_result, (char *)res);
		(void) memset((char *)res, 0, sizeof (nis_result));
		res->status = NIS_NOTFOUND;
	} else if (__type_of(obj) != NIS_TABLE_OBJ) {
		/*
		 * This shouldn't happen because the server should
		 * catch it when it attempts the search.
		 */
		xdr_free(xdr_nis_result, (char *)res);
		(void) memset((char *)res, 0, sizeof (nis_result));
		res->status = NIS_NOTSEARCHABLE;
	} else {
		/*
		 * Now we know its a table object and that our search failed.
		 */
		tdata = &(obj->TA_data);
		if (((flags & FOLLOW_PATH) != 0) && (tdata->ta_path) &&
		    (strlen(tdata->ta_path) > (size_t)0)) {
			obj = res->objects.objects_val;
			res->objects.objects_val = NULL;
			res->objects.objects_len = 0;
			res = __nis_path_list(obj, 0, res, req, flags,
								cback, cbdata);
			/* free up the table object */
			xdr_free(xdr_nis_object, (char *)obj);
			free(obj);
			/* ticks are updated by __nis_path_list */
			aticks = res->aticks;
			cticks = res->cticks;
			dticks = res->dticks;
			zticks = res->zticks;
		} else {
			xdr_free(xdr_nis_result, (char *)res);
			(void) memset((char *)res, 0, sizeof (nis_result));
			/*
			 *  If a search criteria was specified, indicate
			 *  that we didn't find the entry.  If there was
			 *  no search criteria, then we return success
			 *  (i.e., table was listed successfully, but
			 *  there were no entries in the table).
			 */
			if (req->ibr_srch.ibr_srch_len)
				res->status = NIS_NOTFOUND;
			else if (cback)
				res->status = NIS_CBRESULTS;
			else
				res->status = NIS_SUCCESS;
		}
	}
	res->aticks = aticks;
	res->dticks = dticks;
	res->zticks = zticks;
	res->cticks = cticks;
	return (res);
}

/*
 *  Make a call to a nis+ server based on the call state in 'state'.
 *  We loop until we either get a response or until we can no longer
 *  get a client handle to any server.
 */
nis_error
nis_call(nis_call_state *state, rpcproc_t func,
	xdrproc_t req_proc, char *req, xdrproc_t res_proc, char *res)
{
	CLIENT *clnt;
	nis_error err = NIS_SUCCESS;
	enum clnt_stat status;

	for (;;) {
		clnt = __nis_get_server(state);
		if (clnt == NULL) {
			err = state->niserror;
			break;
		}

		if (__nis_debug_rpc)
			__nis_print_call(clnt, func);

		status = clnt_call(clnt, func,
				req_proc, req, res_proc, res,
				state->timeout);

		if (__nis_debug_rpc)
			__nis_print_rpc_result(status);

		__nis_release_server(state, clnt, status);

		if (status == RPC_SUCCESS)
			break;
	}

	return (err);
}

/*
 * nis_nameops()
 *
 * This generic function calls all of the name operations.
 */

static nis_result *
nis_nameops(nis_name name, nis_object *obj, rpcproc_t func)
{
	nis_call_state		state;
	nis_result		*res;
	nis_error		err;
	ns_request		req;
	nis_name		oname, odomain;
	nis_name		oowner, ogroup;
	char			nname[1024], ndomain[1024];
	nis_name		tname;
	int			times = 0;

	if (name != 0 && strlen(name) >= NIS_MAXNAMELEN) {
		return (nis_make_error(NIS_BADNAME, 0, 0, 0, 0));
	}

	if (obj) {
		/*
		 * Enforce correct name policy on NIS+ objects stored
		 * into the namespace. This code insures that zo_name
		 * and zo_domain are correct.
		 */
		oname = obj->zo_name;
		if ((tname = nis_leaf_of(name)) == NULL ||
		    strlcpy(nname, tname, sizeof (nname)) >= sizeof (nname))
			return (nis_make_error(NIS_BADNAME, 0, 0, 0, 0));
		obj->zo_name = nname;
		odomain = obj->zo_domain;
		if ((tname = nis_domain_of(name)) == NULL ||
		    strlcpy(ndomain, tname, sizeof (ndomain))
				>= sizeof (ndomain))
			return (nis_make_error(NIS_BADNAME, 0, 0, 0, 0));
		obj->zo_domain = ndomain;
		if (ndomain[strlen(ndomain)-1] != '.' &&
				strlcat(ndomain, ".", sizeof (ndomain)) >=
					sizeof (ndomain))
			return (nis_make_error(NIS_BADNAME, 0, 0, 0, 0));

		oowner = obj->zo_owner;
		if (obj->zo_owner == 0)
			obj->zo_owner = nis_local_principal();

		ogroup = obj->zo_group;
		if (obj->zo_group == 0)
			obj->zo_group = nis_local_group();
	}

	(void) memset((char *)&req, 0, sizeof (req));
	req.ns_name = name;
	if (obj) {
		req.ns_object.ns_object_len = 1;
		req.ns_object.ns_object_val = obj;
	} else {
		req.ns_object.ns_object_len = 0;
		req.ns_object.ns_object_val = NULL;
	}

	__nis_init_call_state(&state);
	state.name = name;
	state.flags = MASTER_ONLY;
	state.parent_first = 1;

	res = calloc(1, sizeof (nis_result));
	if (res == NULL)
		return (nis_make_error(NIS_NOMEMORY, 0, 0, 0, 0));

again:
	err = nis_call(&state, func,
			(xdrproc_t)xdr_ns_request, (char *)&req,
			(xdrproc_t)xdr_nis_result, (char *)res);
	if (err == NIS_SUCCESS && res->status == NIS_NOTMASTER &&
	    times++ < MAX_NOTMASTER)
		goto again;
	res->aticks = state.aticks;
	__nis_reset_call_state(&state);
	if (err != NIS_SUCCESS)
		res->status = err;

	if (obj) {
		obj->zo_name = oname;
		obj->zo_domain = odomain;
		obj->zo_owner = oowner;
		obj->zo_group = ogroup;
	}
	return (res);
}

/*
 * nis_add()
 *
 * This function will add an object to the namespace. If it is a
 * table type object the server will create a table for it as well.
 */

nis_result *
nis_add(nis_name name, nis_object *obj)
{
	nis_result	*res;

	(void) __start_clock(CLOCK_CLIENT); /* start the client clock */
	__nis_CacheStart();
	if (__nis_debug_calls) {
		(void) fprintf(__nis_debug_file, "nis_add(%s, 0x%p\n",
			name?name:"(nil)", (void *)obj);
	}
	res = nis_nameops(name, obj, NIS_ADD);
	res->cticks = __stop_clock(CLOCK_CLIENT);
	if (__nis_debug_calls)
		__nis_print_result(res);
	return (res);
}

static void
nis_flush_cache(nis_name name, nis_object *obj)
{
	if (obj == 0 || (obj && __type_of(obj) == NIS_DIRECTORY_OBJ)) {
		directory_obj dobj;
		if (__nis_CacheSearch(name, &dobj) == NIS_SUCCESS &&
		    nis_dir_cmp(name, dobj.do_name) == SAME_NAME) {
			__nis_CacheRemoveEntry(&dobj);
			xdr_free((xdrproc_t)xdr_directory_obj, (char *)&dobj);
		}
	}
}

/*
 * nis_remove()
 *
 * This function will remove an object from the namespace. If it is a
 * table type object the server will destroy the table for it as well.
 */

nis_result *
nis_remove(nis_name name, nis_object *obj)
{
	nis_result	*res;

	(void) __start_clock(CLOCK_CLIENT); /* start the client clock */
	__nis_CacheStart();
	if (__nis_debug_calls) {
		(void) fprintf(__nis_debug_file, "nis_remove(%s, 0x%p)\n",
			name?name:"(nil)", (void *)obj);
	}
	res =  nis_nameops(name, obj, NIS_REMOVE);
	if (res->status == NIS_SUCCESS)
		nis_flush_cache(name, obj);
	res->cticks = __stop_clock(CLOCK_CLIENT);
	if (__nis_debug_calls)
		__nis_print_result(res);
	return (res);
}

/*
 * nis_modify()
 *
 * This function will modify an object in the namespace.
 */

nis_result *
nis_modify(nis_name name, nis_object *obj)
{
	nis_result	*res;

	(void) __start_clock(CLOCK_CLIENT); /* start the client clock */
	__nis_CacheStart();
	if (__nis_debug_calls) {
		(void) fprintf(__nis_debug_file, "nis_modify(%s, 0x%p)\n",
			name?name:"(nil)", (void *)obj);
	}
	res = nis_nameops(name, obj, NIS_MODIFY);
	if (res->status == NIS_SUCCESS)
		nis_flush_cache(name, obj);
	res->cticks = __stop_clock(CLOCK_CLIENT);
	if (__nis_debug_calls)
		__nis_print_result(res);
	return (res);
}


/*
 * The cookie has the name of the server (null-terminated), followed
 * by the "real" cookie from the NIS server.  We make a copy of the
 * server name, copy the "real" cookie to the beginning of the buffer,
 * and then adjust the cookie length.  A zero-length cookie means
 * that the cookie is not valid and we return 0.
 */
static
char *
cookie_to_name(netobj *cookie)
{
	size_t len;
	size_t offset;
	char *s;

	if (cookie->n_bytes == 0)
		return (0);
	if ((s = strdup(cookie->n_bytes)) == 0) {
		syslog(LOG_ERR, "cookie_to_name: strdup failed");
		return (0);
	}
	offset = strlen(s) + 1;
	len = cookie->n_len - offset;
	(void) memmove(cookie->n_bytes, cookie->n_bytes + offset, len);
	cookie->n_len = (uint_t)len;

	return (s);
}

/*
 * We store a server name in a cookie along with the "real"
 * cookie from the NIS server.  The new cookie will include
 * the server name (null-terminated) with the "real" cookie
 * following it.  If we can't allocate memory, we set the
 * cookie length to 0 to indicate that it is an invalid cookie.
 */
static
void
name_to_cookie(char *name, nis_result *res)
{
	size_t len;
	size_t offset;
	netobj *cookie = &res->cookie;
	char *p;

	offset = strlen(name) + 1;
	len = offset + res->cookie.n_len;
	p = malloc(len);
	if (p == 0) {
		cookie->n_len = 0;    /* indicates a bad cookie */
		syslog(LOG_ERR, "name_to_cookie: malloc failed");
		return;
	}
	(void) strcpy(p, name);
	(void) memmove(p+offset, res->cookie.n_bytes, res->cookie.n_len);
	free(res->cookie.n_bytes);
	res->cookie.n_bytes = p;
	res->cookie.n_len = (uint_t)len;
}

/*
 * nis_ibops()
 *
 * This generic function calls all of the table operations.
 *
 * Note that although we use a virtual circuit, there are no keepalives.
 * Because of this, the length of the timeout is vital, and we attempt
 * to tune it here for the various operations.
 */

/* a single modify has been seen to take as long as 180 sec. */
#define	NIS_MODIFY_TIMEOUT	300 /* 5 minutes */

/* netgroup.org_dir.ssi has 48K entries, and will take almost this long */
#define	NIS_REMOVE_MULT_TIMEOUT	(2*60*60) /* 2 hours */

static nis_result *
nis_ibops(ib_request *req, rpcproc_t func)
{
	nis_result		*res;
	nis_object		*obj = NULL;
	nis_name		oname, odomain;
	nis_name		oowner, ogroup;
	nis_name		tname;
	char			nname[NIS_MAXNAMELEN], ndomain[NIS_MAXNAMELEN];
	int			timeout = NIS_GEN_TIMEOUT;	/* in seconds */
	nis_error		call_err;
	nis_call_state		state;
	int			make_cookie = FALSE;
	char			*server_name = NULL;
	uint_t			flags = 0;
	int			times = 0;
	extern char *__nis_server_name(nis_call_state *);

	if (req->ibr_obj.ibr_obj_len) {
		/*
		 * Enforce correct name policy on objects stored into
		 * tables. This code insures that zo_name and zo_domain
		 * are correct.
		 */
		obj = req->ibr_obj.ibr_obj_val;
		oname = obj->zo_name;
		tname = nis_leaf_of(req->ibr_name);
		if (tname == NULL || strlcpy(nname, tname, sizeof (nname)) >=
				sizeof (nname))
			return (nis_make_error(NIS_BADNAME, 0, 0, 0, 0));
		obj->zo_name = nname;
		odomain = obj->zo_domain;
		tname = nis_domain_of(req->ibr_name);
		if (tname == NULL || strlcpy(ndomain, tname,
				sizeof (ndomain)) >= sizeof (ndomain))
			return (nis_make_error(NIS_BADNAME, 0, 0, 0, 0));
		obj->zo_domain = ndomain;
		if (ndomain[strlen(ndomain)-1] != '.' &&
				strlcat(ndomain, ".", sizeof (ndomain)) >=
					sizeof (ndomain))
			return (nis_make_error(NIS_BADNAME, 0, 0, 0, 0));

		oowner = obj->zo_owner;
		if (obj->zo_owner == 0)
			obj->zo_owner = nis_local_principal();

		ogroup = obj->zo_group;
		if (obj->zo_group == 0)
			obj->zo_owner = nis_local_group();
	}

	res = calloc(1, sizeof (nis_result));
	if (res == NULL)
		return (nis_make_error(NIS_NOMEMORY, 0, 0, 0, 0));

	/* determine the timeout (heuristic) */
	switch (func) {
	    case NIS_IBMODIFY:
		flags = MASTER_ONLY;
		timeout = NIS_MODIFY_TIMEOUT;
		break;
	    case NIS_IBREMOVE:
		flags = MASTER_ONLY;
		if (req->ibr_flags & REM_MULTIPLE)
			timeout = NIS_REMOVE_MULT_TIMEOUT;
		else
			timeout = NIS_MODIFY_TIMEOUT;
		break;
	    case NIS_IBFIRST:
		make_cookie = TRUE;
		break;
	    case NIS_IBNEXT:
		make_cookie = TRUE;
		server_name = cookie_to_name(&req->ibr_cookie);
		if (server_name == 0)
			return (nis_make_error(NIS_NOMEMORY, 0,
				__stop_clock(CLOCK_CLIENT), 0, 0));
		break;
	    default:
		flags = MASTER_ONLY;
		timeout = NIS_GEN_TIMEOUT;
		break;
	}

	__nis_init_call_state(&state);
	state.name = req->ibr_name;
	state.flags = flags;
	state.timeout.tv_sec = timeout;
	state.timeout.tv_usec = 0;
	state.parent_first = 1;
	state.server_name = server_name;

again:
	call_err = nis_call(&state, func,
			(xdrproc_t)xdr_ib_request, (char *)req,
			(xdrproc_t)xdr_nis_result, (char *)res);
	if (call_err == NIS_SUCCESS && res->status == NIS_NOTMASTER &&
	    times++ < MAX_NOTMASTER)
		goto again;
	res->aticks = state.aticks;
	if (make_cookie) {
		if (server_name == NULL)
			server_name = __nis_server_name(&state);
		if (server_name != NULL)
			name_to_cookie(server_name, res);
	}
	if (server_name != NULL)
		free(server_name);
	__nis_reset_call_state(&state);

	if (obj) {
		obj->zo_name = oname;
		obj->zo_domain = odomain;
		obj->zo_owner = oowner;
		obj->zo_group = ogroup;
	}
	if (call_err)
		res->status = call_err;
	return (res);
}


/*
 * nis_add_entry()
 *
 * This function will add an entry to the named NIS table.
 */
nis_result *
nis_add_entry(
	nis_name	name,		/* Table to use 		*/
	nis_object	*obj,		/* Entry object to add. 	*/
	uint_t		flags)		/* Semantic modification flags	*/
{
	nis_result	*res;
	ib_request	req;
	nis_error	stat;

	(void) __start_clock(CLOCK_CLIENT);
	__nis_CacheStart();
	if (__nis_debug_calls) {
		(void) fprintf(__nis_debug_file,
		    "nis_add_entry(%s, 0x%p, 0x%x\n", name?name:"(nil)",
		    (void *)obj, flags);
	}
	stat = nis_get_request(name, obj, NULL, &req);
	if (stat != NIS_SUCCESS) {
		res = nis_make_error(stat, 0, __stop_clock(CLOCK_CLIENT), 0, 0);
		if (__nis_debug_calls)
			__nis_print_result(res);
		return (res);
	}
	req.ibr_flags = flags;
	res = nis_ibops(&req, NIS_IBADD);
	nis_free_request(&req); /* free up memory associated with request */
	res->cticks += __stop_clock(CLOCK_CLIENT);
	if (__nis_debug_calls)
		__nis_print_result(res);
	return (res);
}

/*
 * nis_remove_entry()
 *
 * This function will remove an entry to the named NIS table.
 */
nis_result *
nis_remove_entry(
	nis_name	name,		/* Table to use 		*/
	nis_object	*obj,		/* Entry object to remove. 	*/
	uint_t		flags)		/* semantic modification flags	*/
{
	nis_result	*res;
	ib_request	req;
	nis_error	stat;

	(void) __start_clock(CLOCK_CLIENT);
	__nis_CacheStart();
	if (__nis_debug_calls) {
		(void) fprintf(__nis_debug_file,
		    "nis_remove_entry(%s, 0x%p, 0x%x)\n", name?name:"(nil)",
		    (void *)obj, flags);
	}
	stat = nis_get_request(name, obj, NULL, &req);
	if (stat != NIS_SUCCESS) {
		res = nis_make_error(stat, 0, __stop_clock(CLOCK_CLIENT), 0, 0);
		if (__nis_debug_calls)
			__nis_print_result(res);
		return (res);
	}

	req.ibr_flags = flags;
	res = nis_ibops(&req, NIS_IBREMOVE);
	nis_free_request(&req); /* free up memory associated with request */
	res->cticks += __stop_clock(CLOCK_CLIENT);
	if (__nis_debug_calls)
		__nis_print_result(res);
	return (res);
}

/*
 * nis_modify_entry()
 *
 * This function will modify an entry to the named NIS table.
 */
nis_result *
nis_modify_entry(
	nis_name	name,		/* Table to use 		*/
	nis_object	*obj,		/* Entry object to modify. 	*/
	uint_t		flags)		/* Semantic modification flags	*/
{
	nis_result	*res;
	ib_request	req;
	nis_error	stat;

	(void) __start_clock(CLOCK_CLIENT);
	__nis_CacheStart();
	if (__nis_debug_calls) {
		(void) fprintf(__nis_debug_file,
		    "nis_modify_entry(%s, 0x%p, 0x%x)\n", name?name:"(nil)",
		    (void *)obj, flags);
	}
	stat = nis_get_request(name, obj, NULL, &req);
	if (stat != NIS_SUCCESS) {
		res = nis_make_error(stat, 0, __stop_clock(CLOCK_CLIENT), 0, 0);
		if (__nis_debug_calls)
			__nis_print_result(res);
		return (res);
	}

	req.ibr_flags = flags;
	res = nis_ibops(&req, NIS_IBMODIFY);
	nis_free_request(&req); /* free up memory associated with request */
	res->cticks += __stop_clock(CLOCK_CLIENT);
	if (__nis_debug_calls)
		__nis_print_result(res);
	return (res);
}

/*
 * nis_first_entry()
 *
 * This function will fetch the "first" entry in a table.
 */
nis_result *
nis_first_entry(nis_name table)		/* Table to read 	*/
{
	nis_result	*res;
	ib_request	req;
	nis_error	stat;

	(void) __start_clock(CLOCK_CLIENT);
	__nis_CacheStart();
	if (__nis_debug_calls) {
		(void) fprintf(__nis_debug_file, "nis_first_entry(%s)\n",
		    table);
	}
	stat = nis_get_request(table, NULL, NULL, &req);
	if (stat != NIS_SUCCESS) {
		res = nis_make_error(stat, 0, __stop_clock(CLOCK_CLIENT), 0, 0);
		if (__nis_debug_calls)
			__nis_print_result(res);
		return (res);
	}

	if (req.ibr_srch.ibr_srch_len) {
		res = nis_make_error(NIS_TOOMANYATTRS, 0,
				__stop_clock(CLOCK_CLIENT), 0, 0);
		if (__nis_debug_calls)
			__nis_print_result(res);
		return (res);
	}

	res = nis_ibops(&req, NIS_IBFIRST);
	nis_free_request(&req);
	/* XXX at this point we should put the server in the cookie. */
	/* free up memory associated with request */
	res->cticks += __stop_clock(CLOCK_CLIENT);
	if (__nis_debug_calls)
		__nis_print_result(res);
	return (res);
}

/*
 * nis_next_entry()
 *
 * This function will fetch the "first" entry in a table.
 */
nis_result *
nis_next_entry(
	nis_name	table,		/* Table to read 	*/
	netobj		*cookie)	/* First/Next Cookie	*/
{
	nis_result	*res;
	ib_request	req;
	nis_error	stat;

	(void) __start_clock(CLOCK_CLIENT);
	__nis_CacheStart();
	if (__nis_debug_calls) {
		(void) fprintf(__nis_debug_file, "nis_next_entry(%s, 0x%p)\n",
			table, (void *)cookie);
	}
	stat = nis_get_request(table, NULL, cookie, &req);
	if (stat != NIS_SUCCESS) {
		res = nis_make_error(stat, 0, __stop_clock(CLOCK_CLIENT), 0, 0);
		if (__nis_debug_calls)
			__nis_print_result(res);
		return (res);
	}

	res = nis_ibops(&req, NIS_IBNEXT);
	/* free up memory associated with request */
	nis_free_request(&req);
	res->cticks += __stop_clock(CLOCK_CLIENT);
	if (__nis_debug_calls)
		__nis_print_result(res);
	return (res);
}

nis_result *
nis_checkpoint(nis_name name)
{
	nis_result *res;
	cp_result cpr;
	nis_error call_err;
	nis_call_state state;
	int times = 0;

	(void) __start_clock(CLOCK_CLIENT);

	res = calloc(1, sizeof (nis_result));
	if (res == NULL) {
		(void) __stop_clock(CLOCK_CLIENT);
		return (NULL);
	}

	__nis_init_call_state(&state);
	state.name = name;
	state.flags = MASTER_ONLY;
again:
	call_err = nis_call(&state, NIS_CHECKPOINT,
			(xdrproc_t)xdr_nis_name, (char *)&name,
			(xdrproc_t)xdr_cp_result, (char *)&cpr);
	if (call_err == NIS_SUCCESS && cpr.cp_status == NIS_NOTMASTER &&
	    times++ < MAX_NOTMASTER)
		goto again;
	res->zticks = cpr.cp_zticks;
	res->dticks = cpr.cp_dticks;
	res->cticks = __stop_clock(CLOCK_CLIENT);
	res->aticks = state.aticks;
	__nis_reset_call_state(&state);
	if (call_err != NIS_SUCCESS)
		res->status = call_err;
	return (res);
}

/*
 * nis_mkdir()
 *
 * This function is designed to allow a client to remotely create
 * a directory on a NIS server. When the server is contacted, it
 * will look up the directory object and determine if it should
 * really execute this command and if it should then everythings
 * cool. It returns an error if it can't create the directory.
 */

nis_error
nis_mkdir(nis_name name, nis_server *srv)
{
	nis_error err;
	nis_error call_err;
	nis_call_state state;

	__nis_CacheStart();
	if (__nis_debug_calls) {
		(void) fprintf(__nis_debug_file, "nis_mkdir(%s, %s)\n",
			name, srv->name);
	}
	__nis_init_call_state(&state);
	state.srv = srv;
	state.nsrv = 1;
	call_err = nis_call(&state, NIS_MKDIR,
			(xdrproc_t)xdr_nis_name, (char *)&name,
			(xdrproc_t)xdr_nis_error, (char *)&err);
	__nis_reset_call_state(&state);
	if (call_err != NIS_SUCCESS)
		err = call_err;
	if (__nis_debug_calls) {
		(void) fprintf(__nis_debug_file, "status=%s\n",
		    nis_sperrno(err));
	}
	return (err);
}

/*
 * nis_rmdir()
 *
 * This function is designed to allow a client to remotely remove
 * a directory on a NIS server. When the server is contacted, it
 * will look up the directory object and determine if it should
 * really execute this command and if it should then everythings
 * cool. It returns an error if it can't remove the directory.
 */

nis_error
nis_rmdir(nis_name name, nis_server *srv)
{
	nis_error err;
	nis_error call_err;
	nis_call_state state;

	__nis_CacheStart();
	if (__nis_debug_calls) {
		(void) fprintf(__nis_debug_file, "nis_rmdir(%s, %s)\n",
			name, srv->name);
	}
	__nis_init_call_state(&state);
	state.srv = srv;
	state.nsrv = 1;
	call_err = nis_call(&state, NIS_RMDIR,
		    (xdrproc_t)xdr_nis_name, (char *)&name,
		    (xdrproc_t)xdr_nis_error, (char *)&err);
	__nis_reset_call_state(&state);
	if (call_err != NIS_SUCCESS)
		err = call_err;
	if (__nis_debug_calls) {
		(void) fprintf(__nis_debug_file, "status=%s\n",
		    nis_sperrno(err));
	}
	return (err);
}

nis_error
__nis_send_msg(nis_server *srv, int proc, xdrproc_t out, char *msg)
{
	nis_error err;
	nis_error call_err;
	nis_call_state state;

	__nis_CacheStart();
	if (__nis_debug_calls) {
		(void) fprintf(__nis_debug_file, "nis_send_msg(%s, %d)\n",
			srv->name, proc);
	}
	__nis_init_call_state(&state);
	state.srv = srv;
	state.nsrv = 1;
	state.timeout.tv_sec = 0;
	state.timeout.tv_usec = 0;
	call_err = nis_call(&state, proc,
		    out, msg,
		    (xdrproc_t)0, (char *)0);
	__nis_reset_call_state(&state);
	if (call_err != NIS_SUCCESS)
		err = call_err;
	if (__nis_debug_calls) {
		(void) fprintf(__nis_debug_file, "status=%s\n",
		    nis_sperrno(err));
	}
	return (err);
}

/*
 * A version of nis_list that takes a callback function, but doesn't do
 * callbacks over the wire (it gets the objects in the reply and then
 * feeds them to the callback function itself).
 */

nis_result *
__nis_list_localcb(
	nis_name	name,	/* list name like '[foo=bar].table.name' */
	uint_t		flags,		/* Flags for the search */
	int		(*cback)(),	/* Callback function. */
	void		*cbdata)	/* Callback private data */
{
	nis_result *res;
	int no;
	nis_object *o;
	char *tab;
	int i;

	/*
	 * Do list without callbacks
	 */
	if ((res = nis_list(name, flags, 0, 0)) == 0)
		return (0);

	/*
	 * Run callback locally
	 */
	if (cback)
		switch (res->status) {
		case NIS_SUCCESS:
		case NIS_S_SUCCESS:
			/*
			 * Always at least one object on success
			 */
			no = res->objects.objects_len;
			o = res->objects.objects_val;
			/*
			 * Figure out the table name
			 */
			if (tab = strchr(name, ']')) {
				tab++;
				while (isspace(*tab) || (*tab == ','))
					tab++;
			} else
				tab = name;
			/*
			 * Run callback
			 */
			for (i = 0; i < no; i++) {
				if ((*cback)(tab, &(o[i]), cbdata))
					break;
			}
			/*
			 * Free objects
			 */
			for (i = 0; i < no; i++)
				xdr_free(xdr_nis_object, (char *)&(o[i]));
			free(res->objects.objects_val);
			/*
			 * Fixup result
			 */
			res->objects.objects_len = 0;
			res->objects.objects_val = 0;
			res->status = NIS_CBRESULTS;
			break;
		};

	return (res);
}
