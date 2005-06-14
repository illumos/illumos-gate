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
 * Copyright (c) 1990-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Ported from :
 *	"@(#)nis_ns_proc.c 1.15 91/03/01 Copyr 1990 Sun Micro";
 *
 *	nis_ns_proc.c
 *
 * This module contains the actual implementation of NIS version 3.
 * NB : It provides the routines that the dispatch function in nis_svc.c
 * call. That file, nis_svc.c, is automatically generated and reflects the
 * interface definition that is described in the nis.x file. When the
 * nis.x file changes, you must make sure that any parameters that change
 * get reflected in these routines.
 *
 * This module contains the Namespace manipulation procedures.
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
#include "nis_proc.h"

extern bool_t	xdr_nis_result();

extern nis_object* get_root_object();
extern int update_root_object(nis_name, nis_object *);
extern void add_pingitem_with_name(char *buf, nis_object *dir,
				    u_long ptime, NIS_HASH_TABLE *tbl);
extern nis_name __nis_local_root();
extern char *relative_name();

/*
 * Handle the case in which we have the directory object but not its table.
 * It is called when we try to lookup an item and get back a NIS_NOSUCHTABLE.
 * On master, table should always exist; missing due to a mkdir failure
 *	master: create table & return (item) not found
 *	master & readonly: return system error
 * On replica: indicates we have not seen directory's update yet.
 *	replica: add to pinglist and return NIS_NOT_ME
 *	replica & readonly: return NIS_NOT_ME
 */
nis_error
recover_from_no_table(nis_object* d_obj, nis_name dirname)
{
	if (we_serve(&(d_obj->DI_data), MASTER_ONLY)) {
		if (readonly)
			return (NIS_TRYAGAIN);
		else {
			/* create table */
			nis_error status;

			if ((status = db_create(dirname, &tbl_prototype)) !=
			    NIS_SUCCESS) {
				syslog(LOG_ERR,
					"Unable to create table %s: %s.",
					dirname, nis_sperrno(status));
				return (status);
			} else
				return (NIS_SUCCESS);
		}
	} else {
		/* replica */
		if (!readonly) /* force update */
			add_pingitem(d_obj, time(0), &upd_list);
		return (NIS_NOT_ME);
	}
}

/*
 * nis_lookup is the basic function used by clients of the name service.
 * This function translates the request into an access of the local
 * database.
 */
nis_result *
nis_lookup_svc(argp, reqstp)
	ns_request *argp;
	struct svc_req *reqstp;
{
	nis_result	*res;
	nis_db_result	*dbres;
	nis_object	*d_obj = 0;
	char		pname[1024];
	struct ticks	t;
	int		read_dir,	/* read access on directory */
			read_obj;	/* read access on an object */
	nis_error	xx;
	char		*p;

	if (verbose)
		syslog(LOG_INFO, "LOOKUP_SVC : '%s'", argp->ns_name);
	__start_clock(0);
	res = (nis_result *)XCALLOC(1, sizeof (nis_result));
	add_cleanup((void (*)()) XFREE, (char *)(res), "ns_lookup result");

	if (reqstp)
		nis_getprincipal(pname, reqstp);
	else
		pname[0] = '\0';

	if ((p = relative_name(argp->ns_name)) == NULL) {
		int want_root;
		nis_name root_dir = __nis_local_root();

		want_root = root_dir &&
			(nis_dir_cmp(argp->ns_name, root_dir) == SAME_NAME);
		if (!want_root)
			res->status = NIS_NOT_ME;
		else {
			if (! root_server) {
				/* maybe we have been added */
				xx = __directory_object(argp->ns_name,
							&t, 0, &d_obj);
				res->aticks = t.aticks;
				res->dticks = t.dticks;
				res->zticks = t.zticks;
				res->cticks = t.cticks;
				if (d_obj == NULL)
					res->status = NIS_NOT_ME;
				else {
					/* make copy to be returned */
					nis_object* clone;

					clone = nis_clone_object(d_obj, 0);
					d_obj = clone;
				}
			} else {
				d_obj = get_root_object();
				if (d_obj == NULL)
					res->status = NIS_NAMEUNREACHABLE;
			}

			if (d_obj) {
				read_dir = __can_do(NIS_READ_ACC,
						    d_obj->zo_access,
						    d_obj, pname);
				if (! read_dir) {
					res->status = NIS_PERMISSION;
					nis_destroy_object(d_obj);
				} else {
					NIS_RES_OBJECT(res) = d_obj;
					NIS_RES_NUMOBJ(res) = 1;
					res->status = NIS_SUCCESS;
					add_cleanup(nis_destroy_object,
						(char *)(d_obj),
						"ns_lookup objects");
				}
			}
		}
		res->zticks = __stop_clock(0);
		return (res);
	}
	free((void *)p);

	/*
	 * Make sure we are allowed to READ this directory.
	 *
	 * POLICY: servers _must_ be able to read their own directory
	 * objects.
	 */
	xx = __directory_object(nis_domain_of(argp->ns_name), &t, 0, &d_obj);
	res->aticks = t.aticks;
	res->dticks = t.dticks;
	res->zticks = t.zticks;
	res->cticks = t.cticks;
	if (d_obj == NULL) {
		res->status = xx;  /* status from __directory_object call */
		res->zticks = __stop_clock(0);
		return (res);
	}

	read_dir = __can_do(NIS_READ_ACC, d_obj->zo_access, d_obj, pname);

	/* Look it up in the data base */
	dbres = db_lookup(argp->ns_name);
	if (dbres->status != NIS_SUCCESS) {
		if (dbres->status == NIS_NOSUCHTABLE) {
			/* This means table of domain does not exist */
			dbres->status =
			recover_from_no_table(d_obj,
					    nis_domain_of(argp->ns_name));
			/* for sure, argp->ns_name will not be there */
			if (dbres->status == NIS_SUCCESS)
				dbres->status = NIS_NOTFOUND;
		}
		if (read_dir) {
			res->status = dbres->status;
			res->dticks = dbres->ticks;
		} else {
			res->status = NIS_PERMISSION;
			res->dticks = 0;
		}
		res->zticks = __stop_clock(0);
		if (verbose)
			syslog(LOG_INFO, "nis_lookup : exit status %s",
						nis_sperrno(res->status));
		return (res);
	}

	read_obj = __can_do(NIS_READ_ACC, dbres->obj->zo_access,
						dbres->obj, pname);

	if (! read_dir && ! read_obj) {
		res->status = NIS_PERMISSION;
		res->zticks = __stop_clock(0);
		if (verbose)
			syslog(LOG_INFO,
				"nis_lookup : exit status PERMISSION DENIED");
		return (res);
	}

	res->status = NIS_SUCCESS;
	res->objects.objects_len = 1;
	res->objects.objects_val = dbres->obj;
	res->dticks = dbres->ticks;
	res->zticks = __stop_clock(0);

	if (verbose)
		syslog(LOG_INFO, "nis_lookup : exit status %s",
						nis_sperrno(res->status));

	return (res);
}

/*
 * Internal function that adds an object into the namespace.
 */
static void
add_object(name, obj, dobj, princp, res)
	nis_name	name;
	nis_object	*obj,
			*dobj;
	nis_name	princp;
	nis_result	*res;
{
	directory_obj	*d;
	nis_db_result	*dbres;
	u_long		xid, ttime;
	int		i;
	int		add_ok = 0;

	/*
	 * d points at the directory specific information
	 */
	d = &(dobj->DI_data);

	dbres = db_lookup(name);
	res->dticks += dbres->ticks;
	if (dbres->status != NIS_NOTFOUND) {
		if (dbres->status == NIS_SUCCESS)
			res->status = NIS_NAMEEXISTS;
		else
			res->status = dbres->status;
		return;
	}

	/*
	 * If we are adding a directory, make sure that it is a legitimate
	 * name, i.e. the new directory must be a descendant of the domain
	 * whose server is making this request.  If we are in the root domain,
	 * then we can add a new directory object in the same domain.
	 */
	if (__type_of(obj) == NIS_DIRECTORY_OBJ) {
	    switch (nis_dir_cmp(obj->DI_data.do_name, dobj->DI_data.do_name)) {
		case LOWER_NAME:
		    break;
		case SAME_NAME:
		    if (root_server) break;
		default:
		    res->status = NIS_BADNAME;
		    return;
	    }
	}

	/*
	 * Verify access rights. Check first to see if the directory object
	 * grants the right. If not, then check to see if the object access
	 * rights for that type of object grant the right. And if that
	 * doesn't then abort with PERMISSION denied.
	 */
	add_ok = __can_do(NIS_CREATE_ACC, dobj->zo_access, dobj, princp);
	if (! add_ok) {
		if (auth_verbose) {
			syslog(LOG_INFO,
			    "add_object : create DENIED by directory %s.%s",
						dobj->zo_name, dobj->zo_domain);
		}
		for (i = 0; i < d->do_armask.do_armask_len; i++) {
			if (obj->zo_data.zo_type == OATYPE(d, i)) {
				add_ok = __can_do(NIS_CREATE_ACC,
						OARIGHTS(d, i), dobj, princp);
				if (auth_verbose) {
					syslog(LOG_INFO,
				    "add_object : create %s by object type.",
					(add_ok) ? "ALLOWED" : "DENIED");
				}
				break;
			}
		}
	} else if (auth_verbose) {
		syslog(LOG_INFO,
			"add_object : create is ALLOWED by the directory.");
	}

	if (! add_ok) {
		res->status = NIS_PERMISSION;
		return;
	}

	/*
	 * Start the transaction, if we can't get an XID abort
	 */
	xid = begin_transaction(princp);
	if (! xid) {
		res->status = NIS_TRYAGAIN;
		return;
	}

	/* Do the add operation */
	obj->zo_oid.ctime = (unsigned long)time(0);
	obj->zo_oid.mtime = obj->zo_oid.ctime;
	dbres = db_add(name, obj, 0);
	res->dticks += dbres->ticks;
	res->status = dbres->status;
	if (res->status != NIS_SUCCESS)
		abort_transaction(xid);
	else {
		ttime = (u_long)(time(0));
		end_transaction(xid); /* COMMIT */
		/* Notify replicates of the change. */
		if (dobj->DI_data.do_servers.do_servers_len > 1)
			add_pingitem(dobj, ttime, &ping_list);
	}
	return;

}

/*
 * Internal function that removes an object from the namespace.
 */
static void
remove_object(name, obj, dobj, princp, res)
	nis_name	name;
	nis_object	*obj,
			*dobj;
	nis_name	princp;
	nis_result	*res;
{
	directory_obj	*d;
	nis_object	*old;
	nis_db_result	*dbres;
	u_long		xid, ttime;
	int		i, rem_ok;

	/*
	 * d points at the directory specific information
	 */
	d = &(dobj->DI_data);

	dbres = db_lookup(name);
	res->dticks += dbres->ticks;
	if (dbres->status != NIS_SUCCESS) {
		res->status = dbres->status;
		return;
	}

	/* This is the existing object in the database */
	old = dbres->obj;

	if (obj && ! same_oid(obj, old)) {
		res->status = NIS_NOTSAMEOBJ;
		return;
	}

	/*
	 * Verify delete access rights. Check first to see if the directory
	 * object grants the right. If not, then check to see if the object
	 * itself grants the right, then finally check to see of we have
	 * this access right for this type of object.
	 */
	rem_ok = __can_do(NIS_DESTROY_ACC, dobj->zo_access, dobj, princp);
	if (auth_verbose) {
		syslog(LOG_INFO,
			    "remove_object : destroy %s by directory %s.%s",
					(rem_ok) ? "ALLOWED" : "DENIED",
					dobj->zo_name, dobj->zo_domain);
	}
	if (! rem_ok) {
		rem_ok = __can_do(NIS_DESTROY_ACC, old->zo_access, old, princp);
		if (auth_verbose) {
			syslog(LOG_INFO,
			    "remove_object : destroy %s by object %s.%s",
					(rem_ok) ? "ALLOWED" : "DENIED",
					old->zo_name, old->zo_domain);
		}
	}

	if (! rem_ok) {
		for (i = 0; i < d->do_armask.do_armask_len; i++) {
			if (old->zo_data.zo_type == OATYPE(d, i)) {
				rem_ok =  __can_do(NIS_DESTROY_ACC,
						OARIGHTS(d, i), dobj, princp);
				break;
			}
		}
	}
	if (! rem_ok) {
		res->status = NIS_PERMISSION;
		if (auth_verbose) {
			syslog(LOG_INFO,
			    "remove_object : destroy DENIED by object type.");
		}
		return;
	} else if (auth_verbose) {
			syslog(LOG_INFO,
			    "remove_object : destroy ALLOWED by object type.");
		}

	/*
	 * Start the transaction, if we can't get an XID abort
	 */
	xid = begin_transaction(princp);
	if (! xid) {
		res->status = NIS_TRYAGAIN;
		return;
	}

	/* Do the remove operation */
	dbres = db_remove(name, old, time(0));
	res->dticks += dbres->ticks;
	res->status = dbres->status;
	if (res->status != NIS_SUCCESS)
		abort_transaction(xid);
	else {
		ttime = (u_long)(time(0));
		end_transaction(xid); /* COMMIT */
		/* Notify replicates of the change. */
		if (dobj->DI_data.do_servers.do_servers_len > 1)
			add_pingitem(dobj, ttime, &ping_list);
		/*
		 * No need to flush the caches - they have been flushed
		 * inside db_remove
		 */
	}
}

/* macro to get to the table column structures */
#define	TABLE_COL(o, n) o->TA_data.ta_cols.ta_cols_val[n]

/*
 * Internal function that modifies an object in the namespace.
 */
static void
modify_object(name, obj, dobj, princp, res)
	nis_name	name;
	nis_object	*obj,
			*dobj;
	nis_name	princp;
	nis_result	*res;
{
	directory_obj	*d;
	nis_object	*old;
	nis_db_result	*dbres;
	u_long		xid, ttime;
	int		i, mod_ok;
	log_entry	le;
	nis_object	mod_obj;

	/*
	 * d points at the directory specific information
	 */
	d = &(dobj->DI_data);

	dbres = db_lookup(name);
	res->dticks += dbres->ticks;
	if (dbres->status != NIS_SUCCESS) {
		res->status = dbres->status;
		return;
	}

	/* This is the existing object in the database */
	old = dbres->obj;

	/*
	 * Verify modify access rights. Check first to see if the directory
	 * object grants the right. If not, then check to see if the object
	 * itself grants the right, then finally check to see if we have
	 * this access right for this type of object.
	 */
	mod_ok = __can_do(NIS_MODIFY_ACC, dobj->zo_access, dobj, princp);
	if (auth_verbose) {
		syslog(LOG_INFO,
			    "modify_object : modify %s by directory %s.%s",
					(mod_ok) ? "ALLOWED" : "DENIED",
					dobj->zo_name, dobj->zo_domain);
	}
	if (! mod_ok) {
		mod_ok = __can_do(NIS_MODIFY_ACC, old->zo_access, old, princp);
		if (auth_verbose) {
			syslog(LOG_INFO,
			    "remove_object : modify %s by object %s.%s",
					(mod_ok) ? "ALLOWED" : "DENIED",
					old->zo_name, old->zo_domain);
		}
	}

	if (! mod_ok) {
		for (i = 0; i < d->do_armask.do_armask_len; i++) {
			if (old->zo_data.zo_type == OATYPE(d, i)) {
				if (! __can_do(NIS_MODIFY_ACC, OARIGHTS(d, i),
							dobj, princp)) {
					res->status = NIS_PERMISSION;
					if (auth_verbose) {
						syslog(LOG_INFO,
			    "modify_object : modify DENIED by object type.");
					}
					return;
				} else {
					if (auth_verbose) {
						syslog(LOG_INFO,
			    "modify_object : modify ALLOWED by object type.");
					}
					mod_ok = 1;
					break;
				}
			}
		}
	}
	/*
	 * if no one allows modify then fail.
	 */
	if (! mod_ok) {
		res->status = NIS_PERMISSION;
		return;
	}

	/*
	 * POLICY : Allow changing type ?
	 *
	 * ANSWER : No, only changing the meta data
	 * such as access etc is allowed.
	 */
	if (__type_of(old) != __type_of(obj)) {
		res->status = NIS_BADOBJECT;
		return;
	}

	if (nis_dir_cmp(old->zo_domain, obj->zo_domain) != SAME_NAME) {
		res->status = NIS_BADNAME;
		return;
	}

	/*
	 * Start the transaction, if we can't get an XID abort
	 */
	xid = begin_transaction(princp);
	if (! xid) {
		res->status = NIS_TRYAGAIN;
		return;
	}

	/*
	 * Now we generate a log entry with the old value so that if
	 * we crash, the transaction system can restore the object
	 * to its pre-modified state.
	 */
	memset((char *)&le, 0, sizeof (le));
	le.le_type = MOD_NAME_OLD;
	le.le_time = (u_long) (time(0));
	le.le_name = name;
	le.le_attrs.le_attrs_len = 0;
	le.le_object = *old;
	add_update(&le);

	mod_obj = *old;
	if (same_oid(old, obj)) {
		mod_obj.zo_owner  = obj->zo_owner;
		mod_obj.zo_group  = obj->zo_group;
		mod_obj.zo_access = obj->zo_access;
		mod_obj.zo_ttl    = obj->zo_ttl;
	} else if (obj->zo_oid.mtime || obj->zo_oid.ctime) {
		res->status = NIS_NOTSAMEOBJ;
		abort_transaction(xid);
		return;
	}

	/*
	 * Data replacement of the variant part.
	 * NOTE: We play games with TABLE objects because we can't
	 *	 allow their schema to change on the fly. But there are
	 *	 fields in the table data that _can_ change such as the
	 *	 path of the table, separator character, and access rights.
	 *
	 * As in the case of ENTRY objects, we let the 'same oid' test be
	 * the signal that it is ok to overwrite these variables. This
	 * is overloading the OID value but I can't think of any other
	 * way to signal this operation without changing the protocol at
	 * this point.
	 */
	if (__type_of(old) != NIS_TABLE_OBJ)
		mod_obj.zo_data = obj->zo_data;
	else if (same_oid(old, obj)) {
		mod_obj.TA_data.ta_path = obj->TA_data.ta_path;
		mod_obj.TA_data.ta_sep = obj->TA_data.ta_sep;
		mod_obj.TA_data.ta_type = obj->TA_data.ta_type;
		for (i = 0; i < mod_obj.TA_data.ta_maxcol; i++) {
			if (TABLE_COL(obj, i).tc_flags & TA_MODIFIED)
				TABLE_COL((&mod_obj), i).tc_rights =
					TABLE_COL(obj, i).tc_rights;
		}
	}

	mod_obj.zo_oid.mtime = (unsigned long)time(0);
	/*
	 * Now we add the object over the previous
	 * one. This instructs the database to
	 * discard the current one and replace it
	 * with our modified one. (And it's atomic)
	 */
	dbres = db_add(name, &mod_obj, 1);
	res->dticks += dbres->ticks;
	res->status = dbres->status;
	if (res->status != NIS_SUCCESS)
		abort_transaction(xid);
	else {
		nis_taglist	taglist;
		nis_tag		tags;

		ttime = (u_long)(time(0));
		end_transaction(xid); /* COMMIT */

		/* Notify replicates of the change. */
		if (dobj->DI_data.do_servers.do_servers_len > 1)
			add_pingitem(dobj, ttime, &ping_list);

		/*
		 * No need to flush the caches - they have been flushed
		 * inside db_remove
		 */
		if (__type_of(old) == NIS_DIRECTORY_OBJ) {
			/*
			 * Send all the servers that serve this particular
			 * directory object a flush_cache message.
			 * We dont do this for group and table caches because
			 * they are served by those servers; and we can
			 * just hope that they get the updates real fast.
			 * For Directory objects, since we dont want the servers
			 * to throw out the cached directory objects and then go
			 * and refresh it with the stale copies, we will use
			 * TAG_DCACHE_ONE_REFRESH which will
			 * get a fresh copy of the object from the master.
			 *
			 * XXX: Since we are sending this message to all
			 * servers (including MASTER), this will lead to
			 * multiple calls to the master.  One could have
			 * perhaps passed a modified directory object
			 * without the master.
			 */
			tags.tag_type = TAG_DCACHE_ONE_REFRESH;
			tags.tag_val = old->DI_data.do_name;
			taglist.tags.tags_len = 1;
			taglist.tags.tags_val = &tags;
			(void) nis_mcast_tags(&old->DI_data, &taglist);
		}
	}
}

/*
 * If prim and sec contain the same servers, return 0.
 * If sec contains different servers than prim, result is set to:
 *	<all prim servers> <sec servers that are not in prim's list>
 */
static int
merge_srv_list(directory_obj* prim, directory_obj* sec, nis_server**result)
{
	nis_server* answer = 0;
	int psize = prim->do_servers.do_servers_len;
	int ssize = sec->do_servers.do_servers_len;
	nis_server* prim_server = prim->do_servers.do_servers_val;
	nis_server* sec_server = sec->do_servers.do_servers_val;
	int i, j, diff = 0, newsize = 0, newadd;

	/* First count how many names in sec are different */
	for (i = 0; i < ssize; i++) {
		for (j = 0; j < psize; j++) {
			if (nis_dir_cmp(prim_server[j].name,
					sec_server[i].name) == SAME_NAME)
				break;
		}
		if (j == psize)
			++diff;
	}

	if (diff == 0)
		return (0);

	/* different names were found on sec_server list */
	newsize = psize+diff;
	answer = (nis_server*)malloc(newsize*sizeof (nis_server));

	if (answer == 0)
		return (0);

	/* Copy prim first */
	for (i = 0; i < psize; i++)
		answer[i] = prim_server[i];

	newadd = i;
	for (i = 0; i < ssize; i++) {
		for (j = 0; j < psize; j++) {
			if (nis_dir_cmp(prim_server[j].name,
					sec_server[i].name) == SAME_NAME)
				break;
		}
		if (j == psize)
			answer[newadd++] = sec_server[i];
	}

	*result = answer;
	return (newsize);
}

static void
modify_root_object(nis_name	name,
		nis_object	*obj,
		nis_name	princp,
		nis_result	*res)
{
	nis_object* oldroot = get_root_object();
	nis_object newroot;
	u_long ttime;

	if (! oldroot) {
		syslog(LOG_ERR, "Cannot read %s!", ROOT_OBJ);
		res->status = NIS_SYSTEMERROR;
		return;
	}

	if (__can_do(NIS_MODIFY_ACC, oldroot->zo_access, oldroot, princp)) {
		newroot = *oldroot;    /* copy all fields from old object */

		if (same_oid(oldroot, obj)) {
			/* updating non-data portion as well. */
			newroot.zo_owner  = obj->zo_owner;
			newroot.zo_group  = obj->zo_group;
			newroot.zo_access = obj->zo_access;
			newroot.zo_ttl    = obj->zo_ttl;
		} else if (obj->zo_oid.mtime || obj->zo_oid.ctime) {
			/* somehow got an outdated copy of object. */
			res->status = NIS_NOTSAMEOBJ;
			nis_destroy_object(oldroot);
			return;
		} /* else, only interested in changing data portion. */

		newroot.DI_data = obj->DI_data;  /* always update data */
		ttime = (u_long)(time(0));
		newroot.zo_oid.mtime = ttime;
		if (update_root_object(name, &newroot)) {
			nis_server* merged_srvs = 0;
			int howmany;

			howmany = merge_srv_list(&(newroot.DI_data),
						    &(oldroot->DI_data),
						    &merged_srvs);
			/* howmany is 0 if new and old list are the same */
			if (howmany > 0) {
				directory_obj *dobj = &(newroot.DI_data);
				dobj->do_servers.do_servers_val = merged_srvs;
				dobj->do_servers.do_servers_len = howmany;
			}
			if (newroot.DI_data.do_servers.do_servers_len > 1)
				add_pingitem_with_name(ROOT_OBJ,
							&newroot,
							ttime,
							&ping_list);
			if (merged_srvs)
				free(merged_srvs);
			res->status = NIS_SUCCESS;
		} else
			res->status = NIS_MODFAIL;
	} else
		res->status = NIS_PERMISSION;

	/* newroot just copies contents of other objects; need not be freed */
	nis_destroy_object(oldroot);
}

/*
 * __nis_nameops()
 *
 * This code actually implements the operation that is requested.
 * It is collected here in one place.
 */
static nis_result *
nis_nameops(op, name, obj, princp)
	int		op;	/* operation to perform		*/
	nis_name	name;	/* Object's name		*/
	nis_object	*obj;	/* Object to use (NULL for rem)	*/
	nis_name	princp;	/* Principal making the request */
{
	nis_result		*res;
	nis_object		*d_obj;
	struct ticks		t;
	nis_error		xx;
	char			optxt[32];

	res = (nis_result *)XCALLOC(1, sizeof (nis_result));
	add_cleanup((void (*)())XFREE, (char *)res, "nameops result");
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
		syslog(LOG_INFO, "Object operation '%s' for principal %s",
				optxt, princp);
	}

	if (((op == ADD_OP) || (op == MOD_OP)) && (obj == NULL)) {
		res->status = NIS_BADOBJECT;
		return (res);
	}

	/*
	 * don't allow an object to be added without an owner.
	 */
	if ((op == ADD_OP) && (strlen(obj->zo_owner) < 2)) {
		res->status = NIS_BADOBJECT;
		return (res);
	}

	/*
	 * We have to handle the root object specially if we want to
	 * manipulate it using the NIS code.
	 */
	if (root_server &&
	    (nis_dir_cmp(name, __nis_rpc_domain()) == SAME_NAME)) {

		/* All we allow is a modify */
		if (op != MOD_OP) {
			res->status = NIS_BADREQUEST;
			return (res);
		}
		modify_root_object(name, obj, princp, res);
		return (res);
	}

	/*
	 * Fetch the directory object for this domain.
	 */
	xx = __directory_object(nis_domain_of(name), &t, TRUE, &d_obj);
	res->aticks = t.aticks;
	res->dticks = t.dticks;
	res->zticks = t.zticks;
	res->cticks = t.cticks;
	if ((xx != NIS_SUCCESS) && (xx != NIS_S_SUCCESS)) {
		res->status = xx;
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

	switch (op) {
	case ADD_OP :
		add_object(name, obj, d_obj, princp, res);
		break;
	case REM_OP :
		remove_object(name, obj, d_obj, princp, res);
		break;
	case MOD_OP :
		modify_object(name, obj, d_obj, princp, res);
		break;
	}

	return (res);
}

/*
 * nis_add, this function will add a name to the name space if the
 * permissions are allowed. The object that is about to be added to
 * must allow "CREATE" access to the principal making the request.
 */
nis_result *
nis_add_svc(argp, reqstp)
	ns_request *argp;
	struct svc_req *reqstp;
{
	nis_result 		*res;
	char			pname[1024];
	char			*p;

	__start_clock(0);	/* Timing information */
	if (verbose)
		syslog(LOG_INFO, "ADD_SVC : '%s'", argp->ns_name);
	if ((p = relative_name(argp->ns_name)) == NULL)
		return (nis_make_error(NIS_BADNAME, 0, 0, 0, __stop_clock(0)));
	free((void *)p);

	nis_getprincipal(pname, reqstp);
	res = nis_nameops(ADD_OP, argp->ns_name,
					argp->ns_object.ns_object_val, pname);
	if (verbose)
		syslog(LOG_INFO, "nis_add : exit status %s",
			nis_sperrno(res->status));

	res->zticks += __stop_clock(0);
	return (res);
}

/*
 * nis_modify, this function modifies the contents of the object that
 * are named. It checks the MODIFY access right in the existing object
 * and then does the operation.
 */
nis_result *
nis_modify_svc(argp, reqstp)
	ns_request *argp;
	struct svc_req *reqstp;
{
	nis_result 		*res;
	char			pname[1024];
	char			*p = NULL;

	__start_clock(0);
	if (verbose)
		syslog(LOG_INFO, "MODIFY_SVC : '%s'", argp->ns_name);
	if (! root_server && ((p = relative_name(argp->ns_name)) == NULL))
		return (nis_make_error(NIS_BADNAME, 0, 0, 0, __stop_clock(0)));
	if (p)
		free((void *)p);

	nis_getprincipal(pname, reqstp);
	res = nis_nameops(MOD_OP, argp->ns_name,
					argp->ns_object.ns_object_val, pname);
	if (verbose)
		syslog(LOG_INFO, "nis_modify : exit status %s",
			nis_sperrno(res->status));
	res->zticks += __stop_clock(0);
	return (res);
}

/*
 * nis_remove removes and object from the name space. You will notice it
 * shares a lot of code with the Add and remove functions.
 */
nis_result *
nis_remove_svc(argp, reqstp)
	ns_request *argp;
	struct svc_req *reqstp;
{
	nis_result		*res;
	char			*principal, pname[1024];
	char			*p;

	__start_clock(0);
	if (verbose)
		syslog(LOG_INFO, "REMOVE_SVC : '%s'", argp->ns_name);
	if ((p = relative_name(argp->ns_name)) == NULL)
		return (nis_make_error(NIS_BADNAME, 0, 0, 0, __stop_clock(0)));
	free((void *)p);

	/*
	 * If 'reqstp' is NULL, we're being called internally, and supply
	 * the local principal.
	 */
	if (reqstp != 0) {
		nis_getprincipal(pname, reqstp);
		principal = pname;
	} else {
		principal = nis_local_principal();
	}
	res = nis_nameops(REM_OP, argp->ns_name,
					argp->ns_object.ns_object_val,
					principal);
	if (verbose)
		syslog(LOG_INFO, "nis_remove : exit status %s",
			nis_sperrno(res->status));
	res->zticks += __stop_clock(0);
	return (res);
}
