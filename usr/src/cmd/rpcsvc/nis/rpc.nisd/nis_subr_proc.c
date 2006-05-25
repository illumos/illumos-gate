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

/*
 * nis_subr_proc.c
 *
 * This module contains subroutines that are used by the NIS+ service but
 * _not_ the NIS+ clients.  NIS+ client routines are in the library module
 * nis_subr.c
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <pwd.h>
#include <thread.h>
#include <gssapi/gssapi.h>
#include <rpc/rpc.h>
#include <rpc/clnt.h>
#include <rpc/svc.h>
#include <rpc/auth.h>
#include <rpc/auth_sys.h>
#include <rpc/auth_des.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nis_callback.h>
#include <rpcsvc/nis_dhext.h>
#include <errno.h>
#include <sys/stat.h>
#include <limits.h>
#include <rpcsvc/nis_db.h>
#include "nis_svc.h"
/* nis_proc.h includes nis_mt.h */
#include "nis_proc.h"
#include "log.h"
#include "ldap_parse.h"
#include "ldap_util.h"
#include "nisdb_mt.h"

#define	GETSERVER(o, n) (((o)->DI_data.do_servers.do_servers_val) + n)
#define	MAXSERVER(o)    (o)->DI_data.do_servers.do_servers_len

extern void __nis_destroy_callback();
extern nis_result *nis_iblist_svc(), *nis_lookup_svc();
extern CLIENT *__nis_get_server(directory_obj *, int);
extern fd_result *__fd_res(nis_name, nis_error, directory_obj*);
extern nis_result *__nis_remote_lookup(ib_request *req, ulong_t flags,
		int list_op, void *cbdata, int (*cback)());
extern fd_result *__nis_finddirectory_remote(nis_bound_directory **binding,
		char *dname);

/* routines for registering server's availability wrt given dirctory */
extern db_status nis_put_offline(nis_name, bool_t);
extern db_status nis_put_online(nis_name, __nis_defer_t, bool_t);
extern nis_name __nis_local_root();

extern FILE *cons;

fd_result *dup_fdres(fd_result *, fd_result *);
static nis_error	apply_update(log_entry *);

struct directory_item {
	NIS_HASH_ITEM	dl_item;	/* Generic ITEM tag 	*/
	nis_object	*dl_obj;	/* Directory object	*/
	ulong_t		dl_expires;	/* Expiration time	*/
	ulong_t		dl_serve;	/* nonzero if we serve	*/
	ulong_t		*dl_stamps; 	/* Replica timestamps	*/
};
typedef	struct directory_item dirItem_t;

static NIS_HASH_TABLE *dl = NULL;
DECLRWLOCK(dl);

/*
 * Release cached directory object. Intended for use by the cleanup
 * code, executed when the thread is about to return to the RPC dispatch.
 */
void
dirCacheReleaseRO(void *ptr) {
	struct directory_item	*d = ptr;

	if (d != 0)
		(void) __nis_release_item(d, dl, 1);
}

void
dirCacheReleaseWR(void *ptr) {
	struct directory_item	*d = ptr;

	if (d != 0)
		(void) __nis_release_item(d, dl, -1);
}

/*
 * Called when function is done with the directory_item, but release
 * should be deferred until the thread is done with the current RPC
 * request, or exits.
 */
void
dirDeferRelease(struct directory_item *d, int wr) {
	if (d != 0) {
		if (wr) {
			add_cleanup(dirCacheReleaseWR, d, "dir obj from cache");
		} else {
			add_cleanup(dirCacheReleaseRO, d, "dir obj from cache");
		}
	}
}

/*
 * Destroy a directory cache item.
 */
void
destroyDirCacheItem(void *item) {
	struct directory_item	*d = item;

	if (d != 0) {
		if (d->dl_item.name != 0)
			free(d->dl_item.name);
		if (d->dl_stamps != 0)
			free(d->dl_stamps);
		if (d->dl_obj != 0)
			nis_destroy_object(d->dl_obj);
		free(d);
	}
}

/*
 * free_dlitem()
 *
 * This function will remove a directory_item from the cache. The memory
 * will be re-used when no thread is referencing it anymore.
 */
static void
free_dlitem(dd)
	struct directory_item	*dd;
{
	if (dd != 0)
		(void) nis_remove_item(dd->dl_item.name, dl);
}


/*
 * 1. Flush server's local directory cache.
 * 2. Flush cachemgr's cache, using one of the following
 *    a.  given directory object
 *    b.  if none given and directory is in local cache, use its dir object.
 *    c.  if directory is not in local cache, look it up from cachemgr,
 *		if found, delete it.
 * 3. Flush the associated table cache.
 */
void
flush_dircache(name, dobj)
	nis_name	name;
	directory_obj *dobj;
{
	struct directory_item	*dd;
	int cachemgr_updated = 0;

	if (verbose)
		syslog(LOG_INFO, "flush_dircache: name '%s'", name);

	/* Flush given directory object from cachemgr. */
	if (dobj) {
		__nis_CacheRemoveEntry(dobj);
		cachemgr_updated = 1;
	}

	/* Update server's local directory cache. */
	if (dl) {
		dd = (struct directory_item *)nis_find_item(name, dl);
		if (dd) {
			if (cachemgr_updated == 0) {
				__nis_CacheRemoveEntry(&(dd->dl_obj->DI_data));
				cachemgr_updated = 1;
			}
			free_dlitem(dd);
			__nis_release_item(dd, dl, -1);
		}
	}

	/* Update cachemgr if have not done so yet. */
	if (cachemgr_updated == 0) {
		directory_obj dobj2;
		if (__nis_CacheSearch(name, &dobj2) == NIS_SUCCESS &&
		    nis_dir_cmp(name, dobj2.do_name) == SAME_NAME) {
			__nis_CacheRemoveEntry(&dobj2);
			xdr_free((xdrproc_t)xdr_directory_obj, (char *)&dobj2);
		}
	}

	/*
	 * Since we cache the table for this dir object,
	 * we will flush that away as well.
	 */
	flush_tablecache(name);
}

void
flush_dircache_refresh(name)
	nis_name	name;
{
	struct ticks	t;
	nis_object	*obj;

	if (verbose)
		syslog(LOG_INFO, "flush_dircache_refresh: name '%s'", name);

	flush_dircache(name, (directory_obj *) NULL);	/* Flush it first */
	/*
	 * Refresh it from the master.
	 * XXX: We may have some scalability problems
	 * if all servers go to the master at the same time.  Hopefully
	 * directory objects would not be updated very frequently, so it
	 * should not be such a big problem.
	 */
	(void) __directory_object(name, &t, NO_CACHE, &obj);
}

/*
 * Flush all cached directory objects from dircache and cachemgr.
 */
void
flush_dircache_all()
{
	struct directory_item	*dd, *nxt;

	if (verbose)
		syslog(LOG_INFO, "flush_dircache_all");

	while ((dd = __nis_pop_item_mt(dl)) != 0) {
		/*
		 * Since a destructor is in effect for this list,
		 * we have nothing to do; 'dd' will be freed when
		 * it's no longer in use.
		 */
	}
}

void
flush_local_dircache(name)
	nis_name	name;
{
	struct directory_item	*dd;

	if (verbose)
		syslog(LOG_INFO, "flush_local_dircache: name '%s'", name);
	if (dl) {
		dd = (struct directory_item *)nis_find_item(name, dl);
		if (dd) {
			free_dlitem(dd);
			__nis_release_item(dd, dl, -1);
		}
	}
}

/*
 * Flushes the local TABLE cache.  Called when the database changes.
 */
void
flush_tablecache(name)
	nis_name	name;
{
	struct table_item	*ti;

	if (verbose)
		syslog(LOG_INFO, "flush_tablecache: name '%s'", name);
	if (table_cache) {
		ti = (struct table_item *)nis_remove_item(name, table_cache);
		/*
		 * We've established an item destructor for the table_cache,
		 * so the item will be destroyed automatically when it's
		 * no longer referenced.
		 */
	}
}

/*
 * Flushes all TABLE caches.
 */
void
flush_tablecache_all()
{
	struct table_item	*ti;

	if (verbose)
		syslog(LOG_INFO, "flush_tablecache_all");
	if (table_cache) {
		while (ti = (struct table_item *)nis_pop_item(table_cache)) {
			/*
			 * We've established an item destructor for the
			 * table_cache, so the item will be destroyed
			 * automatically when it's no longer referenced.
			 */
		}
	}
}

/*
 * Flushes a specific item from the group cache.
 */
void
flush_groupcache(name)
	nis_name	name;
{
	if (verbose)
		syslog(LOG_INFO, "flush_groupcache: name '%s'", name);

	__nis_flush_group_exp_name(name);
}

/*
 * Flushes all group caches.
 */
void
flush_groupcache_all()
{
	if (verbose)
		syslog(LOG_INFO, "flush_groupcache_all");

	nis_flushgroups();
}

extern enum clnt_stat __nis_cast_proc();

/*
 * A convenient wrapper around __nis_cast_proc().
 */
bool_t
nis_mcast_tags(dobj, tags)
	directory_obj	*dobj;
	nis_taglist	*tags;
{
	int i;
	int nsrv;
	nis_server *srv;

	if (dobj == NULL)
		return (FALSE);
	srv = dobj->do_servers.do_servers_val;
	nsrv = dobj->do_servers.do_servers_len;
	for (i = 0; i < nsrv; i++) {
		__nis_send_msg(&srv[i], NIS_SERVSTATE, xdr_nis_taglist, tags);
	}
	return (1);
}

/*
 * We need this function, since the root object is stored as a directory
 * obj structure and not a nis_object. directory_obj strucs don't have the
 * domain name.
 *
 * Note: Synchronization of access to 'tbl' is the responsibility of the
 *       caller.
 */
void
add_pingitem_with_name(buf, dir, ptime, tbl)
	char		*buf;
	nis_object	*dir;
	ulong_t		ptime;
	NIS_HASH_TABLE	*tbl;
{
	ping_item	*pp;

	pp = (ping_item *)nis_find_item(buf, tbl);
	if (pp) {
		if (verbose)
			syslog(LOG_INFO, "add_pingitem: updated %s", buf);
		switch (ldapConfig.updateBatching) {
		case upd_none:
			/*
			 * We're not accumulating updates, so we only allow
			 * the mtime to go backwards.
			 */
			if (ptime < pp->mtime) {
				pp->mtime = ptime;
				setPingWakeup(pp->mtime +
					updateBatchingTimeout());
			}
			break;
		case bounded_accumulate:
			/* Leave pp->mtime unchanged */
			break;
		case accumulate:
		default:
			if (ptime != pp->mtime) {
				pp->mtime = ptime;
				setPingWakeup(pp->mtime +
					updateBatchingTimeout());
			}
			break;
		}
		/*
		 * Reset update time and backoff delta, since it appears
		 * that we can talk to the master.
		 */
		pp->utime = 0;
		pp->delta = INIT_UPD_LIST_TIME_INCR;
		__nis_release_item(pp, tbl, -1);
		return;
	}

	pp = (ping_item *)XCALLOC(1, sizeof (ping_item));
	if (! pp) {
		if (verbose)
			syslog(LOG_ERR,
		    "add_pingitem: Couldn't add '%s' to pinglist (no memory)",
									buf);
		return;
	}
	pp->item.name = (nis_name) XSTRDUP(buf);
	if (pp->item.name == NULL) {
		if (verbose)
			syslog(LOG_ERR,
		    "add_pingitem: Couldn't add '%s' to pinglist (no memory)",
									buf);
		XFREE(pp);
		return;
	}
	pp->mtime = ptime;
	if (dir)
		pp->obj = nis_clone_object(dir, NULL);
	else
		pp->obj = NULL;
	/* Update time (utime) == 0 means resync ASAP */
	pp->utime = 0;
	pp->delta = INIT_UPD_LIST_TIME_INCR;
	(void) __nis_insert_item_mt(pp, tbl, 0);
	setPingWakeup(ptime + updateBatchingTimeout());
	if (verbose)
		syslog(LOG_INFO, "add_pingitem: added %s", buf);
}

void
add_pingitem(dir, ptime, tbl)
	nis_object	*dir;
	ulong_t		ptime;
	NIS_HASH_TABLE	*tbl;
{
	char		buf[1024];

	if (dir == NULL)
		return;

	sprintf(buf, "%s.%s", dir->zo_name, dir->zo_domain);
	add_pingitem_with_name(buf, dir, ptime, tbl);
}

/*
 * Only to be called from update_dl_item() via nis_scan_table()
 *
 * If the master server of the directory in the hash entry matches the
 * master that isn't responding reset the expiry time to some point in
 * the future. This is only applied to directories due to expire before
 * the new expiry time.
 */

struct reset_dl_expires_args {
	nis_name	master;
	ulong_t		expiry;
};

static bool_t
reset_dl_expires(NIS_HASH_ITEM *nhi, void *funcarg)
{
	struct directory_item		*dd = (struct directory_item *)nhi;
	struct reset_dl_expires_args	*args = funcarg;

	if (strcmp(GETSERVER(dd->dl_obj, 0)->name, args->master) == 0) {
		if (dd->dl_expires < args->expiry) {
			dd->dl_expires = args->expiry;
			if (verbose)
				syslog(LOG_DEBUG, "reset_dl_expires: reset "
				    "expiry for directory %s to %d",
				    dd->dl_item.name, args->expiry);
		} else {
			if (verbose)
				syslog(LOG_DEBUG, "reset_dl_expires: skipping "
				    "directory %s, expiry %d is later",
				    dd->dl_item.name, dd->dl_expires);
		}
	} else {
		if (verbose)
			syslog(LOG_DEBUG, "reset_dl_expires: skipping "
			    "directory %s as master (%s) doesn't match",
			    dd->dl_item.name, GETSERVER(dd->dl_obj, 0)->name);
	}
	/* Return false as true would terminate the scan */
	return (FALSE);
}

/*
 * Updates directory item with given information.
 * If directory requires update, add it to 'upd_list'.
 * If directory is root directory, check whether root object requires
 * update.
 */
static void
update_dl_item(nis_name name,
	struct directory_item *dd,
	nis_object* d_obj,
	struct timeval *tv,
	enum name_pos p)
{
	nis_name rootname;
	nis_server *master;
	int retry_time = 1800; /* Backoff time for a dead master */
	struct reset_dl_expires_args funcarg;

	dd->dl_expires = tv->tv_sec + d_obj->zo_ttl;
	dd->dl_obj = d_obj;

	if ((dd->dl_serve = nis_isserving(d_obj)) == 0)
		return;

	/*
	 * Add it to the list of directories served by this
	 * server if not already listed.
	 */
	nis_server_control(SERVING_LIST, DIR_ADD, name);

	if (dd->dl_serve == 1) /* master */
		dd->dl_stamps[0] = last_update(name);
	else { /* replica */

		ulong_t	timestamp;

		/*
		 * schedule update for directory contents but don't
		 * try too hard.
		 */
		master = GETSERVER(d_obj, 0);
		timestamp = nis_cptime_msg(master, name, FALSE, FALSE);
		/*
		 * If timestamp == 0, (i.e., failed to retrieve a timestamp
		 * from the master), force the directory object to expire 30
		 * minutes later so that we can check the master again.  In
		 * the meantime, we will use the expired directory cache.
		 *
		 * We use nis_scan_table_mt() to reset the expiry time on
		 * all cached directories from this master server.
		 */
		if (timestamp == 0) {
			if (verbose)
				syslog(LOG_WARNING, "update_dl_item: "
				    "unable to get timestamp for %s "
				    "from master %s",
				    name, master->name);
			funcarg.master = master->name;
			funcarg.expiry = tv->tv_sec + retry_time;
			if (verbose)
				syslog(LOG_INFO, "update_dl_item: "
				    "reseting expiry to %d", funcarg.expiry);
			/* Update the hash list */
			nis_scan_table(dl, reset_dl_expires, &funcarg);
			/*
			 * The current entry may not be on the hash
			 * list yet so we explicitly reset it here.
			 */
			dd->dl_expires = funcarg.expiry;
			return;
		}
		/*
		 * We have a valid timestamp from the master.  Check and
		 * update upd_list accordingly.
		 */
		dd->dl_stamps[0] = timestamp;
		if (!readonly && last_update(name) < timestamp) {
			add_pingitem(dd->dl_obj, timestamp, &upd_list);
		}

		/* If root object, schedule update for object itself too */
		if (!readonly && p == SAME_NAME &&
		    ((rootname = __nis_local_root()) != 0) &&
		    nis_dir_cmp(name, rootname) == SAME_NAME &&
		    last_update(ROOT_OBJ) < d_obj->zo_oid.mtime) {
			add_pingitem_with_name(ROOT_OBJ,
						d_obj,
						d_obj->zo_oid.mtime,
						&upd_list);
		}
	}
}


/*
 * These statistics are used to calculate the effectiveness of the
 * directory object cache. You can retrieve them with a TAG_DIRCACHE
 * in the stats call.
 */
int	dircachecall = 0,
	dircachehit  = 0,
	dircachemiss = 0;

nis_error
__directory_object(name, ticks, is_master, obj)
	nis_name	name;
	struct ticks 	*ticks;
	int		is_master;	/* Need we be the master ? */
	nis_object	**obj;
{
	return (__directory_object_msg(name, ticks, is_master, obj, 1));
}

#define	INCDIRSTAT(stat)	WLOCK(dircachestats); \
				stat ++; \
				WULOCK(dircachestats);

/*
 * __directory_object()
 * This function is used to search for directory objects that describe
 * directories that this server serves. When called it will either
 * return a directory object which describes a directory that is served
 * or NULL if the directory is not served by this server.
 * It takes three parameters, name, ticks and is_master. Name is
 * presumed to be the NIS+ name of the directory we're looking for, ticks
 * points to a ticks structure that we can fill in with some statistics
 * and is_master indicates that not only should we serve the directory
 * but also we must be the master server for that directory.
 */
nis_error
__directory_object_msg(name, ticks, is_master, obj, msg)
	nis_name	name;
	struct ticks 	*ticks;
	int		is_master;	/* Need we be the master ? */
	nis_object	**obj;
	int		msg;
{
	register nis_object		*d_obj = NULL;
	register struct directory_item	*dd;
	nis_db_result			*dbres = NULL;
	nis_result			*zres = NULL;
	int				lookup_flags = 0;
	struct timeval 			tv;
	enum name_pos			p;
	int				serve;

	/*
	 * A sanity check, if nis_name_of() returns NULL then either the
	 * name passed is identical to the local directory (in which case
	 * we can't possibly serve it unless we are a root server of a
	 * local root), or the name isn't in our tree at all (shares
	 * no common path). In which case we can't possibly serve it.
	 */
	*obj = NULL;

	if (name == NULL)
		return (NIS_BADNAME); /* illegal name */

	p = nis_dir_cmp(name, __nis_rpc_domain());
	if ((p == HIGHER_NAME) || (p == NOT_SEQUENTIAL) || (p == BAD_NAME))
			return (NIS_BADNAME);

	/*
	 * XXX intermediate workaround, until the next source
	 * crank. The is_master "boolean" gets expanded here to
	 * be a set of bit flags. In particular, the new flag
	 * "NO_CACHE" is used to identify when the function calling
	 * this function wants it to retrieve a new copy of the
	 * directory object from the cache.
	 */
	if ((is_master & NO_CACHE) != 0) {
		is_master = ((is_master & TRUE) != 0);
		/* get latest copy of directory object */
		lookup_flags = MASTER_ONLY+NO_CACHE;
	}

	WLOCK(dl);
	if (! dl) {
		dl = (NIS_HASH_TABLE *)calloc(1, sizeof (NIS_HASH_TABLE));
		if (!dl) {
			syslog(LOG_ERR, "__directory_object: out of memory");
			WULOCK(dl);
			return (NIS_NOMEMORY);
		}
		__nis_init_hash_table(dl, destroyDirCacheItem);
	}
	WULOCK(dl);

	/* some statistics stuff ... */
	memset((char *)ticks, 0, sizeof (struct ticks));
	INCDIRSTAT(dircachecall);
	if (verbose)
		syslog(LOG_INFO, "Looking for directory object %s", name);

	/*
	 * Now we check the cache to see if we have it cached locally.
	 */
	(void) gettimeofday(&tv, NULL);
	dd = (struct directory_item *)__nis_find_item_mt(name, dl, 1, 0);

	/*
	 * If we found it in the cache, and we're asking for the
	 * "no cache" version, then we flush the cache and
	 * cause it to be re-looked up.
	 */
	if (dd && (lookup_flags & NO_CACHE)) {
		free_dlitem(dd);
		(void) __nis_release_item(dd, dl, 1);
		dd = NULL;
	}

	if (dd) {
		if (verbose)
			syslog(LOG_INFO, "__directory_object: Cache hit.");
		INCDIRSTAT(dircachehit);
		/*
		 * Found it in the cache. First we check to see if it
		 * has expired, and then we check to see if we are the
		 * master server. (we must serve it, otherwise it wouldn't
		 * be in our cache!)
		 *
		 * Check the expiration date on the object
		 */
		if ((tv.tv_sec < dd->dl_expires) && !(is_master)) {
			if (dd->dl_serve) {
				*obj = dd->dl_obj;
				dirDeferRelease(dd, 0);
				return (NIS_SUCCESS);	/* Here it is ... */
			} else {
				/* Should never happen */
				*obj = NULL;
				(void) __nis_release_item(dd, dl, 1);
				return (NIS_NOT_ME);
			}
		} else if ((tv.tv_sec < dd->dl_expires) && is_master) {
			if (dd->dl_serve == 1) {
				*obj = dd->dl_obj;
				dirDeferRelease(dd, 0);
				return (NIS_SUCCESS);	/* Here it is ... */
			} else {
				(void) __nis_release_item(dd, dl, 1);
				return (NIS_NOTMASTER);	/* Not master */
			}
		}
		/* Else it is expired so we're refreshing it. */
	}
	if (! dd) {
		if (verbose)
			syslog(LOG_INFO, "__directory_object: Cache miss.");
		INCDIRSTAT(dircachemiss);
	}

	/*
	 * At this point we either don't have it in our cache (dd == NULL)
	 * or it is expired (dd != NULL) so we have to go looking for it
	 * from either inside (our database) or outside (our parent).
	 * First, we check to see if we are a root server and they want
	 * the root directory.
	 */

	dbres = db_lookup(name);
	ticks->dticks += dbres->ticks;
	if (dbres->status == NIS_SUCCESS) {
		d_obj = nis_clone_object(dbres->obj, NULL);
	} else if (dbres->status == NIS_SYSTEMERROR) {
		syslog(LOG_ERR,
			"__directory_object: internal database error.");
	} else if (dbres->status != NIS_NOTFOUND) {
		/*
		 * (db result-> no such table )
		 * Ask the "parent" of "name" since this should not
		 * recurse to the same server, we don't
		 * worry about screwing up the current
		 * server clock (clock(2)). But we will
		 * get ticks back from the other server
		 * so we return those in the ticks structure.
		 */
		zres = nis_lookup(name, lookup_flags);
		if (zres->status == NIS_SUCCESS) {
			d_obj = nis_clone_object(
					zres->objects.objects_val, 0);
			ticks->zticks += zres->zticks;
			ticks->dticks += zres->dticks;
			ticks->cticks += zres->cticks;
			ticks->aticks += zres->aticks;
		} else if (zres->status == NIS_NOTFOUND) {
			if (dd) {
				/* It no longer exists */
				free_dlitem(dd);
				(void) __nis_release_item(dd, dl, 1);
				dd = NULL;
			}
		} else {
			if (msg)
				syslog(LOG_WARNING,
			"__directory_object: Failed to lookup %s, status %s",
				name, nis_sperrno(zres->status));
		}
		nis_freeresult(zres);
	} else if (dd) {
		/* It no longer exists */
		free_dlitem(dd);
		(void) __nis_release_item(dd, dl, 1);
		dd = NULL;
	}

	/*
	 * At this point, if d_obj is null then we couldn't find
	 * it. We check to see if we have an expired cached version
	 * and if so, log a warning and go ahead and use it. If
	 * we don't have a cached version we just return NOTFOUND.
	 */
	if (! d_obj) {
		if (dd) {
			syslog(LOG_WARNING,
	"__directory_object: Using expired directory object for %s", name);
			if ((!(is_master) && (dd->dl_serve)) ||
			    (is_master && (dd->dl_serve == 1))) {
				*obj = dd->dl_obj;
				dirDeferRelease(dd, 0);
				return (NIS_S_SUCCESS);
			} else {
				*obj = NULL;
				(void) __nis_release_item(dd, dl, 1);
				return (NIS_NOT_ME);
			}
		} else
			return (NIS_NOTFOUND);
	}

	/* If we found one, and it isn't a directory abort */
	if (__type_of(d_obj) != NIS_DIRECTORY_OBJ) {
		if (msg)
			syslog(LOG_WARNING, "Object %s isn't a directory.",
			    name);
		/* If the cache had one toss it out */
		if (dd) {
			free_dlitem(dd);
			(void) __nis_release_item(dd, dl, 1);
		}
		nis_destroy_object(d_obj);
		return (NIS_BADOBJECT);
	}


	if (dd) {
		/*
		 * We could re-acquire the item with a write lock,
		 * and update it in place. However, in order to reduce
		 * contention with other threads that might be using
		 * the directory item, we instead remove it from the list,
		 * and insert a new one with the updated info.
		 */
		free_dlitem(dd);
		(void) __nis_release_item(dd, dl, 1);
		dd = 0;
	}

	dd = calloc(1, sizeof (*dd));
	if (dd) {
		dd->dl_item.name = (nis_name) strdup(name);
		dd->dl_stamps = (ulong_t *)calloc(MAXSERVER(d_obj),
						sizeof (ulong_t));
		update_dl_item(name, dd, d_obj, &tv, p);
		if (!__nis_insert_item_mt(dd, dl, 1)) {
			/*
			 * Some other thread got there before us.
			 * Look in the cache for a new copy.
			 */
			destroyDirCacheItem(dd);
			dd = __nis_find_item_mt(name, dl, 1, 0);
			if (dd != 0) {
				d_obj = dd->dl_obj;
			} else {
				/*
				 * It's disappeared. Inform the
				 * caller.
				 */
				return (NIS_NOTFOUND);
			}
		}
	}

	/*
	 * Ok we found the directory object, do we really serve it ?
	 * Check to see if this server is supposed to serve this
	 * domain. (Must be master to manipulate the name space)
	 */
	if (dd) {
		serve = dd->dl_serve;
	} else {
		serve = nis_isserving(d_obj);
	}

	/* Check the master requirement */
	if (is_master) {
		if (serve != 1) {
			if (dd)
				(void) __nis_release_item(dd, dl, 1);
			else
				nis_destroy_object(d_obj);
			return (NIS_NOTMASTER);
		} else {
			*obj = d_obj;
			dirDeferRelease(dd, 0);
			return (NIS_SUCCESS);
		}
	}

	if (serve) {
		*obj = d_obj;
		dirDeferRelease(dd, 0);
		return (NIS_SUCCESS);
	}

	if (dd)
		(void) __nis_release_item(dd, dl, 1);
	else
		nis_destroy_object(d_obj);

	return (NIS_NOT_ME);
}

/*
 * Returns the NIS+ principal name of the person making the request
 * XXX This is set up to use Secure RPC only at the moment, it should
 * be possible for any authentication scheme to be incorporated if it
 * has a "full name" that we can return as the principal name.
 */
static const nis_name nobody = "nobody";

static NIS_HASH_TABLE credtbl = NIS_HASH_TABLE_MT_INIT;

struct creditem {
	NIS_HASH_ITEM	item;
	char	pname[1024];
	time_t	cred_expires;
};

static void
add_cred_item(char *netname, char *pname, time_t cred_expires)
{
	struct creditem *foo, *old;

	if (strlen(pname) >= sizeof (foo->pname)) {
		syslog(LOG_ERR,
		"add_cred_item: principal name too long '%s'",
			pname);
		return;
	}

	old = (struct creditem *)nis_find_item(netname, &credtbl);
	if (old) {
		__nis_release_item((NIS_HASH_ITEM *)old, &credtbl, -1);
		return;
	}

	foo = (struct creditem *)calloc(1, sizeof (struct creditem));
	foo->cred_expires = cred_expires;
	foo->item.name = strdup(netname);
	strcpy(foo->pname, pname);
	__nis_insert_item_mt(foo, &credtbl, 0);
}

static int
find_cred_item(char *netname, char *pname)
{
	struct creditem	*old;

	old = (struct creditem *)nis_find_item(netname, &credtbl);
	if (! old || (old->cred_expires < time(0))) {
		struct creditem *toremove;

		if (toremove =
			(struct creditem *)nis_remove_item(netname,
								&credtbl)) {
			free(toremove->item.name);
			free(toremove);
		}
		return (0);
	}
	strcpy(pname, old->pname);
	__nis_release_item((NIS_HASH_ITEM *)old, &credtbl, -1);
	return (1);
}

/*
 * Check security conf file for classic des compat entry.
 *
 * Return TRUE if entry found or if no valid mech entries
 * exist, else return FALSE.
 */
static bool_t
auth_des_permitted(void)
{
	mechanism_t **mechs;

	if (mechs = __nis_get_mechanisms(FALSE)) {
		mechanism_t	**mpp;

		for (mpp = mechs; *mpp; mpp++) {
			mechanism_t *mp = *mpp;

			if (AUTH_DES_COMPAT_CHK(mp)) {
				__nis_release_mechanisms(mechs);
				return (TRUE);
			}
		}
		__nis_release_mechanisms(mechs);
		return (FALSE);
	} else
		return (TRUE);
}

/*
 * Check conf file list of mech entries to see if this raw cred mechanism
 * type is permitted.  Stop processing if the "des" compat entry is reached.
 *
 * Return TRUE on validation, else FALSE.
 */
static bool_t
mech_is_permitted(rpc_gss_rawcred_t *rcred)
{
	mechanism_t **mechs;

	if (mechs = __nis_get_mechanisms(FALSE)) {
		mechanism_t	**mpp;

		for (mpp = mechs; *mpp; mpp++) {
			mechanism_t *mp = *mpp;

			if (AUTH_DES_COMPAT_CHK(mp))
				break;

			if (mp->mechname && rcred->mechanism) {
				if (strcasecmp(mp->mechname,
						rcred->mechanism) == 0) {
					__nis_release_mechanisms(mechs);
					return (TRUE);
				}
			}
		}
		__nis_release_mechanisms(mechs);
	}

	return (FALSE);
}

static char *
flavor2str(int flavor)
{
	switch (flavor) {
	case AUTH_SYS:
		return ("SYS");
	case AUTH_DES:
		return ("DES");
	case RPCSEC_GSS:
		return ("GSS");
	default:
		return ("unknown");
	}
}

/*
 * Given a RPC netname, return the NIS+ principal.
 */
void
nis_getprincipal(
	char		*name,		/* NIS+ principal (out) */
	struct svc_req	*req)		/* service request (in) */
{
	struct authsys_parms	*au;
	struct authdes_cred	*ad;
	char			*rmtdomain;
	char			srch[2048]; /* search criteria */
	nis_result		*res;
	int			message;
	caddr_t			auth;
	enum_t			flavor;
	char			netname[MAXNETNAMELEN+1] = {0};
	char			auth_type[MECH_MAXATNAME+1] = {0};

	message = verbose || auth_verbose;
	strcpy(name, nobody); /* default is "nobody" */

	if (req) {
		flavor = req->rq_cred.oa_flavor;
		auth   = req->rq_clntcred;
	} else {
		syslog(LOG_ERR,
			"RPC request is NULL: returning '%s'", nobody);
		return;
	}

	if (flavor == AUTH_NONE) {
		if (message) {
			syslog(LOG_INFO,
		    "nis_getprincipal: flavor = NONE: returning '%s'", nobody);
		}
		return;
	} else if (flavor == AUTH_SYS) { /* XXX ifdef this for 4.1 */
		if (secure_level > 1) {
			if (message) {
				syslog(LOG_INFO,
			"nis_getprincipal: flavor = SYS: returning '%s'",
								nobody);
			}
			return;
		}
		au = (struct authsys_parms *)(auth);
		rmtdomain = nis_domain_of(au->aup_machname);
		if (au->aup_uid == 0) {
			sprintf(name, "%s", au->aup_machname);
			if (! rmtdomain)
				strcat(name, __nis_rpc_domain());
			if (name[strlen(name) - 1] != '.')
				strcat(name, ".");
			if (message) {
				syslog(LOG_INFO,
		    "nis_getprincipal: flavor = SYS: returning '%s'", name);
			}
			return;
		}
		sprintf(srch,
		    "[auth_name=\"%d\", auth_type=LOCAL], cred.org_dir.%s",
				au->aup_uid, (*rmtdomain == '.') ?
				(char *)nis_local_directory() : rmtdomain);
		if (srch[strlen(srch) - 1] != '.') {
			strcat(srch, ".");
		}
	} else if (flavor == AUTH_DES) {

		if (secure_level > 1 && ! auth_des_permitted()) {
			if (message) {
				syslog(LOG_INFO,
		"nis_getprincipal: AUTH_DES not permitted: returning '%s'",
					nobody);
			}
			return;
		}

		ad = (struct authdes_cred *)(auth);
		if (find_cred_item(ad->adc_fullname.name, name)) {
			if (message)
				syslog(LOG_INFO,
		"nis_getprincipal: flavor = DES: returning from cache '%s'",
					name);
			return;
		}
		rmtdomain = strchr(ad->adc_fullname.name, '@');
		if (rmtdomain) {
			rmtdomain++;
			sprintf(srch,
			    "[auth_name=%s, auth_type=DES], cred.org_dir.%s",
					ad->adc_fullname.name, rmtdomain);
			if (srch[strlen(srch) - 1] != '.') {
				strcat(srch, ".");
				(void) strncpy(netname, ad->adc_fullname.name,
						sizeof (netname));
				netname[sizeof (netname) - 1] = '\0';
			}
		} else {
			if (auth_verbose) {
				syslog(LOG_INFO,
			    "nis_getprincipal: flavor = DES: returning '%s'",
					nobody);
			}
			return;
		}
	} else if (flavor == RPCSEC_GSS) {
		rpc_gss_rawcred_t	*rcred;
		void			*cookie;

		if (! rpc_gss_getcred(req, &rcred, NULL, &cookie)) {
			if (message) {
				syslog(LOG_WARNING,
		    "nis_getprincipal: GSS getcred failure:  returning '%s'",
					nobody);
			}
			return;
		}

		if (secure_level > 1 && ! mech_is_permitted(rcred)) {
			if (message)
				syslog(LOG_INFO,
"nis_getprincipal: RPC GSS mechanism '%s' not permitted: returning nobody",
					rcred->mechanism ? rcred->mechanism
					: "NULL");
			return;
		}

		if (__nis_gssprin2netname(rcred->client_principal,
						netname) < 0) {
			syslog(LOG_ERR,
"nis_getprincipal: can't extract netname from RPC GSS cred: returning nobody");
			return;
		}

		if (find_cred_item(netname, name)) {
			if (message)
				syslog(LOG_INFO,
		"nis_getprincipal: flavor = GSS: returning '%s' from cache",
					name);
			return;
		}
		rmtdomain = strchr(netname, '@');
		if (rmtdomain) {
			char alias[MECH_MAXALIASNAME+1] = { 0 };

			rmtdomain++;
			if (! __nis_mechname2alias(rcred->mechanism, alias,
			    sizeof (alias))) {
				syslog(LOG_ERR,
	"nis_getprincipal:  GSS mechname '%s' not found: returning nobody",
					rcred->mechanism);
				return;
			}

			if (alias[0] != '\0') {
				(void) __nis_mechalias2authtype(alias,
							auth_type,
							sizeof (auth_type));

				(void) snprintf(srch, NIS_MAXNAMELEN,
			    "[auth_name=%s, auth_type=%s], cred.org_dir.%s",
					netname, auth_type, rmtdomain);

				if (srch[strlen(srch) - 1] != '.') {
					strcat(srch, ".");
				}
			} else {
				syslog(LOG_ERR,
"nis_getprincipal: no alias was found for mechname '%s': returning 'nobody'",
				rcred->mechanism);
				return;
			}
		} else {
			if (auth_verbose) {
				syslog(LOG_INFO,
		    "nis_getprincipal: flavor = GSS: returning '%s'",
					nobody);
			}
			return;
		}
	} else {
		syslog(LOG_WARNING,
		"nis_getprincipal: flavor = %d(unknown): returning '%s'",
							flavor, nobody);
		return;
	}

	if (message)
		if (flavor == AUTH_DES || flavor == RPCSEC_GSS)
			syslog(LOG_INFO,
		"nis_getprincipal: calling list with name '%s' and type '%s'",
							netname,
				flavor == AUTH_DES ? "DES" : auth_type);
		else /* AUTH_SYS */
			syslog(LOG_INFO,
			"nis_getprincipal: calling list with uid (LOCAL) '%d'",
				au->aup_uid);

	res = nis_list(srch, NO_AUTHINFO+USE_DGRAM+FOLLOW_LINKS, NULL, NULL);
	if (res->status != NIS_SUCCESS) {
		if (message)
			syslog(LOG_INFO,
				"nis_getprincipal: error doing nis_list: %s",
						nis_sperrno(res->status));
	} else {
		if (strlcpy(name,
		    ENTRY_VAL(res->objects.objects_val, 0), 1024) >= 1024) {
			(void) strcpy(name, nobody); /* default is "nobody" */
			syslog(LOG_ERR,
		"nis_getprincipal: buffer overflow, returning '%s'", nobody);
			nis_freeresult(res);
			return;
		}
		if (flavor == AUTH_DES || flavor == RPCSEC_GSS) {
			if (message)
				syslog(LOG_INFO,
					"nis_getprincipal: caching '%s'/'%s'",
					netname, name);
			add_cred_item(netname, name,
				res->objects.objects_val[0].zo_ttl+time(0));
		}
	}

	nis_freeresult(res);
	if (message)
		syslog(LOG_INFO,
		"nis_getprincipal: flavor = %s: returning : '%s'",
			flavor2str(flavor), name);
}

/*
 * __can_do()
 * This function returns true if the given principal has the right to
 * do the requested function on the given object. It could be a define
 * if that would save time. At the moment it is a function.
 * NOTE: It recursively calls NIS by doing the lookup on the group if
 * the conditional gets that far.
 *
 * N.B. If the principal passed is 'null' then we're recursing and don't
 * need to check it. (we always let ourselves look at the data)
 */
int
__can_do(right, mask, obj, pr)
	unsigned long	right;	/* The Access right we desire 		*/
	unsigned long	mask;	/* The mask for World/Group/Owner 	*/
	nis_object	*obj;	/* A pointer to the object		*/
	nis_name	pr;	/* Principal making the request		*/
{
	if ((secure_level == 0) || (*pr == 0))
		return (1);

	return (NIS_NOBODY(mask, right) ||
		(NIS_WORLD(mask, right) &&
			(strcmp(pr, "nobody") != 0)) ||
		(NIS_OWNER(mask, right) &&
			(nis_dir_cmp(pr, obj->zo_owner) == SAME_NAME)) ||
		(NIS_GROUP(mask, right) &&
			(strlen(obj->zo_group) > (size_t)(1)) &&
			__do_ismember(pr, obj, nis_lookup)));
}

/* BEGIN CSTYLED */
/*
 * Get an xdr buffer
 */
u_char *
__get_xdr_buf(size)
	int	size;	/* Size in bytes of the buffer */
{
#ifdef	local_buf
#undef	local_buf
#endif
#define	local_buf	(__nis_get_tsd()->local_buf__get_xdr_buf)

	return ((u_char *)nis_get_static_storage(&local_buf, 1, size));
}
/* END CSTYLED */

/*
 * Get a string buffer
 */
char *
__get_string_buf(size)
	int	size;	/* Size in bytes of the buffer */
{
#ifdef	local_buf
#undef	local_buf
#endif
#define	local_buf	(__nis_get_tsd()->local_buf__get_string_buf)

	return ((char *)nis_get_static_storage(&local_buf, 1, size));
}

/*
 * get an array of entry columns
 */
entry_col *
__get_entry_col(n)
	int	n;	/* required array size */
{
#ifdef	local_buf
#undef	local_buf
#endif
#define	local_buf	(__nis_get_tsd()->local_buf__get_entry_col)

	return ((entry_col *)nis_get_static_storage(&local_buf,
						sizeof (entry_col), n));
}

/*
 * get an array of table columns
 */
table_col *
__get_table_col(n)
	int	n;	/* required array size */
{
#ifdef	local_buf
#undef	local_buf
#endif
#define	local_buf	(__nis_get_tsd()->local_buf__get_table_col)

	return ((table_col *)nis_get_static_storage(&local_buf,
						sizeof (table_col), n));
}

/*
 * get an array of nis attributes
 */
nis_attr *
__get_attrs(n)
	int	n;	/* required array size */
{
#ifdef	local_buf
#undef	local_buf
#endif
#define	local_buf	(__nis_get_tsd()->local_buf__get_attrs)

	return ((nis_attr *)nis_get_static_storage(&local_buf,
						sizeof (nis_attr), n));
}

/*
 * Stability functions. These functions check to see if a transaction
 * has been propogated to all replicas.
 *
 * nis_isstable()
 * This function checks to see if an update has been propogated to all
 * of the replicates for the given domain. If so, the log code will be
 * free to delete it, otherwise we will continue to hold it until the
 * replicate picks up the change. If we can't figure out if it is stable
 * or not we return 0 and hold onto it.
 */
int
nis_isstable(le, first)
	log_entry	*le;
	int		first;
{
	int			i;
	struct directory_item	*dd;
	nis_object		*dobj;
	struct ticks		t;
	nis_name		dirname;
	nis_error		err;
	bool_t			ret;


	if (le->le_type == UPD_STAMP)
		dirname = le->le_name;
	else
		dirname = nis_domain_of(le->le_name);

	/*
	 * get object for the domain, if this is the first time we're
	 * "visitin" this domain then get a fresh copy (NO_CACHE)
	 */
	if (first)
		err = __directory_object(dirname, &t, NO_CACHE+1, &dobj);
	else
		err = __directory_object(dirname, &t, 1, &dobj);

	/*
	 * If we aren't the master any more, or the directory doesn't exist
	 * anymore we can toss this update.
	 */
	if ((err == NIS_NOTMASTER) || (err == NIS_NOTFOUND) ||
			(err == NIS_BADNAME))
		return (TRUE);

	/*
	 * If we encountered a problem trying to get the directory object
	 * we hold on to the update.
	 */
	if ((err != NIS_SUCCESS) && (err != NIS_S_SUCCESS))
		return (FALSE);

	/*
	 * If we look at the object and there is only one server then
	 * the update has by definition propogated.
	 */
	if (MAXSERVER(dobj) == 1)
		return (TRUE);

	/*
	 * Otherwise we go ahead and check to see if it is stable.
	 * In the single-threaded case, the find_item will always work
	 * if the __directory_object() call worked. Not necessarily true
	 * in MT case, where other threads may do work in between
	 * __directory_object() and nis_find_item().
	 */
	dd = __nis_find_item_mt(dirname, dl, 1, 0);
	if (!dd)
		return (TRUE);
	ret = TRUE;
	for (i = 1; i < MAXSERVER(dobj); i++) {
		if (dd->dl_stamps[i] == 0) {
			/* Fetch the time from the replica */
			dd->dl_stamps[i] = nis_cptime_msg(GETSERVER(dobj, i),
							    dd->dl_item.name,
							    FALSE, TRUE);

			if (! dd->dl_stamps[i]) {
				dd->dl_stamps[i] = 1;
			}
		}

		if (dd->dl_stamps[i] < le->le_time)
			ret = FALSE;
	}
	__nis_release_item((NIS_HASH_ITEM *)dd, dl, 1);
	return (ret);
}

/*
 * add_fenceposts()
 *
 * This function will put "fenceposts" into the log for each directory we
 * serve. This makes the "lastupdate()" function faster and is essential
 * for directories that have been stable long enough that there are no
 * delta's left.
 */
void
add_fenceposts()
{
	int			i;
	struct directory_item	*dd;

	LOCK_LIST(dl, "add_fenceposts(dl)");
	for (dd = (struct directory_item *)dl->first; dd;
			dd = (struct directory_item *)(dd->dl_item.nxt_item)) {
		for (i = 0; i < MAXSERVER(dd->dl_obj); i++) {
			if (nis_dir_cmp(GETSERVER(dd->dl_obj, i)->name,
				nis_local_host()) == SAME_NAME) {
				if (dd->dl_stamps[i] >
					last_update(dd->dl_item.name)) {
					make_stamp(dd->dl_item.name,
							    dd->dl_stamps[i]);
					break;
				}
			}
		}
	}
	ULOCK_LIST(dl, "add_fenceposts(dl)");
}

/*
 * apply_update()
 *
 * This function applies a log entry that we've received from the master
 * for a given domain to the log and the database.
 */
static nis_error
apply_update(le)
	log_entry	*le;
{
	nis_error	status;
	char		*msg;

	if (cons) {
		fprintf(cons, "update type %d, name %s.%s\n", le->le_type,
				le->le_object.zo_name, le->le_object.zo_domain);
	}

	switch (le->le_type) {
		case ADD_NAME :
			status = __db_add(le->le_name, &(le->le_object), 0);
			msg = "Failed to add object ";
			break;
		case MOD_NAME_NEW :
			status = __db_add(le->le_name, &(le->le_object), 1);
			msg = "Failed to modify object ";
			break;

		case REM_NAME :
			status = __db_remove(le->le_name, &(le->le_object));
			msg = "Failed to remove object ";
			break;

		/* For old modified objects, just add this to the log */
		case MOD_NAME_OLD :
			status = NIS_SUCCESS;
			break;

		case ADD_IBASE :
			status = __db_addib_nosync(le->le_name,
						    le->le_attrs.le_attrs_len,
						    le->le_attrs.le_attrs_val,
						    &(le->le_object));
			msg = "Failed to add entry ";
			break;

		case REM_IBASE :
			status = __db_remib_nosync(le->le_name,
						le->le_attrs.le_attrs_len,
						le->le_attrs.le_attrs_val);
			msg = "Failed to remove entry ";
			break;
		/* ignore these as they are both NOPs */
		case UPD_STAMP :
		case LOG_NOP :
			status = NIS_SUCCESS;
			break;

		default :
			status = NIS_SYSTEMERROR;
			msg = "Illegal transaction type on ";
			break;
	}
	if (status != NIS_SUCCESS) {
		syslog(LOG_ERR, "apply_update : %s %s NIS+ STATUS : %s",
			msg, __make_name(le), nis_sperrno(status));
		if (cons)
			fprintf(cons, "apply_update : %s %s\n",
				msg, __make_name(le));
	}

	return (status);
}

extern table_obj tbl_prototype;

/*
 * clear_directory()
 *
 * This function will restores a directory to "virgin" status. This is
 * accomplished by deleting any databases (tables) that are contained in
 * that directory, then destroying and recreating the database for the
 * directory.
 */
int
clear_directory(name)
	nis_name	name;
{
	nis_db_list_result	*tables;
	int			i, n;
	char			namebuf[NIS_MAXNAMELEN+1];
	nis_error		status;

	tables = db_list_flags(name, 0, NULL, FN_NOMANGLE+FN_NORAGS);
	if (tables != NULL && tables->status == NIS_SUCCESS) {
		for (i = 0; i < tables->numo; i++) {
			n = snprintf(namebuf, sizeof (namebuf), "%s.%s",
					tables->objs[i].o->zo_name,
					tables->objs[i].o->zo_domain);
			if (n < 1 || n > sizeof (namebuf)) {
				syslog(LOG_WARNING,
		"clear_directory: buffer (%d) insufficient for \"%s.%s\" (%d)",
					sizeof (namebuf),
					tables->objs[i].o->zo_name,
					tables->objs[i].o->zo_domain,
					strlen(tables->objs[i].o->zo_name)+
					strlen(tables->objs[i].o->zo_domain)+
					2 /* dot and NUL */);
				continue;
			}
			if (__type_of(tables->objs[i].o) == NIS_TABLE_OBJ) {
				if ((status = db_destroy(namebuf)) !=
						NIS_SUCCESS)
					syslog(LOG_WARNING,
			"clear_directory: Could not destroy table \"%s\": %s.",
						namebuf, nis_sperrno(status));
			} else {
				/* Not a table, so just remove the object */
				status = __db_remove(namebuf,
							tables->objs[i].o);
				if (status != NIS_SUCCESS)
					syslog(LOG_WARNING,
			"clear_directory: Could not remove object \"%s\": %s",
						namebuf, nis_sperrno(status));
			}
		}
	} else if (tables == NULL || tables->status != NIS_NOTFOUND) {
		syslog(LOG_WARNING,
		"clear_directory: could not get object list for \"%s\": %s",
			name, (tables != NULL) ? nis_sperrno(tables->status) :
						"<nil>");
		free_db_list(tables);	/* (tables == NULL) OK */
		return (0);
	}
	/*
	 * else (tables->status == NIS_NOTFOUND), which is fine by us;
	 * someone already did our work.
	 */

	free_db_list(tables);	/* (tables == NULL) OK */
	if ((status = db_destroy(name)) != NIS_SUCCESS) {
		syslog(LOG_WARNING,
			"Could not destroy table %s: %s.",
			name, nis_sperrno(status));
		/* XXX recover? */
	}

	/* Make a clean version. */
	if ((status = db_create(name, &tbl_prototype)) != NIS_SUCCESS) {
		syslog(LOG_WARNING,
			"Could not create table %s: %s.",
			name, nis_sperrno(status));
		/* XXX recover? */
	}

	if (verbose)
		syslog(LOG_INFO, "directory '%s' cleared.", name);
	return (1);
}

#define	repl_stats	(__nis_get_tsd()->repl_stats)

/*
 * nis_makename()
 *
 * This function prints out a nice name for a objects.
 */
void
nis_makename(obj, tobj, str)
	nis_object	*obj;
	nis_object	*tobj;
	char		*str;
{
	int		i;
	table_col	*tcols;
	entry_col	*ecols;
	int		ncols;

	if (tobj == NULL) {
		sprintf(str, "%s.%s", obj->zo_name, obj->zo_domain);
		return;
	}

	strcpy(str, "[");
	tcols = tobj->TA_data.ta_cols.ta_cols_val;
	ncols = tobj->TA_data.ta_cols.ta_cols_len;
	ecols = obj->EN_data.en_cols.en_cols_val;

	for (i = 0; i < ncols; i++) {
		if (tcols[i].tc_flags & TA_SEARCHABLE) {
			strcat(str, tcols[i].tc_name);
			strcat(str, " = \"");
			if (ecols[i].ENLEN)
				strncat(str, ecols[i].ENVAL, ecols[i].ENLEN);
			strcat(str, "\", ");
		}
	}

	str[strlen(str) - 2] = '\0';
	strcat(str, "],");
	strcat(str, obj->zo_name);
	strcat(str, ".");
	if (strlen(obj->zo_domain)) {
		strcat(str, obj->zo_domain);
	}
}

/*
 * During full resyncs, repl_objs caches the table objects, so that
 * we don't have to look them up every time we add an entry to
 * the table.
 */
static NIS_HASH_TABLE repl_objs = NIS_HASH_TABLE_MT_INIT;

/* This is the callback for nis_dump (Full Resyncs) */
int
update_directory(name, obj, x)
	nis_name	name;
	nis_object	*obj;
	void		*x;
{
	nis_db_result	*dbres;
	nis_error	status;
	nis_object	*tobj;
	char		namebuf[NIS_MAXNAMELEN+1];
	int		i, na, mc;
	entry_col	*ec;
	table_col	*tc;
	nis_attr	*attr_list;
	ping_item	*pp;
	int		release_pp = 0;

	if (obj->zo_oid.mtime > repl_stats.utime) {
		repl_stats.utime = obj->zo_oid.mtime;
	}

	/*
	 * Note :
	 *	Once entered this if block returns to the caller.
	 */
	if (__type_of(obj) == NIS_ENTRY_OBJ) {
		pp = (ping_item *)nis_find_item(name, &repl_objs);
		if (! pp) {
			dbres = db_lookup_deferred(name, FALSE);
			repl_stats.ticks += dbres->ticks;
			if (dbres->status == NIS_SUCCESS)
				add_pingitem(dbres->obj, 1, &repl_objs);
			tobj = dbres->obj;
		} else {
			release_pp = 1;
			tobj = pp->obj;
		}

		if (tobj) {
			if (verbose) {
				nis_makename(obj, tobj, namebuf);
				syslog(LOG_INFO, "update_dir: %s", namebuf);
			}
			/* Build a fully specified name from the entry */
			mc = tobj->TA_data.ta_cols.ta_cols_len;
			tc = tobj->TA_data.ta_cols.ta_cols_val;
			ec = obj->EN_data.en_cols.en_cols_val;
			attr_list = __get_attrs(mc);
			if (attr_list == NULL) {
				syslog(LOG_WARNING,
			"update_directory: out of memory resync aborted.");
				repl_stats.errors++;
				if (release_pp)
					__nis_release_item(
					(NIS_HASH_ITEM *)pp, &repl_objs, -1);
				return (1);
			}
			for (i = 0, na = 0; i < mc; i++) {
				if ((tc[i].tc_flags & TA_SEARCHABLE) != 0) {
					attr_list[na].zattr_ndx = tc[i].tc_name;
					attr_list[na].ZAVAL = ec[i].ENVAL;
					attr_list[na].ZALEN = ec[i].ENLEN;
					na++;
				}
			}
			status = __db_addib_nolog(name, na, attr_list, obj);
			if (status == NIS_SUCCESS) {
				repl_stats.successes++;
				if ((repl_stats.successes % 1000) == 0)
					syslog(LOG_INFO,
				"update_directory : %d objects, still running.",
						repl_stats.successes);
				if (release_pp)
					__nis_release_item(
					(NIS_HASH_ITEM *)pp, &repl_objs, -1);
				return (0);
			} else {
				nis_makename(obj, tobj, namebuf);
				syslog(LOG_ERR,
		"replica_update (update_directory): adding %s returned %s",
						namebuf, nis_sperrno(status));
				repl_stats.errors++;
				if (release_pp)
					__nis_release_item(
					(NIS_HASH_ITEM *)pp, &repl_objs, -1);
				return (1);
			}
		} else {
			syslog(LOG_ERR,
	"replica_update (update_directory): adding entry to %s returned %s",
				name, dbres->status);
			repl_stats.errors++;
			if (release_pp)
				__nis_release_item(
					(NIS_HASH_ITEM *)pp, &repl_objs, -1);
			return (1);
		}
	}

	/*
	 * At this point it isn't an ENTRY object so we're not adding
	 * it to a table.
	 */
	if (verbose) {
		nis_makename(obj, NULL, namebuf);
		syslog(LOG_INFO, "update_dir: %s", namebuf);
	}
	status = __db_add(name, obj, 0);
	if (status == NIS_SUCCESS) {
		repl_stats.successes++;
		if (release_pp)
			__nis_release_item((NIS_HASH_ITEM *)pp, &repl_objs,
						-1);
		return (0);
	} else {
		/*
		 * xxx sometimes clear_directory doesn't successfully
		 * clear out tables (bug), this tries again before
		 * giving up on the table object.
		 */
		if (__type_of(obj) == NIS_TABLE_OBJ) {
			if ((status = db_destroy(name)) == NIS_SUCCESS) {
				status = __db_add(name, obj, 0);
				if (status == NIS_SUCCESS) {
					repl_stats.successes++;
					return (0);
				}
			}
		}
		repl_stats.errors++;
		if (release_pp)
			__nis_release_item((NIS_HASH_ITEM *)pp, &repl_objs,
						-1);
		return (1);
	}
}


/*
 * Make sure the directory exists, if it doesn't then we've
 * missed a create somewhere or we were just added as a replica
 * of the directory.
 */
int
verify_table_exists(nis_name name)
{
	nis_error status;

	status = db_find_table(name);
	switch (status) {
	case NIS_NOSUCHTABLE:
		if ((status = db_create(name, &tbl_prototype)) !=
		    NIS_SUCCESS) {
			syslog(LOG_ERR,
			"verify_table_exists: cannot create table for %s:%s.",
				name, nis_sperrno(status));
			return (0);
		}
		break;
	case NIS_SUCCESS:
		break;
	default:
		syslog(LOG_ERR,
		"verify_table_exists: unexpected database error for %s: %s.",
			name, nis_sperrno(status));
		return (0);
	}

	return (1);
}

/*
 * Update root object (creating it if not there before) or remove root object
 * depending on whether we're still listed as a root replica.
 * Affects root_server flag.
 * Returns 1 if successful; 0 otherwise.
 */
int
root_replica_update()
{
	nis_object	*obj;
	nis_result	*res = 0;
	nis_name	root_dir = __nis_rpc_domain();
	int		readok;
	char		*myself = "root_replica_update";

	/* If we're reading the root dir from LDAP, do nothing */
	if (getObjMapping(root_dir, 0, 1, &readok, 0) != 0 && readok) {
		logmsg(MSG_NOTIMECHECK,
#ifdef	NIS_LDAP_DEBUG
			LOG_WARNING,
#else
			LOG_INFO,
#endif	/* NIS_LDAP_DEBUG */
			"%s: Mapping root dir object from LDAP", myself);
		return (1);
	}

	res = nis_lookup(root_dir, MASTER_ONLY);
	if (res->status != NIS_SUCCESS) {
		syslog(LOG_WARNING,
"root_replica_update: update failed '%s': could not fetch object from master.",
			root_dir);
		nis_freeresult(res);
		return (0);    /* failed, try again later. */
	}

	obj = res->objects.objects_val;
	if (we_serve(&(obj->DI_data), 0)) {
		if (verbose)
			syslog(LOG_INFO,
				"root_replica_update: updating '%s'",
				root_dir);
		if (!update_root_object(root_dir, obj)) {
			nis_freeresult(res);
			return (0);  /* failed, try again later. */
		}
	} else {
		if (verbose)
			syslog(LOG_INFO,
				"root_replica_update: removing '%s'",
				root_dir);
		remove_root_object(root_dir, obj);
	}
	nis_freeresult(res);
	return (1);
}

/*
 * Return 1 if all objects in the directory 'dirname' are read mapped
 * from LDAP, 0 otherwise. For table objects, the definition of "all
 * objects" includes the table object itself, as well as entried in
 * the table.
 *
 * Most of the code to retrieve a directory listing and traverse same
 * was borrowed from clear_directory().
 */
static int
isAllMapped(nis_name dirname) {
	nis_db_list_result	*objs;
	int			i, n, ok;
	char			namebuf[NIS_MAXNAMELEN+1];
	nis_error		status;
	char			*myself = "isAllMapped";

	objs = db_list_flags(dirname, 0, 0, FN_NOMANGLE+FN_NORAGS);
	if (objs == 0 || objs->status != NIS_SUCCESS) {
		logmsg(MSG_NOTIMECHECK,
#ifdef	NIS_LDAP_DEBUG
			LOG_WARNING,
#else
			LOG_INFO,
#endif	/* NIS_LDAP_DEBUG */
			"%s: Unable to get directory list for \"%s\": %s",
			myself, NIL(dirname),
			objs == 0 ? "<NULL>" : nis_sperrno(objs->status));
		return (0);
	}

	for (ok = 1, i = 0; ok && i < objs->numo; i++) {
		int	readok;

		n = snprintf(namebuf, sizeof (namebuf), "%s.%s",
			objs->objs[i].o->zo_name, objs->objs[i].o->zo_domain);
		if (n < 1 || n > sizeof (namebuf)) {
			logmsg(MSG_NOTIMECHECK,
#ifdef	NIS_LDAP_DEBUG
				LOG_WARNING,
#else
				LOG_INFO,
#endif	/* NIS_LDAP_DEBUG */
		"%s: Buffer size (%d) insufficient for \"%s.%s\" (need %d)",
				myself, sizeof (namebuf),
				objs->objs[i].o->zo_name,
				objs->objs[i].o->zo_domain,
				strlen(objs->objs[i].o->zo_name) +
					strlen(objs->objs[i].o->zo_domain) + 2);
			ok = 0;
			continue;
		}

		if (getObjMapping(namebuf, 0, 1, &readok, 0) == 0 ||
				readok == 0) {
			logmsg(MSG_NOTIMECHECK,
#ifdef	NIS_LDAP_DEBUG
				LOG_WARNING,
#else
				LOG_INFO,
#endif	/* NIS_LDAP_DEBUG */
				"%s: No read mapping for obj \"%s\"",
				myself, namebuf);
			ok = 0;
			continue;
		}

		if (__type_of(objs->objs[i].o) == NIS_TABLE_OBJ &&
			(getObjMapping(namebuf, 0, 0, &readok, 0) == 0 ||
				readok == 0)) {
			logmsg(MSG_NOTIMECHECK,
#ifdef  NIS_LDAP_DEBUG
				LOG_WARNING,
#else
				LOG_INFO,
#endif	/* NIS_LDAP_DEBUG */
				"%s: No read mapping for entries in \"%s\"",
				myself, namebuf);
			ok = 0;
			continue;
		}
	}

	free_db_list(objs);

	return (ok);
}

/*
 * Returns 1 if the log_entry:s 'l1' and 'l2' pertain to the same
 * entry object, 0 otherwise.
 *
 * Since this function works on log entries alone, it may not
 * correctly handle cases where different attribute selector lists
 * resolve to the same entry. For example, it's quite possible that
 * '[key1=abc]tab.org_dir' and '[key2=def]tab.org_dir' unambiguously
 * specify the same entry, but we wouldn't know without looking
 * in the DB (and even that wouldn't work if one of the operations
 * is an ADD, in which case the entry migh tnot exist yet).
 */
static int
sameEntryObj(log_entry *l1, log_entry *l2) {
	int	i;

	if (l1 == 0 || l2 == 0)
		return (0);

	/* Must both be entry objects */
	if (l1->le_object.zo_data.zo_type != l2->le_object.zo_data.zo_type)
		return (0);

	if (l1->le_object.zo_data.zo_type != NIS_ENTRY_OBJ)
		return (0);

	/* Same table name */
	if (l1->le_name == 0 || l2->le_name == 0 ||
			strcmp(l1->le_name, l2->le_name) != 0)
		return (0);

	/* Same number of entry selector attributes */
	if (l1->le_attrs.le_attrs_len != l2->le_attrs.le_attrs_len)
		return (0);

	/*
	 * Check the selector attribute names/values. For simplicity,
	 * we require that they're in the same order.
	 */
	for (i = 0; i < l1->le_attrs.le_attrs_len; i++) {
		if (l1->le_attrs.le_attrs_val[i].zattr_ndx == 0 ||
			l2->le_attrs.le_attrs_val[i].zattr_ndx == 0 ||
			strcmp(l1->le_attrs.le_attrs_val[i].zattr_ndx,
				l2->le_attrs.le_attrs_val[i].zattr_ndx) != 0)
			return (0);
		if (l1->le_attrs.le_attrs_val[i].zattr_val.zattr_val_len !=
			l2->le_attrs.le_attrs_val[i].zattr_val.zattr_val_len)
			return (0);
		if (memcmp(l1->le_attrs.le_attrs_val[i].zattr_val.zattr_val_val,
			l2->le_attrs.le_attrs_val[i].zattr_val.zattr_val_val,
			l1->le_attrs.le_attrs_val[i].zattr_val.zattr_val_len) !=
				0)
			return (0);
	}

	return (1);
}

/* define buffer size for ctime_r() */
#define	CTBUFSIZ	26

/*
 * replica_update();
 *
 * This function is used by the replicas to keep themselves up to date
 * with the master server. When called, it iteratively removes the names
 * of directories that have changed from it's list.
 *
 * Note: replica_update() is called either from main() before we go MT,
 *       of from check_updaters() with an exclusive lock on the 'upd_list'.
 *       Thus, there's no need to enforce exclusion in replica_update()
 *       itself.
 */
int
replica_update(upd)
	ping_item	*upd;
{
	nis_name	name;	/* Directory name		*/
	nis_server	*srv;	/* Endpoint for the server	*/
	log_result	*lres;
	log_entry	*le;
	log_upd		*curr_upd = 0;
	char		ctbuf[CTBUFSIZ];
	ulong_t		ttime;	/* timestamp retrieved from last_update() */
	extern void __nis_freelogresult(log_result *);

	/* timestamp used to write back into log when full resync is done */
	ulong_t		xttime;
	int		i, xid, nument, lstat;
	ping_item	*pp, *nxt;
	db_status	dbStatus = DB_SUCCESS;
	__nisdb_retry_t	dumpRetry = ldapConfig.dumpErrorTimeout;
	/* If a full dump fails, is it unsafe to return (i.e.,  try again) ? */
	bool_t		dumpReturnUnsafe = FALSE;
	char		*myself = "replica_update";

	if (verbose)
		syslog(LOG_INFO, "replica_update:");

	memset((char *)(&repl_stats), 0, sizeof (repl_stats));

	if (cons)
		fprintf(cons, "replica_update: %s\n", upd->item.name);
	name = upd->item.name;

	/* check to see if we're replicating the root object */
	if (root_object_p(name)) {
		return (root_replica_update());
	}

	srv = GETSERVER(upd->obj, 0); /* master server for directory */

	if (nis_dir_cmp(srv->name, nis_local_host()) == SAME_NAME) {
		syslog(LOG_WARNING,
"host %s thinks that it is the replica for %s, but it is the master!",
			nis_local_host(), name);
		return (1);
	}

	if (verbose)
		syslog(LOG_INFO, "replica_update: updating '%s'", name);

	if (verify_table_exists(name) == 0) {
		return (0);   /* failed, try again later. */
	}

	/*
	 * If every object in the directory, including table entries, are
	 * mapped from LDAP, we just get the update time from the master,
	 * and write an UPDATE time stamp to trans.log.
	 */
	if (isAllMapped(name)) {
		ttime = nis_cptime_msg(srv, name, FALSE, TRUE);
		if (ttime != 0L && ttime != ULONG_MAX) {
			make_stamp(name, ttime);
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: All objects in \"%s\" mapped from LDAP; "
				"setting update time to %s",
				myself, name, ctime_r((time_t *)&ttime, ctbuf,
				CTBUFSIZ));
			return (1);
		} else {
			logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: Unable to get update time for \"%s\" from \"%s\"",
				myself, name, srv->name);
			/* Fall through to normal resync */
		}
	}

	/*
	 * We now intend do things that might want to update the trans.log.
	 * While the actual transactions are protected by begin_transaction()/
	 * end_transaction(), we don't want to have some other thread changing
	 * the trans.log under our feet from this point on, so we acquire
	 * a write lock on the trans.log.
	 */
	lstat = lockTransLog(myself, 1, 0);
	if (lstat != 0)
		return (0);

	ttime = last_update(name);
	/*
	 * If ttime is non-zero, then get the delta from the master using
	 * nis_dumplog().
	 * If ttime is zero, then go directly to the full resync section.
	 * There is no need to even try to get the delta from the master.
	 */
	if (ttime != 0L && ttime != ULONG_MAX) {
		/* get the delta from transaction log */
		if (cons)
			fprintf(cons,
				"replica_update: dumping master's log.\n");
		syslog(LOG_INFO, "replica_update: delta update of %s", name);
		lres = nis_dumplog(srv, name, ttime);
		if (lres == NULL) {
			unlockTransLog(myself, 1);
			return (0);
		}
		if ((lres->lr_status != NIS_SUCCESS) && cons)
			fprintf(cons, "replica_update: error result was %s\n",
				nis_sperrno(lres->lr_status));
		if (lres->lr_status == NIS_SYSTEMERROR) {
			syslog(LOG_WARNING,
	"replica_update: Couldn't contact '%s' serving '%s' for an update.",
						srv->name, name);
			__nis_freelogresult(lres);
			unlockTransLog(myself, 1);
			return (0);
		}

		if (lres->lr_status == NIS_DUMPLATER) {
			syslog(LOG_INFO,
		    "replica_update: master server is busy, will try later.");
			__nis_freelogresult(lres);
			unlockTransLog(myself, 1);
			return (0);
		}

		if (lres->lr_status == NIS_SUCCESS) {
			int	skipped = 0;

			if (verbose)
				syslog(LOG_INFO,
				"replica_update: %d updates from '%s'",
				lres->lr_entries.lr_entries_len, srv->name);
			if (cons)
				fprintf(cons,
				"replica_update: %d updates from '%s'\n",
				lres->lr_entries.lr_entries_len, srv->name);
			nument = lres->lr_entries.lr_entries_len;
			if (nument == 0) {
				syslog(LOG_WARNING,
	"replica_update: master server returned NIS_SUCCESS, but 0 updates!");
				__nis_freelogresult(lres);
				unlockTransLog(myself, 1);
				return (1);
			}

			le = lres->lr_entries.lr_entries_val;

			/*
			 * If there are objects in the directory that are mapped
			 * from LDAP, we intend to skip those during the resync.
			 * This means that the time stamp of the last update in
			 * trans.log after the resync isn't necessarily the same
			 * as the last update known to the master. Hence, we
			 * save the latter in 'xttime'.
			 */
			xttime = le[nument-1].le_time;

			/* invalidate this directory in case of crash */
			make_stamp(name, ULONG_MAX);
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: Temporarily setting update time for "
				"\"%s\" to 0x%lx",
				myself, name, ULONG_MAX);
			xid = begin_transaction(nis_local_principal());
			begin_update();
			dbStatus = nis_put_offline(name, FALSE);
			if (dbStatus != DB_SUCCESS) {
				syslog(LOG_ERR,
			"replica_update: offline DB error %d for \"%s\"",
					dbStatus, name);
			}
			for (i = 0; i < nument; i++) {
				int		shouldskip, readok, io,
						doingModify = 0;
				nis_error	nerr;
				/*
				 * Is the object mapped from LDAP ?  If so,
				 * skip the update, but consider the
				 * application of the change a success.
				 */
				io = 0;
				switch (le[i].le_object.zo_data.zo_type) {
				case NIS_DIRECTORY_OBJ:
				case NIS_GROUP_OBJ:
				case NIS_TABLE_OBJ:
				case NIS_LINK_OBJ:
					io = 1;
					/* Fall through to entry obj */
				case NIS_ENTRY_OBJ:
					shouldskip =
						(getObjMapping(le[i].le_name, 0,
							io, &readok, 0) != 0 &&
						readok != 0);
					break;
				default:
					shouldskip = 0;
					break;
				}
				if (shouldskip) {
					logmsg(MSG_NOTIMECHECK,
#ifdef	NIS_LDAP_DEBUG
						LOG_WARNING,
#else
						LOG_INFO,
#endif	/* NIS_LDAP_DEBUG */
				"%s: skipping LDAP-mapped entry for \"%s\"",
						myself, NIL(le[i].le_name));
					skipped++;
					repl_stats.successes++;
					continue;
				}

				/*
				 * If the current operation is an entry
				 * removal, and the next one is an add
				 * of the same entry, tell the DB that
				 * we're in a modify, so that it can
				 * merge the remove/add into a single
				 * LDAP update.
				 */
				if (le[i].le_type == REM_IBASE &&
					i < nument-1 &&
					le[i+1].le_type == ADD_IBASE &&
					sameEntryObj(&le[i], &le[i+1])) {
					__nisdb_get_tsd()->doingModify = 1;
					doingModify = 1;
				}

				nerr = apply_update(&(le[i]));

				/*
				 * If we had informed the DB that this was
				 * part of a modify, and we've done the
				 * add (or the log update failed), turn
				 * off the modify indicaton.
				 */
				if (doingModify &&
					(le[i].le_type == ADD_IBASE ||
						nerr != NIS_SUCCESS)) {
					__nisdb_get_tsd()->doingModify = 0;
					doingModify = 0;
				}

				if (nerr != NIS_SUCCESS) {
					if (cons)
						fprintf(cons,
						"Failed to apply update.\n");
					syslog(LOG_ERR,
				"replica_update: Unable to apply update.");
					repl_stats.errors++;
					break;
				}
				if (cons)
					fprintf(cons,
					"Add update #%d to trans.log\n", i+1);
				if (add_update_nosync(&(le[i]),
					    (void **)&curr_upd) == 0) {
					repl_stats.errors++;
					break;
				} else {
					if (cons)
						fprintf(cons,
						"Added update to trans.log.\n");
					repl_stats.successes++;
				}
			}
			if (repl_stats.errors == 0) {
				if (cons)
					fprintf(cons,
						"Successfully updated.\n");
				end_update();
				dbStatus = nis_put_online(name, d_commit,
								FALSE);
				if (dbStatus != DB_SUCCESS) {
					syslog(LOG_ERR,
			"replica_update: online DB error %d for \"%s\"",
						dbStatus, name);
				}
				nis_db_sync_log();	/* *.log */
				sync_log();		/* trans.log */
				end_transaction(xid);
				if (curr_upd != 0)
					ttime = curr_upd->lu_time;
				else
					ttime = 0;
				if (!ttime && !skipped)
					/*
					 * This should never happen, otherwise
					 * this can force the replica to go
					 * into full resync.
					 */
					syslog(LOG_INFO,
			"replica_update: WARNING: last_update(%s) returned 0!",
					name);
				/*
				 * If we skipped updates because the object
				 * was mapped from LDAP, 'ttime' may not be
				 * valid, so we use the time from the master
				 * that we saved in 'xttime'.
				 */
				make_stamp(name, skipped ? xttime : ttime);
				__nis_freelogresult(lres);
				logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: Setting update time for \"%s\" to %s",
					myself, name,
					ctime_r(skipped ? (time_t *)&xttime :
							(time_t *)&ttime,
							ctbuf, CTBUFSIZ));
				unlockTransLog(myself, 1);
				return (1);
			} else {
				if (cons)
					fprintf(cons, "Aborted the update.\n");
				abort_transaction(xid);
				dbStatus = nis_put_online(name, d_rollback,
								FALSE);
				if (dbStatus != DB_SUCCESS) {
					syslog(LOG_ERR,
			"replica_update: online DB error %d for \"%s\"",
						dbStatus, name);
				}
				nis_db_sync_log();	/* *.log */
				sync_log();		/* trans.log */
				__nis_freelogresult(lres);
				unlockTransLog(myself, 1);
				return (0);
			}
		}

		if (lres->lr_status != NIS_RESYNC) {
			syslog(LOG_WARNING,
	"replica_update: nis_dumplog failed: srv='%s', dir='%s', err='%s'",
			srv->name, name, nis_sperrno(lres->lr_status));
			if (cons)
				fprintf(cons,
	"replica_update: nis_dumplog failed: srv='%s', dir='%s', err='%s'\n",
				srv->name, name, nis_sperrno(lres->lr_status));
			__nis_freelogresult(lres);
			unlockTransLog(myself, 1);
			return (0);
		}

		__nis_freelogresult(lres);
	}	/* end of delta update */

	/*
	 * Our log and the masters are sufficently out of date that we
	 * need to completely resync.
	 */
	if (verbose) {
		if (cons)
			fprintf(cons, "replica_update: Full dump required.\n");
		syslog(LOG_INFO, "replica_update: Full dump required.");
	}

	/*
	 * The following code handles full dump (resync) from the
	 * master.  Full dump only happens if the local timestamp
	 * returned from last_update():
	 * 	1) is 0 (zero), or
	 * 	2) cannot be found in on the master.
	 */
	syslog(LOG_INFO, "replica_update: Full dump of %s", name);

	dbStatus = nis_put_offline(name, TRUE);
	if (dbStatus != DB_SUCCESS) {
		syslog(LOG_ERR,
			"replica_update: offline DB error %d for \"%s\"",
			dbStatus, name);
		/* Haven't actually done anything, so return failure */
		unlockTransLog(myself, 1);
		return (0);
	}

	/* clear_directory(name); */ /* we might serve stale data */
	/*
	 * Note we *don't* transact this because if we fail we'll simply
	 * restart from the beginning. However, we hang on to the trans.log
	 * lock in order to prevent other threads from performing updates.
	 */
try_again:
	__nis_init_hash_table(&repl_objs, 0);
	__nis_destroy_callback();
	/*
	 * The case where all objects in the directory were mapped from LDAP
	 * was already handled above. If we get here, it may be that _some_
	 * of the objects are mapped from LDAP, but we also know that we're
	 * out-of-sync with the master for at least one object.
	 *
	 * The usual reason that we get to this point is that this is a
	 * newly created replica, and we'd probably like to build up its
	 * disk database ASAP. For this reason, and in the interest of
	 * simplicity (don't want to make libnsl, where nis_dump() lives,
	 * aware of LDAP mapping), we let the full dump get everything
	 * from the master, whether or not it's mapped from LDAP.
	 */
	lres = nis_dump(srv, name, update_directory);
	if (lres) {
		syslog(LOG_INFO, "replica_update: nis_dump result %s",
				nis_sperrno(lres->lr_status));
		syslog(LOG_INFO, "replica_update: %d updates, %d errors.",
				repl_stats.successes, repl_stats.errors);
	}
	/*
	 * Free up the cache of table objects
	 */
	LOCK_LIST(&repl_objs, "replica_update(repl_objs)");
	for (pp = (ping_item *)(repl_objs.first); pp; pp = nxt) {
		nxt = (ping_item *)(pp->item.nxt_item);
		if (!checkpoint_table(pp->item.name)) {
			/*
			 *  If lres indicates success, mark the error,
			 *  but continue so that repl_objs will be
			 *  cleaned up.  The status in lres will
			 *  be checked below.
			 */
			if (lres->lr_status == NIS_CBRESULTS)
				lres->lr_status = NIS_FAIL;
		}
		(void) nis_remove_item(pp->item.name, &repl_objs);
		XFREE(pp->item.name);
		nis_destroy_object(pp->obj);
		XFREE(pp);
	}
	ULOCK_LIST(&repl_objs, "replica_update(repl_objs)");

	if (lres == NULL || lres->lr_status == NIS_DUMPLATER) {
		if (lres)
			syslog(LOG_INFO,
	"replica_update: master server busy, rescheduling the resync.");
		if (ttime != 0L) {
			ttime = 0;
			make_stamp(name, ttime);
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: Setting update time for \"%s\" to 0x%lx",
				myself, name, ttime);
		}
		/*
		 * Note, we are not addressing the case when several replicas
		 * are initialized simultaneously i.e several nismkdir -s
		 * are executed before a nisping.
		 */
		dbStatus = nis_put_online(name, d_rollback, TRUE);
		if (dbStatus != DB_SUCCESS) {
			syslog(LOG_ERR,
			"replica_update: online DB error %d for \"%s\"",
				dbStatus, name);
		}
		__nis_freelogresult(lres);

		if (__nis_retry_sleep(&dumpRetry,
			dumpReturnUnsafe || (dbStatus != DB_SUCCESS))) {
			syslog(LOG_INFO,
				"replica_update: trying a full resync again");
			goto try_again;
		} else {
			/*
			 * Returning zero makes sure that this directory is not
			 * deleted from the upd_list. We'll try again after our
			 * poll times out.
			 */
			unlockTransLog(myself, 1);
			return (0);
		}
	}

	if (lres->lr_status == NIS_RPCERROR) { /* callback _setup_ failed */
		if (ttime != 0L) {
			ttime = 0;
			make_stamp(name, ttime);
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: Setting update time for \"%s\" to 0x%lx",
				myself, name, ttime);
		}
		/*
		 * Put back online, since the directory would not have been
		 * cleared.
		 */
		dbStatus = nis_put_online(name, d_rollback, TRUE);
		if (dbStatus != DB_SUCCESS) {
			syslog(LOG_ERR,
			"replica_update: online DB error %d for \"%s\"",
				dbStatus, name);
		}
		__nis_freelogresult(lres);

		if (__nis_retry_sleep(&dumpRetry,
			dumpReturnUnsafe || (dbStatus != DB_SUCCESS))) {
			syslog(LOG_INFO,
				"replica_update: trying a full resync again");
			goto try_again;
		} else {
			unlockTransLog(myself, 1);
			return (0); /* don't delete from upd_list */
		}

	} else if (lres->lr_status == NIS_NOTFOUND) { /* No longer on master */
		logmsg(MSG_NOTIMECHECK, LOG_INFO,
		    "%s: nis_dump failed: srv='%s', dir='%s', "
		    "No longer served by master", myself, srv->name, name);
		if (ttime != 0L) {
			ttime = 0;
			make_stamp(name, ttime);
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
			    "%s: Setting update time for \"%s\" to 0x%lx",
			    myself, name, ttime);
		}
		/*
		 * Put back online, nothing more we can do
		 */
		dbStatus = nis_put_online(name, d_rollback, TRUE);
		if (dbStatus != DB_SUCCESS) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
			    "replica_update: online DB error %d for \"%s\"",
			    myself, dbStatus, name);
		}
		__nis_freelogresult(lres);
		unlockTransLog(myself, 1);
		return (1); /* do delete from upd_list */

	} else if (lres->lr_status != NIS_CBRESULTS) { /* CB itself failed */
		syslog(LOG_WARNING,
	"replica_update: nis_dump failed: srv='%s', dir='%s', err='%s'",
			    srv->name, name, nis_sperrno(lres->lr_status));
		if (ttime != 0L) {
			ttime = 0;
			make_stamp(name, ttime);
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: Setting update time for \"%s\" to 0x%lx",
				myself, name, ttime);
		}
		__nis_freelogresult(lres);

		if (ldapConfig.dumpError == rollback) {
			dbStatus = nis_put_online(name, d_rollback, TRUE);
			if (dbStatus != DB_SUCCESS) {
				syslog(LOG_ERR,
			"replica_update: online DB error %d for \"%s\"",
					dbStatus, name);
			}
		}

		dumpReturnUnsafe = TRUE;

		/*
		 * Wait before retrying, abort dump if we've used up the
		 * allowed number of attempts. However, if rollback failed,
		 * we disregard 'dumpRetry.attempts' and always continue
		 * trying (since the data may not only be stale, but
		 * inconsistent or corrupted).
		 */
		if (!__nis_retry_sleep(&dumpRetry,
					(dbStatus != DB_SUCCESS))) {
			syslog(LOG_WARNING,
	"replica_update: Used %d dump attempts for \"%s\", serving stale data",
				ldapConfig.dumpErrorTimeout.attempts, name);
			unlockTransLog(myself, 1);
			return (0);
		}

		syslog(LOG_INFO, "replica_update: trying a full resync again.");

		if (ldapConfig.dumpError == rollback &&
				dbStatus == DB_SUCCESS) {
			dbStatus = nis_put_offline(name, TRUE);
			if (dbStatus != DB_SUCCESS) {
				syslog(LOG_ERR,
			"replica_update: offline DB error %d for \"%s\"",
					dbStatus, name);
			}
		}

		goto try_again;
	} else if (repl_stats.errors)  {
		syslog(LOG_WARNING,
		"replica_update: errors during resync : srv='%s', dir='%s'",
				    srv->name, name);
		xttime = 0;
		__nis_freelogresult(lres);
		if (ttime != 0L) {
			ttime = 0;
			make_stamp(name, ttime);
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: Setting update time for \"%s\" to 0x%lx",
				myself, name, ttime);
		}

		if (ldapConfig.dumpError == rollback) {
			dbStatus = nis_put_online(name, d_rollback, TRUE);
			if (dbStatus != DB_SUCCESS) {
				syslog(LOG_ERR,
			"replica_update: online DB error %d for \"%s\"",
					dbStatus, name);
			}
		}

		dumpReturnUnsafe = TRUE;

		/*
		 * Wait before retrying, abort dump if we've used up the
		 * allowed number of attempts. However, if rollback failed,
		 * we disregard 'dumpRetry.attempts' and always continue
		 * trying (since the data may not only be stale, but
		 * inconsistent or corrupted).
		 */
		if (!__nis_retry_sleep(&dumpRetry,
					(dbStatus != DB_SUCCESS))) {
			syslog(LOG_WARNING,
	"replica_update: Used %d dump attempts for \"%s\", serving stale data",
				ldapConfig.dumpErrorTimeout.attempts, name);
			unlockTransLog(myself, 1);
			return (0);
		}

		syslog(LOG_INFO, "replica_update: trying a full resync again.");

		if (ldapConfig.dumpError == rollback &&
				dbStatus == DB_SUCCESS) {
			dbStatus = nis_put_offline(name, TRUE);
			if (dbStatus != DB_SUCCESS) {
				syslog(LOG_ERR,
			"replica_update: offline DB error %d for \"%s\"",
					dbStatus, name);
			}
		}

		goto try_again;
	}
	/*
	 * Mark the now resync'd directory as stable.
	 * This is done by comparing the latest timestamp of
	 * all the objects we've seen with the latest timestamp
	 * from the master. This is required because the master
	 * stamps "remove" operations but they won't show up
	 * on a full resync.
	 */
	if (lres->lr_entries.lr_entries_len) {
		xttime = lres->lr_entries.lr_entries_val[0].le_time;
	} else {
		syslog(LOG_INFO,
"replica_update: downrev version of NIS+ service serving dir %s as master.",
			name);
		xttime = nis_cptime_msg(srv, name, FALSE, TRUE);
		xttime = (xttime < repl_stats.utime) ?
					repl_stats.utime : xttime;
	}
	if (cons)
		fprintf(cons, "Latest update was %s",
				ctime_r((time_t *)&repl_stats.utime, ctbuf,
				CTBUFSIZ));
	if (verbose)
		syslog(LOG_INFO,
			"replica_update: directory %s updated", name);

	/* Add it to the list of directories that it serves */
	nis_server_control(SERVING_LIST, DIR_ADD, name);
	__nis_freelogresult(lres);
	dbStatus = nis_put_online(name, d_commit, TRUE);
	if (dbStatus != NIS_SUCCESS) {
		syslog(LOG_ERR,
			"replica_update: online DB error %d for \"%s\"",
			dbStatus, name);
	}

	/*
	 * The full resync is now complete.  We need to put the
	 * current timestamp for the directory in the local
	 * transaction log.
	 * NOTE: variable "xttime" contains the valid timestamp
	 * for the directory.  It should never be 0.  However,
	 * if we do get this, we'll have to assume that there
	 * were some problem and we should force another resync.
	 */
	if ((xttime != 0L) || ((xttime == 0L) && (ttime != 0L))) {
		/*
		 * Always stamp with valid timestamp.
		 * We only stamp with timestamp of 0 if there
		 * isn't already a timestamp of 0 in the
		 * transaction log.
		 */
		make_stamp(name, xttime);
		logmsg(MSG_NOTIMECHECK, LOG_INFO,
			"%s: Setting update time for \"%s\" after "
			"full resync to %s",
			myself, name,
			ctime_r((time_t *)&xttime, ctbuf, CTBUFSIZ));
	}
	if (xttime == 0L)
		syslog(LOG_DEBUG,
	"replica_update: timestamp=0 after full resync completed!");
	unlockTransLog(myself, 1);
	return (1);
}

static void
ping_replicas_thread(t_pung)
	ping_item	*t_pung;
{

	if (verbose)
		syslog(LOG_INFO, "ping_replicas: Pinging %s",
			t_pung->item.name);

	nis_ping(t_pung->item.name, t_pung->mtime, t_pung->obj);

	if (t_pung->obj)
		nis_destroy_object(t_pung->obj);

	if (verbose)
		syslog(LOG_INFO, "ping_replicas_thread: directory %s time %ld",
			t_pung->item.name, t_pung->mtime);

	XFREE(t_pung->item.name);
	XFREE(t_pung);

	thr_exit(0);	/*	thread simply exits	*/
}


/*
 * ping_replicas()
 *
 * This function will send a "ping" to the replicas for a given directory
 * indicating that they should be ready to get updates to the database.
 *
 * It creates a thread to send the ping.
 * NOTE:        The main thread destroys the ping_item "pung" when
 *              ping_replicas() returns. To avoid problems, the
 *              ping_item is first cloned. The cloned ping_item
 *              must be destroyed in the thread.
 *
 * Once the thr_create is successful the operation is presumed to complete.
 *
 */
int
ping_replicas(pung)
	ping_item	*pung;
{
	thread_t	tid;
	sigset_t	new_mask, orig_mask;
	int		error;

	if (sigemptyset(&new_mask) != 0) {
		if (verbose)
			syslog(LOG_ERR,
				"ping_replicas: Error (%d) zeroing mask for %s",
				errno, pung->item.name);
		return (FALSE);
	}
	if (thr_sigsetmask(SIG_SETMASK, &new_mask, &orig_mask) != 0) {
		if (verbose)
			syslog(LOG_ERR,
				"ping_replicas: Error (%d) setting mask for %s",
				errno, pung->item.name);
		return (FALSE);
	}
	error = thr_create(NULL, 0,
		(void *(*)(void *))ping_replicas_thread, (void *)pung,
		THR_DETACHED, &tid);
	if (thr_sigsetmask(SIG_SETMASK, &orig_mask, NULL) != 0) {
		if (verbose)
			syslog(LOG_ERR,
			"ping_replicas: Error (%d) restoring mask for %s",
			errno, pung->item.name);
	}
	if (error) {
		if (verbose)
			syslog(LOG_ERR,
			"ping_replicas: Error (%d) creating ping thread for %s",
				error, pung->item.name);
		return (FALSE);
	}
	if (tid) {
		if (verbose)
			syslog(LOG_INFO,
				"ping_replicas: Created ping thread %d for %s",
				tid, pung->item.name);
		return (TRUE);
	} else
		return (FALSE);
}

/*
 * Recursion Safe versions of the lookup internals.
 *
 * These functions are the internal functions that are used by the
 * lookup and list functions in the library. When the server is linked
 * against libnsl, these functions replace those in the library and make
 * it safe for use to call nis_lookup() or nis_list().
 */

/*
 * nis_local_lookup()
 *
 * Lookup the requested information by calling the services listsvc or
 * lookup_svc entry points.
 */
nis_result *
__nis_local_lookup(req, flags, list_op, cbdata, cback)
	ib_request	*req;		/* name parameters		*/
	ulong_t		flags;		/* user flags			*/
	int		list_op;	/* list semantics		*/
	void		*cbdata;	/* Callback data		*/
	int		(*cback)();	/* Callback (for list calls)	*/
{
	ns_request	nsr;
	nis_result	*res;
	nis_result	*local_res;
	int		i;

	if (verbose)
		syslog(LOG_INFO, "nis_local_lookup: making local call.");

	res = XCALLOC(1, sizeof (nis_result));
	if (res == NULL)
		return (NULL);

	/*
	 * Depending on name or list_op either
	 * list it or look it up in the namespace.
	 */
	if ((req->ibr_srch.ibr_srch_len > 0) || (list_op)) {
		if (verbose)
			syslog(LOG_INFO, "local LIST");
		local_res = nis_iblist_svc(req, NULL);
	} else {
		char *name = req->ibr_name;
		size_t namelen = 0;

		if (name)
			namelen = strlen(name);

		/* sanity check on object name */
		if (namelen == 0 || name[namelen-1] != '.') {
			if (verbose)
				syslog(LOG_INFO,
					"nis_local_lookup: bad name '%s'",
					namelen ? name : "<NULL or empty>");
			res->status = NIS_BADNAME;
			return (res);
		}

		if (verbose)
			syslog(LOG_INFO, "local LOOKUP");
		nsr.ns_name = req->ibr_name;
		nsr.ns_object.ns_object_len = 0;
		nsr.ns_object.ns_object_val = NULL;
		local_res = nis_lookup_svc(&nsr, NULL);
	}

	/*
	 * Now duplicate the result for the client so that the
	 * client can call nis_freeresult() with impunity.
	 */
	*res = *local_res;
	if (res->objects.objects_len) {
		res->objects.objects_val = (nis_object *)
		    calloc(res->objects.objects_len,
				sizeof (nis_object));
		for (i = 0; i < res->objects.objects_len; i++) {
			(void) nis_clone_object(
				local_res->objects.objects_val+i,
				res->objects.objects_val+i);
		}
	}
	if (res->cookie.n_len) {
		res->cookie.n_bytes = (char *)
				malloc(res->cookie.n_len);
		memcpy(res->cookie.n_bytes, local_res->cookie.n_bytes,
					    local_res->cookie.n_len);
	}
	return (res);
}

/*
 * we_serve()
 *
 * return TRUE if an RPC call to this directory might call us
 * back.
 */
int
we_serve(srv, flags)
	directory_obj	*srv;
	ulong_t		flags;
{
	nis_server	*servers;
	int		ns, i;

	if (flags & MASTER_ONLY)
		ns = 1;
	else
		ns = srv->do_servers.do_servers_len;
	servers = srv->do_servers.do_servers_val;
	/*
	 * XXX NB: if the server name doesn't match but the
	 * address does, then we'll miss this check and recurse
	 * anyway. Sigh.
	 */
	for (i = 0; i < ns; i++)
		if (nis_dir_cmp(servers[i].name, nis_local_host())
				== SAME_NAME)
			return (1);
	return (0);
}

/*
 * nis_core_lookup()
 *
 * The bones of the lookup and list function, this function binds to, then
 * calls the appropriate NIS+ server for the given name. If the HARD_LOOKUP
 * flag is set it is ignored because the server cannot afford to block.
 *
 * NB: This function now follows links if flags is set up correctly. THis
 * localized this policy to this function and eliminated about 4
 * implementations of the same code in other modules.
 */
nis_result *
__nis_core_lookup(req, flags, list_op, cbdata, cback)
	ib_request	*req;		/* name parameters		*/
	ulong_t		flags;		/* user flags			*/
	int		list_op;	/* list semantics 		*/
	void		*cbdata;	/* Callback data		*/
	int		(*cback)();	/* Callback (for list calls) 	*/
{
	int parent_first;
	nis_error err;
	nis_result *res = NULL;
	directory_obj *dir;
	nis_bound_directory *binding;

	if (verbose)
		syslog(LOG_INFO, "__nis_core_lookup: (safe) called on %s",
							req->ibr_name);
	/*
	 * AS THE SERVICE, we don't support callbacks
	 */
	if (cbdata || cback) {
		return (nis_make_error(NIS_NOCALLBACK, 0, 0, 0, 0));
	}

	if (list_op && req->ibr_srch.ibr_srch_len == 0)
		parent_first = 0;
	else
		parent_first = 1;

	flags &= ~HARD_LOOKUP;	/* server doesn't do HARD_LOOKUP */
	err = nis_bind_dir(req->ibr_name, parent_first, &binding, flags);
	if (err != NIS_SUCCESS) {
		return (nis_make_error(err, 0, 0, 0, 0));
	}

	dir = &binding->dobj;

	/*
	 * special handling for root replicas.
	 *
	 * If the following conditions are met :
	 * 1) the directory we're going to query == our domain name
	 * 2) we allegedly serve it.
	 * 3) we don't have the "root_server" flag set
	 * Then we are a root_replica and we need to shunt this
	 * request to the master root server who will read the
	 * root object and return it to us.
	 */
	if ((nis_dir_cmp(dir->do_name, __nis_rpc_domain()) == SAME_NAME) &&
			! root_server && we_serve(dir, flags)) {
		flags |= MASTER_ONLY;
		if (we_serve(dir, flags)) {
			nis_free_binding(binding);
			return (nis_make_error(NIS_FAIL, 0, 0, 0, 0));
		}
	}

	/*
	 * As a server, we may serve the indicated directory, if we
	 * do then we *DON'T* do an RPC, rather we just call our
	 * selves. Note this *can* recurse.
	 */
	if (we_serve(dir, flags)) {
		res = __nis_local_lookup(req, flags, list_op, cbdata, cback);
		if (res && res->status == NIS_NOSUCHTABLE &&
			!we_serve(dir, MASTER_ONLY)) {
			/*
			 *  We supposedly serve the directory, but we don't
			 *  have a database for it (or the table), yet.
			 *  Try the master for now, until we get the
			 *  directory back in sync.  Of course, we shouldn't
			 *  do this if we are the master.
			 */
			nis_freeresult(res);
			res = __nis_remote_lookup(req, flags | MASTER_ONLY,
					list_op, cbdata, cback);
		}
	} else {
		res = __nis_remote_lookup(req, flags, list_op, cbdata, cback);
	}

	nis_free_binding(binding);

	return (res);
}

/*
 * __nis_finddirectory()
 *
 * This function will ask one of the servers of the given directory
 * where some unknown directory "name" is. This function is called
 * from within the __nis_CacheBind() code so is generally not needed by
 * the client. If the directory cannot be found it returns NULL.
 */
fd_result *
__nis_finddirectory(binding, name)
	nis_bound_directory **binding;
	nis_name		name;
{
	directory_obj	*slist;
	fd_result	*res;
	fd_result	*svc_res;
	fd_args		argp;
	int		i, ns;
	nis_server	*srvlist;
	enum name_pos	p;

	slist = &(*binding)->dobj;
	if (verbose)
		syslog(LOG_INFO, "nis_finddirectory (safe) : called.");
	memset((char *)&argp, 0, sizeof (argp));
	res = (fd_result *) XCALLOC(1, sizeof (fd_result));
	argp.dir_name = name;
	argp.requester = nis_local_host();
	p = nis_dir_cmp(name, __nis_rpc_domain());

	if (root_server && p == HIGHER_NAME) {
		res->status = NIS_NOTFOUND;
		return (res);
	}

	ns = slist->do_servers.do_servers_len;
	/*
	 * special case the root replica servers.
	 */
	if (we_serve(slist, 0) && (p != LOWER_NAME) && ! root_server)
		ns = 1; /* effectively "master only" */

	srvlist = slist->do_servers.do_servers_val;

	/*
	 * If this server is on the list and we have a database for it,
	 * just call the svc routine
	 */
	for (i = 0; i < ns; i++) {
		if (nis_dir_cmp(srvlist[i].name, argp.requester) == SAME_NAME) {
			/* Make sure we've got a database for it. */
			nis_error tab_status = db_find_table(slist->do_name);
			if (tab_status == NIS_NOSUCHTABLE) {
				if (we_serve(slist, MASTER_ONLY))
					tab_status = NIS_SYSTEMERROR;
				else
					tab_status = NIS_NOT_ME;
			}

			switch (tab_status) {
			case NIS_SUCCESS:
				svc_res = nis_finddirectory_svc(&argp, NULL);
				/*
				 * Note, we "clone" the find directory result
				 * because the cache client code will free it.
				 */
				if (svc_res && dup_fdres(svc_res, res)) {
					return (res);
				}
				return (NULL);

			case NIS_NOT_ME:
				/* not master */
				free((void *)res);
				goto try_srvlist;

			default:
				/* _fd_res puts returned obj on rags list */
				svc_res = __fd_res(argp.requester, tab_status,
						    NULL);
				/* clone fd_result for cache to free */
				if (svc_res && dup_fdres(svc_res, res))
					return (res);
				return (NULL);
			}
		}
	}

	/* Make an RPC call to locate the directory. */

try_srvlist:
	res = __nis_finddirectory_remote(binding, name);
	return (res);
}

int
__nis_host_is_server(nis_server *srv, int nsrv)
{
	int i;
	char *name = nis_local_host();

	for (i = 0; i < nsrv; i++) {
		if (nis_dir_cmp(srv[i].name, name) == SAME_NAME)
			return (1);
	}
	return (0);
}

fd_result *
dup_fdres(o, n)
	fd_result	*o;	/* The result to duplicate 	*/
	fd_result	*n;	/* Where to put the data	*/
{

#ifdef DEBUG
	if (verbose)
		syslog(LOG_INFO, "dup_fdres: cloning the FD result.");
#endif

	*n = *o;

	if (o->source)
		n->source = strdup(o->source);

	if (o->dir_data.dir_data_val) {
		n->dir_data.dir_data_val = (char *)
					    malloc(o->dir_data.dir_data_len);
		if (! n->dir_data.dir_data_val) {
			syslog(LOG_ERR, "dup_fdres: Out of memory!");
			return (NULL);
		}
		memcpy(n->dir_data.dir_data_val, o->dir_data.dir_data_val,
						o->dir_data.dir_data_len);
	}
	if (o->signature.signature_val) {
		n->signature.signature_val = (char *)
					    malloc(o->signature.signature_len);
		if (! n->signature.signature_val) {
			syslog(LOG_ERR, "dup_fdres: Out of memory!");
			if (n->dir_data.dir_data_val)
				free(n->dir_data.dir_data_val);
			return (NULL);
		}
		memcpy(n->signature.signature_val, o->signature.signature_val,
						o->signature.signature_len);
	}
	return (n);
}

DECLRWLOCK(root_object);

int
update_root_object(nis_name root_dir, nis_object *d_obj)
{
	WLOCK(root_object);
	if (nis_write_obj(nis_data(ROOT_OBJ), d_obj)) {
		writeColdStartFile(&(d_obj->DI_data));
		root_server = 1;
		WULOCK(root_object);
		__nis_CacheRestart();
		flush_local_dircache(root_dir);
		return (1);
	} else {
		WULOCK(root_object);
		return (0);
	}
}

nis_object*
get_root_object()
{
	/*
	 * XXX Maybe this can be cached and updated whenever
	 * update_root_object is called instead of being reread ???
	 */
	nis_object* d_obj;

	RLOCK(root_object);
	d_obj = nis_read_obj(nis_data(ROOT_OBJ));
	RULOCK(root_object);
	return (d_obj);
}

int
root_object_p(nis_name name)
{
	return (strcmp(name, ROOT_OBJ) == 0);
}

int
remove_root_object(nis_name root_dir, nis_object* d_obj)
{
	WLOCK(root_object);
	unlink(nis_data(ROOT_OBJ));
	writeColdStartFile(&(d_obj->DI_data));
	root_server = 0;
	WULOCK(root_object);
	__nis_CacheRestart();
	flush_local_dircache(root_dir);
	return (1);
}
