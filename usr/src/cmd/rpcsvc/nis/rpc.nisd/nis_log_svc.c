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
 * 	nis_log_svc.c
 *
 * This is the other part of the NIS+ logging facility. It contains functions
 * used by the service. The other part, nis_log_common.c contains functions
 * that are shared between the service and nislog the executable.
 *
 * These functions are implemented on top of the mmap primitives and
 * will change when user level threads are available. Mostly they can benefit
 * from having reader/writer locks in the log itself.
 *
 * The normal sequence of events is as follows :
 * 	At boot time :
 *		map_log(SHARED);
 *
 * 	For each update :
 *		xid = begin_transaction(who);
 *		add_update(entry);
 *			...
 *	Then on commit :
 *		end_transaction(xid);
 * 	Else on abort :
 *		abort_transaction();
 */

#include <time.h>
#include <syslog.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <rpc/types.h>
#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpcsvc/nis.h>
#include <limits.h>
#include "nis_proc.h"
#include "log.h"
#include "nis_mt.h"
#include "nisdb_mt.h"

u_long   cur_xid;
nis_name cur_princp;

/*
 * in_checkpoint, in_update, updatetime_cache moved to nis_log_common.c,
 * extern'd here.
 */
extern NIS_HASH_TABLE	*updatetime_cache;
extern int	in_checkpoint;
extern int	in_update;
extern log_hdr	*__nis_log;
extern int	__nis_logfd;
extern unsigned long __maxloglen, __loghiwater, __nis_logsize, __nis_filesize;

/*
 * variable used to assure that nisping warnings both do not flood the log
 * and also do get sent out periodically (moved to nis_log_common.c).
 */
extern long	next_warntime;

extern nis_object* get_root_object();

/*
 * abort_transaction()
 *
 * This function backs out a transaction in progress that was interrupted
 * by a server crash or some other unrecoverable error.
 * Note that the updates are backed out in reverse order from the way they
 * were applied. This is currently not strictly required for correctness
 * but will be required if a gang-modify operation is ever supported.
 */
int
abort_transaction(n_xid)
	int	n_xid;
{
	log_hdr		*log = __nis_log;
	XDR		xdrs;
	u_char		*data;
	log_entry	le;
	log_upd		*cur, *upd;
	int		error;
	nis_error	stat;
	nis_db_result	*dbres;
	nis_db_list_result	*lres;
	u_long		xid;
	int		prevWasModify, doingModify = 0;

	ASSERTWHELD(translog);

	/*
	 * Check to see if the update was written to the
	 * log.
	 */
	upd = log->lh_tail;
	xid  = upd->lu_xid;
	for (cur = upd; cur->lu_xid > log->lh_xid; cur = cur->lu_prev) {
		xdrmem_create(&xdrs, (char *)cur->lu_data, cur->lu_size,
								XDR_DECODE);
		memset((char *)&le, 0, sizeof (le));
		if (! xdr_log_entry(&xdrs, &le)) {
			syslog(LOG_ERR,
			    "Unable to decode transaction in log! Data LOST");
			continue;
		}

		prevWasModify = doingModify;
		doingModify = cur->lu_magic == LOG_UPD_MODMAG;
		/*
		 * Toggle the TSD 'doingModify' flag if necessary.
		 */
		if (doingModify && !prevWasModify) {
			__nisdb_get_tsd()->doingModify = 1;
		} else if (!doingModify && prevWasModify) {
			__nisdb_get_tsd()->doingModify = 0;
		}

		switch (le.le_type) {
			case ADD_NAME :
				dbres = db_lookup(le.le_name);
				if (dbres->status == NIS_SUCCESS) {
					stat = __db_remove(le.le_name,
								dbres->obj);
					if (stat != NIS_SUCCESS) {
						syslog(LOG_CRIT,
	"abort_transaction: Failed to remove '%s'.", le.le_name);
						abort();
					}
				} else if (dbres->status != NIS_NOTFOUND) {
					syslog(LOG_CRIT,
	"abort_transaction: Internal database error (%d)", dbres->status);
					abort();
				}
				/* Successfully backed it out */
				break;

			case REM_NAME :
				dbres = db_lookup(le.le_name);
				if (dbres->status == NIS_NOTFOUND) {
					stat = __db_add(le.le_name,
							&(le.le_object), 0);
					if (stat != NIS_SUCCESS) {
						syslog(LOG_CRIT,
	"abort_transaction: Failed to add '%s'.", le.le_name);
						abort();
					}
				} else if (dbres->status != NIS_SUCCESS) {
					syslog(LOG_CRIT,
	"abort_transaction: Internal database error.");
					abort();
				}
				/* Successfully backed it out */
				break;

			/* Skip the new modified object */
			case MOD_NAME_NEW :
				break;

			/* Add the old modified object over the new one */
			case MOD_NAME_OLD :
				dbres = db_lookup(le.le_name);
				if (dbres->status != NIS_SUCCESS) {
					syslog(LOG_CRIT,
			"abort_transaction: Internal database error.");
					abort();
				}
				if (! same_oid(dbres->obj, &le.le_object)) {
					stat = __db_add(le.le_name,
							&(le.le_object), 1);
					if (stat != NIS_SUCCESS) {
						syslog(LOG_CRIT,
	"abort_transaction: Failed to unmodify '%s'.", le.le_name);
						abort();
					}
				}
				/* Successfully backed it out */
				break;

			case ADD_IBASE :
				lres = db_list(le.le_name,
						    le.le_attrs.le_attrs_len,
						    le.le_attrs.le_attrs_val);
				if (lres->status == NIS_SUCCESS) {
					if (lres->numo > 1) {
						syslog(LOG_CRIT,
	"abort_transaction: Internal error, log entry corrupt (%s).",
							__make_name(&le));
						abort();
					}
					stat = __db_remib(le.le_name,
						    le.le_attrs.le_attrs_len,
						    le.le_attrs.le_attrs_val);
					if (stat != NIS_SUCCESS) {
						syslog(LOG_CRIT,
	"abort_transaction: Failed to remove '%s'.", __make_name(&le));
						abort();
					}
				} else if (lres->status != NIS_NOTFOUND) {
					syslog(LOG_CRIT,
	"abort_transaction: Internal database error.");
					abort();
				}
				/* Successfully backed it out */
				break;
			case REM_IBASE :
				lres = db_list(le.le_name,
						    le.le_attrs.le_attrs_len,
						    le.le_attrs.le_attrs_val);
				if (lres->status == NIS_NOTFOUND) {
					stat = __db_addib(le.le_name,
						    le.le_attrs.le_attrs_len,
						    le.le_attrs.le_attrs_val,
						    &(le.le_object));
					if (stat != NIS_SUCCESS) {
						syslog(LOG_CRIT,
	"abort_transaction: Failed to re-add '%s'.", __make_name(&le));
						abort();
					}
				} else if (lres->status == NIS_SUCCESS) {
					if (lres->numo > 1) {
						syslog(LOG_CRIT,
	"abort_transaction: Internal error, log entry corrupt (%s).",
							__make_name(&le));
						abort();
					}
				} else {
					syslog(LOG_CRIT,
	"abort_transaction: Internal database error.");
					abort();
				}
				break;
		}
		xdr_free((xdrproc_t)xdr_log_entry, (char *)&le);
		/* back up one update */
		log->lh_tail = cur->lu_prev;
	}

	if (log->lh_tail->lu_xid != log->lh_xid) {
		unlockTransLog("abort_transaction", 1);
		return (-1); /* Didn't back them all out! */
	}

	log->lh_state = LOG_STABLE;
	sync_header();

	unlockTransLog("abort_transaction", 1);

	return (0);
}

NIS_HASH_TABLE	stamp_list	= NIS_HASH_TABLE_MT_INIT;
NIS_HASH_TABLE	old_stamp_list	= NIS_HASH_TABLE_MT_INIT;

static int
add_stamp(name, utime)
	nis_name	name;
	u_long		utime;
{
	stamp_item	*si;

	si = (stamp_item *)(nis_find_item(name, &stamp_list));
	if (si) {
		if (si->utime < utime)
			si->utime = utime;
		__nis_release_item((NIS_HASH_ITEM *)si, &stamp_list, -1);
		return (0);
	}
	si = (stamp_item *)(XCALLOC(1, sizeof (stamp_item)));
	if (! si) {
		syslog(LOG_CRIT, "add_stamp(): out of memory.");
		abort();
	}
	si->item.name = (nis_name) XSTRDUP(name);
	if (! si->item.name) {
		syslog(LOG_CRIT, "add_stamp(): out of memory.");
		abort();
	}
	si->utime = utime;
	if (__nis_insert_item_mt((NIS_HASH_ITEM *)si, &stamp_list, 0) == 0) {
		free(si->item.name);
		free(si);
		si = __nis_find_item_mt(name, &stamp_list, 0, 0);
		/*
		 * If we can find it now, then __nis_insert_item_mt()
		 * probably failed because the item already existed, which
		 * is OK. If we can't find it, it's still possible that
		 * everything's fine (item didn't exist when we first tried
		 * to find it, had been created when we tried to insert, and
		 * then had been removed when we tried to find it again),
		 * so we just issue a warning.
		 */
		if (si == 0) {
			syslog(LOG_WARNING, "add_stamp(): unable to insert "
				"item for \"%s\"", name);
		}
	}
	return (1); /* first time we've seen it. */
}

static void
add_old_stamp(name, utime, uxid)
	nis_name	name;
	u_long		utime;
	u_long		uxid;
{
	old_stamp_item	*si;

	si = (old_stamp_item *)(nis_find_item(name, &old_stamp_list));
	if (si) {
		if (si->utime < utime)
			si->utime = utime;
		__nis_release_item((NIS_HASH_ITEM *)si, &old_stamp_list, -1);
		return;
	}
	si = (old_stamp_item *)(XCALLOC(1, sizeof (old_stamp_item)));
	if (! si) {
		syslog(LOG_CRIT, "add_old_stamp(): out of memory.");
		abort();
	}
	si->item.name = (nis_name) XSTRDUP(name);
	if (! si->item.name) {
		syslog(LOG_CRIT, "add_old_stamp(): out of memory.");
		abort();
	}
	si->utime = utime;
	si->stamped = 0;
	si->xid = uxid;
	if (__nis_insert_item_mt((NIS_HASH_ITEM *)si, &old_stamp_list, 0) ==
			0) {
		free(si->item.name);
		free(si);
		si = __nis_find_item_mt(name, &old_stamp_list, 0, 0);
		/*
		 * If we can find it now, then __nis_insert_item_mt()
		 * probably failed because the item already existed, which
		 * is OK. If we can't find it, it's still possible that
		 * everything's fine (item didn't exist when we first tried
		 * to find it, had been created when we tried to insert, and
		 * then had been removed when we tried to find it again),
		 * so we just issue a warning.
		 */
		if (si == 0) {
			syslog(LOG_WARNING, "add_old_stamp(): unable to insert "
				"item for \"%s\"", name);
		}
	}
}


/*
 * This routine inserts the specified update timestamp for the specified
 * directory into the new checkpointed data area.  It tries to insert a
 * timestamp with the xid specified.  If this xid is less than or equal
 * to the last xid appended to the new checkpointed data area, then
 * increment the offset_xid and use the (last_xid + offset_xid) as the
 * new xid for the timestamp entry.
 */
static void
insert_chkpt_stamp(name, utime, xid, offset_xid, last_xid, addr_p)
nis_name	name;	/* directory name */
ulong		utime;	/* last update timestamp */
ulong		xid;	/* last xid seen for this directory */
ulong		*offset_xid;	/* xid offset which is only incremented   */
				/* when xid to be inserted is <= the last */
				/* xid in the new checkpoint area.	  */
ulong		*last_xid;	/* last xid for checkpointed transactions */
ulong		*addr_p;	/* address pointer where the update */
				/* timestamp should go.		    */
{
	XDR		o_xdrs;
	log_upd		*o_upd;
	log_entry	to_le;
	u_long		o_upd_size, o_le_size;

	ASSERTWHELD(translog);

	if (name == NULL)
		return;
	memset((char *)&to_le, 0, sizeof (to_le));
	to_le.le_princp = nis_local_principal();
	to_le.le_time = utime;
	to_le.le_type = UPD_STAMP;
	to_le.le_name = name;
	__type_of(&(to_le.le_object)) = NIS_NO_OBJ;
	to_le.le_object.zo_name = "";
	to_le.le_object.zo_owner = "";
	to_le.le_object.zo_group = "";
	to_le.le_object.zo_domain = name;
	o_le_size = xdr_sizeof(xdr_log_entry, &to_le);
		/* value 20 below is a random added for extra padding */
	if ((o_upd = (log_upd *) malloc(o_le_size + sizeof (log_upd) + 20 +
			strlen(to_le.le_object.zo_domain))) == NULL) {
		syslog(LOG_CRIT, "insert_chkpt_stamp(): out of memory.");
		abort();
	}
	o_upd->lu_magic = LOG_UPD_MAGIC;
	o_upd->lu_prev = NULL;
	o_upd->lu_next = NULL;
	if (xid <= *last_xid) {
		(*offset_xid)++;
		o_upd->lu_xid = (*last_xid) + (*offset_xid);
	} else
		o_upd->lu_xid = xid;
	*last_xid = o_upd->lu_xid;
	o_upd->lu_time = utime;
	o_upd->lu_size = o_le_size;
	xdrmem_create(&o_xdrs, (char *)o_upd->lu_data, o_upd->lu_size,
		XDR_ENCODE);
	if (!xdr_log_entry(&o_xdrs, &to_le)) {
		syslog(LOG_CRIT,
		    "insert_chkpt_stamp(): xdr_log_entry failed.");
		abort();	}
	o_upd->lu_dirname = (char *)(NISRNDUP((((u_long) o_upd) +
		sizeof (log_upd) + o_upd->lu_size)));
	strcpy(o_upd->lu_dirname, to_le.le_object.zo_domain);
	o_upd_size = XID_SIZE(o_upd);
	memmove((char *)(*addr_p), (char *)o_upd, o_upd_size);
	*addr_p += o_upd_size;

	if (verbose) {
		syslog(LOG_INFO,
		"checkpoint_log: tombstone xid %d, time %d (%s) created",
		o_upd->lu_xid, o_upd->lu_time, o_upd->lu_dirname);
	}
	free(o_upd);
}


/*
 * make_tombstone creates the timestamp (tombstone) for the name
 * specified.
 * If no old timestamp found in old_stamp_list, just stamp it with utime.
 * If it's already stamped with an old timestamp don't stamp it again.
 * If it's not already stamped with the old timestamp, stamp it with utime.
 *
 * make_tombstone will also remove the item from old_stamp_list.
 */
static void
make_tombstone(name, utime)
nis_name	name;
ulong		utime;
{
	old_stamp_item	*o_si;
	log_entry	le;
	u_long		xid;

	ASSERTWHELD(translog);

	o_si = (old_stamp_item *)(nis_find_item(name, &old_stamp_list));
	if ((!o_si) || (!o_si->stamped)) {
		if (verbose)
			syslog(LOG_INFO,
				"make_tombstone: making timestamp %d for %s",
				utime, name);

		/* set up the log entry */
		memset((char *)&le, 0, sizeof (le));
		le.le_princp = nis_local_principal();
		le.le_time = utime;
		le.le_type = UPD_STAMP;
		le.le_name = name;
		__type_of(&(le.le_object)) = NIS_NO_OBJ;
		le.le_object.zo_name = "";
		le.le_object.zo_owner = "";
		le.le_object.zo_group = "";
		le.le_object.zo_domain = name;
		cur_xid = __nis_log->lh_xid + 1;
		cur_princp = le.le_princp;
		add_update(&le);
		__nis_log->lh_xid++;
		sync_header();
	}
	if (o_si) {
		o_si = nis_remove_item(o_si->item.name, &old_stamp_list);
		if (o_si != 0) {
			if (o_si->item.name != 0)
				free(o_si->item.name);
			free(o_si);
		}
	}
}


/*
 * checkpoint_log()
 *
 * This function removes all transactions up to the indicated time from
 * the log file.
 *
 * It returns 0 on failure, 1 on success.
 */

int
checkpoint_log()
{
	log_upd		*cur, *nxt;
	u_long		addr_p, upd_size;
	int		error;
	int		fd, i, num = 0;
	XDR		xdrs;
	log_entry	le;
	int		first, ret;
	stamp_item	*si;
	old_stamp_item	*o_si;
	char		backup[1024];
	ulong		last_xid = 0, offset_xid = 0;

	if (verbose)
		syslog(LOG_INFO, "Checkpointing the log.");

	if (lockTransLog("checkpoint_log", 1, 0) != 0)
		return (0);

	{
		__nis_hash_item_mt	*e;
		while ((e = __nis_pop_item_mt(&stamp_list)) != 0) {
			XFREE(e);
		}
	}

	if (__nis_log->lh_state != LOG_STABLE) {
		syslog(LOG_INFO,
			"checkpoint_log: Unable to checkpoint, log unstable.");
		unlockTransLog("checkpoint_log", 1);
		return (0);
	}

	/* XXX This should be a spin locks for the transaction funcs */
	in_checkpoint = TRUE;
	strcpy(backup, nis_data(BACKUP_LOG));

	fd = open(backup, O_WRONLY+O_SYNC+O_CREAT+O_TRUNC, 0600);
	if (fd == -1) {
		syslog(LOG_ERR,
	"checkpoint_log: Unable to checkpoint, can't open backup log (%s).",
								backup);
		in_checkpoint = FALSE;
		unlockTransLog("checkpoint_log", 1);
		return (0);
	}

	/*
	 * Make a backup of the log in two steps, write the size of the log
	 * and then a copy of the log.
	 */
	__nis_logsize = (__nis_log->lh_tail) ? LOG_SIZE(__nis_log) :
							sizeof (log_hdr);
	if (write(fd, &__nis_logsize, sizeof (long)) != sizeof (long)) {
		syslog(LOG_ERR,
			"checkpoint_log: Unable to checkpoint, disk full.");
		close(fd);
		unlink(backup);
		in_checkpoint = FALSE;
		unlockTransLog("checkpoint_log", 1);
		return (0);
	}
	if (verbose)
		syslog(LOG_INFO,
			"checkpoint_log: Backup log %s created.", backup);
	/*
	 * Now set the state to RESYNC so if we have to recover and read
	 * this back in, and we get screwed while reading it, we won't
	 * get into major trouble. This still leaves open one window :
	 * a) Start checkpoint
	 * b) Successfully backup to BACKUP
	 * c) Set log state to CHECKPOINT
	 * c) crash.
	 * d) Reboot and start reading in the backup log
	 * e) crash.
	 * f) reboot and now the log appears to be resync'ing without
	 *    all of its data.
	 */
	__nis_log->lh_state = LOG_RESYNC;
	if (write(fd, __nis_log, __nis_logsize) != __nis_logsize) {
		syslog(LOG_ERR,
			"checkpoint_log: Unable to checkpoint, disk full.");
		close(fd);
		unlink(backup);
		__nis_log->lh_state = LOG_STABLE;
		sync_header();
		in_checkpoint = FALSE;	/* Unlock */
		unlockTransLog("checkpoint_log", 1);
		return (0);
	}
	if (verbose)
		syslog(LOG_INFO, "checkpoint_log: Backup log %s written.",
								backup);
	close(fd);

	/* If we crash here we're ok since the log hasn't changed. */
	__nis_log->lh_state = LOG_CHECKPOINT;
	sync_header();

	addr_p = (u_long)(__nis_log->lh_head);
	/*
	 * If this transaction hasn't been fully replicated then
	 * leave it in the log.	Othersize don't bother moving it.
	 */
	if (verbose)
		syslog(LOG_INFO, "checkpoint_log: Checkpointing ...");

	for (cur = __nis_log->lh_head, num = 0; cur; cur = nxt) {
		nxt = cur->lu_next;
		xdrmem_create(&xdrs, (char *)cur->lu_data, cur->lu_size,
								XDR_DECODE);
		memset((char *)&le, 0, sizeof (log_entry));
		if (!xdr_log_entry(&xdrs, &le)) {
			syslog(LOG_ERR,
		"checkpoint_log: cannot read transaction log entry.");
			/* free up any malloc'd storage */
			xdr_free(xdr_log_entry, (char *)&le);
			unlockTransLog("checkpoint_log", 1);
			return (0);
		}
		/* ignore dummy entries used by delta-update */
		if (cur->lu_time == ULONG_MAX) {
			xdr_free(xdr_log_entry, (char *)&le);
			continue;
		}
		first = add_stamp(cur->lu_dirname, cur->lu_time);
		if (! nis_isstable(&le, first)) {
			/* check the old stamp list */
			o_si = (old_stamp_item *)
				(nis_find_item(cur->lu_dirname,
				&old_stamp_list));
			if ((o_si != NULL) && (o_si->stamped == 0)) {
				/* insert the old timestamp */
				insert_chkpt_stamp(o_si->item.name, o_si->utime,
					o_si->xid, &offset_xid, &last_xid,
					&addr_p);
				o_si->stamped = 1;
				num++;
			} else if ((o_si == NULL) &&
						(le.le_type == UPD_STAMP)) {
				/*
				 * if the the trasaction saved is of UPD_STAMP
				 * type, then add it into the old_stamp_list
				 * and mark it as stamped.
				 */
				add_old_stamp(cur->lu_dirname, cur->lu_time,
					cur->lu_xid);
				o_si = (old_stamp_item *)
					(nis_find_item(cur->lu_dirname,
					&old_stamp_list));
				if (o_si != 0)
					o_si->stamped = 1;
			}
			__nis_release_item((NIS_HASH_ITEM *)o_si,
						&old_stamp_list, -1);
			cur->lu_xid += offset_xid;
			last_xid = cur->lu_xid;
			if (verbose)
				syslog(LOG_INFO,
			"checkpoint_log: Transaction %d, time %d (%s) kept",
				cur->lu_xid, cur->lu_time, cur->lu_dirname);

			upd_size = XID_SIZE(cur);
			memmove((char *)addr_p, (char *)cur, upd_size);
			addr_p += upd_size;
			num++;
		} else {
			if (verbose)
				syslog(LOG_INFO,
			"checkpoint_log: Transaction %d, time %d (%s) removed",
				cur->lu_xid, cur->lu_time, cur->lu_dirname);
			add_old_stamp(cur->lu_dirname, cur->lu_time,
				cur->lu_xid);
		}
		/* free up any malloc'd storage */
		xdr_free(xdr_log_entry, (char *)&le);
	}

	if (num == 0) {
		/* Deleted all of the entries. */
		if (verbose)
			syslog(LOG_INFO,
				"checkpoint_log: all entries removed.");
		__nis_log->lh_head = NULL;
		__nis_log->lh_tail = NULL;
		__nis_log->lh_num = 0;
		sync_header();
		ret = ftruncate(__nis_logfd, FILE_BLK_SZ);
		if (ret == -1) {
			syslog(LOG_ERR,
			"checkpoint_log: cannot truncate transaction log file");
			abort();
		}
		__nis_filesize = FILE_BLK_SZ;
		ret = (int)lseek(__nis_logfd, __nis_filesize, SEEK_SET);
		if (ret == -1) {
			syslog(LOG_ERR,
		"checkpoint_log: cannot increase transaction log file size");
			abort();
		}
		ret = (int)write(__nis_logfd, "+", 1);
		if (ret != 1) {
			syslog(LOG_ERR,
			"cannot write one character to transaction log file");
			abort();
		}
		__nis_logsize = sizeof (log_hdr);
		if (msync((caddr_t)__nis_log, __nis_logsize, MS_SYNC)) {
			perror("msync:");
			syslog(LOG_CRIT, "unable to mysnc() LOG");
			abort();
		}

	} else {
		if (verbose)
			syslog(LOG_INFO,
				"checkpoint_log: some entries removed.");
		__nis_log->lh_xid = last_xid;
		__nis_log->lh_num = num;
		sync_header();
		error = __log_resync(__nis_log, FCHKPT);
		if (error) {
			syslog(LOG_CRIT,
		"checkpoint_log: Checkpoint failed, unable to resync.");
			abort();
		}
	}

	/*
	 * Write back "last update" stamps for all of the directories
	 * we've processed.
	 */
	LOCK_LIST(&stamp_list, "checkpoint_log(stamp_list)");
	in_checkpoint = FALSE;
	while (stamp_list.first) {
		nis_result	*res;
		nis_object	*d_obj;
		int		srv;
		ulong_t		ttime;

		si = (stamp_item *)(stamp_list.first);
		(void) nis_remove_item(si->item.name, &stamp_list);
		d_obj = NULL;
		res = nis_lookup(si->item.name, MASTER_ONLY);
		if ((res->status != NIS_NOTFOUND) &&
				(res->status != NIS_NOSUCHNAME)) {
			d_obj = res->objects.objects_val;
			if (res->status == NIS_SUCCESS) {
				if (__type_of(d_obj) != NIS_DIRECTORY_OBJ) {
					syslog(LOG_WARNING,
		"checkpoint_log: removed timestamp for %s (not a directory)",
						si->item.name);
				} else if ((srv = nis_isserving(d_obj)) != 0) {
					/*
					 * If we're a replica, we want to keep
					 * the last_update() time as our
					 * UPD_STAMP. We may have LDAP-sourced
					 * updates that are more recent, but
					 * that shouldn't show up to a
					 * NIS_CPTIME.
					 */
					if (srv == 1) {
						ttime = si->utime;
					} else {
						ttime =
						last_update(si->item.name);
						if (ttime == 0)
							ttime = si->utime;
					}
					make_tombstone(si->item.name,
							ttime);
				} else {
					if (verbose)
						syslog(LOG_INFO,
		"checkpoint_log: removed timestamp for %s (we no longer serve)",
						si->item.name);
				}
			} else {
				/*
				 * If nis_lookup() failed, we most likely
				 * aren't the master. Hence, we retain the
				 * existing last_update() time as our
				 * UPD_STAMP
				 */
				ttime = last_update(si->item.name);
				if (ttime == 0)
					ttime = si->utime;
				make_tombstone(si->item.name, ttime);
			}
		} else {
			if (verbose)
				syslog(LOG_INFO,
		"checkpoint_log: removed timestamp for %s (no longer exists)",
				si->item.name);
		}
		XFREE(si->item.name);
		XFREE(si);
		nis_freeresult(res);
	}
	ULOCK_LIST(&stamp_list, "checkpoint_log(stamp_list)");

	__nis_log->lh_state = LOG_STABLE;
	sync_header();
	unlink(backup);
	next_warntime = 0l;
	if (verbose)
		syslog(LOG_INFO, "checkpoint_log: Checkpoint complete.");

	/* re-generate the timestamp cache */
	init_updatetime();
	unlockTransLog("checkpoint_log", 1);

	return (1);
}

/*
 * last_update()
 *
 * This function scans the log backwards for the last timestamp of an update
 * that occurred on the named directory. If it cannot find an update for that
 * directory it returns 0L.
 */
u_long
last_update(name)
	nis_name	name;
{
	log_upd		*upd;

	/*
	 * Last update time for the root object is gotten from the object
	 * itself, or, it that does not exist, 0.
	 */
	if (root_object_p(name)) {
		nis_object* robj;

		if (robj = get_root_object()) {
			u_long ttime;
			ttime = robj->zo_oid.mtime;
			nis_destroy_object(robj);
			return (ttime);
		} else {
			return (0L);
		}
	}

	/*
	 * Always uses the cached update timestamp.  However, if somehow
	 * the cache is not available, it will fallback to the old way of
	 * using the transaction log.  In a readonly child, we insist on
	 * using the cache to avoid using corrupted data in the shared
	 * transaction log address space.
	 */

	if (updatetime_cache != NULL) {
		stamp_item	*si;
		u_long		utime;

		si = (stamp_item *)(nis_find_item(name, updatetime_cache));
		if (si) {
			utime = si->utime;
			if (verbose)
				syslog(LOG_INFO,
				"last_update: (cached) returning %d for %s.",
					utime, name);
			__nis_release_item(si, updatetime_cache, -1);
			/*
			 * If the update time is ULONG_MAX, the directory
			 * is invalid and should be dumped in its entirety.
			 * That's supposed to be handled during startup
			 * (the 'invalid_directory' code in nis_main.c),
			 * but if we got ULONG_MAX here, we do what we
			 * can to force a full dump by returning zero.
			 */
			return ((utime != ULONG_MAX) ? utime : 0);
		}
	} else {
		if (verbose)
			syslog(LOG_INFO, "last_update: No cache.");
		if (readonly) {
			if (verbose)
				syslog(LOG_INFO,
				    "last_update: returning 0 for %s", name);
			return (0L);
		}
		(void) lockTransLog("last_update", 1, 0);
		upd = __nis_log->lh_tail;
		while (upd) {
			if (nis_dir_cmp(name, upd->lu_dirname) == SAME_NAME) {
				if (verbose)
					syslog(LOG_INFO,
				"last_update: (log) returning %d for %s.",
					upd->lu_time, name);
				unlockTransLog("last_update", 1);
				return (upd->lu_time);
			}
			upd = upd->lu_prev;
		}
		unlockTransLog("last_update", 1);
	}
	if (verbose)
		syslog(LOG_INFO, "last_update: returning 0 for %s", name);
	return (0L);
}

/*
 * entries_since()
 *
 * This function returns a malloc'd array of entries for the passed
 * directory since the given timestamp. This is used when dumping
 * deltas to the replicas.  It returns NULL if it can't find any
 * entries.
 *
 * As part of the fix for bug 4186012, avoid including entries with
 * a time stamp greater than or equal to the current time. This avoids
 * distributing information about entries in the current second until
 * that time has passed. This means that, say, replicas see all the
 * updates for that second rather than there being a question about
 * which of the many possible updates with the same time stamp they
 * last saw. In the event of there being outstanding entries the
 * directory is added to the ping list so that the master will, in
 * time, nisping the replicas again.
 */
void
entries_since(dobj, dtime, res)
	nis_object	*dobj;
	u_long		dtime;
	log_result	*res;
{
	log_upd		*upd;
	log_upd		*first;
	u_char		**updates, **tmp;
	int		n_updates, total_updates, i;
	XDR		xdrs;
	time_t		currtime;
	char		name[NIS_MAXPATH];

	snprintf(name, NIS_MAXPATH, "%s.%s", dobj->zo_name, dobj->zo_domain);

	if (verbose)
		syslog(LOG_INFO, "entries_since: dir '%s', time %d.",
								name, dtime);

	res->lr_status = NIS_SUCCESS;
	(void) lockTransLog("entries_since", 0, 0);
	first = __nis_log->lh_tail;
	while (first) {
		if ((nis_dir_cmp(name, first->lu_dirname) == SAME_NAME) &&
		    (first->lu_time == dtime))
			break;
		first = first->lu_prev;
	}

	if (! first) {
		syslog(LOG_INFO, "entries_since: Replica of %s is out of date.",
					name);
		res->lr_status = NIS_RESYNC;
		unlockTransLog("entries_since", 0);
		return;
	}

	total_updates = 128;
	updates = (u_char **)XMALLOC(total_updates * sizeof (char *));
	if (! updates) {
		if (verbose)
			syslog(LOG_INFO, "entries_since(): out of memory");
		res->lr_status = NIS_NOMEMORY;
		unlockTransLog("entries_since", 0);
		return;
	}

	n_updates = 0;
	currtime = time(0);
	for (upd = first->lu_next; upd && (upd->lu_xid <= __nis_log->lh_xid);
							upd = upd->lu_next) {
		if ((nis_dir_cmp(name, upd->lu_dirname) == SAME_NAME) &&
		    (upd->lu_size > 4)) {
			if (upd->lu_time >= currtime) {
				if (verbose)
					syslog(LOG_INFO,
		"entries_since: avoiding returning entries updated "
		"this second (from xid %d)", upd->lu_xid);
				/*
				 * Make sure we ping the replicas
				 * soon. The master will only ping
				 * replicas once the updateBatchingTimeout
				 * has passed, so we estabtabllish a ping
				 * time that's the current time, minus the
				 * updateBatchingTimeout, plus one. This
				 * ensures the ping doesn't occur this second
				 * but ASAP afterwards.
				 */
				add_pingitem(dobj,
					currtime - updateBatchingTimeout() + 1,
					&ping_list);
				break;
			}
			if (verbose)
				syslog(LOG_INFO, "entries_since: xid %d",
								upd->lu_xid);
			updates[n_updates++] = &(upd->lu_data[0]);
			if ((n_updates % 128) == 126) {
				tmp = updates;
				total_updates += 128;
				updates = (u_char **)
					XMALLOC(total_updates*sizeof (u_char*));
				if (! updates) {
					syslog(LOG_INFO,
					"entries_since(): out of memory");
					res->lr_status = NIS_NOMEMORY;
					XFREE(tmp);
					unlockTransLog("entries_since", 0);
					return;
				}
				for (i = 0; i < n_updates; i++)
					updates[i] = tmp[i];
				XFREE(tmp);
			}
		}
	}
	syslog(LOG_INFO, "entries_since: Found %d deltas for dir %s",
		n_updates, name);
	if (n_updates == 0) {
		res->lr_status = NIS_SUCCESS;
		XFREE(updates);
		unlockTransLog("entries_since", 0);
		return;
	}
	res->lr_entries.lr_entries_val = (log_entry *)
					XCALLOC(n_updates, sizeof (log_entry));
	if (! res->lr_entries.lr_entries_val) {
		res->lr_status = NIS_NOMEMORY;
		XFREE(updates);
		unlockTransLog("entries_since", 0);
		return;
	}
	for (i = 0; i < n_updates; i++) {
		/*
		 * NOTE : Since we're xdr decoding we don't really care
		 * what the "size" value is, we're only going to decode
		 * one log entry anyway.
		 */
		xdrmem_create(&xdrs, (char *)updates[i], 0x4000000,
								XDR_DECODE);
		if (!xdr_log_entry(&xdrs, (res->lr_entries.lr_entries_val+i))) {
			res->lr_status = NIS_NOMEMORY;
			break;
		}
	}
	res->lr_entries.lr_entries_len = n_updates;
	XFREE(updates);
	unlockTransLog("entries_since", 0);
}
