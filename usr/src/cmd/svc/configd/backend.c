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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2017 Joyent, Inc.
 */

/*
 * sqlite is not compatible with _FILE_OFFSET_BITS=64, but we need to
 * be able to statvfs(2) possibly large systems.  This define gives us
 * access to the transitional interfaces.  See lfcompile64(5) for how
 * _LARGEFILE64_SOURCE works.
 */
#define	_LARGEFILE64_SOURCE

#include <assert.h>
#include <atomic.h>
#include <door.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>
#include <zone.h>
#include <libscf_priv.h>

#include "configd.h"
#include "repcache_protocol.h"

#include <sqlite.h>
#include <sqlite-misc.h>

/*
 * This file has two purposes:
 *
 * 1. It contains the database schema, and the code for setting up our backend
 *    databases, including installing said schema.
 *
 * 2. It provides a simplified interface to the SQL database library, and
 *    synchronizes MT access to the database.
 */

#define	IS_VOLATILE(be)		((be)->be_ppath != NULL)
#define	MAX_FLIGHT_RECORDER_EVENTS	100

typedef enum backend_switch_results {
	BACKEND_SWITCH_FATAL =	-1,
	BACKEND_SWITCH_OK =	0,
	BACKEND_SWITCH_RO
} backend_switch_results_t;

typedef struct backend_spent {
	uint64_t bs_count;
	hrtime_t bs_time;
	hrtime_t bs_vtime;
} backend_spent_t;

typedef struct backend_totals {
	backend_spent_t	bt_lock;	/* waiting for lock */
	backend_spent_t	bt_exec;	/* time spent executing SQL */
} backend_totals_t;

/*
 * There are times when svcadm asks configd to move the BACKEND_TYPE_NORMAL
 * repository to volatile storage.  See backend_switch().  When the
 * repository is on volatile storage, we save the location of the permanent
 * repository in be_ppath.  We use the saved path when the time comes to
 * move the repository back.  When the repository is on permanent storage,
 * be_ppath is set to NULL.  Also see the definition of IS_VOLATILE() above
 * for testing if the repository is on volatile storage.
 */
typedef struct sqlite_backend {
	pthread_mutex_t	be_lock;
	pthread_t	be_thread;	/* thread holding lock */
	struct sqlite	*be_db;
	const char	*be_path;	/* path to db */
	const char	*be_ppath;	/* saved path to persistent db when */
					/* backend is volatile */
	const char	*be_checkpoint;	/* path to repository checkpoint */
	int		be_readonly;	/* readonly at start, and still is */
	int		be_writing;	/* held for writing */
	backend_type_t	be_type;	/* type of db */
	hrtime_t	be_lastcheck;	/* time of last read-only check */
	backend_totals_t be_totals[2];	/* one for reading, one for writing */
} sqlite_backend_t;

struct backend_tx {
	sqlite_backend_t	*bt_be;
	int			bt_readonly;
	int			bt_type;
	int			bt_full;	/* SQLITE_FULL during tx */
};

#define	UPDATE_TOTALS_WR(sb, writing, field, ts, vts) { \
	backend_spent_t *__bsp = &(sb)->be_totals[!!(writing)].field; \
	__bsp->bs_count++;						\
	__bsp->bs_time += (gethrtime() - ts);				\
	__bsp->bs_vtime += (gethrvtime() - vts);			\
}

#define	UPDATE_TOTALS(sb, field, ts, vts) \
	UPDATE_TOTALS_WR(sb, (sb)->be_writing, field, ts, vts)

struct backend_query {
	char	*bq_buf;
	size_t	bq_size;
};

struct backend_tbl_info {
	const char *bti_name;
	const char *bti_cols;
};

struct backend_idx_info {
	const char *bxi_tbl;
	const char *bxi_idx;
	const char *bxi_cols;
};

/* Definitions for the flight recorder: */

typedef enum be_flight_type {
	BE_FLIGHT_EV_NOEVENT = 0,	/* No event yet recorded. */
	BE_FLIGHT_EV_BACKUP,		/* Information about repo. backup */
	BE_FLIGHT_EV_BACKUP_ENTER,	/* Enter */
					/* backend_create_backup_locked() */
	BE_FLIGHT_EV_CHECKPOINT,	/* Request to checkpoint repository */
					/* for boot time backup */
	BE_FLIGHT_EV_CHECKPOINT_EXISTS,	/* Existing checkpoint detected on */
					/* restart */
	BE_FLIGHT_EV_LINGERING_FAST,	/* Use lingering fast repository */
	BE_FLIGHT_EV_NO_BACKUP,		/* Requested backup not made */
	BE_FLIGHT_EV_REPO_CREATE,	/* Main repository created */
	BE_FLIGHT_EV_RESTART,		/* This is a restart of configd */
	BE_FLIGHT_EV_SWITCH,		/* Switch repositories */
	BE_FLIGHT_EV_TRANS_RW		/* Root transitioned to read/write */
} be_flight_type_t;

typedef enum be_flight_status {
	BE_FLIGHT_ST_INFO = 0,		/* No status.  Event is informative */
	BE_FLIGHT_ST_BOOT_BACKUP,	/* Boot time backup */
	BE_FLIGHT_ST_CHECKPOINT_BACKUP,	/* Backup from checkpoint */
	BE_FLIGHT_ST_CLIENT,		/* Request form client as opposed to */
					/* internal call */
	BE_FLIGHT_ST_DUPLICATE,		/* Backup duplicates existing one */
	BE_FLIGHT_ST_FAIL,		/* Operation failed. */
	BE_FLIGHT_ST_FAST,		/* Fast repository (tmpfs) */
	BE_FLIGHT_ST_MI_BACKUP,		/* Manifest-import backup */
	BE_FLIGHT_ST_NO_SWITCH,		/* Don't switch repositories */
	BE_FLIGHT_ST_OTHER_BACKUP,	/* Other type of backup */
	BE_FLIGHT_ST_PERMANENT,		/* Repository on permanet storage */
	BE_FLIGHT_ST_REPO_BACKUP,	/* Backup from repository */
	BE_FLIGHT_ST_RO,		/* Main repository is read-only */
	BE_FLIGHT_ST_RW,		/* Main repository is read/write */
	BE_FLIGHT_ST_SUCCESS,		/* Operation was successful */
	BE_FLIGHT_ST_SWITCH		/* Switch repository */
} be_flight_status_t;

typedef struct be_flight_event {
	be_flight_type_t	bfe_type;	/* Type of event. */
	be_flight_status_t	bfe_status;	/* Result of the event. */
	time_t			bfe_time;	/* Time of the event. */
	uint_t			bfe_sequence;	/* Sequence number. */
} be_flight_event_t;

static pthread_mutex_t backend_panic_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t backend_panic_cv = PTHREAD_COND_INITIALIZER;
pthread_t backend_panic_thread = 0;

int backend_do_trace = 0;		/* invoke tracing callback */
int backend_print_trace = 0;		/* tracing callback prints SQL */
int backend_panic_abort = 0;		/* abort when panicking */

/* Data for the flight_recorder. */

static pthread_mutex_t backend_flight_recorder_lock = PTHREAD_MUTEX_INITIALIZER;
static be_flight_event_t flight_recorder[MAX_FLIGHT_RECORDER_EVENTS];
static uint_t flight_recorder_next = 0;
static uint_t flight_recorder_missed = 0;
static uint_t flight_recorder_sequence = 0;

/* interval between read-only checks while starting up */
#define	BACKEND_READONLY_CHECK_INTERVAL	(2 * (hrtime_t)NANOSEC)

/*
 * Any incompatible change to the below schema should bump the version number.
 * The schema has been changed to support value ordering,  but this change
 * is backwards-compatible - i.e. a previous svc.configd can use a
 * repository database with the new schema perfectly well.  As a result,
 * the schema version has not been updated,  allowing downgrade of systems
 * without losing repository data.
 */
#define	BACKEND_SCHEMA_VERSION		5

static struct backend_tbl_info tbls_normal[] = { /* BACKEND_TYPE_NORMAL */
	/*
	 * service_tbl holds all services.  svc_id is the identifier of the
	 * service.
	 */
	{
		"service_tbl",
		"svc_id          INTEGER PRIMARY KEY,"
		"svc_name        CHAR(256) NOT NULL"
	},

	/*
	 * instance_tbl holds all of the instances.  The parent service id
	 * is instance_svc.
	 */
	{
		"instance_tbl",
		"instance_id     INTEGER PRIMARY KEY,"
		"instance_name   CHAR(256) NOT NULL,"
		"instance_svc    INTEGER NOT NULL"
	},

	/*
	 * snapshot_lnk_tbl links (instance, snapshot name) with snapshots.
	 */
	{
		"snapshot_lnk_tbl",
		"lnk_id          INTEGER PRIMARY KEY,"
		"lnk_inst_id     INTEGER NOT NULL,"
		"lnk_snap_name   CHAR(256) NOT NULL,"
		"lnk_snap_id     INTEGER NOT NULL"
	},

	/*
	 * snaplevel_tbl maps a snapshot id to a set of named, ordered
	 * snaplevels.
	 */
	{
		"snaplevel_tbl",
		"snap_id                 INTEGER NOT NULL,"
		"snap_level_num          INTEGER NOT NULL,"
		"snap_level_id           INTEGER NOT NULL,"
		"snap_level_service_id   INTEGER NOT NULL,"
		"snap_level_service      CHAR(256) NOT NULL,"
		"snap_level_instance_id  INTEGER NULL,"
		"snap_level_instance     CHAR(256) NULL"
	},

	/*
	 * snaplevel_lnk_tbl links snaplevels to property groups.
	 * snaplvl_pg_* is identical to the original property group,
	 * and snaplvl_gen_id overrides the generation number.
	 * The service/instance ids are as in the snaplevel.
	 */
	{
		"snaplevel_lnk_tbl",
		"snaplvl_level_id INTEGER NOT NULL,"
		"snaplvl_pg_id    INTEGER NOT NULL,"
		"snaplvl_pg_name  CHAR(256) NOT NULL,"
		"snaplvl_pg_type  CHAR(256) NOT NULL,"
		"snaplvl_pg_flags INTEGER NOT NULL,"
		"snaplvl_gen_id   INTEGER NOT NULL"
	},

	{ NULL, NULL }
};

static struct backend_idx_info idxs_normal[] = { /* BACKEND_TYPE_NORMAL */
	{ "service_tbl",	"name",	"svc_name" },
	{ "instance_tbl",	"name",	"instance_svc, instance_name" },
	{ "snapshot_lnk_tbl",	"name",	"lnk_inst_id, lnk_snap_name" },
	{ "snapshot_lnk_tbl",	"snapid", "lnk_snap_id" },
	{ "snaplevel_tbl",	"id",	"snap_id" },
	{ "snaplevel_lnk_tbl",	"id",	"snaplvl_pg_id" },
	{ "snaplevel_lnk_tbl",	"level", "snaplvl_level_id" },
	{ NULL, NULL, NULL }
};

static struct backend_tbl_info tbls_np[] = { /* BACKEND_TYPE_NONPERSIST */
	{ NULL, NULL }
};

static struct backend_idx_info idxs_np[] = {	/* BACKEND_TYPE_NONPERSIST */
	{ NULL, NULL, NULL }
};

static struct backend_tbl_info tbls_common[] = { /* all backend types */
	/*
	 * pg_tbl defines property groups.  They are associated with a single
	 * service or instance.  The pg_gen_id links them with the latest
	 * "edited" version of its properties.
	 */
	{
		"pg_tbl",
		"pg_id           INTEGER PRIMARY KEY,"
		"pg_parent_id    INTEGER NOT NULL,"
		"pg_name         CHAR(256) NOT NULL,"
		"pg_type         CHAR(256) NOT NULL,"
		"pg_flags        INTEGER NOT NULL,"
		"pg_gen_id       INTEGER NOT NULL"
	},

	/*
	 * prop_lnk_tbl links a particular pg_id and gen_id to a set of
	 * (prop_name, prop_type, val_id) trios.
	 */
	{
		"prop_lnk_tbl",
		"lnk_prop_id     INTEGER PRIMARY KEY,"
		"lnk_pg_id       INTEGER NOT NULL,"
		"lnk_gen_id      INTEGER NOT NULL,"
		"lnk_prop_name   CHAR(256) NOT NULL,"
		"lnk_prop_type   CHAR(2) NOT NULL,"
		"lnk_val_id      INTEGER"
	},

	/*
	 * value_tbl maps a value_id to a set of values.  For any given
	 * value_id, value_type is constant.  The table definition here
	 * is repeated in backend_check_upgrade(),  and must be kept in-sync.
	 */
	{
		"value_tbl",
		"value_id        INTEGER NOT NULL,"
		"value_type      CHAR(1) NOT NULL,"
		"value_value     VARCHAR NOT NULL,"
		"value_order     INTEGER DEFAULT 0"
	},

	/*
	 * id_tbl has one row per id space
	 */
	{
		"id_tbl",
		"id_name         STRING NOT NULL,"
		"id_next         INTEGER NOT NULL"
	},

	/*
	 * schema_version has a single row, which contains
	 * BACKEND_SCHEMA_VERSION at the time of creation.
	 */
	{
		"schema_version",
		"schema_version  INTEGER"
	},
	{ NULL, NULL }
};

/*
 * The indexing of value_tbl is repeated in backend_check_upgrade() and
 * must be kept in sync with the indexing specification here.
 */
static struct backend_idx_info idxs_common[] = { /* all backend types */
	{ "pg_tbl",		"parent", "pg_parent_id" },
	{ "pg_tbl",		"name",	"pg_parent_id, pg_name" },
	{ "pg_tbl",		"type",	"pg_parent_id, pg_type" },
	{ "prop_lnk_tbl",	"base",	"lnk_pg_id, lnk_gen_id" },
	{ "prop_lnk_tbl",	"val",	"lnk_val_id" },
	{ "value_tbl",		"id",	"value_id" },
	{ "id_tbl",		"id",	"id_name" },
	{ NULL, NULL, NULL }
};

struct run_single_int_info {
	uint32_t	*rs_out;
	int		rs_result;
};

static rep_protocol_responseid_t backend_copy_repository(const char *,
    const char *, int);
static rep_protocol_responseid_t backend_do_copy(const char *, int,
    const char *, int, size_t *);

/*
 * The flight recorder keeps track of events that happen primarily while
 * the system is booting.  Once the system is up an running, one can take a
 * gcore(1) of configd and examine the events with mdb.  Since we're most
 * interested in early boot events, we stop recording events when the
 * recorder is full.
 */
static void
flight_recorder_event(be_flight_type_t type, be_flight_status_t res)
{
	be_flight_event_t *data;
	uint_t item;
	uint_t sequence;

	if (pthread_mutex_lock(&backend_flight_recorder_lock) != 0) {
		atomic_inc_uint(&flight_recorder_missed);
		return;
	}
	if (flight_recorder_next >= MAX_FLIGHT_RECORDER_EVENTS) {
		/* Hit end of the array.  No more event recording. */
		item = flight_recorder_next;
	} else {
		item = flight_recorder_next++;
		sequence = flight_recorder_sequence++;
	}
	(void) pthread_mutex_unlock(&backend_flight_recorder_lock);

	if (item >= MAX_FLIGHT_RECORDER_EVENTS) {
		/* Array is filled.  Stop recording events */
		atomic_inc_uint(&flight_recorder_missed);
		return;
	}
	data = &flight_recorder[item];
	(void) memset(data, 0, sizeof (*data));
	data->bfe_type = type;
	data->bfe_status = res;
	data->bfe_sequence = sequence;
	data->bfe_time = time(NULL);
}

/*ARGSUSED*/
static int
run_single_int_callback(void *arg, int columns, char **vals, char **names)
{
	struct run_single_int_info *info = arg;
	uint32_t val;

	char *endptr = vals[0];

	assert(info->rs_result != REP_PROTOCOL_SUCCESS);
	assert(columns == 1);

	if (vals[0] == NULL)
		return (BACKEND_CALLBACK_CONTINUE);

	errno = 0;
	val = strtoul(vals[0], &endptr, 10);
	if ((val == 0 && endptr == vals[0]) || *endptr != 0 || errno != 0)
		backend_panic("malformed integer \"%20s\"", vals[0]);

	*info->rs_out = val;
	info->rs_result = REP_PROTOCOL_SUCCESS;
	return (BACKEND_CALLBACK_CONTINUE);
}

/*ARGSUSED*/
int
backend_fail_if_seen(void *arg, int columns, char **vals, char **names)
{
	return (BACKEND_CALLBACK_ABORT);
}

/*
 * check to see if we can successfully start a transaction;  if not, the
 * filesystem is mounted read-only.
 */
static int
backend_is_readonly(struct sqlite *db, const char *path)
{
	int r;
	statvfs64_t stat;

	if (statvfs64(path, &stat) == 0 && (stat.f_flag & ST_RDONLY))
		return (SQLITE_READONLY);

	r = sqlite_exec(db,
	    "BEGIN TRANSACTION; "
	    "UPDATE schema_version SET schema_version = schema_version; ",
	    NULL, NULL, NULL);
	(void) sqlite_exec(db, "ROLLBACK TRANSACTION", NULL, NULL, NULL);
	return (r);
}

static void
backend_trace_sql(void *arg, const char *sql)
{
	sqlite_backend_t *be = arg;

	if (backend_print_trace) {
		(void) fprintf(stderr, "%d: %s\n", be->be_type, sql);
	}
}

static sqlite_backend_t be_info[BACKEND_TYPE_TOTAL];
static sqlite_backend_t *bes[BACKEND_TYPE_TOTAL];

/*
 * For a native build,  repositories are created from scratch, so upgrade
 * is not an issue.  This variable is implicitly protected by
 * bes[BACKEND_TYPE_NORMAL]->be_lock.
 */
#ifdef NATIVE_BUILD
static boolean_t be_normal_upgraded = B_TRUE;
#else
static boolean_t be_normal_upgraded = B_FALSE;
#endif	/* NATIVE_BUILD */

/*
 * Has backend been upgraded? In nonpersistent case, answer is always
 * yes.
 */
boolean_t
backend_is_upgraded(backend_tx_t *bt)
{
	if (bt->bt_type == BACKEND_TYPE_NONPERSIST)
		return (B_TRUE);
	return (be_normal_upgraded);
}

#define	BACKEND_PANIC_TIMEOUT	(50 * MILLISEC)
/*
 * backend_panic() -- some kind of database problem or corruption has been hit.
 * We attempt to quiesce the other database users -- all of the backend sql
 * entry points will call backend_panic(NULL) if a panic is in progress, as
 * will any attempt to start a transaction.
 *
 * We give threads holding a backend lock 50ms (BACKEND_PANIC_TIMEOUT) to
 * either drop the lock or call backend_panic().  If they don't respond in
 * time, we'll just exit anyway.
 */
void
backend_panic(const char *format, ...)
{
	int i;
	va_list args;
	int failed = 0;

	(void) pthread_mutex_lock(&backend_panic_lock);
	if (backend_panic_thread != 0) {
		(void) pthread_mutex_unlock(&backend_panic_lock);
		/*
		 * first, drop any backend locks we're holding, then
		 * sleep forever on the panic_cv.
		 */
		for (i = 0; i < BACKEND_TYPE_TOTAL; i++) {
			if (bes[i] != NULL &&
			    bes[i]->be_thread == pthread_self())
				(void) pthread_mutex_unlock(&bes[i]->be_lock);
		}
		(void) pthread_mutex_lock(&backend_panic_lock);
		for (;;)
			(void) pthread_cond_wait(&backend_panic_cv,
			    &backend_panic_lock);
	}
	backend_panic_thread = pthread_self();
	(void) pthread_mutex_unlock(&backend_panic_lock);

	for (i = 0; i < BACKEND_TYPE_TOTAL; i++) {
		if (bes[i] != NULL && bes[i]->be_thread == pthread_self())
			(void) pthread_mutex_unlock(&bes[i]->be_lock);
	}

	va_start(args, format);
	configd_vcritical(format, args);
	va_end(args);

	for (i = 0; i < BACKEND_TYPE_TOTAL; i++) {
		timespec_t rel;

		rel.tv_sec = 0;
		rel.tv_nsec = BACKEND_PANIC_TIMEOUT;

		if (bes[i] != NULL && bes[i]->be_thread != pthread_self()) {
			if (pthread_mutex_reltimedlock_np(&bes[i]->be_lock,
			    &rel) != 0)
				failed++;
		}
	}
	if (failed) {
		configd_critical("unable to quiesce database\n");
	}

	if (backend_panic_abort)
		abort();

	exit(CONFIGD_EXIT_DATABASE_BAD);
}

/*
 * Returns
 *   _SUCCESS
 *   _DONE - callback aborted query
 *   _NO_RESOURCES - out of memory (_FULL & _TOOBIG?)
 */
static int
backend_error(sqlite_backend_t *be, int error, char *errmsg)
{
	if (error == SQLITE_OK)
		return (REP_PROTOCOL_SUCCESS);

	switch (error) {
	case SQLITE_ABORT:
		free(errmsg);
		return (REP_PROTOCOL_DONE);

	case SQLITE_NOMEM:
	case SQLITE_FULL:
	case SQLITE_TOOBIG:
		free(errmsg);
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);

	default:
		backend_panic("%s: db error: %s", be->be_path, errmsg);
		/*NOTREACHED*/
	}
}

static void
backend_backup_cleanup(const char **out_arg, ssize_t out_sz)
{
	char **out = (char **)out_arg;

	while (out_sz-- > 0)
		free(*out++);
	free(out_arg);
}

/*
 * builds a inverse-time-sorted array of backup files.  The path is a
 * a single buffer, and the pointers look like:
 *
 *	/this/is/a/full/path/to/repository-name-YYYYMMDDHHMMSS
 *	^pathname		^	       ^(pathname+pathlen)
 *				basename
 *
 * dirname will either be pathname, or ".".
 *
 * Returns the number of elements in the array, 0 if there are no previous
 * backups, or -1 on error.
 */
static ssize_t
backend_backup_get_prev(char *pathname, size_t pathlen, const char ***out_arg)
{
	char b_start, b_end;
	DIR *dir;
	char **out = NULL;
	char *name, *p;
	char *dirname, *basename;
	char *pathend;
	struct dirent *ent;

	size_t count = 0;
	size_t baselen;

	/*
	 * year, month, day, hour, min, sec, plus an '_'.
	 */
	const size_t ndigits = 4 + 5*2 + 1;
	const size_t baroffset = 4 + 2*2;

	size_t idx;

	pathend = pathname + pathlen;
	b_end = *pathend;
	*pathend = '\0';

	basename = strrchr(pathname, '/');

	if (basename != NULL) {
		assert(pathend > pathname && basename < pathend);
		basename++;
		dirname = pathname;
	} else {
		basename = pathname;
		dirname = ".";
	}

	baselen = strlen(basename);

	/*
	 * munge the string temporarily for the opendir(), then restore it.
	 */
	b_start = basename[0];

	basename[0] = '\0';
	dir = opendir(dirname);
	basename[0] = b_start;		/* restore path */

	if (dir == NULL)
		goto fail;


	while ((ent = readdir(dir)) != NULL) {
		/*
		 * Must match:
		 *	basename-YYYYMMDD_HHMMSS
		 * or we ignore it.
		 */
		if (strncmp(ent->d_name, basename, baselen) != 0)
			continue;

		name = ent->d_name;
		if (name[baselen] != '-')
			continue;

		p = name + baselen + 1;

		for (idx = 0; idx < ndigits; idx++) {
			char c = p[idx];
			if (idx == baroffset && c != '_')
				break;
			if (idx != baroffset && (c < '0' || c > '9'))
				break;
		}
		if (idx != ndigits || p[idx] != '\0')
			continue;

		/*
		 * We have a match.  insertion-sort it into our list.
		 */
		name = strdup(name);
		if (name == NULL)
			goto fail_closedir;
		p = strrchr(name, '-');

		for (idx = 0; idx < count; idx++) {
			char *tmp = out[idx];
			char *tp = strrchr(tmp, '-');

			int cmp = strcmp(p, tp);
			if (cmp == 0)
				cmp = strcmp(name, tmp);

			if (cmp == 0) {
				free(name);
				name = NULL;
				break;
			} else if (cmp > 0) {
				out[idx] = name;
				name = tmp;
				p = tp;
			}
		}

		if (idx == count) {
			char **new_out = realloc(out,
			    (count + 1) * sizeof (*out));

			if (new_out == NULL) {
				free(name);
				goto fail_closedir;
			}

			out = new_out;
			out[count++] = name;
		} else {
			assert(name == NULL);
		}
	}
	(void) closedir(dir);

	basename[baselen] = b_end;

	*out_arg = (const char **)out;
	return (count);

fail_closedir:
	(void) closedir(dir);
fail:
	basename[0] = b_start;
	*pathend = b_end;

	backend_backup_cleanup((const char **)out, count);

	*out_arg = NULL;
	return (-1);
}

/*
 * Copies the repository path into out, a buffer of out_len bytes,
 * removes the ".db" (or whatever) extension, and, if name is non-NULL,
 * appends "-name" to it.  If name is non-NULL, it can fail with:
 *
 *	_TRUNCATED	will not fit in buffer.
 *	_BAD_REQUEST	name is not a valid identifier
 */
static rep_protocol_responseid_t
backend_backup_base(sqlite_backend_t *be, const char *name,
    char *out, size_t out_len)
{
	char *p, *q;
	size_t len;

	/*
	 * for paths of the form /path/to/foo.db, we truncate at the final
	 * '.'.
	 */
	(void) strlcpy(out, IS_VOLATILE(be) ? be->be_ppath : be->be_path,
	    out_len);

	p = strrchr(out, '/');
	q = strrchr(out, '.');

	if (p != NULL && q != NULL && q > p)
		*q = 0;

	if (name != NULL) {
		len = strlen(out);
		assert(len < out_len);

		out += len;
		out_len -= len;

		len = strlen(name);

		/*
		 * verify that the name tag is entirely alphabetic,
		 * non-empty, and not too long.
		 */
		if (len == 0 || len >= REP_PROTOCOL_NAME_LEN ||
		    uu_check_name(name, UU_NAME_DOMAIN) < 0)
			return (REP_PROTOCOL_FAIL_BAD_REQUEST);

		if (snprintf(out, out_len, "-%s", name) >= out_len)
			return (REP_PROTOCOL_FAIL_TRUNCATED);
	}

	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Make a checkpoint of the repository, so that we can use it for a backup
 * when the root file system becomes read/write.  We'll first copy the
 * repository into a temporary file and then rename it to
 * REPOSITORY_CHECKPOINT.  This is protection against configd crashing in
 * the middle of the copy and leaving a partial copy at
 * REPOSITORY_CHECKPOINT.  Renames are atomic.
 */
static rep_protocol_responseid_t
backend_checkpoint_repository(sqlite_backend_t *be)
{
	rep_protocol_responseid_t r;

	assert(be->be_readonly);	/* Only need a checkpoint if / is ro */
	assert(be->be_type == BACKEND_TYPE_NORMAL);
	assert(be->be_checkpoint == NULL); /* Only 1 checkpoint */

	r = backend_copy_repository(be->be_path, REPOSITORY_CHECKPOINT, 0);
	if (r == REP_PROTOCOL_SUCCESS)
		be->be_checkpoint = REPOSITORY_CHECKPOINT;

	flight_recorder_event(BE_FLIGHT_EV_CHECKPOINT,
	    r == REP_PROTOCOL_SUCCESS ? BE_FLIGHT_ST_SUCCESS :
	    BE_FLIGHT_ST_FAIL);

	return (r);
}

/*
 * See if a backup is needed.  We do a backup unless both files are
 * byte-for-byte identical.
 */
static int
backend_check_backup_needed(const char *rep_name, const char *backup_name)
{
	int repfd = open(rep_name, O_RDONLY);
	int fd = open(backup_name, O_RDONLY);
	struct stat s_rep, s_backup;
	int c1, c2;

	FILE *f_rep = NULL;
	FILE *f_backup = NULL;

	if (repfd < 0 || fd < 0)
		goto fail;

	if (fstat(repfd, &s_rep) < 0 || fstat(fd, &s_backup) < 0)
		goto fail;

	/*
	 * if they are the same file, we need to do a backup to break the
	 * hard link or symlink involved.
	 */
	if (s_rep.st_ino == s_backup.st_ino && s_rep.st_dev == s_backup.st_dev)
		goto fail;

	if (s_rep.st_size != s_backup.st_size)
		goto fail;

	if ((f_rep = fdopen(repfd, "r")) == NULL ||
	    (f_backup = fdopen(fd, "r")) == NULL)
		goto fail;

	do {
		c1 = getc(f_rep);
		c2 = getc(f_backup);
		if (c1 != c2)
			goto fail;
	} while (c1 != EOF);

	if (!ferror(f_rep) && !ferror(f_backup)) {
		(void) fclose(f_rep);
		(void) fclose(f_backup);
		(void) close(repfd);
		(void) close(fd);
		return (0);
	}

fail:
	if (f_rep != NULL)
		(void) fclose(f_rep);
	if (f_backup != NULL)
		(void) fclose(f_backup);
	if (repfd >= 0)
		(void) close(repfd);
	if (fd >= 0)
		(void) close(fd);
	return (1);
}

/*
 * This interface is called to perform the actual copy
 *
 * Return:
 *	_FAIL_UNKNOWN		read/write fails
 *	_FAIL_NO_RESOURCES	out of memory
 *	_SUCCESS		copy succeeds
 */
static rep_protocol_responseid_t
backend_do_copy(const char *src, int srcfd, const char *dst,
    int dstfd, size_t *sz)
{
	char *buf;
	off_t nrd, nwr, n, r_off = 0, w_off = 0;

	if ((buf = malloc(8192)) == NULL)
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);

	while ((nrd = read(srcfd, buf, 8192)) != 0) {
		if (nrd < 0) {
			if (errno == EINTR)
				continue;

			configd_critical(
			    "Backend copy failed: fails to read from %s "
			    "at offset %d: %s\n", src, r_off, strerror(errno));
			free(buf);
			return (REP_PROTOCOL_FAIL_UNKNOWN);
		}

		r_off += nrd;

		nwr = 0;
		do {
			if ((n = write(dstfd, &buf[nwr], nrd - nwr)) < 0) {
				if (errno == EINTR)
					continue;

				configd_critical(
				    "Backend copy failed: fails to write to %s "
				    "at offset %d: %s\n", dst, w_off,
				    strerror(errno));
				free(buf);
				return (REP_PROTOCOL_FAIL_UNKNOWN);
			}

			nwr += n;
			w_off += n;

		} while (nwr < nrd);
	}

	if (sz)
		*sz = w_off;

	free(buf);
	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Can return:
 *	_BAD_REQUEST		name is not valid
 *	_TRUNCATED		name is too long for current repository path
 *	_UNKNOWN		failed for unknown reason (details written to
 *				console)
 *	_BACKEND_READONLY	backend is not writable
 *	_NO_RESOURCES		out of memory
 *	_SUCCESS		Backup completed successfully.
 */
static rep_protocol_responseid_t
backend_create_backup_locked(sqlite_backend_t *be, const char *name)
{
	const char **old_list;
	ssize_t old_sz;
	ssize_t old_max = max_repository_backups;
	ssize_t cur;
	char *finalname;
	char *finalpath;
	char *tmppath;
	int infd, outfd;
	size_t len;
	time_t now;
	struct tm now_tm;
	be_flight_status_t backup_type;
	rep_protocol_responseid_t result;
	const char *src;
	int use_checkpoint;

	if (strcmp(name, REPOSITORY_BOOT_BACKUP) == 0) {
		backup_type = BE_FLIGHT_ST_BOOT_BACKUP;
	} else if (strcmp(name, "manifest_import") ==  0) {
		backup_type = BE_FLIGHT_ST_MI_BACKUP;
	} else {
		backup_type = BE_FLIGHT_ST_OTHER_BACKUP;
	}
	flight_recorder_event(BE_FLIGHT_EV_BACKUP_ENTER, backup_type);

	if ((finalpath = malloc(PATH_MAX)) == NULL)
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);

	if ((tmppath = malloc(PATH_MAX)) == NULL) {
		free(finalpath);
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);
	}

	if (be->be_readonly) {
		flight_recorder_event(BE_FLIGHT_EV_NO_BACKUP, BE_FLIGHT_ST_RO);
		result = REP_PROTOCOL_FAIL_BACKEND_READONLY;
		goto out;
	}

	result = backend_backup_base(be, name, finalpath, PATH_MAX);
	if (result != REP_PROTOCOL_SUCCESS)
		goto out;

	/*
	 * If this is a boot backup and if we made a checkpoint before the
	 * root file system became read/write, then we should use the
	 * checkpoint as the source.  Otherwise, we'll use the actual
	 * repository as the source.
	 */
	if (be->be_checkpoint && name &&
	    strcmp(REPOSITORY_BOOT_BACKUP, name) == 0) {
		backup_type = BE_FLIGHT_ST_CHECKPOINT_BACKUP;
		use_checkpoint = 1;
		src = be->be_checkpoint;
	} else {
		backup_type = BE_FLIGHT_ST_REPO_BACKUP;
		use_checkpoint = 0;
		src = be->be_path;
	}
	flight_recorder_event(BE_FLIGHT_EV_BACKUP, backup_type);
	if (!backend_check_backup_needed(src, finalpath)) {
		/*
		 * No changes, so there is no need for a backup.
		 */
		flight_recorder_event(BE_FLIGHT_EV_NO_BACKUP,
		    BE_FLIGHT_ST_DUPLICATE);
		result = REP_PROTOCOL_SUCCESS;
		goto out;
	}

	/*
	 * remember the original length, and the basename location
	 */
	len = strlen(finalpath);
	finalname = strrchr(finalpath, '/');
	if (finalname != NULL)
		finalname++;
	else
		finalname = finalpath;

	(void) strlcpy(tmppath, finalpath, PATH_MAX);
	if (strlcat(tmppath, "-tmpXXXXXX", PATH_MAX) >= PATH_MAX) {
		result = REP_PROTOCOL_FAIL_TRUNCATED;
		goto out;
	}

	now = time(NULL);
	if (localtime_r(&now, &now_tm) == NULL) {
		configd_critical(
		    "\"%s\" backup failed: localtime(3C) failed: %s\n", name,
		    strerror(errno));
		result = REP_PROTOCOL_FAIL_UNKNOWN;
		goto out;
	}

	if (strftime(finalpath + len, PATH_MAX - len,
	    "-%Y""%m""%d""_""%H""%M""%S", &now_tm) >= PATH_MAX - len) {
		result = REP_PROTOCOL_FAIL_TRUNCATED;
		goto out;
	}

	infd = open(src, O_RDONLY);
	if (infd < 0) {
		configd_critical("\"%s\" backup failed: opening %s: %s\n", name,
		    src, strerror(errno));
		result = REP_PROTOCOL_FAIL_UNKNOWN;
		goto out;
	}

	outfd = mkstemp(tmppath);
	if (outfd < 0) {
		configd_critical("\"%s\" backup failed: mkstemp(%s): %s\n",
		    name, tmppath, strerror(errno));
		(void) close(infd);
		result = REP_PROTOCOL_FAIL_UNKNOWN;
		goto out;
	}

	if ((result = backend_do_copy(src, infd, (const char *)tmppath,
	    outfd, NULL)) != REP_PROTOCOL_SUCCESS)
		goto fail;

	/*
	 * grab the old list before doing our re-name.
	 */
	if (old_max > 0)
		old_sz = backend_backup_get_prev(finalpath, len, &old_list);

	if (rename(tmppath, finalpath) < 0) {
		configd_critical(
		    "\"%s\" backup failed: rename(%s, %s): %s\n",
		    name, tmppath, finalpath, strerror(errno));
		result = REP_PROTOCOL_FAIL_UNKNOWN;
		goto fail;
	}

	tmppath[len] = 0;	/* strip -XXXXXX, for reference symlink */

	(void) unlink(tmppath);
	if (symlink(finalname, tmppath) < 0) {
		configd_critical(
		    "\"%s\" backup completed, but updating "
		    "\"%s\" symlink to \"%s\" failed: %s\n",
		    name, tmppath, finalname, strerror(errno));
	}

	if (old_max > 0 && old_sz > 0) {
		/* unlink all but the first (old_max - 1) files */
		for (cur = old_max - 1; cur < old_sz; cur++) {
			(void) strlcpy(finalname, old_list[cur],
			    PATH_MAX - (finalname - finalpath));
			if (unlink(finalpath) < 0)
				configd_critical(
				    "\"%s\" backup completed, but removing old "
				    "file \"%s\" failed: %s\n",
				    name, finalpath, strerror(errno));
		}

		backend_backup_cleanup(old_list, old_sz);
	}

	result = REP_PROTOCOL_SUCCESS;
	flight_recorder_event(BE_FLIGHT_EV_BACKUP, BE_FLIGHT_ST_SUCCESS);

fail:
	(void) close(infd);
	(void) close(outfd);
	if (result != REP_PROTOCOL_SUCCESS) {
		flight_recorder_event(BE_FLIGHT_EV_BACKUP, BE_FLIGHT_ST_FAIL);
		(void) unlink(tmppath);
	}

out:
	/* Get rid of the checkpoint file now that we've used it. */
	if (use_checkpoint && (result == REP_PROTOCOL_SUCCESS)) {
		(void) unlink(be->be_checkpoint);
		be->be_checkpoint = NULL;
	}
	free(finalpath);
	free(tmppath);

	return (result);
}

/*
 * Check if value_tbl has been upgraded in the main database,  and
 * if not (if the value_order column is not present),  and do_upgrade is true,
 * upgrade value_tbl in repository to contain the additional value_order
 * column. The version of sqlite used means ALTER TABLE is not
 * available, so we cannot simply use "ALTER TABLE value_tbl ADD COLUMN".
 * Rather we need to create a temporary table with the additional column,
 * import the value_tbl, drop the original value_tbl, recreate the value_tbl
 * with the additional column, import the values from value_tbl_tmp,
 * reindex and finally drop value_tbl_tmp.  During boot, we wish to check
 * if the repository has been upgraded before it is writable,  so that
 * property value retrieval can use the appropriate form of the SELECT
 * statement that retrieves property values.  As a result, we need to check
 * if the repository has been upgraded prior to the point when we can
 * actually carry out the update.
 */
void
backend_check_upgrade(sqlite_backend_t *be, boolean_t do_upgrade)
{
	char *errp;
	int r;

	if (be_normal_upgraded)
		return;
	/*
	 * Test if upgrade is needed. If value_order column does not exist,
	 * we need to upgrade the schema.
	 */
	r = sqlite_exec(be->be_db, "SELECT value_order FROM value_tbl LIMIT 1;",
	    NULL, NULL, NULL);
	if (r == SQLITE_ERROR && do_upgrade) {
		/* No value_order column - needs upgrade */
		configd_info("Upgrading SMF repository format...");
		r = sqlite_exec(be->be_db,
		    "BEGIN TRANSACTION; "
		    "CREATE TABLE value_tbl_tmp ( "
		    "value_id   INTEGER NOT NULL, "
		    "value_type CHAR(1) NOT NULL, "
		    "value_value VARCHAR NOT NULL, "
		    "value_order INTEGER DEFAULT 0); "
		    "INSERT INTO value_tbl_tmp "
		    "(value_id, value_type, value_value) "
		    "SELECT value_id, value_type, value_value FROM value_tbl; "
		    "DROP TABLE value_tbl; "
		    "CREATE TABLE value_tbl( "
		    "value_id   INTEGER NOT NULL, "
		    "value_type CHAR(1) NOT NULL, "
		    "value_value VARCHAR NOT NULL, "
		    "value_order INTEGER DEFAULT 0); "
		    "INSERT INTO value_tbl SELECT * FROM value_tbl_tmp; "
		    "CREATE INDEX value_tbl_id ON value_tbl (value_id); "
		    "DROP TABLE value_tbl_tmp; "
		    "COMMIT TRANSACTION; "
		    "VACUUM; ",
		    NULL, NULL, &errp);
		if (r == SQLITE_OK) {
			configd_info("SMF repository upgrade is complete.");
		} else {
			backend_panic("%s: repository upgrade failed: %s",
			    be->be_path, errp);
			/* NOTREACHED */
		}
	}
	if (r == SQLITE_OK)
		be_normal_upgraded = B_TRUE;
	else
		be_normal_upgraded = B_FALSE;
}

static int
backend_check_readonly(sqlite_backend_t *be, int writing, hrtime_t t)
{
	const char *check_path;
	char *errp;
	struct sqlite *new;
	int r;

	assert(be->be_readonly);
	assert(be == bes[BACKEND_TYPE_NORMAL]);

	/*
	 * If we don't *need* to be writable, only check every once in a
	 * while.
	 */
	if (!writing) {
		if ((uint64_t)(t - be->be_lastcheck) <
		    BACKEND_READONLY_CHECK_INTERVAL)
			return (REP_PROTOCOL_SUCCESS);
		be->be_lastcheck = t;
	}

	/*
	 * It could be that the repository has been moved to non-persistent
	 * storage for performance reasons.  In this case we need to check
	 * the persistent path to see if it is writable.  The
	 * non-persistent path will always be writable.
	 */
	check_path = IS_VOLATILE(be) ? be->be_ppath : be->be_path;

	new = sqlite_open(check_path, 0600, &errp);
	if (new == NULL) {
		backend_panic("reopening %s: %s\n", check_path, errp);
		/*NOTREACHED*/
	}
	r = backend_is_readonly(new, check_path);

	if (r != SQLITE_OK) {
		/*
		 * The underlying storage for the permanent repository is
		 * still read-only, so we don't want to change the state or
		 * move the checkpointed backup if it exists.  On the other
		 * hand if the repository has been copied to volatile
		 * storage, we'll let our caller go ahead and write to the
		 * database.
		 */
		sqlite_close(new);
		if (writing && (IS_VOLATILE(be) == 0))
			return (REP_PROTOCOL_FAIL_BACKEND_READONLY);
		return (REP_PROTOCOL_SUCCESS);
	}

	/*
	 * We can write!  If the repository is not on volatile storage,
	 * swap the db handles.  Mark ourself as writable, upgrade the
	 * repository if necessary and make a backup.
	 */
	be->be_readonly = 0;
	flight_recorder_event(BE_FLIGHT_EV_TRANS_RW, BE_FLIGHT_ST_RW);
	if (IS_VOLATILE(be)) {
		/*
		 * If the repository is on volatile storage, don't switch
		 * the handles.  We'll continue to use the repository that
		 * is on tmpfs until we're told to move it back by one of
		 * our clients.  Clients, specifically manifest_import,
		 * move the repository to tmpfs for performance reasons,
		 * and that is the reason to not switch it back until we're
		 * told to do so.
		 */
		flight_recorder_event(BE_FLIGHT_EV_TRANS_RW,
		    BE_FLIGHT_ST_NO_SWITCH);
		sqlite_close(new);
	} else {
		flight_recorder_event(BE_FLIGHT_EV_TRANS_RW,
		    BE_FLIGHT_ST_SWITCH);
		sqlite_close(be->be_db);
		be->be_db = new;
	}

	if (be->be_type == BACKEND_TYPE_NORMAL)
		backend_check_upgrade(be, B_TRUE);

	if (backend_create_backup_locked(be, REPOSITORY_BOOT_BACKUP) !=
	    REP_PROTOCOL_SUCCESS) {
		configd_critical(
		    "unable to create \"%s\" backup of \"%s\"\n",
		    REPOSITORY_BOOT_BACKUP, be->be_path);
	}

	return (REP_PROTOCOL_SUCCESS);
}

/*
 * If t is not BACKEND_TYPE_NORMAL, can fail with
 *   _BACKEND_ACCESS - backend does not exist
 *
 * If writing is nonzero, can also fail with
 *   _BACKEND_READONLY - backend is read-only
 */
static int
backend_lock(backend_type_t t, int writing, sqlite_backend_t **bep)
{
	sqlite_backend_t *be = NULL;
	hrtime_t ts, vts;

	*bep = NULL;

	assert(t == BACKEND_TYPE_NORMAL ||
	    t == BACKEND_TYPE_NONPERSIST);

	be = bes[t];
	if (t == BACKEND_TYPE_NORMAL)
		assert(be != NULL);		/* should always be there */

	if (be == NULL)
		return (REP_PROTOCOL_FAIL_BACKEND_ACCESS);

	if (backend_panic_thread != 0)
		backend_panic(NULL);		/* don't proceed */

	ts = gethrtime();
	vts = gethrvtime();
	(void) pthread_mutex_lock(&be->be_lock);
	UPDATE_TOTALS_WR(be, writing, bt_lock, ts, vts);

	if (backend_panic_thread != 0) {
		(void) pthread_mutex_unlock(&be->be_lock);
		backend_panic(NULL);		/* don't proceed */
	}
	be->be_thread = pthread_self();

	if (be->be_readonly) {
		int r;
		assert(t == BACKEND_TYPE_NORMAL);

		r = backend_check_readonly(be, writing, ts);
		if (r != REP_PROTOCOL_SUCCESS) {
			be->be_thread = 0;
			(void) pthread_mutex_unlock(&be->be_lock);
			return (r);
		}
	}

	if (backend_do_trace)
		(void) sqlite_trace(be->be_db, backend_trace_sql, be);
	else
		(void) sqlite_trace(be->be_db, NULL, NULL);

	be->be_writing = writing;
	*bep = be;
	return (REP_PROTOCOL_SUCCESS);
}

static void
backend_unlock(sqlite_backend_t *be)
{
	be->be_writing = 0;
	be->be_thread = 0;
	(void) pthread_mutex_unlock(&be->be_lock);
}

static void
backend_destroy(sqlite_backend_t *be)
{
	if (be->be_db != NULL) {
		sqlite_close(be->be_db);
		be->be_db = NULL;
	}
	be->be_thread = 0;
	(void) pthread_mutex_unlock(&be->be_lock);
	(void) pthread_mutex_destroy(&be->be_lock);
}

static void
backend_create_finish(backend_type_t backend_id, sqlite_backend_t *be)
{
	assert(MUTEX_HELD(&be->be_lock));
	assert(be == &be_info[backend_id]);

	bes[backend_id] = be;
	(void) pthread_mutex_unlock(&be->be_lock);
}

static int
backend_fd_write(int fd, const char *mess)
{
	int len = strlen(mess);
	int written;

	while (len > 0) {
		if ((written = write(fd, mess, len)) < 0)
			return (-1);
		mess += written;
		len -= written;
	}
	return (0);
}

/*
 * Can return:
 *	_BAD_REQUEST		name is not valid
 *	_TRUNCATED		name is too long for current repository path
 *	_UNKNOWN		failed for unknown reason (details written to
 *				console)
 *	_BACKEND_READONLY	backend is not writable
 *	_NO_RESOURCES		out of memory
 *	_SUCCESS		Backup completed successfully.
 */
rep_protocol_responseid_t
backend_create_backup(const char *name)
{
	rep_protocol_responseid_t result;
	sqlite_backend_t *be;

	flight_recorder_event(BE_FLIGHT_EV_BACKUP, BE_FLIGHT_ST_CLIENT);
	result = backend_lock(BACKEND_TYPE_NORMAL, 0, &be);
	assert(result == REP_PROTOCOL_SUCCESS);

	result = backend_create_backup_locked(be, name);
	backend_unlock(be);

	return (result);
}

/*
 * This function makes a copy of the repository at src, placing the copy at
 * dst.  It is used to copy a repository on permanent storage to volatile
 * storage or vice versa.  If the source file is on volatile storage, it is
 * often times desirable to delete it after the copy has been made and
 * verified.  To remove the source repository, set remove_src to 1.
 *
 * Can return:
 *
 *	REP_PROTOCOL_SUCCESS		successful copy and rename
 *	REP_PROTOCOL_FAIL_UNKNOWN	file operation error
 *	REP_PROTOCOL_FAIL_NO_RESOURCES	out of memory
 */
static rep_protocol_responseid_t
backend_copy_repository(const char *src, const char *dst, int remove_src)
{
	int srcfd, dstfd;
	char *tmppath = malloc(PATH_MAX);
	rep_protocol_responseid_t res = REP_PROTOCOL_SUCCESS;
	struct stat s_buf;
	size_t cpsz, sz;

	if (tmppath == NULL) {
		res = REP_PROTOCOL_FAIL_NO_RESOURCES;
		goto out;
	}

	/*
	 * Create and open the related db files
	 */
	(void) strlcpy(tmppath, dst, PATH_MAX);
	sz = strlcat(tmppath, "-XXXXXX", PATH_MAX);
	assert(sz < PATH_MAX);
	if (sz >= PATH_MAX) {
		configd_critical(
		    "Backend copy failed: strlcat %s: overflow\n", tmppath);
		abort();
	}

	if ((dstfd = mkstemp(tmppath)) < 0) {
		configd_critical("Backend copy failed: mkstemp %s: %s\n",
		    tmppath, strerror(errno));
		res = REP_PROTOCOL_FAIL_UNKNOWN;
		goto out;
	}

	if ((srcfd = open(src, O_RDONLY)) < 0) {
		configd_critical("Backend copy failed: opening %s: %s\n",
		    src, strerror(errno));
		res = REP_PROTOCOL_FAIL_UNKNOWN;
		goto errexit;
	}

	/*
	 * fstat the backend before copy for sanity check.
	 */
	if (fstat(srcfd, &s_buf) < 0) {
		configd_critical("Backend copy failed: fstat %s: %s\n",
		    src, strerror(errno));
		res = REP_PROTOCOL_FAIL_UNKNOWN;
		goto errexit;
	}

	if ((res = backend_do_copy(src, srcfd, dst, dstfd, &cpsz)) !=
	    REP_PROTOCOL_SUCCESS)
		goto errexit;

	if (cpsz != s_buf.st_size) {
		configd_critical("Backend copy failed: incomplete copy\n");
		res = REP_PROTOCOL_FAIL_UNKNOWN;
		goto errexit;
	}

	/*
	 * Rename tmppath to dst
	 */
	if (rename(tmppath, dst) < 0) {
		configd_critical(
		    "Backend copy failed: rename %s to %s: %s\n",
		    tmppath, dst, strerror(errno));
		res = REP_PROTOCOL_FAIL_UNKNOWN;
	}

errexit:
	if (res != REP_PROTOCOL_SUCCESS && unlink(tmppath) < 0)
		configd_critical(
		    "Backend copy failed: remove %s: %s\n",
		    tmppath, strerror(errno));

	(void) close(srcfd);
	(void) close(dstfd);

out:
	free(tmppath);
	if (remove_src) {
		if (unlink(src) < 0)
			configd_critical(
			    "Backend copy failed: remove %s: %s\n",
			    src, strerror(errno));
	}

	return (res);
}

/*
 * Perform sanity check on the repository.
 * Return 0 if check succeeds or -1 if fails.
 */
static int
backend_switch_check(struct sqlite *be_db, char **errp)
{
	struct run_single_int_info info;
	uint32_t val = -1UL;
	int r;

	info.rs_out = &val;
	info.rs_result = REP_PROTOCOL_FAIL_NOT_FOUND;

	r = sqlite_exec(be_db,
	    "SELECT schema_version FROM schema_version;",
	    run_single_int_callback, &info, errp);

	if (r == SQLITE_OK &&
	    info.rs_result != REP_PROTOCOL_FAIL_NOT_FOUND &&
	    val == BACKEND_SCHEMA_VERSION)
		return (0);
	else
		return (-1);
}

/*
 * backend_switch() implements the REP_PROTOCOL_SWITCH request from
 * clients.  First, it blocks all other clients from accessing the
 * repository by calling backend_lock to lock the repository.  It either
 * copies the repository from it's permanent storage location
 * (REPOSITORY_DB) to its fast volatile location (FAST_REPOSITORY_DB), or
 * vice versa.  dir determines the direction of the copy.
 *
 *	dir = 0	Copy from permanent location to volatile location.
 *	dir = 1	Copy from volatile location to permanent location.
 *
 * Can return:
 *	REP_PROTOCOL_SUCCESS			successful switch
 *	REP_PROTOCOL_FAIL_BACKEND_ACCESS	backen access fails
 *	REP_PROTOCOL_FAIL_BACKEND_READONLY	backend is not writable
 *	REP_PROTOCOL_FAIL_UNKNOWN		file operation error
 *	REP_PROTOCOL_FAIL_NO_RESOURCES		out of memory
 */
rep_protocol_responseid_t
backend_switch(int dir)
{
	rep_protocol_responseid_t result;
	sqlite_backend_t *be;
	struct sqlite *new;
	char *errp;
	const char *dst;

	flight_recorder_event(BE_FLIGHT_EV_SWITCH, BE_FLIGHT_ST_CLIENT);

	/*
	 * If switching back to the main repository, lock for writing.
	 * Otherwise, lock for reading.
	 */
	result = backend_lock(BACKEND_TYPE_NORMAL, dir ? 1 : 0,
	    &be);
	if (result != REP_PROTOCOL_SUCCESS)
		return (result);

	if (dir) {
		flight_recorder_event(BE_FLIGHT_EV_SWITCH,
		    BE_FLIGHT_ST_PERMANENT);
		dst = REPOSITORY_DB;
	} else {
		flight_recorder_event(BE_FLIGHT_EV_SWITCH,
		    BE_FLIGHT_ST_FAST);
		dst = FAST_REPOSITORY_DB;
	}

	/*
	 * Do the actual copy and rename
	 */
	if (strcmp(be->be_path, dst) == 0) {
		flight_recorder_event(BE_FLIGHT_EV_SWITCH,
		    BE_FLIGHT_ST_DUPLICATE);
		result = REP_PROTOCOL_SUCCESS;
		goto errout;
	}

	result = backend_copy_repository(be->be_path, dst, dir);
	if (result != REP_PROTOCOL_SUCCESS) {
		goto errout;
	}

	/*
	 * Do the backend sanity check and switch
	 */
	new = sqlite_open(dst, 0600, &errp);
	if (new != NULL) {
		/*
		 * Sanity check
		 */
		if (backend_switch_check(new, &errp) == 0) {
			free((char *)be->be_path);
			be->be_path = strdup(dst);
			if (be->be_path == NULL) {
				configd_critical(
				    "Backend switch failed: strdup %s: %s\n",
				    dst, strerror(errno));
				result = REP_PROTOCOL_FAIL_NO_RESOURCES;
				sqlite_close(new);
			} else {
				sqlite_close(be->be_db);
				be->be_db = new;
				if (dir) {
					/* We're back on permanent storage. */
					be->be_ppath = NULL;
				} else {
					/*
					 * Repository is now on volatile
					 * storage.  Save the location of
					 * the persistent repository.
					 */
					be->be_ppath = REPOSITORY_DB;
				}
			}
		} else {
			configd_critical(
			    "Backend switch failed: integrity check %s: %s\n",
			    dst, errp);
			result = REP_PROTOCOL_FAIL_BACKEND_ACCESS;
		}
	} else {
		configd_critical("Backend switch failed: sqlite_open %s: %s\n",
		    dst, errp);
		result = REP_PROTOCOL_FAIL_BACKEND_ACCESS;
	}

errout:
	if (result == REP_PROTOCOL_SUCCESS) {
		flight_recorder_event(BE_FLIGHT_EV_SWITCH,
		    BE_FLIGHT_ST_SUCCESS);
	} else {
		flight_recorder_event(BE_FLIGHT_EV_SWITCH, BE_FLIGHT_ST_FAIL);
	}
	backend_unlock(be);
	return (result);
}

/*
 * This routine is called to attempt the recovery of
 * the most recent valid repository if possible when configd
 * is restarted for some reasons or when system crashes
 * during the switch operation.  The repository databases
 * referenced here are indicators of successful switch
 * operations.
 */
static backend_switch_results_t
backend_switch_recovery(void)
{
	const char *fast_db = FAST_REPOSITORY_DB;
	char *errp = NULL;
	struct stat s_buf;
	struct sqlite *be_db;
	int r;
	backend_switch_results_t res = BACKEND_SWITCH_OK;

	/*
	 * A good transient db containing most recent data can
	 * exist if svc.configd crashes during the
	 * switch operation.  If that is the case, check its
	 * integrity and use it.
	 */
	if (stat(fast_db, &s_buf) < 0) {
		return (BACKEND_SWITCH_OK);
	}

	/* Determine if persistent repository is read-only */
	be_db = sqlite_open(REPOSITORY_DB, 0600, &errp);
	if (be_db == NULL) {
		configd_critical("Unable to open \"%s\".  %s\n",
		    REPOSITORY_DB, errp == NULL ? "" : errp);
		free(errp);
		return (BACKEND_SWITCH_FATAL);
	}
	r = backend_is_readonly(be_db, REPOSITORY_DB);
	sqlite_close(be_db);
	if (r != SQLITE_OK) {
		if (r == SQLITE_READONLY) {
			return (BACKEND_SWITCH_RO);
		}
		return (BACKEND_SWITCH_FATAL);
	}

	/*
	 * Do sanity check on the db
	 */
	be_db = sqlite_open(fast_db, 0600, &errp);

	if (be_db != NULL) {
		if (backend_switch_check(be_db, &errp) == 0) {
			if (backend_copy_repository(fast_db,
			    REPOSITORY_DB, 1) != REP_PROTOCOL_SUCCESS) {
				res = BACKEND_SWITCH_FATAL;
			}
		}
		sqlite_close(be_db);
	}
	free(errp);

	/*
	 * If we get to this point, the fast_db has either been copied or
	 * it is useless.  Either way, get rid of it.
	 */
	(void) unlink(fast_db);

	return (res);
}

/*ARGSUSED*/
static int
backend_integrity_callback(void *private, int narg, char **vals, char **cols)
{
	char **out = private;
	char *old = *out;
	char *new;
	const char *info;
	size_t len;
	int x;

	for (x = 0; x < narg; x++) {
		if ((info = vals[x]) != NULL &&
		    strcmp(info, "ok") != 0) {
			len = (old == NULL)? 0 : strlen(old);
			len += strlen(info) + 2;	/* '\n' + '\0' */

			new = realloc(old, len);
			if (new == NULL)
				return (BACKEND_CALLBACK_ABORT);
			if (old == NULL)
				new[0] = 0;
			old = *out = new;
			(void) strlcat(new, info, len);
			(void) strlcat(new, "\n", len);
		}
	}
	return (BACKEND_CALLBACK_CONTINUE);
}

#define	BACKEND_CREATE_LOCKED		-2
#define	BACKEND_CREATE_FAIL		-1
#define	BACKEND_CREATE_SUCCESS		0
#define	BACKEND_CREATE_READONLY		1
#define	BACKEND_CREATE_NEED_INIT	2
static int
backend_create(backend_type_t backend_id, const char *db_file,
    sqlite_backend_t **bep)
{
	char *errp;
	char *integrity_results = NULL;
	sqlite_backend_t *be;
	int r;
	uint32_t val = -1UL;
	struct run_single_int_info info;
	int fd;

	assert(backend_id >= 0 && backend_id < BACKEND_TYPE_TOTAL);

	be = &be_info[backend_id];

	assert(be->be_db == NULL);

	(void) pthread_mutex_init(&be->be_lock, NULL);
	(void) pthread_mutex_lock(&be->be_lock);

	be->be_type = backend_id;
	be->be_path = strdup(db_file);
	if (be->be_path == NULL) {
		perror("malloc");
		goto fail;
	}

	be->be_db = sqlite_open(be->be_path, 0600, &errp);

	if (be->be_db == NULL) {
		if (strstr(errp, "out of memory") != NULL) {
			configd_critical("%s: %s\n", db_file, errp);
			free(errp);

			goto fail;
		}

		/* report it as an integrity failure */
		integrity_results = errp;
		errp = NULL;
		goto integrity_fail;
	}

	/*
	 * check if we are inited and of the correct schema version
	 *
	 */
	info.rs_out = &val;
	info.rs_result = REP_PROTOCOL_FAIL_NOT_FOUND;

	r = sqlite_exec(be->be_db, "SELECT schema_version FROM schema_version;",
	    run_single_int_callback, &info, &errp);
	if (r == SQLITE_ERROR &&
	    strcmp("no such table: schema_version", errp) == 0) {
		free(errp);
		/*
		 * Could be an empty repository, could be pre-schema_version
		 * schema.  Check for id_tbl, which has always been there.
		 */
		r = sqlite_exec(be->be_db, "SELECT count() FROM id_tbl;",
		    NULL, NULL, &errp);
		if (r == SQLITE_ERROR &&
		    strcmp("no such table: id_tbl", errp) == 0) {
			free(errp);
			*bep = be;
			return (BACKEND_CREATE_NEED_INIT);
		}

		configd_critical("%s: schema version mismatch\n", db_file);
		goto fail;
	}
	if (r == SQLITE_BUSY || r == SQLITE_LOCKED) {
		free(errp);
		*bep = NULL;
		backend_destroy(be);
		return (BACKEND_CREATE_LOCKED);
	}
	if (r == SQLITE_OK) {
		if (info.rs_result == REP_PROTOCOL_FAIL_NOT_FOUND ||
		    val != BACKEND_SCHEMA_VERSION) {
			configd_critical("%s: schema version mismatch\n",
			    db_file);
			goto fail;
		}
	}

	/*
	 * pull in the whole database sequentially.
	 */
	if ((fd = open(db_file, O_RDONLY)) >= 0) {
		size_t sz = 64 * 1024;
		char *buffer = malloc(sz);
		if (buffer != NULL) {
			while (read(fd, buffer, sz) > 0)
				;
			free(buffer);
		}
		(void) close(fd);
	}

	/*
	 * run an integrity check
	 */
	r = sqlite_exec(be->be_db, "PRAGMA integrity_check;",
	    backend_integrity_callback, &integrity_results, &errp);

	if (r == SQLITE_BUSY || r == SQLITE_LOCKED) {
		free(errp);
		*bep = NULL;
		backend_destroy(be);
		return (BACKEND_CREATE_LOCKED);
	}
	if (r == SQLITE_ABORT) {
		free(errp);
		errp = NULL;
		integrity_results = "out of memory running integrity check\n";
	} else if (r != SQLITE_OK && integrity_results == NULL) {
		integrity_results = errp;
		errp = NULL;
	}

integrity_fail:
	if (integrity_results != NULL) {
		const char *fname = "/etc/svc/volatile/db_errors";
		if ((fd = open(fname, O_CREAT|O_WRONLY|O_APPEND, 0600)) < 0) {
			fname = NULL;
		} else {
			if (backend_fd_write(fd, "\n\n") < 0 ||
			    backend_fd_write(fd, db_file) < 0 ||
			    backend_fd_write(fd,
			    ": PRAGMA integrity_check; failed.  Results:\n") <
			    0 || backend_fd_write(fd, integrity_results) < 0 ||
			    backend_fd_write(fd, "\n\n") < 0) {
				fname = NULL;
			}
			(void) close(fd);
		}

		if (!is_main_repository ||
		    backend_id == BACKEND_TYPE_NONPERSIST) {
			if (fname != NULL)
				configd_critical(
				    "%s: integrity check failed. Details in "
				    "%s\n", db_file, fname);
			else
				configd_critical(
				    "%s: integrity check failed.\n",
				    db_file);
		} else {
			(void) fprintf(stderr,
"\n"
"svc.configd: smf(5) database integrity check of:\n"
"\n"
"    %s\n"
"\n"
"  failed. The database might be damaged or a media error might have\n"
"  prevented it from being verified.  Additional information useful to\n"
"  your service provider%s%s\n"
"\n"
"  The system will not be able to boot until you have restored a working\n"
"  database.  svc.startd(1M) will provide a sulogin(1M) prompt for recovery\n"
"  purposes.  The command:\n"
"\n"
"    /lib/svc/bin/restore_repository\n"
"\n"
"  can be run to restore a backup version of your repository.  See\n"
"  http://illumos.org/msg/SMF-8000-MY for more information.\n"
"\n",
			    db_file,
			    (fname == NULL)? ":\n\n" : " is in:\n\n    ",
			    (fname == NULL)? integrity_results : fname);
		}
		free(errp);
		goto fail;
	}

	/*
	 * Simply do check if backend has been upgraded.  We do not wish
	 * to actually carry out upgrade here - the main repository may
	 * not be writable at this point.  Actual upgrade is carried out
	 * via backend_check_readonly().  This check is done so that
	 * we determine repository state - upgraded or not - and then
	 * the appropriate SELECT statement (value-ordered or not)
	 * can be used when retrieving property values early in boot.
	 */
	if (backend_id == BACKEND_TYPE_NORMAL)
		backend_check_upgrade(be, B_FALSE);
	/*
	 * check if we are writable
	 */
	r = backend_is_readonly(be->be_db, be->be_path);

	if (r == SQLITE_BUSY || r == SQLITE_LOCKED) {
		free(errp);
		*bep = NULL;
		backend_destroy(be);
		return (BACKEND_CREATE_LOCKED);
	}
	if (r != SQLITE_OK && r != SQLITE_FULL) {
		free(errp);
		be->be_readonly = 1;
		*bep = be;
		return (BACKEND_CREATE_READONLY);
	}

	*bep = be;
	return (BACKEND_CREATE_SUCCESS);

fail:
	*bep = NULL;
	backend_destroy(be);
	return (BACKEND_CREATE_FAIL);
}

/*
 * (arg & -arg) is, through the magic of twos-complement arithmetic, the
 * lowest set bit in arg.
 */
static size_t
round_up_to_p2(size_t arg)
{
	/*
	 * Don't allow a zero result.
	 */
	assert(arg > 0 && ((ssize_t)arg > 0));

	while ((arg & (arg - 1)) != 0)
		arg += (arg & -arg);

	return (arg);
}

/*
 * Returns
 *   _NO_RESOURCES - out of memory
 *   _BACKEND_ACCESS - backend type t (other than _NORMAL) doesn't exist
 *   _DONE - callback aborted query
 *   _SUCCESS
 */
int
backend_run(backend_type_t t, backend_query_t *q,
    backend_run_callback_f *cb, void *data)
{
	char *errmsg = NULL;
	int ret;
	sqlite_backend_t *be;
	hrtime_t ts, vts;

	if (q == NULL || q->bq_buf == NULL)
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);

	if ((ret = backend_lock(t, 0, &be)) != REP_PROTOCOL_SUCCESS)
		return (ret);

	ts = gethrtime();
	vts = gethrvtime();
	ret = sqlite_exec(be->be_db, q->bq_buf, cb, data, &errmsg);
	UPDATE_TOTALS(be, bt_exec, ts, vts);
	ret = backend_error(be, ret, errmsg);
	backend_unlock(be);

	return (ret);
}

/*
 * Starts a "read-only" transaction -- i.e., locks out writers as long
 * as it is active.
 *
 * Fails with
 *   _NO_RESOURCES - out of memory
 *
 * If t is not _NORMAL, can also fail with
 *   _BACKEND_ACCESS - backend does not exist
 *
 * If writable is true, can also fail with
 *   _BACKEND_READONLY
 */
static int
backend_tx_begin_common(backend_type_t t, backend_tx_t **txp, int writable)
{
	backend_tx_t *ret;
	sqlite_backend_t *be;
	int r;

	*txp = NULL;

	ret = uu_zalloc(sizeof (*ret));
	if (ret == NULL)
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);

	if ((r = backend_lock(t, writable, &be)) != REP_PROTOCOL_SUCCESS) {
		uu_free(ret);
		return (r);
	}

	ret->bt_be = be;
	ret->bt_readonly = !writable;
	ret->bt_type = t;
	ret->bt_full = 0;

	*txp = ret;
	return (REP_PROTOCOL_SUCCESS);
}

int
backend_tx_begin_ro(backend_type_t t, backend_tx_t **txp)
{
	return (backend_tx_begin_common(t, txp, 0));
}

static void
backend_tx_end(backend_tx_t *tx)
{
	sqlite_backend_t *be;

	be = tx->bt_be;

	if (tx->bt_full) {
		struct sqlite *new;

		/*
		 * sqlite tends to be sticky with SQLITE_FULL, so we try
		 * to get a fresh database handle if we got a FULL warning
		 * along the way.  If that fails, no harm done.
		 */
		new = sqlite_open(be->be_path, 0600, NULL);
		if (new != NULL) {
			sqlite_close(be->be_db);
			be->be_db = new;
		}
	}
	backend_unlock(be);
	tx->bt_be = NULL;
	uu_free(tx);
}

void
backend_tx_end_ro(backend_tx_t *tx)
{
	assert(tx->bt_readonly);
	backend_tx_end(tx);
}

/*
 * Fails with
 *   _NO_RESOURCES - out of memory
 *   _BACKEND_ACCESS
 *   _BACKEND_READONLY
 */
int
backend_tx_begin(backend_type_t t, backend_tx_t **txp)
{
	int r;
	char *errmsg;
	hrtime_t ts, vts;

	r = backend_tx_begin_common(t, txp, 1);
	if (r != REP_PROTOCOL_SUCCESS)
		return (r);

	ts = gethrtime();
	vts = gethrvtime();
	r = sqlite_exec((*txp)->bt_be->be_db, "BEGIN TRANSACTION", NULL, NULL,
	    &errmsg);
	UPDATE_TOTALS((*txp)->bt_be, bt_exec, ts, vts);
	if (r == SQLITE_FULL)
		(*txp)->bt_full = 1;
	/*
	 * We explicitly handle an ENOSPC error here for the beginning of the
	 * transaction, instead of in backend_error, which calls backend_panic
	 * for this case, resulting in the death of svc.configd. That may be
	 * appropriate in other cases, but in this case we would rather fail so
	 * that configd remains up and the caller gets an approprate error. The
	 * failure mode is that there is not enough swap space to open the
	 * non-persistent database, so there won't be enough space to restart
	 * configd, leaving SMF in a state requiring manual intervention.
	 */
	if (r == SQLITE_CANTOPEN && errno == ENOSPC &&
	    (*txp)->bt_type == BACKEND_TYPE_NONPERSIST) {
		configd_info("Warning: no space to open %s\n",
		    bes[BACKEND_TYPE_NONPERSIST]->be_path);
		r = REP_PROTOCOL_FAIL_NO_RESOURCES;
	} else {
		r = backend_error((*txp)->bt_be, r, errmsg);
	}

	if (r != REP_PROTOCOL_SUCCESS) {
		assert(r != REP_PROTOCOL_DONE);
		(void) sqlite_exec((*txp)->bt_be->be_db,
		    "ROLLBACK TRANSACTION", NULL, NULL, NULL);
		backend_tx_end(*txp);
		*txp = NULL;
		return (r);
	}

	(*txp)->bt_readonly = 0;

	return (REP_PROTOCOL_SUCCESS);
}

void
backend_tx_rollback(backend_tx_t *tx)
{
	int r;
	char *errmsg;
	sqlite_backend_t *be;
	hrtime_t ts, vts;

	assert(tx != NULL && tx->bt_be != NULL && !tx->bt_readonly);
	be = tx->bt_be;

	ts = gethrtime();
	vts = gethrvtime();
	r = sqlite_exec(be->be_db, "ROLLBACK TRANSACTION", NULL, NULL,
	    &errmsg);
	UPDATE_TOTALS(be, bt_exec, ts, vts);
	if (r == SQLITE_FULL)
		tx->bt_full = 1;
	(void) backend_error(be, r, errmsg);

	backend_tx_end(tx);
}

/*
 * Fails with
 *   _NO_RESOURCES - out of memory
 */
int
backend_tx_commit(backend_tx_t *tx)
{
	int r, r2;
	char *errmsg;
	sqlite_backend_t *be;
	hrtime_t ts, vts;

	assert(tx != NULL && tx->bt_be != NULL && !tx->bt_readonly);
	be = tx->bt_be;
	ts = gethrtime();
	vts = gethrvtime();
	r = sqlite_exec(be->be_db, "COMMIT TRANSACTION", NULL, NULL,
	    &errmsg);
	UPDATE_TOTALS(be, bt_exec, ts, vts);
	if (r == SQLITE_FULL)
		tx->bt_full = 1;

	r = backend_error(be, r, errmsg);
	assert(r != REP_PROTOCOL_DONE);

	if (r != REP_PROTOCOL_SUCCESS) {
		r2 = sqlite_exec(be->be_db, "ROLLBACK TRANSACTION", NULL, NULL,
		    &errmsg);
		r2 = backend_error(be, r2, errmsg);
		if (r2 != REP_PROTOCOL_SUCCESS)
			backend_panic("cannot rollback failed commit");

		backend_tx_end(tx);
		return (r);
	}
	backend_tx_end(tx);
	return (REP_PROTOCOL_SUCCESS);
}

static const char *
id_space_to_name(enum id_space id)
{
	switch (id) {
	case BACKEND_ID_SERVICE_INSTANCE:
		return ("SI");
	case BACKEND_ID_PROPERTYGRP:
		return ("PG");
	case BACKEND_ID_GENERATION:
		return ("GEN");
	case BACKEND_ID_PROPERTY:
		return ("PROP");
	case BACKEND_ID_VALUE:
		return ("VAL");
	case BACKEND_ID_SNAPNAME:
		return ("SNAME");
	case BACKEND_ID_SNAPSHOT:
		return ("SHOT");
	case BACKEND_ID_SNAPLEVEL:
		return ("SLVL");
	default:
		abort();
		/*NOTREACHED*/
	}
}

/*
 * Returns a new id or 0 if the id argument is invalid or the query fails.
 */
uint32_t
backend_new_id(backend_tx_t *tx, enum id_space id)
{
	struct run_single_int_info info;
	uint32_t new_id = 0;
	const char *name = id_space_to_name(id);
	char *errmsg;
	int ret;
	sqlite_backend_t *be;
	hrtime_t ts, vts;

	assert(tx != NULL && tx->bt_be != NULL && !tx->bt_readonly);
	be = tx->bt_be;

	info.rs_out = &new_id;
	info.rs_result = REP_PROTOCOL_FAIL_NOT_FOUND;

	ts = gethrtime();
	vts = gethrvtime();
	ret = sqlite_exec_printf(be->be_db,
	    "SELECT id_next FROM id_tbl WHERE (id_name = '%q');"
	    "UPDATE id_tbl SET id_next = id_next + 1 WHERE (id_name = '%q');",
	    run_single_int_callback, &info, &errmsg, name, name);
	UPDATE_TOTALS(be, bt_exec, ts, vts);
	if (ret == SQLITE_FULL)
		tx->bt_full = 1;

	ret = backend_error(be, ret, errmsg);

	if (ret != REP_PROTOCOL_SUCCESS) {
		return (0);
	}

	return (new_id);
}

/*
 * Returns
 *   _NO_RESOURCES - out of memory
 *   _DONE - callback aborted query
 *   _SUCCESS
 */
int
backend_tx_run(backend_tx_t *tx, backend_query_t *q,
    backend_run_callback_f *cb, void *data)
{
	char *errmsg = NULL;
	int ret;
	sqlite_backend_t *be;
	hrtime_t ts, vts;

	assert(tx != NULL && tx->bt_be != NULL);
	be = tx->bt_be;

	if (q == NULL || q->bq_buf == NULL)
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);

	ts = gethrtime();
	vts = gethrvtime();
	ret = sqlite_exec(be->be_db, q->bq_buf, cb, data, &errmsg);
	UPDATE_TOTALS(be, bt_exec, ts, vts);
	if (ret == SQLITE_FULL)
		tx->bt_full = 1;
	ret = backend_error(be, ret, errmsg);

	return (ret);
}

/*
 * Returns
 *   _NO_RESOURCES - out of memory
 *   _NOT_FOUND - the query returned no results
 *   _SUCCESS - the query returned a single integer
 */
int
backend_tx_run_single_int(backend_tx_t *tx, backend_query_t *q, uint32_t *buf)
{
	struct run_single_int_info info;
	int ret;

	info.rs_out = buf;
	info.rs_result = REP_PROTOCOL_FAIL_NOT_FOUND;

	ret = backend_tx_run(tx, q, run_single_int_callback, &info);
	assert(ret != REP_PROTOCOL_DONE);

	if (ret != REP_PROTOCOL_SUCCESS)
		return (ret);

	return (info.rs_result);
}

/*
 * Fails with
 *   _NO_RESOURCES - out of memory
 */
int
backend_tx_run_update(backend_tx_t *tx, const char *format, ...)
{
	va_list a;
	char *errmsg;
	int ret;
	sqlite_backend_t *be;
	hrtime_t ts, vts;

	assert(tx != NULL && tx->bt_be != NULL && !tx->bt_readonly);
	be = tx->bt_be;

	va_start(a, format);
	ts = gethrtime();
	vts = gethrvtime();
	ret = sqlite_exec_vprintf(be->be_db, format, NULL, NULL, &errmsg, a);
	UPDATE_TOTALS(be, bt_exec, ts, vts);
	if (ret == SQLITE_FULL)
		tx->bt_full = 1;
	va_end(a);
	ret = backend_error(be, ret, errmsg);
	assert(ret != REP_PROTOCOL_DONE);

	return (ret);
}

/*
 * returns REP_PROTOCOL_FAIL_NOT_FOUND if no changes occured
 */
int
backend_tx_run_update_changed(backend_tx_t *tx, const char *format, ...)
{
	va_list a;
	char *errmsg;
	int ret;
	sqlite_backend_t *be;
	hrtime_t ts, vts;

	assert(tx != NULL && tx->bt_be != NULL && !tx->bt_readonly);
	be = tx->bt_be;

	va_start(a, format);
	ts = gethrtime();
	vts = gethrvtime();
	ret = sqlite_exec_vprintf(be->be_db, format, NULL, NULL, &errmsg, a);
	UPDATE_TOTALS(be, bt_exec, ts, vts);
	if (ret == SQLITE_FULL)
		tx->bt_full = 1;
	va_end(a);

	ret = backend_error(be, ret, errmsg);

	return (ret);
}

#define	BACKEND_ADD_SCHEMA(be, file, tbls, idxs) \
	(backend_add_schema((be), (file), \
	    (tbls), sizeof (tbls) / sizeof (*(tbls)), \
	    (idxs), sizeof (idxs) / sizeof (*(idxs))))

static int
backend_add_schema(sqlite_backend_t *be, const char *file,
    struct backend_tbl_info *tbls, int tbl_count,
    struct backend_idx_info *idxs, int idx_count)
{
	int i;
	char *errmsg;
	int ret;

	/*
	 * Create the tables.
	 */
	for (i = 0; i < tbl_count; i++) {
		if (tbls[i].bti_name == NULL) {
			assert(i + 1 == tbl_count);
			break;
		}
		ret = sqlite_exec_printf(be->be_db,
		    "CREATE TABLE %s (%s);\n",
		    NULL, NULL, &errmsg, tbls[i].bti_name, tbls[i].bti_cols);

		if (ret != SQLITE_OK) {
			configd_critical(
			    "%s: %s table creation fails: %s\n", file,
			    tbls[i].bti_name, errmsg);
			free(errmsg);
			return (-1);
		}
	}

	/*
	 * Make indices on key tables and columns.
	 */
	for (i = 0; i < idx_count; i++) {
		if (idxs[i].bxi_tbl == NULL) {
			assert(i + 1 == idx_count);
			break;
		}

		ret = sqlite_exec_printf(be->be_db,
		    "CREATE INDEX %s_%s ON %s (%s);\n",
		    NULL, NULL, &errmsg, idxs[i].bxi_tbl, idxs[i].bxi_idx,
		    idxs[i].bxi_tbl, idxs[i].bxi_cols);

		if (ret != SQLITE_OK) {
			configd_critical(
			    "%s: %s_%s index creation fails: %s\n", file,
			    idxs[i].bxi_tbl, idxs[i].bxi_idx, errmsg);
			free(errmsg);
			return (-1);
		}
	}
	return (0);
}

static int
backend_init_schema(sqlite_backend_t *be, const char *db_file, backend_type_t t)
{
	int i;
	char *errmsg;
	int ret;

	assert(t == BACKEND_TYPE_NORMAL || t == BACKEND_TYPE_NONPERSIST);

	if (t == BACKEND_TYPE_NORMAL) {
		ret = BACKEND_ADD_SCHEMA(be, db_file, tbls_normal, idxs_normal);
	} else if (t == BACKEND_TYPE_NONPERSIST) {
		ret = BACKEND_ADD_SCHEMA(be, db_file, tbls_np, idxs_np);
	} else {
		abort();		/* can't happen */
	}

	if (ret < 0) {
		return (ret);
	}

	ret = BACKEND_ADD_SCHEMA(be, db_file, tbls_common, idxs_common);
	if (ret < 0) {
		return (ret);
	}

	/*
	 * Add the schema version to the table
	 */
	ret = sqlite_exec_printf(be->be_db,
	    "INSERT INTO schema_version (schema_version) VALUES (%d)",
	    NULL, NULL, &errmsg, BACKEND_SCHEMA_VERSION);
	if (ret != SQLITE_OK) {
		configd_critical(
		    "setting schema version fails: %s\n", errmsg);
		free(errmsg);
	}

	/*
	 * Populate id_tbl with initial IDs.
	 */
	for (i = 0; i < BACKEND_ID_INVALID; i++) {
		const char *name = id_space_to_name(i);

		ret = sqlite_exec_printf(be->be_db,
		    "INSERT INTO id_tbl (id_name, id_next) "
		    "VALUES ('%q', %d);", NULL, NULL, &errmsg, name, 1);
		if (ret != SQLITE_OK) {
			configd_critical(
			    "id insertion for %s fails: %s\n", name, errmsg);
			free(errmsg);
			return (-1);
		}
	}
	/*
	 * Set the persistance of the database.  The normal database is marked
	 * "synchronous", so that all writes are synchronized to stable storage
	 * before proceeding.
	 */
	ret = sqlite_exec_printf(be->be_db,
	    "PRAGMA default_synchronous = %s; PRAGMA synchronous = %s;",
	    NULL, NULL, &errmsg,
	    (t == BACKEND_TYPE_NORMAL)? "ON" : "OFF",
	    (t == BACKEND_TYPE_NORMAL)? "ON" : "OFF");
	if (ret != SQLITE_OK) {
		configd_critical("pragma setting fails: %s\n", errmsg);
		free(errmsg);
		return (-1);
	}

	return (0);
}

int
backend_init(const char *db_file, const char *npdb_file, int have_np)
{
	sqlite_backend_t *be;
	char *errp;
	struct sqlite *fast_db;
	int r;
	backend_switch_results_t switch_result = BACKEND_SWITCH_OK;
	int writable_persist = 1;

	/* set up our temporary directory */
	sqlite_temp_directory = "/etc/svc/volatile";

	if (strcmp(SQLITE_VERSION, sqlite_version) != 0) {
		configd_critical("Mismatched link!  (%s should be %s)\n",
		    sqlite_version, SQLITE_VERSION);
		return (CONFIGD_EXIT_DATABASE_INIT_FAILED);
	}

	if (db_file == NULL)
		db_file = REPOSITORY_DB;
	if (strcmp(db_file, REPOSITORY_DB) != 0) {
		is_main_repository = 0;
	}

	/*
	 * If the svc.configd crashed, there might be a leftover transient
	 * database at FAST_REPOSITORY_DB,which contains useful
	 * information.  Both early manifest import and late manifest
	 * import use svcadm to copy the repository to FAST_REPOSITORY_DB.
	 * One reason for doing this is that it improves the performance of
	 * manifest import.  The other reason is that the repository may be
	 * on read-only root in the case of early manifest import.
	 *
	 * If FAST_REPOSITORY_DB exists, it is an indication that
	 * svc.configd has been restarted for some reason.  Since we have
	 * no way of knowing where we are in the boot process, the safe
	 * thing to do is to move the repository back to it's non-transient
	 * location, REPOSITORY_DB.  This may slow manifest import
	 * performance, but it avoids the problem of missing the command to
	 * move the repository to permanent storage.
	 *
	 * There is a caveat, though.  If root is read-only, we'll need to
	 * leave the repository at FAST_REPOSITORY_DB.  If root is
	 * read-only, late manifest import has not yet run, so it will move
	 * the repository back to permanent storage when it runs.
	 */
	if (is_main_repository)
		switch_result = backend_switch_recovery();

	r = backend_create(BACKEND_TYPE_NORMAL, db_file, &be);
	switch (r) {
	case BACKEND_CREATE_FAIL:
		return (CONFIGD_EXIT_DATABASE_INIT_FAILED);
	case BACKEND_CREATE_LOCKED:
		return (CONFIGD_EXIT_DATABASE_LOCKED);
	case BACKEND_CREATE_SUCCESS:
		break;		/* success */
	case BACKEND_CREATE_READONLY:
		writable_persist = 0;
		break;
	case BACKEND_CREATE_NEED_INIT:
		if (backend_init_schema(be, db_file, BACKEND_TYPE_NORMAL)) {
			backend_destroy(be);
			return (CONFIGD_EXIT_DATABASE_INIT_FAILED);
		}
		break;
	default:
		abort();
		/*NOTREACHED*/
	}
	backend_create_finish(BACKEND_TYPE_NORMAL, be);
	flight_recorder_event(BE_FLIGHT_EV_REPO_CREATE,
	    writable_persist == 1 ? BE_FLIGHT_ST_RW : BE_FLIGHT_ST_RO);
	/*
	 * If there was a transient repository that could not be copied
	 * back because the root file system was read-only, switch over to
	 * using the transient repository.
	 */
	if (switch_result == BACKEND_SWITCH_RO) {
		char *db_name_copy = NULL;

		fast_db = sqlite_open(FAST_REPOSITORY_DB, 0600, &errp);
		if (fast_db == NULL) {
			/* Can't open fast repository.  Stick with permanent. */
			configd_critical("Cannot open \"%s\".  %s\n",
			    FAST_REPOSITORY_DB, errp == NULL ? "" : errp);
			free(errp);
		} else {
			db_name_copy = strdup(FAST_REPOSITORY_DB);
			if (db_name_copy == NULL) {
				configd_critical("backend_init: out of "
				    "memory.\n");
				sqlite_close(fast_db);
				return (CONFIGD_EXIT_INIT_FAILED);
			} else {
				flight_recorder_event(
				    BE_FLIGHT_EV_LINGERING_FAST,
				    BE_FLIGHT_ST_RO);
				sqlite_close(be->be_db);
				be->be_db = fast_db;
				be->be_ppath = be->be_path;
				be->be_path = db_name_copy;
			}
		}
	}

	if (have_np) {
		if (npdb_file == NULL)
			npdb_file = NONPERSIST_DB;

		r = backend_create(BACKEND_TYPE_NONPERSIST, npdb_file, &be);
		switch (r) {
		case BACKEND_CREATE_SUCCESS:
			break;		/* success */
		case BACKEND_CREATE_FAIL:
			return (CONFIGD_EXIT_DATABASE_INIT_FAILED);
		case BACKEND_CREATE_LOCKED:
			return (CONFIGD_EXIT_DATABASE_LOCKED);
		case BACKEND_CREATE_READONLY:
			configd_critical("%s: unable to write\n", npdb_file);
			return (CONFIGD_EXIT_DATABASE_INIT_FAILED);
		case BACKEND_CREATE_NEED_INIT:
			if (backend_init_schema(be, db_file,
			    BACKEND_TYPE_NONPERSIST)) {
				backend_destroy(be);
				return (CONFIGD_EXIT_DATABASE_INIT_FAILED);
			}
			break;
		default:
			abort();
			/*NOTREACHED*/
		}
		backend_create_finish(BACKEND_TYPE_NONPERSIST, be);

		if (r != BACKEND_CREATE_NEED_INIT) {
			flight_recorder_event(BE_FLIGHT_EV_RESTART,
			    BE_FLIGHT_ST_INFO);
		}

		/*
		 * If we started up with a writable filesystem, but the
		 * non-persistent database needed initialization, we are
		 * booting a non-global zone or a system with a writable
		 * root (ZFS), so do a backup.  Checking to see if the
		 * non-persistent database needed initialization also keeps
		 * us from making additional backups if configd gets
		 * restarted.
		 */
		if (r == BACKEND_CREATE_NEED_INIT && writable_persist &&
		    backend_lock(BACKEND_TYPE_NORMAL, 0, &be) ==
		    REP_PROTOCOL_SUCCESS) {
			if (backend_create_backup_locked(be,
			    REPOSITORY_BOOT_BACKUP) != REP_PROTOCOL_SUCCESS) {
				configd_critical(
				    "unable to create \"%s\" backup of "
				    "\"%s\"\n", REPOSITORY_BOOT_BACKUP,
				    be->be_path);
			}
			backend_unlock(be);
		}

		/*
		 * On the other hand if we started with a read-only file
		 * system and the non-persistent database needed
		 * initialization, then we need to take a checkpoint of the
		 * repository.  We grab the checkpoint now before Early
		 * Manifest Import starts modifying the repository.  Then
		 * when the file system becomes writable, the checkpoint
		 * can be used to create the boot time backup of the
		 * repository.  Checking that the non-persistent database
		 * needed initialization, keeps us from making additional
		 * checkpoints if configd gets restarted.
		 */
		if (r == BACKEND_CREATE_NEED_INIT && writable_persist == 0 &&
		    backend_lock(BACKEND_TYPE_NORMAL, 0, &be) ==
		    REP_PROTOCOL_SUCCESS) {
			r = backend_checkpoint_repository(be);
			if (r != REP_PROTOCOL_SUCCESS) {
				configd_critical("unable to create checkpoint "
				    "of \"%s\"\n", be->be_path);
			}
			backend_unlock(be);
		}

		/*
		 * If the non-persistent database did not need
		 * initialization, svc.configd has been restarted.  See if
		 * the boot time checkpoint exists.  If it does, use it to
		 * make a backup if root is writable.
		 */
		if (r != BACKEND_CREATE_NEED_INIT &&
		    backend_lock(BACKEND_TYPE_NORMAL, 0, &be) ==
		    REP_PROTOCOL_SUCCESS) {
			struct stat sb;

			if ((stat(REPOSITORY_CHECKPOINT, &sb) == 0) &&
			    (sb.st_size > 0) && (sb.st_mode & S_IFREG)) {
				be->be_checkpoint = REPOSITORY_CHECKPOINT;
				flight_recorder_event(
				    BE_FLIGHT_EV_CHECKPOINT_EXISTS,
				    BE_FLIGHT_ST_INFO);
			}

			/*
			 * If we have a checkpoint and root is writable,
			 * make the backup now.
			 */
			if (be->be_checkpoint && writable_persist) {
				if (backend_create_backup_locked(be,
				    REPOSITORY_BOOT_BACKUP) !=
				    REP_PROTOCOL_SUCCESS) {
					configd_critical(
					    "unable to create \"%s\" backup of "
					    "\"%s\"\n", REPOSITORY_BOOT_BACKUP,
					    be->be_path);
				}
			}
			backend_unlock(be);
		}
	}

	/*
	 * If the persistent backend is writable at this point, upgrade it.
	 * This can occur in a few cases, most notably on UFS roots if
	 * we are operating on the backend from another root, as is the case
	 * during alternate-root BFU.
	 *
	 * Otherwise, upgrade will occur via backend_check_readonly() when
	 * the repository is re-opened read-write.
	 */
	if (writable_persist) {
		r = backend_lock(BACKEND_TYPE_NORMAL, 1, &be);
		assert(r == REP_PROTOCOL_SUCCESS);
		backend_check_upgrade(be, B_TRUE);
		backend_unlock(be);
	}

	return (CONFIGD_EXIT_OKAY);
}

/*
 * quiesce all database activity prior to exiting
 */
void
backend_fini(void)
{
	sqlite_backend_t *be_normal, *be_np;

	(void) backend_lock(BACKEND_TYPE_NORMAL, 1, &be_normal);
	(void) backend_lock(BACKEND_TYPE_NONPERSIST, 1, &be_np);
}

#define	QUERY_BASE	128
backend_query_t *
backend_query_alloc(void)
{
	backend_query_t *q;
	q = calloc(1, sizeof (backend_query_t));
	if (q != NULL) {
		q->bq_size = QUERY_BASE;
		q->bq_buf = calloc(1, q->bq_size);
		if (q->bq_buf == NULL) {
			q->bq_size = 0;
		}

	}
	return (q);
}

void
backend_query_append(backend_query_t *q, const char *value)
{
	char *alloc;
	int count;
	size_t size, old_len;

	if (q == NULL) {
		/* We'll discover the error when we try to run the query. */
		return;
	}

	while (q->bq_buf != NULL) {
		old_len = strlen(q->bq_buf);
		size = q->bq_size;
		count = strlcat(q->bq_buf, value, size);

		if (count < size)
			break;				/* success */

		q->bq_buf[old_len] = 0;
		size = round_up_to_p2(count + 1);

		assert(size > q->bq_size);
		alloc = realloc(q->bq_buf, size);
		if (alloc == NULL) {
			free(q->bq_buf);
			q->bq_buf = NULL;
			break;				/* can't grow */
		}

		q->bq_buf = alloc;
		q->bq_size = size;
	}
}

void
backend_query_add(backend_query_t *q, const char *format, ...)
{
	va_list args;
	char *new;

	if (q == NULL || q->bq_buf == NULL)
		return;

	va_start(args, format);
	new = sqlite_vmprintf(format, args);
	va_end(args);

	if (new == NULL) {
		free(q->bq_buf);
		q->bq_buf = NULL;
		return;
	}

	backend_query_append(q, new);

	free(new);
}

void
backend_query_free(backend_query_t *q)
{
	if (q != NULL) {
		if (q->bq_buf != NULL) {
			free(q->bq_buf);
		}
		free(q);
	}
}
