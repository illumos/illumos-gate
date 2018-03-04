/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * lib/kdb/kdb_db2.c
 *
 * Copyright 1997,2006 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "k5-int.h"
#include <kdb_log.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <db.h>
#include <stdio.h>
#include <errno.h>
#include <utime.h>
#include "kdb5.h"
#include "kdb_db2.h"
#include "kdb_xdr.h"
#include "policy_db.h"
#include <libintl.h>

#define KDB_DB2_DATABASE_NAME "database_name"

#include "kdb_db2.h"

static char *gen_dbsuffix(char *, char *);

static krb5_error_code krb5_db2_db_start_update(krb5_context);
static krb5_error_code krb5_db2_db_end_update(krb5_context);

static krb5_error_code krb5_db2_db_set_name(krb5_context, char *, int);

krb5_error_code krb5_db2_db_lock(krb5_context, int);

static krb5_error_code krb5_db2_db_set_hashfirst(krb5_context, int);

/*
 * Solaris Kerberos
 * Extra error handling
 */
char errbuf[1024];
static void krb5_db2_prepend_err_str(krb5_context , const char *,
    krb5_error_code, krb5_error_code);

static char default_db_name[] = DEFAULT_KDB_FILE;

/*
 * Locking:
 *
 * There are two distinct locking protocols used.  One is designed to
 * lock against processes (the admin_server, for one) which make
 * incremental changes to the database; the other is designed to lock
 * against utilities (kdb5_edit, kpropd, kdb5_convert) which replace the
 * entire database in one fell swoop.
 *
 * The first locking protocol is implemented using flock() in the
 * krb_dbl_lock() and krb_dbl_unlock routines.
 *
 * The second locking protocol is necessary because DBM "files" are
 * actually implemented as two separate files, and it is impossible to
 * atomically rename two files simultaneously.  It assumes that the
 * database is replaced only very infrequently in comparison to the time
 * needed to do a database read operation.
 *
 * A third file is used as a "version" semaphore; the modification
 * time of this file is the "version number" of the database.
 * At the start of a read operation, the reader checks the version
 * number; at the end of the read operation, it checks again.  If the
 * version number changed, or if the semaphore was nonexistant at
 * either time, the reader sleeps for a second to let things
 * stabilize, and then tries again; if it does not succeed after
 * KRB5_DBM_MAX_RETRY attempts, it gives up.
 *
 * On update, the semaphore file is deleted (if it exists) before any
 * update takes place; at the end of the update, it is replaced, with
 * a version number strictly greater than the version number which
 * existed at the start of the update.
 *
 * If the system crashes in the middle of an update, the semaphore
 * file is not automatically created on reboot; this is a feature, not
 * a bug, since the database may be inconsistant.  Note that the
 * absence of a semaphore file does not prevent another _update_ from
 * taking place later.  Database replacements take place automatically
 * only on slave servers; a crash in the middle of an update will be
 * fixed by the next slave propagation.  A crash in the middle of an
 * update on the master would be somewhat more serious, but this would
 * likely be noticed by an administrator, who could fix the problem and
 * retry the operation.
 */

#define free_dbsuffix(name) free(name)

/*
 * Routines to deal with context.
 */
#define	k5db2_inited(c)	(c && c->db_context \
			 && ((kdb5_dal_handle*)c->db_context)->db_context \
                         && ((krb5_db2_context *) ((kdb5_dal_handle*)c->db_context)->db_context)->db_inited)

static krb5_error_code
krb5_db2_get_db_opt(char *input, char **opt, char **val)
{
    char   *pos = strchr(input, '=');
    if (pos == NULL) {
	*opt = NULL;
	*val = strdup(input);
	if (*val == NULL) {
	    return ENOMEM;
	}
    } else {
	*opt = malloc((pos - input) + 1);
	*val = strdup(pos + 1);
	if (!*opt || !*val) {
	    return ENOMEM;
	}
	memcpy(*opt, input, pos - input);
	(*opt)[pos - input] = '\0';
    }
    return (0);

}

/*
 * Restore the default context.
 */
static void
k5db2_clear_context(krb5_db2_context *dbctx)
{
    /*
     * Free any dynamically allocated memory.  File descriptors and locks
     * are the caller's problem.
     */
    if (dbctx->db_lf_name)
	free(dbctx->db_lf_name);
    if (dbctx->db_name && (dbctx->db_name != default_db_name))
	free(dbctx->db_name);
    /*
     * Clear the structure and reset the defaults.
     */
    memset((char *) dbctx, 0, sizeof(krb5_db2_context));
    dbctx->db_name = default_db_name;
    dbctx->db_nb_locks = FALSE;
    dbctx->tempdb = FALSE;
}

static krb5_error_code
k5db2_init_context(krb5_context context)
{
    krb5_db2_context *db_ctx;
    kdb5_dal_handle *dal_handle;

    dal_handle = (kdb5_dal_handle *) context->db_context;

    if (dal_handle->db_context == NULL) {
	db_ctx = (krb5_db2_context *) malloc(sizeof(krb5_db2_context));
	if (db_ctx == NULL)
	    return ENOMEM;
	else {
	    memset((char *) db_ctx, 0, sizeof(krb5_db2_context));
	    k5db2_clear_context((krb5_db2_context *) db_ctx);
	    dal_handle->db_context = (void *) db_ctx;
	}
    }
    return (0);
}

/*
 * Utility routine: generate name of database file.
 */

static char *
gen_dbsuffix(char *db_name, char *sfx)
{
    char   *dbsuffix;

    if (sfx == NULL)
	return ((char *) NULL);

    dbsuffix = malloc(strlen(db_name) + strlen(sfx) + 1);
    if (!dbsuffix)
	return (0);
    /*LINTED*/
    (void) strcpy(dbsuffix, db_name);
    /*LINTED*/
    (void) strcat(dbsuffix, sfx);
    return dbsuffix;
}

static DB *
k5db2_dbopen(krb5_db2_context *dbc, char *fname, int flags, int mode, int tempdb)
{
    DB     *db;
    BTREEINFO bti;
    HASHINFO hashi;
    bti.flags = 0;
    bti.cachesize = 0;
    bti.psize = 4096;
    bti.lorder = 0;
    bti.minkeypage = 0;
    bti.compare = NULL;
    bti.prefix = NULL;

    if (tempdb) {
	fname = gen_dbsuffix(fname, "~");
    } else {
	fname = strdup(fname);
    }
    if (fname == NULL)
    {
	errno = ENOMEM;
	return NULL;
    }
    

    hashi.bsize = 4096;
    hashi.cachesize = 0;
    hashi.ffactor = 40;
    hashi.hash = NULL;
    hashi.lorder = 0;
    hashi.nelem = 1;

    db = dbopen(fname, flags, mode,
		dbc->hashfirst ? DB_HASH : DB_BTREE,
		dbc->hashfirst ? (void *) &hashi : (void *) &bti);
    if (db != NULL) {
	free(fname);
	return db;
    }
    switch (errno) {
#ifdef EFTYPE
    case EFTYPE:
#endif
    case EINVAL:
	db = dbopen(fname, flags, mode,
		    dbc->hashfirst ? DB_BTREE : DB_HASH,
		    dbc->hashfirst ? (void *) &bti : (void *) &hashi);
	if (db != NULL)
	    dbc->hashfirst = !dbc->hashfirst;
	/* FALLTHROUGH */
    default:
	free(fname);
	return db;
    }
}

static krb5_error_code
krb5_db2_db_set_hashfirst(krb5_context context, int hashfirst)
{
    krb5_db2_context *dbc;
    kdb5_dal_handle *dal_handle;

    if (k5db2_inited(context))
	return KRB5_KDB_DBNOTINITED;
    dal_handle = (kdb5_dal_handle *) context->db_context;
    dbc = (krb5_db2_context *) dal_handle->db_context;
    dbc->hashfirst = hashfirst;
    return 0;
}

/*
 * initialization for data base routines.
 */

krb5_error_code
krb5_db2_db_init(krb5_context context)
{
    char   *filename = NULL;
    krb5_db2_context *db_ctx;
    krb5_error_code retval;
    kdb5_dal_handle *dal_handle;
    char    policy_db_name[1024], policy_lock_name[1024];

    if (k5db2_inited(context))
	return 0;

    /* Check for presence of our context, if not present, allocate one. */
    if ((retval = k5db2_init_context(context)))
	return (retval);

    dal_handle = (kdb5_dal_handle *) context->db_context;
    db_ctx = dal_handle->db_context;
    db_ctx->db = NULL;

    if (!(filename = gen_dbsuffix(db_ctx->db_name, db_ctx->tempdb
				  ?KDB2_TEMP_LOCK_EXT:KDB2_LOCK_EXT)))
	return ENOMEM;
    db_ctx->db_lf_name = filename;	/* so it gets freed by clear_context */

    /*
     * should be opened read/write so that write locking can work with
     * POSIX systems
     */
    if ((db_ctx->db_lf_file = open(filename, O_RDWR, 0666)) < 0) {
	if ((db_ctx->db_lf_file = open(filename, O_RDONLY, 0666)) < 0) {
	    retval = errno;

	    /* Solaris Kerberos: Better error logging */
  	    (void) snprintf(errbuf, sizeof(errbuf), gettext("Failed to open \"%s\": "), filename);
	    krb5_db2_prepend_err_str(context, errbuf, retval, retval);

	    goto err_out;
	}
    }
    db_ctx->db_inited++;

    if ((retval = krb5_db2_db_get_age(context, NULL, &db_ctx->db_lf_time)))
	goto err_out;

    sprintf(policy_db_name, db_ctx->tempdb ? "%s~.kadm5" : "%s.kadm5",
	    db_ctx->db_name);
    sprintf(policy_lock_name, "%s.lock", policy_db_name);

    if ((retval = osa_adb_init_db(&db_ctx->policy_db, policy_db_name,
				  policy_lock_name, OSA_ADB_POLICY_DB_MAGIC)))
    {
	/* Solaris Kerberos: Better error logging */
	snprintf(errbuf, sizeof(errbuf),
	    gettext("Failed to initialize db, \"%s\", lockfile, \"%s\" : "),
	    policy_db_name, policy_lock_name);
	krb5_db2_prepend_err_str(context, errbuf, retval, retval);

	goto err_out;
    }
    return 0;

  err_out:
    db_ctx->db = NULL;
    k5db2_clear_context(db_ctx);
    return (retval);
}

/*
 * gracefully shut down database--must be called by ANY program that does
 * a krb5_db2_db_init
 */
krb5_error_code
krb5_db2_db_fini(krb5_context context)
{
    krb5_error_code retval = 0;
    krb5_db2_context *db_ctx;
    kdb5_dal_handle *dal_handle;

    dal_handle = (kdb5_dal_handle *) context->db_context;
    if (dal_handle == NULL) {
	return 0;
    }

    db_ctx = (krb5_db2_context *) dal_handle->db_context;

    if (k5db2_inited(context)) {
	if (close(db_ctx->db_lf_file))
	    retval = errno;
	else
	    retval = 0;
    }
    if (db_ctx) {
	if (db_ctx->policy_db) {
	    retval =
		osa_adb_fini_db(db_ctx->policy_db, OSA_ADB_POLICY_DB_MAGIC);
	    if (retval)
		return retval;
	}

	k5db2_clear_context(db_ctx);
	/*      free(dal_handle->db_context); */
	dal_handle->db_context = NULL;
    }
    return retval;
}

/*
 * Set/Get the master key associated with the database
 */
krb5_error_code
krb5_db2_db_set_mkey(krb5_context context, krb5_keyblock *key)
{
    krb5_db2_context *db_ctx;
    kdb5_dal_handle *dal_handle;

    if (!k5db2_inited(context))
	return (KRB5_KDB_DBNOTINITED);

    dal_handle = (kdb5_dal_handle *) context->db_context;
    db_ctx = dal_handle->db_context;
    db_ctx->db_master_key = key;
    return 0;
}

krb5_error_code
krb5_db2_db_get_mkey(krb5_context context, krb5_keyblock **key)
{
    krb5_db2_context *db_ctx;
    kdb5_dal_handle *dal_handle;

    if (!k5db2_inited(context))
	return (KRB5_KDB_DBNOTINITED);

    dal_handle = (kdb5_dal_handle *) context->db_context;
    db_ctx = dal_handle->db_context;
    *key = db_ctx->db_master_key;

    return 0;
}

/*
 * Set the "name" of the current database to some alternate value.
 *
 * Passing a null pointer as "name" will set back to the default.
 * If the alternate database doesn't exist, nothing is changed.
 *
 * XXX rethink this
 */

static krb5_error_code
krb5_db2_db_set_name(krb5_context context, char *name, int tempdb)
{
    DB     *db;
    krb5_db2_context *db_ctx;
    krb5_error_code kret;
    kdb5_dal_handle *dal_handle;

    if (k5db2_inited(context))
	return KRB5_KDB_DBINITED;

    /* Check for presence of our context, if not present, allocate one. */
    if ((kret = k5db2_init_context(context)))
	return (kret);

    if (name == NULL)
	name = default_db_name;

    dal_handle = (kdb5_dal_handle *) context->db_context;
    db_ctx = dal_handle->db_context;
    db_ctx->tempdb = tempdb;
    db = k5db2_dbopen(db_ctx, name, O_RDONLY, 0, tempdb);
    if (db == NULL)
	return errno;

    db_ctx->db_name = strdup(name);
    if (db_ctx->db_name == NULL) {
	(*db->close) (db);
	return ENOMEM;
    }
    (*db->close) (db);
    return 0;
}

/*
 * Return the last modification time of the database.
 *
 * Think about using fstat.
 */

krb5_error_code
krb5_db2_db_get_age(krb5_context context, char *db_name, time_t *age)
{
    krb5_db2_context *db_ctx;
    kdb5_dal_handle *dal_handle;
    struct stat st;

    if (!k5db2_inited(context))
	return (KRB5_KDB_DBNOTINITED);
    dal_handle = (kdb5_dal_handle *) context->db_context;
    db_ctx = (krb5_db2_context *) dal_handle->db_context;

    if (fstat(db_ctx->db_lf_file, &st) < 0)
	*age = -1;
    else
	*age = st.st_mtime;
    return 0;
}

/*
 * Remove the semaphore file; indicates that database is currently
 * under renovation.
 *
 * This is only for use when moving the database out from underneath
 * the server (for example, during slave updates).
 */

static krb5_error_code
krb5_db2_db_start_update(krb5_context context)
{
    return 0;
}

static krb5_error_code
krb5_db2_db_end_update(krb5_context context)
{
    krb5_error_code retval;
    krb5_db2_context *db_ctx;
    kdb5_dal_handle *dal_handle;
    struct stat st;
    time_t  now;
    struct utimbuf utbuf;

    if (!k5db2_inited(context))
	return (KRB5_KDB_DBNOTINITED);

    retval = 0;
    dal_handle = (kdb5_dal_handle *) context->db_context;
    db_ctx = dal_handle->db_context;
    now = time((time_t *) NULL);
    if (fstat(db_ctx->db_lf_file, &st) == 0) {
	if (st.st_mtime >= now) {
	    utbuf.actime = st.st_mtime + 1;
	    utbuf.modtime = st.st_mtime + 1;
	    if (utime(db_ctx->db_lf_name, &utbuf))
		retval = errno;
	} else {
	    if (utime(db_ctx->db_lf_name, (struct utimbuf *) NULL))
		retval = errno;
	}
	if (retval) {
	    /* Solaris Kerberos: Better error logging */
	    snprintf(errbuf, sizeof(errbuf), gettext("Failed to modify "
	        "access and modification times for \"%s\": "),
	        db_ctx->db_lf_name);
	    krb5_db2_prepend_err_str(context, errbuf, retval, retval);
	}
    } else {
	retval = errno;
	/* Solaris Kerberos: Better error logging */
	snprintf(errbuf, sizeof(errbuf), gettext("Failed to stat \"%s\": "),
	    db_ctx->db_lf_name);
	krb5_db2_prepend_err_str(context, errbuf, retval, retval);
    }
    if (!retval) {
	if (fstat(db_ctx->db_lf_file, &st) == 0)
	    db_ctx->db_lf_time = st.st_mtime;
	else {
	    retval = errno;
	    /* Solaris Kerberos: Better error logging */
	    snprintf(errbuf, sizeof(errbuf), gettext("Failed to stat \"%s\": "),
	        db_ctx->db_lf_name);
	    krb5_db2_prepend_err_str(context, errbuf, retval, retval);
	}
    }
    return (retval);
}

#define MAX_LOCK_TRIES 5

krb5_error_code
krb5_db2_db_lock(krb5_context context, int in_mode)
{
    krb5_db2_context *db_ctx;
    int     krb5_lock_mode;
    DB     *db;
    krb5_error_code retval;
    time_t  mod_time;
    kdb5_dal_handle *dal_handle;
    int     mode, gotlock, tries;

    switch (in_mode) {
    case KRB5_DB_LOCKMODE_PERMANENT:
	mode = KRB5_DB_LOCKMODE_EXCLUSIVE;
	break;
    case KRB5_DB_LOCKMODE_EXCLUSIVE:
	mode = KRB5_LOCKMODE_EXCLUSIVE;
	break;

    case KRB5_DB_LOCKMODE_SHARED:
	mode = KRB5_LOCKMODE_SHARED;
	break;
    default:
	return EINVAL;
    }

    if (!k5db2_inited(context))
	return KRB5_KDB_DBNOTINITED;

    dal_handle = (kdb5_dal_handle *) context->db_context;
    db_ctx = (krb5_db2_context *) dal_handle->db_context;
    if (db_ctx->db_locks_held && (db_ctx->db_lock_mode >= mode)) {
	/* No need to upgrade lock, just return */
	db_ctx->db_locks_held++;
	goto policy_lock;
    }

    if ((mode != KRB5_LOCKMODE_SHARED) && (mode != KRB5_LOCKMODE_EXCLUSIVE))
	return KRB5_KDB_BADLOCKMODE;

    krb5_lock_mode = mode | KRB5_LOCKMODE_DONTBLOCK;
    for (gotlock = tries = 0; tries < MAX_LOCK_TRIES; tries++) {
	retval = krb5_lock_file(context, db_ctx->db_lf_file, krb5_lock_mode);
	if (retval == 0) {
	    gotlock++;
	    break;
	} else if (retval == EBADF && mode == KRB5_DB_LOCKMODE_EXCLUSIVE) {
	    /* tried to exclusive-lock something we don't have */
	    /* write access to */
	    
	    /* Solaris Kerberos: Better error logging */
	    snprintf(errbuf, sizeof(errbuf),
	        gettext("Failed to exclusively lock \"%s\": "),
	        db_ctx->db_lf_name);
	    krb5_db2_prepend_err_str(context, errbuf, EBADF, EBADF);

	    return KRB5_KDB_CANTLOCK_DB;
	}
	sleep(1);
    }

    if (retval) {
	/* Solaris Kerberos: Better error logging */
	snprintf(errbuf, sizeof(errbuf),
	    gettext("Failed to lock \"%s\": "),
	    db_ctx->db_lf_name);
	krb5_db2_prepend_err_str(context, errbuf, retval, retval);
    }

    if (retval == EACCES)
	return KRB5_KDB_CANTLOCK_DB;
    else if (retval == EAGAIN || retval == EWOULDBLOCK)
	return OSA_ADB_CANTLOCK_DB;
    else if (retval != 0)
	return retval;

    if ((retval = krb5_db2_db_get_age(context, NULL, &mod_time)))
	goto lock_error;

    db = k5db2_dbopen(db_ctx, db_ctx->db_name,
		      mode == KRB5_LOCKMODE_SHARED ? O_RDONLY : O_RDWR, 0600, db_ctx->tempdb);
    if (db) {
	db_ctx->db_lf_time = mod_time;
	db_ctx->db = db;
    } else {
	retval = errno;

	/* Solaris Kerberos: Better error logging */
	snprintf(errbuf, sizeof(errbuf),
	    gettext("Failed to open db \"%s\": "),
	    db_ctx->db_name);
	krb5_db2_prepend_err_str(context, errbuf, retval, retval);

	db_ctx->db = NULL;
	goto lock_error;
    }

    db_ctx->db_lock_mode = mode;
    db_ctx->db_locks_held++;

  policy_lock:
    if ((retval = osa_adb_get_lock(db_ctx->policy_db, in_mode))) {
	krb5_db2_db_unlock(context);
    }
    return retval;

  lock_error:;
    db_ctx->db_lock_mode = 0;
    db_ctx->db_locks_held = 0;
    krb5_db2_db_unlock(context);
    return retval;
}

krb5_error_code
krb5_db2_db_unlock(krb5_context context)
{
    krb5_db2_context *db_ctx;
    kdb5_dal_handle *dal_handle;
    DB     *db;
    krb5_error_code retval;

    if (!k5db2_inited(context))
	return KRB5_KDB_DBNOTINITED;

    dal_handle = (kdb5_dal_handle *) context->db_context;
    db_ctx = (krb5_db2_context *) dal_handle->db_context;

    if ((retval = osa_adb_release_lock(db_ctx->policy_db))) {
	return retval;
    }

    if (!db_ctx->db_locks_held)	/* lock already unlocked */
	return KRB5_KDB_NOTLOCKED;
    db = db_ctx->db;
    if (--(db_ctx->db_locks_held) == 0) {
	(*db->close) (db);
	db_ctx->db = NULL;

	retval = krb5_lock_file(context, db_ctx->db_lf_file,
				KRB5_LOCKMODE_UNLOCK);
	db_ctx->db_lock_mode = 0;
	return (retval);
    }
    return 0;
}

/*
 * Create the database, assuming it's not there.
 */
krb5_error_code
krb5_db2_db_create(krb5_context context, char *db_name, krb5_int32 flags)
{
    register krb5_error_code retval = 0;
    kdb5_dal_handle *dal_handle;
    char   *okname;
    char   *db_name2 = NULL;
    int     fd;
    krb5_db2_context *db_ctx;
    DB     *db;
    char    policy_db_name[1024], policy_lock_name[1024];

    if ((retval = k5db2_init_context(context)))
	return (retval);

    dal_handle = (kdb5_dal_handle *) context->db_context;
    db_ctx = (krb5_db2_context *) dal_handle->db_context;
    switch (flags) {
    case KRB5_KDB_CREATE_HASH:
	if ((retval = krb5_db2_db_set_hashfirst(context, TRUE)))
	    return retval;
	break;
    case KRB5_KDB_CREATE_BTREE:
    case 0:
	if ((retval = krb5_db2_db_set_hashfirst(context, FALSE)))
	    return retval;
	break;
    default:
	return KRB5_KDB_BAD_CREATEFLAGS;
    }
    db = k5db2_dbopen(db_ctx, db_name, O_RDWR | O_CREAT | O_EXCL, 0600, db_ctx->tempdb);
    if (db == NULL) {
	retval = errno;

	/* Solaris Kerberos: Better error logging */
  	snprintf(errbuf, sizeof(errbuf), gettext("Failed to open \"%s\": "), db_name);
	krb5_db2_prepend_err_str(context, errbuf, retval, retval);
    }
    else
	(*db->close) (db);
    if (retval == 0) {

	db_name2 = db_ctx->tempdb ? gen_dbsuffix(db_name, "~") : strdup(db_name);
	if (db_name2 == NULL)
	    return ENOMEM;
	okname = gen_dbsuffix(db_name2, KDB2_LOCK_EXT);
	if (!okname)
	    retval = ENOMEM;
	else {
	    fd = open(okname, O_CREAT | O_RDWR | O_TRUNC, 0600);
	    if (fd < 0) {
		retval = errno;
		/* Solaris Kerberos: Better error logging */
		snprintf(errbuf, sizeof(errbuf), gettext("Failed to open \"%s\": "), okname);
		krb5_db2_prepend_err_str(context, errbuf, retval, retval);
	    }
	    else
		close(fd);
	    free_dbsuffix(okname);
	}
    }

    sprintf(policy_db_name, "%s.kadm5", db_name2);
    sprintf(policy_lock_name, "%s.lock", policy_db_name);

    retval = osa_adb_create_db(policy_db_name,
			       policy_lock_name, OSA_ADB_POLICY_DB_MAGIC);
    free(db_name2);
    return retval;
}

/*
 * Destroy the database.  Zero's out all of the files, just to be sure.
 */
static krb5_error_code
destroy_file_suffix(char *dbname, char *suffix)
{
    char   *filename;
    struct stat statb;
    int     nb, fd;
    unsigned int j;
    off_t   pos;
    char    buf[BUFSIZ];
    char    zbuf[BUFSIZ];
    int     dowrite;

    filename = gen_dbsuffix(dbname, suffix);
    if (filename == 0)
	return ENOMEM;
    if ((fd = open(filename, O_RDWR, 0)) < 0) {
	free(filename);
	return errno;
    }
    /* fstat() will probably not fail unless using a remote filesystem
     * (which is inappropriate for the kerberos database) so this check
     * is mostly paranoia.  */
    if (fstat(fd, &statb) == -1) {
	int     retval = errno;
	free(filename);
	return retval;
    }
    /*
     * Stroll through the file, reading in BUFSIZ chunks.  If everything
     * is zero, then we're done for that block, otherwise, zero the block.
     * We would like to just blast through everything, but some DB
     * implementations make holey files and writing data to the holes
     * causes actual blocks to be allocated which is no good, since
     * we're just about to unlink it anyways.
     */
    memset(zbuf, 0, BUFSIZ);
    pos = 0;
    while (pos < statb.st_size) {
	dowrite = 0;
	nb = read(fd, buf, BUFSIZ);
	if (nb < 0) {
	    int     retval = errno;
	    free(filename);
	    return retval;
	}
	for (j = 0; j < nb; j++) {
	    if (buf[j] != '\0') {
		dowrite = 1;
		break;
	    }
	}
	/* For signedness */
	j = nb;
	if (dowrite) {
	    lseek(fd, pos, SEEK_SET);
	    nb = write(fd, zbuf, j);
	    if (nb < 0) {
		int     retval = errno;
		free(filename);
		return retval;
	    }
	}
	pos += nb;
    }
    /* ??? Is fsync really needed?  I don't know of any non-networked
     * filesystem which will discard queued writes to disk if a file
     * is deleted after it is closed.  --jfc */
#ifndef NOFSYNC
    fsync(fd);
#endif
    close(fd);

    if (unlink(filename)) {
	free(filename);
	return (errno);
    }
    free(filename);
    return (0);
}

/*
 * Since the destroy operation happens outside the init/fini bracket, we
 * have some tomfoolery to undergo here.  If we're operating under no
 * database context, then we initialize with the default.  If the caller
 * wishes a different context (e.g. different dispatch table), it's their
 * responsibility to call kdb5_db_set_dbops() before this call.  That will
 * set up the right dispatch table values (e.g. name extensions).
 *
 * Not quite valid due to ripping out of dbops...
 */
krb5_error_code
krb5_db2_db_destroy(krb5_context context, char *dbname)
{
    krb5_error_code retval1, retval2;
    krb5_boolean tmpcontext;
    char    policy_db_name[1024], policy_lock_name[1024];

    tmpcontext = 0;
    if (!context->db_context
	|| !((kdb5_dal_handle *) context->db_context)->db_context) {
	tmpcontext = 1;
	if ((retval1 = k5db2_init_context(context)))
	    return (retval1);
    }

    retval1 = retval2 = 0;
    retval1 = destroy_file_suffix(dbname, "");
    retval2 = destroy_file_suffix(dbname, KDB2_LOCK_EXT);

    if (tmpcontext) {
	k5db2_clear_context((krb5_db2_context *) ((kdb5_dal_handle *) context->
						  db_context)->db_context);
	free(((kdb5_dal_handle *) context->db_context)->db_context);
	((kdb5_dal_handle *) context->db_context)->db_context = NULL;
    }

    if (retval1 || retval2)
	return (retval1 ? retval1 : retval2);

    assert (strlen(dbname) + strlen("%s.kadm5") < sizeof(policy_db_name));
    sprintf(policy_db_name, "%s.kadm5", dbname);
    /* XXX finish this */
    sprintf(policy_lock_name, "%s.lock", policy_db_name);

    retval1 = osa_adb_destroy_db(policy_db_name,
				 policy_lock_name, OSA_ADB_POLICY_DB_MAGIC);

    return retval1;
}

/*
 * look up a principal in the data base.
 * returns number of entries found, and whether there were
 * more than requested.
 */

krb5_error_code
krb5_db2_db_get_principal(krb5_context context,
			  krb5_const_principal searchfor,
			  krb5_db_entry *entries, /* filled in */
			  int *nentries, /* how much room/how many found */
			  krb5_boolean *more) /* are there more? */
{
    krb5_db2_context *db_ctx;
    krb5_error_code retval;
    DB     *db;
    DBT     key, contents;
    krb5_data keydata, contdata;
    int     trynum, dbret;
    kdb5_dal_handle *dal_handle;

    *more = FALSE;
    *nentries = 0;

    if (!k5db2_inited(context))
	return KRB5_KDB_DBNOTINITED;

    dal_handle = (kdb5_dal_handle *) context->db_context;
    db_ctx = (krb5_db2_context *) dal_handle->db_context;

    for (trynum = 0; trynum < KRB5_DB2_MAX_RETRY; trynum++) {
	if ((retval = krb5_db2_db_lock(context, KRB5_LOCKMODE_SHARED))) {
	    if (db_ctx->db_nb_locks)
		return (retval);
	    sleep(1);
	    continue;
	}
	break;
    }
    if (trynum == KRB5_DB2_MAX_RETRY)
	return KRB5_KDB_DB_INUSE;

    /* XXX deal with wildcard lookups */
    retval = krb5_encode_princ_dbkey(context, &keydata, searchfor);
    if (retval)
	goto cleanup;
    key.data = keydata.data;
    key.size = keydata.length;

    db = db_ctx->db;
    dbret = (*db->get) (db, &key, &contents, 0);
    retval = errno;
    krb5_free_data_contents(context, &keydata);
    switch (dbret) {
    case 1:
	retval = 0;
	/* FALLTHROUGH */
    case -1:
    default:
	*nentries = 0;
	goto cleanup;
    case 0:
	contdata.data = contents.data;
	contdata.length = contents.size;
	retval = krb5_decode_princ_contents(context, &contdata, entries);
	if (!retval)
	    *nentries = 1;
	break;
    }

  cleanup:
    (void) krb5_db2_db_unlock(context);	/* unlock read lock */
    return retval;
}

/*
  Free stuff returned by krb5_db2_db_get_principal.
 */
krb5_error_code
krb5_db2_db_free_principal(krb5_context context, krb5_db_entry *entries,
			   int nentries)
{
    register int i;
    for (i = 0; i < nentries; i++)
	krb5_dbe_free_contents(context, &entries[i]);
    return 0;
}

/*
  Stores the *"nentries" entry structures pointed to by "entries" in the
  database.

  *"nentries" is updated upon return to reflect the number of records
  acutally stored; the first *"nstored" records will have been stored in the
  database (even if an error occurs).

 */

krb5_error_code
krb5_db2_db_put_principal(krb5_context context,
			  krb5_db_entry *entries,
			  int *nentries, /* number of entry structs to update */
			  char **db_args)
{
    int     i, n, dbret;
    DB     *db;
    DBT     key, contents;
    krb5_data contdata, keydata;
    krb5_error_code retval;
    krb5_db2_context *db_ctx;
    kdb5_dal_handle *dal_handle;
    kdb_incr_update_t *upd, *fupd;
    char *princ_name = NULL;
    kdb_log_context *log_ctx;

    krb5_clear_error_message (context);
    if (db_args) {
	/* DB2 does not support db_args DB arguments for principal */
	krb5_set_error_message(context, EINVAL,
			       gettext("Unsupported argument \"%s\" for db2"),
			       db_args[0]);
	return EINVAL;
    }

    log_ctx = context->kdblog_context;

    n = *nentries;
    *nentries = 0;
    if (!k5db2_inited(context))
	return KRB5_KDB_DBNOTINITED;

    dal_handle = (kdb5_dal_handle *) context->db_context;
    db_ctx = (krb5_db2_context *) dal_handle->db_context;
    if ((retval = krb5_db2_db_lock(context, KRB5_LOCKMODE_EXCLUSIVE)))
	return retval;

    /*
     * Solaris Kerberos: We need the lock since ulog_conv_2logentry() does a get
     */
    if (log_ctx && (log_ctx->iproprole == IPROP_MASTER)) {
	if (!(upd = (kdb_incr_update_t *)
	  malloc(sizeof (kdb_incr_update_t)*n))) {
	    retval = errno;
	    goto err_lock;
	}
	fupd = upd;

	(void) memset(upd, 0, sizeof(kdb_incr_update_t)*n);

        if ((retval = ulog_conv_2logentry(context, entries, upd, n))) {
	    goto err_lock;
	}
    }

    db = db_ctx->db;
    if ((retval = krb5_db2_db_start_update(context))) {
	(void) krb5_db2_db_unlock(context);
	goto err_lock;
    }

    /* for each one, stuff temps, and do replace/append */
    for (i = 0; i < n; i++) {
	/*
	 * Solaris Kerberos: We'll be sharing the same locks as db for logging
	 */
        if (log_ctx && (log_ctx->iproprole == IPROP_MASTER)) {
		if ((retval = krb5_unparse_name(context, entries->princ,
		    &princ_name)))
			goto err_lock;

		upd->kdb_princ_name.utf8str_t_val = princ_name;
		upd->kdb_princ_name.utf8str_t_len = strlen(princ_name);

                if (retval = ulog_add_update(context, upd))
			goto err_lock;
        }

	retval = krb5_encode_princ_contents(context, &contdata, entries);
	if (retval)
	    break;
	contents.data = contdata.data;
	contents.size = contdata.length;
	retval = krb5_encode_princ_dbkey(context, &keydata, entries->princ);
	if (retval) {
	    krb5_free_data_contents(context, &contdata);
	    break;
	}

	key.data = keydata.data;
	key.size = keydata.length;
	dbret = (*db->put) (db, &key, &contents, 0);
	retval = dbret ? errno : 0;
	krb5_free_data_contents(context, &keydata);
	krb5_free_data_contents(context, &contdata);
	if (retval)
	    break;
	else if (log_ctx && (log_ctx->iproprole == IPROP_MASTER)) {
	    /*
	     * We need to make sure the db record is synced before we mark
	     * it as committed via finish_update.
	     */
	    dbret = (*db->sync)(db, 0);
	    if (dbret) {
		retval = errno;
		goto err_lock;
	    }
	    (void) ulog_finish_update(context, upd);
	    upd++;
	}
	entries++;		/* bump to next struct */
    }

    (void) krb5_db2_db_end_update(context);

err_lock:
    (void) krb5_db2_db_unlock(context);	/* unlock database */

    if (log_ctx && (log_ctx->iproprole == IPROP_MASTER))
        ulog_free_entries(fupd, n);

    *nentries = i;
    return (retval);
}

/*
 * delete a principal from the data base.
 * returns number of entries removed
 */

krb5_error_code
krb5_db2_db_delete_principal(krb5_context context,
			     krb5_const_principal searchfor,
			     int *nentries) /* how many found & deleted */
{
    krb5_error_code retval;
    krb5_db_entry entry;
    krb5_db2_context *db_ctx;
    DB     *db;
    DBT     key, contents;
    krb5_data keydata, contdata;
    int     i, dbret;
    kdb5_dal_handle *dal_handle;
    kdb_incr_update_t upd;
    char *princ_name = NULL;
    kdb_log_context *log_ctx;

    log_ctx = context->kdblog_context;

    if (!k5db2_inited(context))
	return KRB5_KDB_DBNOTINITED;

    dal_handle = (kdb5_dal_handle *) context->db_context;
    db_ctx = (krb5_db2_context *) dal_handle->db_context;
    if ((retval = krb5_db2_db_lock(context, KRB5_LOCKMODE_EXCLUSIVE)))
	return (retval);

    if ((retval = krb5_db2_db_start_update(context))) {
	(void) krb5_db2_db_unlock(context);	/* unlock write lock */
	return (retval);
    }

    if ((retval = krb5_encode_princ_dbkey(context, &keydata, searchfor)))
	goto cleanup;
    key.data = keydata.data;
    key.size = keydata.length;

    db = db_ctx->db;
    dbret = (*db->get) (db, &key, &contents, 0);
    retval = errno;
    switch (dbret) {
    case 1:
	retval = KRB5_KDB_NOENTRY;
	/* FALLTHROUGH */
    case -1:
    default:
	*nentries = 0;
	goto cleankey;
    case 0:
	;
    }
    /*
     * Solaris Kerberos: We'll be sharing the same locks as db for logging
     */
    if (log_ctx && (log_ctx->iproprole == IPROP_MASTER)) {
	if ((retval = krb5_unparse_name(context, searchfor, &princ_name))) {
		(void) krb5_db2_db_unlock(context);
		return retval;
	}

	(void) memset(&upd, 0, sizeof (kdb_incr_update_t));

	upd.kdb_princ_name.utf8str_t_val = princ_name;
	upd.kdb_princ_name.utf8str_t_len = strlen(princ_name);

	if (retval = ulog_delete_update(context, &upd)) {
		free(princ_name);
		(void) krb5_db2_db_unlock(context);
		return retval;
	}

	free(princ_name);
    }

    memset((char *) &entry, 0, sizeof(entry));
    contdata.data = contents.data;
    contdata.length = contents.size;
    retval = krb5_decode_princ_contents(context, &contdata, &entry);
    if (retval)
	goto cleankey;
    *nentries = 1;

    /* Clear encrypted key contents */
    for (i = 0; i < entry.n_key_data; i++) {
	if (entry.key_data[i].key_data_length[0]) {
	    memset((char *) entry.key_data[i].key_data_contents[0], 0,
		   (unsigned) entry.key_data[i].key_data_length[0]);
	}
    }

    retval = krb5_encode_princ_contents(context, &contdata, &entry);
    krb5_dbe_free_contents(context, &entry);
    if (retval)
	goto cleankey;

    contents.data = contdata.data;
    contents.size = contdata.length;
    dbret = (*db->put) (db, &key, &contents, 0);
    retval = dbret ? errno : 0;
    krb5_free_data_contents(context, &contdata);
    if (retval)
	goto cleankey;
    dbret = (*db->del) (db, &key, 0);
    retval = dbret ? errno : 0;

    /*
     * We need to commit our update upon success
     */
    if (!retval)
	if (log_ctx && (log_ctx->iproprole == IPROP_MASTER))
		(void) ulog_finish_update(context, &upd);

  cleankey:
    krb5_free_data_contents(context, &keydata);

  cleanup:
    (void) krb5_db2_db_end_update(context);
    (void) krb5_db2_db_unlock(context);	/* unlock write lock */
    return retval;
}

krb5_error_code
krb5_db2_db_iterate_ext(krb5_context context,
			krb5_error_code(*func) (krb5_pointer, krb5_db_entry *),
			krb5_pointer func_arg,
			int backwards, int recursive)
{
    krb5_db2_context *db_ctx;
    DB     *db;
    DBT     key, contents;
    krb5_data contdata;
    krb5_db_entry entries;
    krb5_error_code retval;
    kdb5_dal_handle *dal_handle;
    int     dbret;
    void   *cookie;

    cookie = NULL;
    if (!k5db2_inited(context))
	return KRB5_KDB_DBNOTINITED;

    dal_handle = (kdb5_dal_handle *) context->db_context;
    db_ctx = (krb5_db2_context *) dal_handle->db_context;
    retval = krb5_db2_db_lock(context, KRB5_LOCKMODE_SHARED);

    if (retval)
	return retval;

    db = db_ctx->db;
    if (recursive && db->type != DB_BTREE) {
	(void) krb5_db2_db_unlock(context);
	return KRB5_KDB_UK_RERROR;	/* Not optimal, but close enough. */
    }

    if (!recursive) {
	dbret = (*db->seq) (db, &key, &contents, backwards ? R_LAST : R_FIRST);
    } else {
#ifdef HAVE_BT_RSEQ
	dbret = bt_rseq(db, &key, &contents, &cookie,
			backwards ? R_LAST : R_FIRST);
#else
	(void) krb5_db2_db_unlock(context);
	return KRB5_KDB_UK_RERROR;	/* Not optimal, but close enough. */
#endif
    }
    while (dbret == 0) {
	contdata.data = contents.data;
	contdata.length = contents.size;
	retval = krb5_decode_princ_contents(context, &contdata, &entries);
	if (retval)
	    break;
	retval = (*func) (func_arg, &entries);
	krb5_dbe_free_contents(context, &entries);
	if (retval)
	    break;
	if (!recursive) {
	    dbret = (*db->seq) (db, &key, &contents,
				backwards ? R_PREV : R_NEXT);
	} else {
#ifdef HAVE_BT_RSEQ
	    dbret = bt_rseq(db, &key, &contents, &cookie,
			    backwards ? R_PREV : R_NEXT);
#else
	    (void) krb5_db2_db_unlock(context);
	    return KRB5_KDB_UK_RERROR;	/* Not optimal, but close enough. */
#endif
	}
    }
    switch (dbret) {
    case 1:
    case 0:
	break;
    case -1:
    default:
	retval = errno;
    }
    (void) krb5_db2_db_unlock(context);
    return retval;
}

krb5_error_code
krb5_db2_db_iterate(krb5_context context,
		    char *match_expr,
		    krb5_error_code(*func) (krb5_pointer, krb5_db_entry *),
		    krb5_pointer func_arg, char **db_args)
{
    char  **t_ptr = db_args;
    int backwards = 0, recursive = 0;

    while (t_ptr && *t_ptr) {
	char   *opt = NULL, *val = NULL;

	krb5_db2_get_db_opt(*t_ptr, &opt, &val);

	/* Solaris Kerberos: adding support for -rev/recurse flags */
	if (val && !strcmp(val, "rev"))
	    backwards = 1;
	else if (val && !strcmp(val, "recurse"))
	    recursive = 1;
	else {
	    krb5_set_error_message(context, EINVAL,
				   gettext("Unsupported argument \"%s\" for db2"),
				   val);
	    free(opt);
	    free(val);
	    return EINVAL;
	}

	free(opt);
	free(val);
	t_ptr++;
    }

    /* Solaris Kerberos: adding support for -rev/recurse flags */
    return krb5_db2_db_iterate_ext(context, func, func_arg, backwards, recursive);
}

krb5_boolean
krb5_db2_db_set_lockmode(krb5_context context, krb5_boolean mode)
{
    krb5_boolean old;
    krb5_db2_context *db_ctx;
    kdb5_dal_handle *dal_handle;

    dal_handle = (kdb5_dal_handle *) context->db_context;
    old = mode;
    if (dal_handle && (db_ctx = (krb5_db2_context *) dal_handle->db_context)) {
	old = db_ctx->db_nb_locks;
	db_ctx->db_nb_locks = mode;
    }
    return old;
}

/*
 *     DAL API functions
 */
krb5_error_code
krb5_db2_lib_init()
{
    return 0;
}

krb5_error_code
krb5_db2_lib_cleanup()
{
    /* right now, no cleanup required */
    return 0;
}

krb5_error_code
krb5_db2_open(krb5_context kcontext,
	      char *conf_section, char **db_args, int mode)
{
    krb5_error_code status = 0;
    char  **t_ptr = db_args;
    int     db_name_set = 0, tempdb=0;
    char *dbname = NULL;

    krb5_clear_error_message (kcontext);

    if (k5db2_inited(kcontext))
	return 0;

    while (t_ptr && *t_ptr) {
	char   *opt = NULL, *val = NULL;

	krb5_db2_get_db_opt(*t_ptr, &opt, &val);
	if (opt && !strcmp(opt, "dbname")) {
	    if (dbname) free(dbname);
	    dbname = strdup(val);
	}
	else if (!opt && !strcmp(val, "temporary") ) {
	    tempdb = 1;
	}
	/* ignore hash argument. Might have been passed from create */
	else if (!opt || strcmp(opt, "hash")) {
	    krb5_set_error_message(kcontext, EINVAL,
				   gettext("Unsupported argument \"%s\" for db2"),
				   opt ? opt : val);
	    free(opt);
	    free(val);
	    return EINVAL;
	}

	free(opt);
	free(val);
	t_ptr++;
    }

    if(dbname) {
	status = krb5_db2_db_set_name(kcontext, dbname, tempdb);
	free(dbname);
	if (status) {
	    /* Solaris Kerberos: Better error logging */
	    snprintf(errbuf, sizeof(errbuf), gettext("Failed to set db2 name to \"%s\": "), dbname);
	    krb5_db2_prepend_err_str(kcontext, errbuf, status, status);

	    goto clean_n_exit;
	}
	db_name_set = 1;
    }
    if (!db_name_set) {
	char   *value = NULL;
	status = profile_get_string(KRB5_DB_GET_PROFILE(kcontext), KDB_MODULE_SECTION, conf_section, KDB_DB2_DATABASE_NAME,	/* under given conf section */
				    NULL, &value);

	if (value == NULL) {
	    /* special case for db2. We might actually be looking at old type config file where database is specified as part of realm */
	    status = profile_get_string(KRB5_DB_GET_PROFILE(kcontext), KDB_REALM_SECTION, KRB5_DB_GET_REALM(kcontext), KDB_DB2_DATABASE_NAME,	/* under given realm */
	        default_db_name, &value);

	    if (status) {
		/* Solaris Kerberos: Better error logging */
		snprintf(errbuf, sizeof(errbuf), gettext("Failed when searching for "
		    "\"%s\", \"%s\", \"%s\" in profile: "), KDB_REALM_SECTION,
		    KRB5_DB_GET_REALM(kcontext), KDB_DB2_DATABASE_NAME);
		krb5_db2_prepend_err_str(kcontext, errbuf, status, status);

		goto clean_n_exit;
	    }
	}

	status = krb5_db2_db_set_name(kcontext, value, tempdb);

	if (status) {

	    /* Solaris Kerberos: Better error logging */
	    snprintf(errbuf, sizeof(errbuf), gettext("Failed to set db2 name to \"%s\": "), value);
	    krb5_db2_prepend_err_str(kcontext, errbuf, status, status);
	    profile_release_string(value);
	    goto clean_n_exit;
	}
	profile_release_string(value);

    }

    status = krb5_db2_db_init(kcontext);
    if (status) {
        /* Solaris Kerberos: Better error logging */
        snprintf(errbuf, sizeof(errbuf), gettext("Failed to initialize db2 db: "));
        krb5_db2_prepend_err_str(kcontext, errbuf, status, status);
    }

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db2_create(krb5_context kcontext, char *conf_section, char **db_args)
{
    krb5_error_code status = 0;
    char  **t_ptr = db_args;
    int     db_name_set = 0, tempdb=0;
    krb5_int32 flags = KRB5_KDB_CREATE_BTREE;
    char   *db_name = NULL;

    krb5_clear_error_message (kcontext);

    if (k5db2_inited(kcontext))
	return 0;

    while (t_ptr && *t_ptr) {
	char   *opt = NULL, *val = NULL;

	krb5_db2_get_db_opt(*t_ptr, &opt, &val);
	if (opt && !strcmp(opt, "dbname")) {
	    db_name = strdup(val);
	    if (db_name == NULL)
		return ENOMEM;
	}
	else if (!opt && !strcmp(val, "temporary")) {
	    tempdb = 1;
	}
	else if (opt && !strcmp(opt, "hash")) {
	    flags = KRB5_KDB_CREATE_HASH;
	} else {
	    krb5_set_error_message(kcontext, EINVAL,
				   gettext("Unsupported argument \"%s\" for db2"),
				   opt ? opt : val);
	    free(opt);
	    free(val);
	    return EINVAL;
	}

	free(opt);
	free(val);
	t_ptr++;
    }
    if (db_name) {
	    status = krb5_db2_db_set_name(kcontext, db_name, tempdb);
	    if (!status) {
		status = EEXIST;
		goto clean_n_exit;
	    }
	    db_name_set = 1;
    }
    if (!db_name_set) {
	char   *value = NULL;
	status = profile_get_string(KRB5_DB_GET_PROFILE(kcontext),
				    KDB_MODULE_SECTION, conf_section,
				    /* under given conf section */
				    KDB_DB2_DATABASE_NAME, NULL, &value);

	if (value == NULL) {
	    /* Special case for db2.  We might actually be looking at
	     * old type config file where database is specified as
	     * part of realm.  */
	    status = profile_get_string(KRB5_DB_GET_PROFILE(kcontext),
					KDB_REALM_SECTION,
					KRB5_DB_GET_REALM(kcontext),
					/* under given realm */
					KDB_DB2_DATABASE_NAME,
					default_db_name, &value);
	    if (status) {
		goto clean_n_exit;
	    }
	}

	db_name = strdup(value);
	/* Solaris Kerberos: for safety */
	if (db_name == NULL) {
	    status = ENOMEM;
	    goto clean_n_exit;
	}
	status = krb5_db2_db_set_name(kcontext, value, tempdb);
	profile_release_string(value);
	if (!status) {
	    status = EEXIST;
	    goto clean_n_exit;
	}

    }

    status = krb5_db2_db_create(kcontext, db_name, flags);
    if (status)
	goto clean_n_exit;
    /* db2 has a problem of needing to close and open the database again. This removes that need */
    status = krb5_db2_db_fini(kcontext);
    if (status)
	goto clean_n_exit;

    status = krb5_db2_open(kcontext, conf_section, db_args, KRB5_KDB_OPEN_RW);

  clean_n_exit:
    if (db_name)
	free(db_name);
    return status;
}

krb5_error_code
krb5_db2_destroy(krb5_context kcontext, char *conf_section, char **db_args)
{
    krb5_error_code status = 0;
    char  **t_ptr = db_args;
    int     db_name_set = 0, tempdb=0;
    char   *db_name = NULL;

    while (t_ptr && *t_ptr) {
	char   *opt = NULL, *val = NULL;

	krb5_db2_get_db_opt(*t_ptr, &opt, &val);
	if (opt && !strcmp(opt, "dbname")) {
	    db_name = strdup(val);
	    if (db_name == NULL)
		return ENOMEM;
	}
	else if (!opt && !strcmp(val, "temporary")) {
	    tempdb = 1;
	}
	/* ignore hash argument. Might have been passed from create */
	else if (!opt || strcmp(opt, "hash")) {
	    free(opt);
	    free(val);
	    return EINVAL;
	}

	free(opt);
	free(val);
	t_ptr++;
    }

    if (db_name) {
	status = krb5_db2_db_set_name(kcontext, db_name, tempdb);
	if (status) {
	    goto clean_n_exit;
	}
	db_name_set = 1;
    }
    if (!db_name_set) {
	char   *value = NULL;
	status = profile_get_string(KRB5_DB_GET_PROFILE(kcontext), KDB_MODULE_SECTION, conf_section, KDB_DB2_DATABASE_NAME,	/* under given conf section */
				    NULL, &value);

	if (value == NULL) {
	    /* special case for db2. We might actually be looking at old type config file where database is specified as part of realm */
	    status = profile_get_string(KRB5_DB_GET_PROFILE(kcontext), KDB_REALM_SECTION, KRB5_DB_GET_REALM(kcontext), KDB_DB2_DATABASE_NAME,	/* under given realm */
					default_db_name, &value);
	    if (status) {
		goto clean_n_exit;
	    }
	}

	db_name = strdup(value);
	if (db_name == NULL) {
	    status = ENOMEM;
	    goto clean_n_exit;
	}
	status = krb5_db2_db_set_name(kcontext, value, tempdb);
	profile_release_string(value);
	if (status) {
	    goto clean_n_exit;
	}

    }

    status = krb5_db2_db_destroy(kcontext, db_name);

  clean_n_exit:
    if (db_name)
	free(db_name);
    return status;
}

krb5_error_code
krb5_db2_set_master_key_ext(krb5_context kcontext,
			    char *pwd, krb5_keyblock * key)
{
    return krb5_db2_db_set_mkey(kcontext, key);
}

krb5_error_code
krb5_db2_db_set_option(krb5_context kcontext, int option, void *value)
{
    krb5_error_code status = 0;
    krb5_boolean oldval;
    krb5_db2_context *db_ctx;
    kdb5_dal_handle *dal_handle;

        if (!k5db2_inited(kcontext))
	return KRB5_KDB_DBNOTINITED;

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    db_ctx = (krb5_db2_context *) dal_handle->db_context;


    switch (option) {
    case KRB5_KDB_OPT_SET_DB_NAME:
	status = krb5_db2_db_set_name(kcontext, (char *) value, db_ctx->tempdb);
	break;

    case KRB5_KDB_OPT_SET_LOCK_MODE:
	oldval = krb5_db2_db_set_lockmode(kcontext, *((krb5_boolean *) value));
	*((krb5_boolean *) value) = oldval;
	break;

    default:
	status = -1;		/* TBD */
	break;
    }

    return status;
}

void   *
krb5_db2_alloc(krb5_context kcontext, void *ptr, size_t size)
{
    return realloc(ptr, size);
}

void
krb5_db2_free(krb5_context kcontext, void *ptr)
{
    free(ptr);
}

/* policy functions */
krb5_error_code
krb5_db2_create_policy(krb5_context kcontext, osa_policy_ent_t policy)
{
    kdb5_dal_handle *dal_handle;
    krb5_db2_context *dbc;

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    dbc = (krb5_db2_context *) dal_handle->db_context;

    return osa_adb_create_policy(dbc->policy_db, policy);
}

krb5_error_code
krb5_db2_get_policy(krb5_context kcontext,
		    char *name, osa_policy_ent_t * policy, int *cnt)
{
    kdb5_dal_handle *dal_handle;
    krb5_db2_context *dbc;

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    dbc = (krb5_db2_context *) dal_handle->db_context;

    return osa_adb_get_policy(dbc->policy_db, name, policy, cnt);
}

krb5_error_code
krb5_db2_put_policy(krb5_context kcontext, osa_policy_ent_t policy)
{
    kdb5_dal_handle *dal_handle;
    krb5_db2_context *dbc;

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    dbc = (krb5_db2_context *) dal_handle->db_context;

    return osa_adb_put_policy(dbc->policy_db, policy);
}

krb5_error_code
krb5_db2_iter_policy(krb5_context kcontext,
		     char *match_entry,
		     osa_adb_iter_policy_func func, void *data)
{
    kdb5_dal_handle *dal_handle;
    krb5_db2_context *dbc;

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    dbc = (krb5_db2_context *) dal_handle->db_context;

    return osa_adb_iter_policy(dbc->policy_db, func, data);
}

krb5_error_code
krb5_db2_delete_policy(krb5_context kcontext, char *policy)
{
    kdb5_dal_handle *dal_handle;
    krb5_db2_context *dbc;

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    dbc = (krb5_db2_context *) dal_handle->db_context;

    return osa_adb_destroy_policy(dbc->policy_db, policy);
}

void
krb5_db2_free_policy(krb5_context kcontext, osa_policy_ent_t entry)
{
    osa_free_policy_ent(entry);
}


/* */

krb5_error_code
krb5_db2_promote_db(krb5_context kcontext, char *conf_section, char **db_args)
{
    krb5_error_code status = 0;
    char *db_name = NULL;
    char *temp_db_name = NULL;

    krb5_clear_error_message (kcontext);

    {
	kdb5_dal_handle *dal_handle = kcontext->db_context;
	krb5_db2_context *db_ctx = dal_handle->db_context;
	db_name = strdup(db_ctx->db_name);
	if (db_name == NULL) {
	    status = ENOMEM;
	    goto clean_n_exit;
	}
    }

    assert(kcontext->db_context != NULL);
    temp_db_name = gen_dbsuffix(db_name, "~");
    if (temp_db_name == NULL) {
	status = ENOMEM;
	goto clean_n_exit;
    }

    status = krb5_db2_db_rename (kcontext, temp_db_name, db_name);

clean_n_exit:
    if (db_name)
	free(db_name);
    if (temp_db_name)
	free(temp_db_name);
    return status;
}

/* Retrieved from pre-DAL code base.  */
/*
 * "Atomically" rename the database in a way that locks out read
 * access in the middle of the rename.
 *
 * Not perfect; if we crash in the middle of an update, we don't
 * necessarily know to complete the transaction the rename, but...
 *
 * Since the rename operation happens outside the init/fini bracket, we
 * have to go through the same stuff that we went through up in db_destroy.
 */
krb5_error_code
krb5_db2_db_rename(context, from, to)
    krb5_context context;
    char *from;
    char *to;
{
    char *fromok;
    krb5_error_code retval;
    krb5_db2_context *s_context, *db_ctx;
    kdb5_dal_handle *dal_handle = context->db_context;
    
    s_context = dal_handle->db_context;
    dal_handle->db_context = NULL;
    if ((retval = k5db2_init_context(context)))
	return retval;
    db_ctx = (krb5_db2_context *) dal_handle->db_context;

    /*
     * Create the database if it does not already exist; the
     * files must exist because krb5_db2_db_lock, called below,
     * will fail otherwise.
     */
    {
	struct stat statbuf;

	if (stat(to, &statbuf) == -1) {
	    if (errno == ENOENT) {
		retval = krb5_db2_db_create(context, to,
					    KRB5_KDB_CREATE_BTREE);
		if (retval)
		    goto errout;
	    }
	    else {
		/* 
		 * XXX assuming we should bail if there is some other stat error
		 */
		retval = errno;
		goto errout;
	    }
	}
    }
    /*
     * Set the database to the target, so that other processes sharing
     * the target will stop their activity, and notice the new database.
     */
    retval = krb5_db2_db_set_name(context, to, 0);
    if (retval)
	goto errout;

    retval = krb5_db2_db_init(context);
    if (retval)
	goto errout;

    /* XXX WAF this needs to be redone (not lock safe)!!! */
    {
	/* Ugly brute force hack.

	   Should be going through nice friendly helper routines for
	   this, but it's a mess of jumbled so-called interfaces right
	   now.  */
	char    policy[2048], new_policy[2048];
	assert (strlen(db_ctx->db_name) < 2000);
	/*LINTED*/
	sprintf(policy, "%s.kadm5", db_ctx->db_name);
	/*LINTED*/
	sprintf(new_policy, "%s~.kadm5", db_ctx->db_name);
	if (0 != rename(new_policy, policy)) {
	    retval = errno;
	    goto errout;
	}
	strcat(new_policy, ".lock");
	(void) unlink(new_policy);
    }

    retval = krb5_db2_db_get_age(context, NULL, &db_ctx->db_lf_time);
    if (retval)
	goto errout;

    fromok = gen_dbsuffix(from, KDB2_LOCK_EXT);
    if (fromok == NULL) {
	retval = ENOMEM;
	goto errout;
    }

    if ((retval = krb5_db2_db_lock(context, KRB5_LOCKMODE_EXCLUSIVE)))
	goto errfromok;

    if ((retval = krb5_db2_db_start_update(context)))
	goto errfromok;

    if (rename(from, to)) {
	retval = errno;
	goto errfromok;
    }
    if (unlink(fromok)) {
	retval = errno;
	goto errfromok;
    }
    retval = krb5_db2_db_end_update(context);
errfromok:
    free_dbsuffix(fromok);
errout:
    if (dal_handle->db_context) {
	if (db_ctx->db_lf_file >= 0) {
	    krb5_db2_db_unlock(context);
	    close(db_ctx->db_lf_file);
	}
	k5db2_clear_context((krb5_db2_context *) dal_handle->db_context);
	free(dal_handle->db_context);
    }

    dal_handle->db_context = s_context;
    (void) krb5_db2_db_unlock(context);	/* unlock saved context db */

    return retval;
}

const char *
krb5_db2_errcode_2_string(krb5_context kcontext, long err_code)
{
    return krb5_get_error_message(kcontext, err_code);
}

void
krb5_db2_release_errcode_string(krb5_context kcontext, const char *msg)
{
    krb5_free_error_message(kcontext, msg);
}


/*
 * Solaris Kerberos:
 * Similar to the ldap plugin.
 */
static void
krb5_db2_prepend_err_str(krb5_context ctx, const char *str, krb5_error_code err,
    krb5_error_code oerr) {
	const char *omsg;
	if (oerr == 0)
		oerr = err;
	omsg = krb5_get_error_message (ctx, err);
	krb5_set_error_message (ctx, err, "%s %s", str, omsg);
	krb5_free_error_message(ctx, omsg);
}

