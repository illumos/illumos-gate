/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/kdb/kdb_db2.c
 *
 * Copyright 1997 by the Massachusetts Institute of Technology.
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

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "k5-int.h"
#include "kdb_log.h"
#include <db.h>
#include <stdio.h>
#include <errno.h>
#include <utime.h>

#define OLD_COMPAT_VERSION_1

#ifdef OLD_COMPAT_VERSION_1
#include "kdb_compat.h"
#endif

#include "kdb_db2.h"

static char *gen_dbsuffix 
	(char *, char * );
static krb5_error_code krb5_db2_db_start_update 
	(krb5_context);
static krb5_error_code krb5_db2_db_end_update 
	(krb5_context);
static krb5_error_code krb5_db2_db_set_hashfirst
	(krb5_context, int);

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
#define	k5db2_inited(c)	(c && c->db_context &&	\
			 ((krb5_db2_context *) c->db_context)->db_inited)

/*
 * Restore the default context.
 */
static void
k5db2_clear_context(dbctx)
    krb5_db2_context *dbctx;
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
}

static krb5_error_code
k5db2_init_context(context)
    krb5_context context;
{
    krb5_db2_context *db_ctx;

    if (context->db_context == NULL) {
	db_ctx = (krb5_db2_context *) malloc(sizeof(krb5_db2_context));
	if (db_ctx == NULL)
	    return ENOMEM;
	else {
	    memset((char *) db_ctx, 0, sizeof(krb5_db2_context));
	    k5db2_clear_context((krb5_db2_context *)db_ctx);
	    context->db_context = (void *) db_ctx;
	}
    }
    return(0);
}

/*
 * Utility routine: generate name of database file.
 */

static char *
gen_dbsuffix(db_name, sfx)
    char *db_name;
    char *sfx;
{
    char *dbsuffix;
    
    if (sfx == NULL)
	return((char *) NULL);

    dbsuffix = malloc (strlen(db_name) + strlen(sfx) + 1);
    if (!dbsuffix)
	return(0);
    (void) strcpy(dbsuffix, db_name);
    (void) strcat(dbsuffix, sfx);
    return dbsuffix;
}

static DB *
k5db2_dbopen(dbc, fname, flags, mode)
    krb5_db2_context *dbc;
    char *fname;
    int flags;
    int mode;
{
    DB *db;
    BTREEINFO bti;
    HASHINFO hashi;

    bti.flags = 0;
    bti.cachesize = 0;
    bti.psize = 4096;
    bti.lorder = 0;
    bti.minkeypage = 0;
    bti.compare = NULL;
    bti.prefix = NULL;

    hashi.bsize = 4096;
    hashi.cachesize = 0;
    hashi.ffactor = 40;
    hashi.hash = NULL;
    hashi.lorder = 0;
    hashi.nelem = 1;

    db = dbopen(fname, flags, mode,
		dbc->hashfirst ? DB_HASH : DB_BTREE,
		dbc->hashfirst ? (void *) &hashi : (void *) &bti);
    if (db != NULL)
	return db;
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
    default:
	return db;
    }
}

static krb5_error_code
krb5_db2_db_set_hashfirst(context, hashfirst)
    krb5_context context;
    int hashfirst;
{
    krb5_db2_context *dbc;

    if (k5db2_inited(context))
	return KRB5_KDB_DBNOTINITED;
    dbc = (krb5_db2_context *) context->db_context;
    dbc->hashfirst = hashfirst;
    return 0;
}

/*
 * initialization for data base routines.
 */

krb5_error_code
krb5_db2_db_init(context)
    krb5_context context;
{
    char *filename = NULL;
    krb5_db2_context *db_ctx;
    krb5_error_code retval;

    if (k5db2_inited(context))
	return 0;

    /* Check for presence of our context, if not present, allocate one. */
    if ((retval = k5db2_init_context(context)))
	return(retval);

    db_ctx = context->db_context;
    db_ctx->db = NULL;

    if (!(filename = gen_dbsuffix(db_ctx->db_name, KDB2_LOCK_EXT)))
	return ENOMEM;
    db_ctx->db_lf_name = filename; /* so it gets freed by clear_context */

    /*
     * should be opened read/write so that write locking can work with
     * POSIX systems
     */
    if ((db_ctx->db_lf_file = open(filename, O_RDWR, 0666)) < 0) {
	if ((db_ctx->db_lf_file = open(filename, O_RDONLY, 0666)) < 0) {
	    retval = errno;
	    goto err_out;
	}
    }
    db_ctx->db_inited++;

    if ((retval = krb5_db2_db_get_age(context, NULL, &db_ctx->db_lf_time))) 
	goto err_out;

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
krb5_db2_db_fini(context)
    krb5_context context;
{
    krb5_error_code retval = 0;
    krb5_db2_context *db_ctx;

    db_ctx = (krb5_db2_context *) context->db_context;

    if (k5db2_inited(context)) {
	if (close(db_ctx->db_lf_file))
	    retval = errno;
	else
	    retval = 0;
    }
    if (db_ctx) {
	k5db2_clear_context(db_ctx);
	free(context->db_context);
	context->db_context = NULL;
    }
    return retval;
}

krb5_error_code
krb5_db2_db_open_database(context)
    krb5_context context;
{
    if (!k5db2_inited(context))
    	return KRB5_KDB_DBNOTINITED;
    return 0;
}

krb5_error_code
krb5_db2_db_close_database(context)
    krb5_context context;
{
    if (!k5db2_inited(context))
    	return KRB5_KDB_DBNOTINITED;
    return 0;
}

/*
 * Set/Get the master key associated with the database
 */
krb5_error_code
krb5_db2_db_set_mkey(context, key)
    krb5_context context;
    krb5_keyblock *key;
{
    krb5_db2_context *db_ctx;

    if (!k5db2_inited(context))
	return(KRB5_KDB_DBNOTINITED);

    db_ctx = context->db_context;
    db_ctx->db_master_key = key;
    return 0;
}

krb5_error_code
krb5_db2_db_get_mkey(context, key)
    krb5_context context;
    krb5_keyblock **key;
{
    krb5_db2_context *db_ctx;

    if (!k5db2_inited(context))
	return(KRB5_KDB_DBNOTINITED);

    db_ctx = context->db_context;
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

krb5_error_code
krb5_db2_db_set_name(context, name)
    krb5_context context;
    char *name;
{
    DB *db;
    krb5_db2_context *db_ctx;
    krb5_error_code kret;

    if (k5db2_inited(context))
	return KRB5_KDB_DBINITED;

    /* Check for presence of our context, if not present, allocate one. */
    if ((kret = k5db2_init_context(context)))
	return(kret);

    if (name == NULL)
	name = default_db_name;

    db_ctx = context->db_context;
    db = k5db2_dbopen(db_ctx, name, O_RDONLY, 0);
    if (db == NULL)
	return errno;

    db_ctx->db_name = strdup(name);
    (*db->close)(db);
    return 0;
}

/*
 * Return the last modification time of the database.
 *
 * Think about using fstat.
 */

krb5_error_code
krb5_db2_db_get_age(context, db_name, age)
    krb5_context context;
    char *db_name;
    time_t *age;
{
    krb5_db2_context *db_ctx;
    struct stat st;

    if (!k5db2_inited(context))
	return(KRB5_KDB_DBNOTINITED);
    db_ctx = (krb5_db2_context *) context->db_context;
    if (fstat (db_ctx->db_lf_file, &st) < 0)
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
krb5_db2_db_start_update(context)
    krb5_context context;
{
    return 0;
}

static krb5_error_code
krb5_db2_db_end_update(context)
    krb5_context context;
{
    krb5_error_code retval;
    krb5_db2_context *db_ctx;
    struct stat st;
    time_t now;
    struct utimbuf utbuf;

    if (!k5db2_inited(context))
	return(KRB5_KDB_DBNOTINITED);

    retval = 0;
    db_ctx = context->db_context;
    now = time((time_t *) NULL);
    if (fstat(db_ctx->db_lf_file, &st) == 0) {
	if (st.st_mtime >= now) {
	    utbuf.actime = st.st_mtime+1;
	    utbuf.modtime = st.st_mtime+1;
	    if (utime(db_ctx->db_lf_name, &utbuf))
		retval = errno;
	}
	else {
	    if (utime(db_ctx->db_lf_name, (struct utimbuf *) NULL))
		retval = errno;
	}
    }
    else
	retval = errno;
    if (!retval) {
	if (fstat(db_ctx->db_lf_file, &st) == 0)
	    db_ctx->db_lf_time = st.st_mtime;
	else
	    retval = errno;
    }
    return(retval);
}

krb5_error_code
krb5_db2_db_lock(context, mode)
    krb5_context 	  context;
    int 	 	  mode;
{
    krb5_db2_context *db_ctx;
    int krb5_lock_mode;
    DB *db;
    krb5_error_code retval;
    time_t mod_time;

    if (!k5db2_inited(context))
	return KRB5_KDB_DBNOTINITED;

    db_ctx = (krb5_db2_context *) context->db_context;
    if (db_ctx->db_locks_held && (db_ctx->db_lock_mode >= mode)) {
	/* No need to upgrade lock, just return */
	db_ctx->db_locks_held++;
	return(0);
    }

    if ((mode != KRB5_LOCKMODE_SHARED) && (mode != KRB5_LOCKMODE_EXCLUSIVE)) 
	return KRB5_KDB_BADLOCKMODE;

    if (db_ctx->db_nb_locks)
	krb5_lock_mode = mode | KRB5_LOCKMODE_DONTBLOCK;
    else
	krb5_lock_mode = mode;
    retval = krb5_lock_file(context, db_ctx->db_lf_file, krb5_lock_mode);
    switch (retval) {
    case EBADF:
	if (mode == KRB5_LOCKMODE_EXCLUSIVE)
	    return KRB5_KDB_CANTLOCK_DB;
    default:
	return retval;
    case 0:
	break;
    }

    if ((retval = krb5_db2_db_get_age(context, NULL, &mod_time)))
	goto lock_error;

    db = k5db2_dbopen(db_ctx, db_ctx->db_name,
		mode == KRB5_LOCKMODE_SHARED ? O_RDONLY : O_RDWR,
		0600);
    if (db) {
	 db_ctx->db_lf_time = mod_time;
	 db_ctx->db = db;
    } else {
	 retval = errno;
	 db_ctx->db = NULL;
	 goto lock_error;
    }

    db_ctx->db_lock_mode = mode;
    db_ctx->db_locks_held++;
    return 0;

lock_error:;
    db_ctx->db_lock_mode = 0;
    db_ctx->db_locks_held = 0;
    (void) krb5_db2_db_unlock(context);
    return retval;
}

krb5_error_code
krb5_db2_db_unlock(context)
    krb5_context context;
{
    krb5_db2_context *db_ctx;
    DB *db;
    krb5_error_code retval;

    if (!k5db2_inited(context))
	return KRB5_KDB_DBNOTINITED;

    db_ctx = (krb5_db2_context *) context->db_context;
    if (!db_ctx->db_locks_held)		/* lock already unlocked */
	return KRB5_KDB_NOTLOCKED;
    db = db_ctx->db;
    if (--(db_ctx->db_locks_held) == 0) {
	(*db->close)(db);
	db_ctx->db = NULL;

    	retval = krb5_lock_file(context, db_ctx->db_lf_file,
				KRB5_LOCKMODE_UNLOCK);
	db_ctx->db_lock_mode = 0;
	return(retval);
    }
    return 0;
}

/*
 * Create the database, assuming it's not there.
 */
krb5_error_code
krb5_db2_db_create(context, db_name, flags)
    krb5_context context;
    char *db_name;
    krb5_int32 flags;
{
    register krb5_error_code retval = 0;
    char *okname;
    int fd;
    krb5_db2_context *db_ctx;
    DB *db;

    if ((retval = k5db2_init_context(context)))
	return(retval);

    db_ctx = (krb5_db2_context *) context->db_context;
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
    db = k5db2_dbopen(db_ctx, db_name, O_RDWR|O_CREAT|O_EXCL, 0600);
    if (db == NULL)
	retval = errno;
    else
	(*db->close)(db);
    if (retval == 0) {
	okname = gen_dbsuffix(db_name, KDB2_LOCK_EXT);
	if (!okname)
	    retval = ENOMEM;
	else {
	    fd = open (okname, O_CREAT|O_RDWR|O_TRUNC, 0600);
	    if (fd < 0)
		retval = errno;
	    else
		close(fd);
	    free_dbsuffix(okname);
	}
    }
    return retval;
}

/*
 * Destroy the database.  Zero's out all of the files, just to be sure.
 */
static krb5_error_code
destroy_file_suffix(dbname, suffix)
    char *dbname;
    char *suffix;
{
    char *filename;
    struct stat statb;
    int nb,fd;
    unsigned int j;
    off_t pos;
    char buf[BUFSIZ];
    char zbuf[BUFSIZ];
    int dowrite;

    filename = gen_dbsuffix(dbname, suffix);
    if (filename == 0)
	return ENOMEM;
    if ((fd = open(filename, O_RDWR, 0)) < 0) {
	free(filename);
	return errno;
    }
    /* fstat() will probably not fail unless using a remote filesystem
       (which is inappropriate for the kerberos database) so this check
       is mostly paranoia.  */
    if (fstat(fd, &statb) == -1) {
	int retval = errno;
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
	    int retval = errno;
	    free(filename);
	    return retval;
	}
	for (j=0; j<nb; j++) {
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
		int retval = errno;
		free(filename);
		return retval;
	    }
	}
	pos += nb;
    }
    /* ??? Is fsync really needed?  I don't know of any non-networked
       filesystem which will discard queued writes to disk if a file
       is deleted after it is closed.  --jfc */
#ifndef NOFSYNC
    fsync(fd);
#endif
    close(fd);

    if (unlink(filename)) {
	free(filename);
	return(errno);
    }
    free(filename);
    return(0);
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
krb5_db2_db_destroy(context, dbname)
    krb5_context context;
    char *dbname;
{
    krb5_error_code retval1, retval2;
    krb5_boolean tmpcontext;

    tmpcontext = 0;
    if (!context->db_context) {
	tmpcontext = 1;
	if ((retval1 = k5db2_init_context(context)))
	    return(retval1);
    }

    retval1 = retval2 = 0;
    retval1 = destroy_file_suffix(dbname, "");
    retval2 = destroy_file_suffix(dbname, KDB2_LOCK_EXT);

    if (tmpcontext) {
	k5db2_clear_context((krb5_db2_context *) context->db_context);
	free(context->db_context);
	context->db_context = NULL;
    }

    if (retval1 || retval2)
	return (retval1 ? retval1 : retval2);
    else
	return 0;
}

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
    DB *db;
    char *fromok;
    krb5_error_code retval;
    krb5_db2_context *s_context, *db_ctx;

    s_context = context->db_context;
    context->db_context = NULL;
    if ((retval = k5db2_init_context(context)))
	return retval;
    db_ctx = (krb5_db2_context *) context->db_context;

    /*
     * Create the database if it does not already exist; the
     * files must exist because krb5_db2_db_lock, called below,
     * will fail otherwise.
     */
    db = k5db2_dbopen(db_ctx, to, O_RDWR|O_CREAT, 0600);
    if (db == NULL) {
	retval = errno;
	goto errout;
    }
    else
	(*db->close)(db);
    /*
     * Set the database to the target, so that other processes sharing
     * the target will stop their activity, and notice the new database.
     */
    retval = krb5_db2_db_set_name(context, to);
    if (retval)
	goto errout;

    db_ctx->db_lf_name = gen_dbsuffix(db_ctx->db_name, KDB2_LOCK_EXT);
    if (db_ctx->db_lf_name == NULL) {
	retval = ENOMEM;
	goto errout;
    }
    db_ctx->db_lf_file = open(db_ctx->db_lf_name, O_RDWR|O_CREAT, 0600);
    if (db_ctx->db_lf_file < 0) {
	retval = errno;
	goto errout;
    }

    db_ctx->db_inited = 1;

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
    if (context->db_context) {
	if (db_ctx->db_lf_file >= 0) {
	    krb5_db2_db_unlock(context);
	    close(db_ctx->db_lf_file);
	}
	k5db2_clear_context((krb5_db2_context *) context->db_context);
	free(context->db_context);
    }

    context->db_context = s_context;
    (void) krb5_db2_db_unlock(context);	/* unlock saved context db */

    return retval;
}

/*
 * look up a principal in the data base.
 * returns number of entries found, and whether there were
 * more than requested. 
 */

krb5_error_code
krb5_db2_db_get_principal(context, searchfor, entries, nentries, more)
    krb5_context context;
    krb5_const_principal searchfor;
    krb5_db_entry *entries;	/* filled in */
    int *nentries;		/* how much room/how many found */
    krb5_boolean *more;		/* are there more? */
{
    krb5_db2_context *db_ctx;
    krb5_error_code retval;
    DB *db;
    DBT key, contents;
    krb5_data keydata, contdata;
    int trynum, dbret;

    *more = FALSE;
    *nentries = 0;

    if (!k5db2_inited(context))
	return KRB5_KDB_DBNOTINITED;

    db_ctx = (krb5_db2_context *) context->db_context;
    for (trynum = 0; trynum < KRB5_DB2_MAX_RETRY; trynum++) {
	if ((retval = krb5_db2_db_lock(context, KRB5_LOCKMODE_SHARED))) {
	    if (db_ctx->db_nb_locks) 
	    	return(retval);
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
    dbret = (*db->get)(db, &key, &contents, 0);
    retval = errno;
    krb5_free_data_contents(context, &keydata);
    switch (dbret) {
    case 1:
	retval = 0;
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
    (void) krb5_db2_db_unlock(context);		/* unlock read lock */
    return retval;
}

/*
  Free stuff returned by krb5_db2_db_get_principal.
 */
void
krb5_db2_db_free_principal(context, entries, nentries)
    krb5_context context;
    krb5_db_entry *entries;
    int nentries;
{
    register int i;
    for (i = 0; i < nentries; i++)
	krb5_dbe_free_contents(context, &entries[i]);
    return;
}

/*
  Stores the *"nentries" entry structures pointed to by "entries" in the
  database.

  *"nentries" is updated upon return to reflect the number of records
  acutally stored; the first *"nstored" records will have been stored in the
  database (even if an error occurs).

 */

krb5_error_code
krb5_db2_db_put_principal(context, entries, nentries)
    krb5_context context;
    krb5_db_entry *entries;
    register int *nentries;		/* number of entry structs to update */
{
    int i, n, dbret;
    DB *db;
    DBT key, contents;
    krb5_data contdata, keydata;
    krb5_error_code retval;
    krb5_db2_context *db_ctx;
    kdb_incr_update_t *upd, *fupd;
    char *princ_name = NULL;
    kdb_log_context *log_ctx;

    log_ctx = context->kdblog_context;

    n = *nentries;
    *nentries = 0;
    if (!k5db2_inited(context))
	return KRB5_KDB_DBNOTINITED;

    db_ctx = (krb5_db2_context *) context->db_context;
    if ((retval = krb5_db2_db_lock(context, KRB5_LOCKMODE_EXCLUSIVE))) {
	return retval;
    }

    /*
     * We need the lock since ulog_conv_2logentry() does a get
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
	goto err_lock;
    }

    /* for each one, stuff temps, and do replace/append */
    for (i = 0; i < n; i++) {
	/*
	 * We'll be sharing the same locks as db for logging
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
	dbret = (*db->put)(db, &key, &contents, 0);
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
	entries++;			/* bump to next struct */
    }

    (void)krb5_db2_db_end_update(context);

err_lock:
    (void)krb5_db2_db_unlock(context);		/* unlock database */

    if (log_ctx && (log_ctx->iproprole == IPROP_MASTER))
        ulog_free_entries(fupd, n);

    *nentries = i;
    return(retval);
}

/*
 * delete a principal from the data base.
 * returns number of entries removed
 */

krb5_error_code
krb5_db2_db_delete_principal(context, searchfor, nentries)
    krb5_context context;
    krb5_const_principal searchfor;
    int *nentries;		/* how many found & deleted */
{
    krb5_error_code retval;
    krb5_db_entry entry;
    krb5_db2_context *db_ctx;
    DB *db;
    DBT key, contents;
    krb5_data keydata, contdata;
    int i, dbret;
    kdb_incr_update_t upd;
    char *princ_name = NULL;
    kdb_log_context *log_ctx;

    log_ctx = context->kdblog_context;

    if (!k5db2_inited(context))
	return KRB5_KDB_DBNOTINITED;

    db_ctx = (krb5_db2_context *) context->db_context;
    if ((retval = krb5_db2_db_lock(context, KRB5_LOCKMODE_EXCLUSIVE)))
	return(retval);

    if ((retval = krb5_db2_db_start_update(context))) {
        (void) krb5_db2_db_unlock(context); /* unlock write lock */
	return(retval);
    }

    if ((retval = krb5_encode_princ_dbkey(context, &keydata, searchfor)))
	goto cleanup;
    key.data = keydata.data;
    key.size = keydata.length;

    db = db_ctx->db;
    dbret = (*db->get)(db, &key, &contents, 0);
    retval = errno;
    switch (dbret) {
    case 1:
	retval = KRB5_KDB_NOENTRY;
    case -1:
    default:
	*nentries = 0;
	goto cleankey;
    case 0:
	;
    }

    /*
     * We'll be sharing the same locks as db for logging
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

    memset((char *)&entry, 0, sizeof(entry));
    contdata.data = contents.data;
    contdata.length = contents.size;
    retval = krb5_decode_princ_contents(context, &contdata, &entry);
    if (retval)
	goto cleankey;
    *nentries = 1;

    /* Clear encrypted key contents */
    for (i = 0; i < entry.n_key_data; i++) {
	if (entry.key_data[i].key_data_length[0]) {
	    memset((char *)entry.key_data[i].key_data_contents[0], 0, 
		   (unsigned) entry.key_data[i].key_data_length[0]); 
	}
    }

    retval = krb5_encode_princ_contents(context, &contdata, &entry);
    krb5_dbe_free_contents(context, &entry);
    if (retval)
	goto cleankey;

    contents.data = contdata.data;
    contents.size = contdata.length;
    dbret = (*db->put)(db, &key, &contents, 0);
    retval = dbret ? errno : 0;
    krb5_free_data_contents(context, &contdata);
    if (retval)
	goto cleankey;
    dbret = (*db->del)(db, &key, 0);
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
krb5_db2_db_iterate_ext(context, func, func_arg, backwards, recursive)
    krb5_context context;
    krb5_error_code (*func) (krb5_pointer, krb5_db_entry *);
    krb5_pointer func_arg;
    int backwards, recursive;
{
    krb5_db2_context *db_ctx;
    DB *db;
    DBT key, contents;
    krb5_data contdata;
    krb5_db_entry entries;
    krb5_error_code retval;
    int dbret;
    void *cookie;

    cookie = NULL;
    if (!k5db2_inited(context))
	return KRB5_KDB_DBNOTINITED;

    db_ctx = (krb5_db2_context *) context->db_context;
    retval = krb5_db2_db_lock(context, KRB5_LOCKMODE_SHARED);

    if (retval)
	return retval;

    db = db_ctx->db;
    if (recursive && db->type != DB_BTREE) {
	(void)krb5_db2_db_unlock(context);
	return KRB5_KDB_UK_RERROR; /* Not optimal, but close enough. */
    }

    if (!recursive) {
	dbret = (*db->seq)(db, &key, &contents,
			   backwards ? R_LAST : R_FIRST);
    } else {
#ifdef HAVE_BT_RSEQ
	dbret = bt_rseq(db, &key, &contents, &cookie,
			backwards ? R_LAST : R_FIRST);
#else
	(void)krb5_db2_db_unlock(context);
	return KRB5_KDB_UK_RERROR; /* Not optimal, but close enough. */
#endif
    }
    while (dbret == 0) {
	contdata.data = contents.data;
	contdata.length = contents.size;
	retval = krb5_decode_princ_contents(context, &contdata, &entries);
	if (retval)
	    break;
	retval = (*func)(func_arg, &entries);
	krb5_dbe_free_contents(context, &entries);
	if (retval)
	    break;
	if (!recursive) {
	    dbret = (*db->seq)(db, &key, &contents,
			       backwards ? R_PREV : R_NEXT);
	} else {
#ifdef HAVE_BT_RSEQ
	    dbret = bt_rseq(db, &key, &contents, &cookie,
			    backwards ? R_PREV : R_NEXT);
#else
	    (void)krb5_db2_db_unlock(context);
	    return KRB5_KDB_UK_RERROR; /* Not optimal, but close enough. */
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
krb5_db2_db_iterate(context, func, func_arg)
    krb5_context context;
    krb5_error_code (*func) (krb5_pointer, krb5_db_entry *);
    krb5_pointer func_arg;
{
    return krb5_db2_db_iterate_ext(context, func, func_arg, 0, 0);
}

krb5_boolean
krb5_db2_db_set_lockmode(context, mode)
    krb5_context context;
    krb5_boolean mode;
{
    krb5_boolean old;
    krb5_db2_context *db_ctx;

    old = mode;
    if ((db_ctx = (krb5_db2_context *) context->db_context)) {
	old = db_ctx->db_nb_locks;
	db_ctx->db_nb_locks = mode;
    }
    return old;
}

/*
 * Context serialization operations.
 *
 * Ick, this is really gross. --- tlyu
 */

/*
 * kdb5_context_size()	- Determine size required to serialize.
 */
static krb5_error_code
kdb5_context_size(kcontext, arg, sizep)
    krb5_context	kcontext;
    krb5_pointer	arg;
    size_t		*sizep;
{
    krb5_error_code	kret;
    size_t		required;
    krb5_db2_context	*dbctx;

    /*
     * The database context requires at minimum:
     *	krb5_int32	for KV5M_DB_CONTEXT
     *	krb5_int32	for db_inited
     *	krb5_int32	for database lockfile non-blocking flag
     *	krb5_int32	for database lockfile lock count
     *	krb5_int32	for database lockfile lock mode
     *	krb5_int32	for length of database name.
     *	krb5_int32	for KV5M_DB_CONTEXT
     */
    kret = EINVAL;
    if ((dbctx = (krb5_db2_context *) arg)) {
	required = (sizeof(krb5_int32) * 7);
	if (dbctx->db_inited && dbctx->db_name)
	    required += strlen(dbctx->db_name);
	kret = 0;
	*sizep += required;
    }
    return(kret);
}

/*
 * kdb5_context_externalize()	- Externalize the database context.
 */
static krb5_error_code
kdb5_context_externalize(kcontext, arg, buffer, lenremain)
    krb5_context	kcontext;
    krb5_pointer	arg;
    krb5_octet		**buffer;
    size_t		*lenremain;
{
    krb5_error_code	kret;
    krb5_db2_context	*dbctx;
    size_t		required;
    krb5_octet		*bp;
    size_t		remain;

    required = 0;
    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    if ((dbctx = (krb5_db2_context *) arg)) {
	kret = ENOMEM;
	if (!kdb5_context_size(kcontext, arg, &required) &&
	    (required <= remain)) {
	    /* Write magic number */
	    (void) krb5_ser_pack_int32(KV5M_DB_CONTEXT, &bp, &remain);

	    /* Write inited flag */
	    (void) krb5_ser_pack_int32((krb5_int32) dbctx->db_inited,
				       &bp, &remain);

	    /* Write blocking lock lockmode */
	    (void) krb5_ser_pack_int32((krb5_int32) dbctx->db_nb_locks,
				       &bp, &remain);

	    /* Write lock count */
	    (void) krb5_ser_pack_int32((krb5_int32)
				       (dbctx->db_inited) ?
				       dbctx->db_locks_held : 0,
				       &bp, &remain);

	    /* Write lock mode */
	    (void) krb5_ser_pack_int32((krb5_int32)
				       (dbctx->db_inited) ?
				       dbctx->db_lock_mode : 0,
				       &bp, &remain);

	    /* Write length of database name */
	    (void) krb5_ser_pack_int32((dbctx->db_inited && dbctx->db_name) ?
				       (krb5_int32) strlen(dbctx->db_name) : 0,
				       &bp, &remain);
	    if (dbctx->db_inited && dbctx->db_name)
		(void) krb5_ser_pack_bytes((krb5_octet *) dbctx->db_name,
					   strlen(dbctx->db_name),
					   &bp, &remain);

	    /* Write trailer */
	    (void) krb5_ser_pack_int32(KV5M_DB_CONTEXT, &bp, &remain);
	    kret = 0;
	    *buffer = bp;
	    *lenremain = remain;
	}
    }
    return(kret);
}

/*
 * kdb5_context_internalize()	- Internalize the database context.
 */
static krb5_error_code
kdb5_context_internalize(kcontext, argp, buffer, lenremain)
    krb5_context	kcontext;
    krb5_pointer	*argp;
    krb5_octet		**buffer;
    size_t		*lenremain;
{
    krb5_error_code	kret;
    krb5_context	tmpctx;
    krb5_db2_context	*dbctx;
    krb5_int32		ibuf;
    krb5_octet		*bp;
    size_t		remain;
    krb5_int32		iflag;
    krb5_int32		nb_lockmode;
    krb5_int32		lockcount;
    krb5_int32		lockmode;
    krb5_int32		dbnamelen;
    krb5_boolean        nb_lock;
    char		*dbname;

    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    dbctx = (krb5_db2_context *) NULL;
    /* Read our magic number */
    if (krb5_ser_unpack_int32(&ibuf, &bp, &remain))
	ibuf = 0;
    if (ibuf == KV5M_DB_CONTEXT) {
	kret = ENOMEM;

	if (!(kret = krb5_ser_unpack_int32(&iflag, &bp, &remain)) &&
	    !(kret = krb5_ser_unpack_int32(&nb_lockmode, &bp, &remain)) &&
	    !(kret = krb5_ser_unpack_int32(&lockcount, &bp, &remain)) &&
	    !(kret = krb5_ser_unpack_int32(&lockmode, &bp, &remain)) &&
	    !(kret = krb5_ser_unpack_int32(&dbnamelen, &bp, &remain)) &&
	    !(kret = krb5_init_context(&tmpctx))) {
	    if (iflag) {
		dbname = (char *) NULL;
		if (dbnamelen &&
		    (dbname = (char *) malloc((size_t) (dbnamelen+1)))) {
		    kret = krb5_ser_unpack_bytes((krb5_octet *) dbname,
						 (size_t) dbnamelen,
						 &bp, &remain);
		    if (!kret)
			dbname[dbnamelen] = '\0';
		}
		if (!kret &&
		    (!dbname || !(kret = krb5_db_set_name(tmpctx, dbname))) &&
		    !(kret = krb5_db_init(tmpctx))) {
		    dbctx = (krb5_db2_context *) tmpctx->db_context;
		    (void) krb5_db2_db_set_lockmode(tmpctx, 0);
		    if (lockmode)
			kret = krb5_db_lock(tmpctx, lockmode);
		    if (!kret && lockmode)
			dbctx->db_locks_held = lockcount;
		    nb_lock = nb_lockmode & 0xff;
		    (void) krb5_db2_db_set_lockmode(tmpctx, nb_lock);
		}
		if (dbname)
		    krb5_xfree(dbname);
	    }
	    if (!kret)
		kret = krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    if (kret || (ibuf != KV5M_DB_CONTEXT))
		kret = EINVAL;

	    if (kret) {
		if (dbctx)
		    krb5_db_fini(tmpctx);
	    }
	    else
		tmpctx->db_context = NULL;
	    krb5_free_context(tmpctx);
	}
    }
    if (!kret) {
	*buffer = bp;
	*lenremain = remain;
	*argp = (krb5_pointer) dbctx;
    }
    return(kret);
}

/* Dispatch entry */
static const krb5_ser_entry kdb5_context_ser_entry = {
    KV5M_DB_CONTEXT,			/* Type			*/
    kdb5_context_size,			/* Sizer routine	*/
    kdb5_context_externalize,		/* Externalize routine	*/
    kdb5_context_internalize		/* Externalize routine	*/
};

/*
 * Register serializer.
 */
krb5_error_code
krb5_ser_db_context_init(kcontext)
    krb5_context	kcontext;
{
    return(krb5_register_serializer(kcontext, &kdb5_context_ser_entry));
}
