#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/kdb/kdb_dbm.c
 *
 * Copyright 1988,1989,1990,1991 by the Massachusetts Institute of Technology. 
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

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

/* Obtain dispatch table definitions from kdb.h */
#define	KDB5_DISPATCH
#define KRB5_KDB5_DBM__
#include "k5-int.h"
#include "krb5/kdb_dbc.h"
#include <stdio.h>
#include <errno.h>
#include <utime.h>

#define OLD_COMPAT_VERSION_1

#ifdef OLD_COMPAT_VERSION_1
#include "kdb_compat.h"
#endif

#define KRB5_DBM_MAX_RETRY 5

#ifdef DEBUG
extern int debug;
extern long krb5_dbm_db_debug;
extern char *progname;
#endif

static char default_db_name[] = DEFAULT_KDB_FILE;

static char *gen_dbsuffix 
	PROTOTYPE((char *, char * ));
static krb5_error_code krb5_dbm_db_start_update 
	PROTOTYPE((krb5_context));
static krb5_error_code krb5_dbm_db_end_update 
	PROTOTYPE((krb5_context));

krb5_error_code
krb5_dbm_db_get_age(krb5_context, char *, time_t *);

krb5_error_code
krb5_dbm_db_unlock(krb5_context);

/*
 * This module contains all of the code which directly interfaces to
 * the underlying representation of the Kerberos database; this
 * implementation uses the Berkeley hash db to store the relations, plus a
 * second file as a semaphore to allow the database to be replaced out
 * from underneath the KDC server.
 */
static kdb5_dispatch_table kdb5_default_dispatch = {
    "Berkeley Hashed Database w/ DBM interface",
    ".db",			/* Index file name ext	*/
    (char *) NULL,		/* Data file name ext	*/
    ".ok",			/* Lock file name ext	*/
    dbm_open,			/* Open Database	*/
    dbm_close,			/* Close Database	*/
    dbm_fetch,			/* Fetch Key		*/
    dbm_firstkey,		/* Fetch First Key	*/
    dbm_nextkey,		/* Fetch Next Key	*/
    dbm_delete,			/* Delete Key		*/
    dbm_store,			/* Store Key		*/
    /*
     * The following are #ifdef'd because they have the potential to be
     * macros rather than functions.
     */
    (int (*)()) NULL,		/* Get DB index FD num	*/
    (int (*)()) NULL,		/* Get DB data FD num	*/
};

/*
 * These macros dispatch via the dispatch table.
 */
#define	KDBM_OPEN(dbc, db, fl, mo)	((*(((krb5_db_context *)dbc)->	\
					    db_dispatch->kdb5_dbm_open)) \
					 (db, fl, mo))
#define	KDBM_CLOSE(dbc, db)		((*(((krb5_db_context *)dbc)->	\
					    db_dispatch->kdb5_dbm_close))(db))
#define	KDBM_FETCH(dbc, db, key)	((*(((krb5_db_context *)dbc)->	\
					    db_dispatch->kdb5_dbm_fetch)) \
					 (db, key))
#define	KDBM_FIRSTKEY(dbc, db)		((*(((krb5_db_context *)dbc)->	\
					    db_dispatch->kdb5_dbm_firstkey)) \
					 (db))
#define	KDBM_NEXTKEY(dbc, db)		((*(((krb5_db_context *)dbc)->	\
					    db_dispatch->kdb5_dbm_nextkey)) \
					 (db))
#define	KDBM_DELETE(dbc, db, key)	((*(((krb5_db_context *)dbc)->	\
					    db_dispatch->kdb5_dbm_delete)) \
					 (db, key))
#define	KDBM_STORE(dbc, db, key, c, f)	((*(((krb5_db_context *)dbc)->	\
					    db_dispatch->kdb5_dbm_store)) \
					 (db, key, c, f))
#define	KDBM_INDEX_EXT(dbc)		(((krb5_db_context *)dbc)->	 \
					  db_dispatch->kdb5_db_index_ext)
#define	KDBM_DATA_EXT(dbc)		(((krb5_db_context *)dbc)->	 \
					  db_dispatch->kdb5_db_data_ext)
#define	KDBM_LOCK_EXT(dbc)		(((krb5_db_context *)dbc)->	 \
					  db_dispatch->kdb5_db_lock_ext)

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
#define	k5dbm_inited(c)	(c && c->db_context &&	\
			 ((krb5_db_context *) c->db_context)->db_inited)

/*
 * Restore the default context.
 */
static void
k5dbm_clear_context(dbctx)
    krb5_db_context *	dbctx;
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
    memset((char *) dbctx, 0, sizeof(krb5_db_context));
    dbctx->db_name = default_db_name;
    dbctx->db_nb_locks = FALSE;
    dbctx->db_dispatch = &kdb5_default_dispatch;
}

static krb5_error_code
k5dbm_init_context(context)
    krb5_context	context;
{
    krb5_db_context *	db_ctx;

    if (context->db_context == NULL) {
	if ((db_ctx = (krb5_db_context *) malloc(sizeof(krb5_db_context)))) {
	    memset((char *) db_ctx, 0, sizeof(krb5_db_context));
	    k5dbm_clear_context((krb5_db_context *)db_ctx);
	    context->db_context = (void *) db_ctx;
	} else 
	    return(ENOMEM);
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

/*
 * initialization for data base routines.
 */

krb5_error_code
krb5_dbm_db_init(context)
    krb5_context 	  context;
{
    char 		* filename = NULL;
    krb5_db_context	* db_ctx;
    krb5_error_code	  retval;

    if (k5dbm_inited(context))
	return 0;

    /* Check for presence of our context, if not present, allocate one. */
    if ((retval = k5dbm_init_context(context)))
	return(retval);

    db_ctx = context->db_context;
    db_ctx->db_dbm_ctx = NULL;

    if (!(filename = gen_dbsuffix (db_ctx->db_name, KDBM_LOCK_EXT(db_ctx))))
	return ENOMEM;

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
    db_ctx->db_lf_name = filename;
    db_ctx->db_inited++;

    if ((retval = krb5_dbm_db_get_age(context, NULL, &db_ctx->db_lf_time))) 
	goto err_out;

    return 0;
    
err_out:
    db_ctx->db_dbm_ctx = (DBM *) NULL;
    k5dbm_clear_context(db_ctx);
    return (retval);
}

/*
 * gracefully shut down database--must be called by ANY program that does
 * a krb5_dbm_db_init 
 */
krb5_error_code
krb5_dbm_db_fini(context)
    krb5_context context;
{
    krb5_error_code retval = 0;
    krb5_db_context	*db_ctx;

    db_ctx = (krb5_db_context *) context->db_context;

    if (k5dbm_inited(context)) {
	if (close(db_ctx->db_lf_file))
	    retval = errno;
	else
	    retval = 0;
    }
    if (db_ctx) {
	k5dbm_clear_context(db_ctx);
	free (context->db_context);
	context->db_context = NULL;
    }
    return retval;
}

krb5_error_code
krb5_dbm_db_open_database(context)
    krb5_context context;
{
    if (!k5dbm_inited(context))
    	return KRB5_KDB_DBNOTINITED;
    return 0;
}

krb5_error_code
krb5_dbm_db_close_database(context)
    krb5_context context;
{
    if (!k5dbm_inited(context))
    	return KRB5_KDB_DBNOTINITED;
    return 0;
}

/*
 * Set/Get the master key associated with the database
 *
 * These only exist because the db_context is part of the kcontext
 * The should really reference the db_context
 */
krb5_error_code
krb5_dbm_db_set_mkey(context, db_context, key)
    krb5_context 	  context;
    krb5_db_context 	* db_context;
    krb5_keyblock  * key;
{
    krb5_db_context *db_ctx;

    if (!k5dbm_inited(context))
	return(KRB5_KDB_DBNOTINITED);

    db_ctx = context->db_context;
    db_ctx->db_master_key = key;
    return 0;
}

krb5_error_code
krb5_dbm_db_get_mkey(context, eblock)

    krb5_context 	  context;
    krb5_encrypt_block  **eblock;
{
    krb5_db_context *db_ctx;

    if (!k5dbm_inited(context))
	return(KRB5_KDB_DBNOTINITED);

    db_ctx = context->db_context;
    *eblock = db_ctx->db_master_key;
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
krb5_dbm_db_set_name(context, name)
    krb5_context context;
    char *name;
{
    DBM *db;
    krb5_db_context *db_ctx;
    krb5_error_code kret;

    if (k5dbm_inited(context))
	return KRB5_KDB_DBINITED;

    /* Check for presence of our context, if not present, allocate one. */
    if ((kret = k5dbm_init_context(context)))
	return(kret);

    if (name == NULL)
	name = default_db_name;

    db_ctx = context->db_context;
    if ((db = KDBM_OPEN(db_ctx, name, O_RDONLY, 0)) == NULL)
	return errno;

    db_ctx->db_name = strdup(name);
    KDBM_CLOSE(db_ctx, db);
    return 0;
}

/*
 * Return the last modification time of the database.
 *
 * Think about using fstat.
 */

krb5_error_code
krb5_dbm_db_get_age(context, db_name, age)
    krb5_context context;
    char *db_name;
    time_t *age;
{
    krb5_db_context *db_ctx;
    struct stat st;
    
    if (!k5dbm_inited(context))
	return(KRB5_KDB_DBNOTINITED);
    db_ctx = (krb5_db_context *) context->db_context;
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
krb5_dbm_db_start_update(context)
    krb5_context context;
{
    return 0;
}

static krb5_error_code
krb5_dbm_db_end_update(context)
    krb5_context context;
{
    krb5_error_code retval;
    krb5_db_context *db_ctx = context->db_context;
    struct stat st;
    time_t now;
    struct utimbuf utbuf;

    if (!k5dbm_inited(context))
	return(KRB5_KDB_DBNOTINITED);

    retval = 0;
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
krb5_dbm_db_lock(context, mode)
    krb5_context 	  context;
    int 	 	  mode;
{
    int 		  krb5_lock_mode;
    krb5_error_code	  retval;
    time_t		  mod_time;
    krb5_db_context	* db_ctx;
    DBM    		* db;

    if (!k5dbm_inited(context))
	return KRB5_KDB_DBNOTINITED;

    db_ctx = (krb5_db_context *) context->db_context;
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

    switch (retval = krb5_lock_file(context,db_ctx->db_lf_file,krb5_lock_mode)){
    case EBADF:
	if (mode == KRB5_LOCKMODE_EXCLUSIVE)
	    return KRB5_KDB_CANTLOCK_DB;
    default:
	return retval;
    case 0:
	break;
    }

    if ((retval = krb5_dbm_db_get_age(context, NULL, &mod_time)))
	goto lock_error;

    if ((db = KDBM_OPEN(db_ctx, db_ctx->db_name,
			mode == KRB5_LOCKMODE_SHARED ? O_RDONLY : O_RDWR,
			0600))) {
	 db_ctx->db_lf_time = mod_time;
	 db_ctx->db_dbm_ctx = db;
    } else {
	 retval = errno;
	 goto lock_error;
    }

    db_ctx->db_lock_mode = mode;
    db_ctx->db_locks_held++;
    return 0;

lock_error:;
    db_ctx->db_lock_mode = 0;
    db_ctx->db_locks_held = 0;
    (void) krb5_dbm_db_unlock(context);
    return retval;
}

krb5_error_code
krb5_dbm_db_unlock(context)
    krb5_context context;
{
    krb5_db_context	* db_ctx;
    krb5_error_code	  retval;

    if (!k5dbm_inited(context))
	return KRB5_KDB_DBNOTINITED;

    db_ctx = (krb5_db_context *) context->db_context;
    if (!db_ctx->db_locks_held)		/* lock already unlocked */
	return KRB5_KDB_NOTLOCKED;

    if (--(db_ctx->db_locks_held) == 0) {
    KDBM_CLOSE(db_ctx, db_ctx->db_dbm_ctx);
	db_ctx->db_dbm_ctx = NULL;

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
krb5_dbm_db_create(context, db_name)
    krb5_context context;
    char *db_name;
{
    char *okname;
    int fd;
    register krb5_error_code retval = 0;
    DBM *db;

    if ((retval = k5dbm_init_context(context)))
	return(retval);
    
    db = KDBM_OPEN(context->db_context, db_name, O_RDWR|O_CREAT|O_EXCL, 0600);
    if (db == NULL)
	retval = errno;
    else
	KDBM_CLOSE(context->db_context, db);
    if (retval == 0) {
	okname = gen_dbsuffix(db_name, KDBM_LOCK_EXT(context->db_context));
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
krb5_error_code
destroy_file_suffix(dbname, suffix)
	char	*dbname;
	char	*suffix;
{
	char	*filename;
	struct stat	statb;
	int		nb,fd,i,j;
	char		buf[BUFSIZ];
	char		zbuf[BUFSIZ];
	int		dowrite;

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
	i = 0;
	while (i < statb.st_size) {
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
		if (dowrite) {
			lseek(fd, i, SEEK_SET);
			nb = write(fd, zbuf, nb);
			if (nb < 0) {
				int retval = errno;
				free(filename);
				return retval;
			}
		}
		i += nb;
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
 */
krb5_error_code
krb5_dbm_db_destroy(context, dbname)
    krb5_context context;
	char	*dbname;
{
	krb5_error_code	retval1, retval2, retval3;
	krb5_boolean tmpcontext;

	tmpcontext = 0;
	if (!context->db_context) {
	    tmpcontext = 1;
	    if ((retval1 = k5dbm_init_context(context)))
		return(retval1);
	}
	retval1 = retval2 = retval3 = 0;
	if (KDBM_DATA_EXT(context->db_context))
	     retval1 = destroy_file_suffix(dbname, 
					   KDBM_DATA_EXT(context->db_context));
	if (KDBM_INDEX_EXT(context->db_context))
	     retval2 = destroy_file_suffix(dbname, 
					  KDBM_INDEX_EXT(context->db_context));
	retval3 = destroy_file_suffix(dbname,
				      KDBM_LOCK_EXT(context->db_context));
	/*
	 * This kludgery is needed because it is possible to link
	 * against BSD DB but use the ndbm interface.  The result is
	 * that the dispatch table thinks the file extensions are
	 * .dir and .pag, but the database layer uses .db.
	 */
	if (retval1 == ENOENT && retval2 == ENOENT &&
	    KDBM_INDEX_EXT(context->db_context) &&
	    strcmp(KDBM_INDEX_EXT(context->db_context), ".dir") == 0 &&
	    KDBM_DATA_EXT(context->db_context) &&
	    strcmp(KDBM_DATA_EXT(context->db_context), ".pag") == 0) {
	     retval1 = retval2 = destroy_file_suffix(dbname, ".db");
	}
	if (retval1 || retval2 || retval3)
	     return (retval1 ? retval1 : (retval2 ? retval2 : retval3));

	if (tmpcontext) {
	    k5dbm_clear_context((krb5_db_context *) context->db_context);
	    free(context->db_context);
	    context->db_context = (void *) NULL;
	}
	return(0);
}

/*
 * "Atomically" rename the database in a way that locks out read
 * access in the middle of the rename.
 *
 * Not perfect; if we crash in the middle of an update, we don't
 * necessarily know to complete the transaction the rename, but...
 */
/*
 * Since the rename operation happens outside the init/fini bracket, we
 * have to go through the same stuff that we went through up in db_destroy.
 */
krb5_error_code
krb5_dbm_db_rename(context, from, to)
    krb5_context context;
    char *from;
    char *to;
{
    DBM *db;
    char *fromdir = 0;
    char *todir = 0;
    char *frompag = 0;
    char *topag = 0;
    char *fromok = 0;
    char *took = 0;
    krb5_error_code retval;
    krb5_db_context *s_context, *db_ctx;

    s_context = context->db_context;
    context->db_context = (void *) NULL;
    if (!(retval = k5dbm_init_context(context))) {
	db_ctx = (krb5_db_context *) context->db_context;

	/*
	 * Create the database if it does not already exist; the
	 * files must exist because krb5_dbm_db_lock, called below,
	 * will fail otherwise.
	 */
	db = KDBM_OPEN(db_ctx, to, O_RDWR|O_CREAT, 0600); 
	if (db == NULL) {
	     retval = errno;
	     goto errout;
	}
	else
	     KDBM_CLOSE(db_ctx, db);
	
	/*
	 * Set the database to the target, so that other processes sharing
	 * the target will stop their activity, and notice the new database.
	 */
	retval = krb5_dbm_db_set_name(context, to);
	if (retval)
		goto errout;
	
	db_ctx->db_lf_name = gen_dbsuffix(db_ctx->db_name,
					  KDBM_LOCK_EXT(db_ctx));
	if (db_ctx->db_lf_name == (char *)NULL) {
	    retval = ENOMEM;
	    goto errout;
	}

	db_ctx->db_lf_file = open(db_ctx->db_lf_name, O_RDWR|O_CREAT, 0600);
	if (db_ctx->db_lf_file < 0) {
	    retval = errno;
	    goto errout;
	}

	db_ctx->db_inited = 1;

	retval = krb5_dbm_db_get_age(context, NULL, &db_ctx->db_lf_time);
	if (retval)
	    goto errout;
    }
    else
	return(retval);

    if (KDBM_INDEX_EXT(context->db_context)) {
	fromdir = gen_dbsuffix (from, KDBM_INDEX_EXT(context->db_context));
	todir = gen_dbsuffix (to, KDBM_INDEX_EXT(context->db_context));
	if (!fromdir || !todir) {
	    retval = ENOMEM;
	    goto errout;
	}
    }

    if (KDBM_DATA_EXT(context->db_context)) {
	frompag = gen_dbsuffix (from, KDBM_DATA_EXT(context->db_context));
	topag = gen_dbsuffix (to, KDBM_DATA_EXT(context->db_context));
	if (!frompag || !topag) {
	    retval = ENOMEM;
	    goto errout;
	}
    }

    if (KDBM_LOCK_EXT(context->db_context)) {
	fromok = gen_dbsuffix (from, KDBM_LOCK_EXT(context->db_context));
	took = gen_dbsuffix (to, KDBM_LOCK_EXT(context->db_context));
	if (!fromok || !took) {
	    retval = ENOMEM;
	    goto errout;
	}
    }

    if ((retval = krb5_dbm_db_lock(context, KRB5_LOCKMODE_EXCLUSIVE)))
	goto errout;

    if ((retval = krb5_dbm_db_start_update(context)))
	goto errout;
    
    if (((!fromdir && !todir) ||
	 (fromdir && todir && (rename (fromdir, todir) == 0))) &&
	((!frompag && !topag) ||
	 (frompag && topag && (rename (frompag, topag) == 0)))) {
	    /* We only need to unlink the source lock file */
	    if (fromok)
		(void) unlink(fromok);
	    retval = krb5_dbm_db_end_update(context);
    } else {
	 /*
	  * This kludgery is needed because it is possible to link
	  * against BSD DB but use the ndbm interface.  The result is
	  * that the dispatch table thinks the file extensions are
	  * .dir and .pag, but the database layer uses .db.
	  */
	 if (errno == ENOENT &&
	     KDBM_INDEX_EXT(context->db_context) &&
	     strcmp(KDBM_INDEX_EXT(context->db_context), ".dir") == 0 &&
	     KDBM_DATA_EXT(context->db_context) &&
	     strcmp(KDBM_DATA_EXT(context->db_context), ".pag") == 0) {
	      free(fromdir); free(todir); free(frompag); free(topag);

	      fromdir = todir = NULL;
	      frompag = gen_dbsuffix (from, ".db");
	      topag = gen_dbsuffix (to, ".db");
	      if (!frompag || !topag) {
		   retval = ENOMEM;
		   goto errout;
	      }
	      if (rename(frompag, topag) == 0) {
		   /* We only need to unlink the source lock file */
		   if (fromok)
			(void) unlink(fromok);
		   retval = krb5_dbm_db_end_update(context);
	      } else {
		   retval = errno;
		   (void) krb5_dbm_db_end_update(context);
	      }
	 } else {
	      retval = errno;
	      (void) krb5_dbm_db_end_update(context);
	 }
    }
    
    
errout:
    if (fromok)
	free_dbsuffix (fromok);
    if (took)
	free_dbsuffix (took);
    if (topag)
	free_dbsuffix (topag);
    if (frompag)
	free_dbsuffix (frompag);
    if (todir)
	free_dbsuffix (todir);
    if (fromdir)
	free_dbsuffix (fromdir);

    if (context->db_context) {
	if (db_ctx->db_lf_file >= 0) {
	    krb5_dbm_db_unlock(context);
	    close(db_ctx->db_lf_file);
	}
	k5dbm_clear_context((krb5_db_context *) context->db_context);
	free (context->db_context);
    }

    context->db_context = s_context;
    (void) krb5_dbm_db_unlock(context);		/* unlock saved context db */

    return retval;
}

/*
 * look up a principal in the data base.
 * returns number of entries found, and whether there were
 * more than requested. 
 */

krb5_error_code
krb5_dbm_db_get_principal(context, searchfor, entries, nentries, more)
    krb5_context context;
krb5_const_principal searchfor;
krb5_db_entry *entries;		/* filled in */
int *nentries;				/* how much room/how many found */
krb5_boolean *more;			/* are there more? */
{
    krb5_error_code retval;
    datum   key, contents;
    krb5_db_context *db_ctx;
    int try;

    *more = FALSE;
    *nentries = 0;

    if (!k5dbm_inited(context))
	return KRB5_KDB_DBNOTINITED;

    db_ctx = (krb5_db_context *) context->db_context;
    for (try = 0; try < KRB5_DBM_MAX_RETRY; try++) {
	if ((retval = krb5_dbm_db_lock(context, KRB5_LOCKMODE_SHARED))) {
	    if (db_ctx->db_nb_locks) 
	    	return(retval);
	    sleep(1);
	    continue;
	}
	break;
    }
    if (try == KRB5_DBM_MAX_RETRY) 
	return KRB5_KDB_DB_INUSE;

    /* XXX deal with wildcard lookups */
    if ((retval = krb5_encode_princ_dbmkey(context, &key, searchfor)))
        goto cleanup;

    contents = KDBM_FETCH(db_ctx, db_ctx->db_dbm_ctx, key);
    krb5_free_princ_dbmkey(context, &key);

    if (contents.dptr) 
    	if (!(retval = krb5_decode_princ_contents(context, &contents,entries)))
	    *nentries = 1;

cleanup:
    (void) krb5_dbm_db_unlock(context);		/* unlock read lock */
    return retval;
}

/*
  Free stuff returned by krb5_dbm_db_get_principal.
 */
void
krb5_dbm_db_free_principal(context, entries, nentries)
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
krb5_dbm_db_put_principal(context, entries, nentries)
    krb5_context context;
    krb5_db_entry *entries;
    register int *nentries;		/* number of entry structs to update */
{
    int i, n;
    datum   key, contents;
    krb5_error_code retval;
    krb5_db_context *db_ctx;

    n = *nentries;
    *nentries = 0;
    if (!k5dbm_inited(context))
	return KRB5_KDB_DBNOTINITED;

    db_ctx = (krb5_db_context *) context->db_context;
    if ((retval = krb5_dbm_db_lock(context, KRB5_LOCKMODE_EXCLUSIVE)))
	return retval;

    if ((retval = krb5_dbm_db_start_update(context))) {
        (void)krb5_dbm_db_unlock(context);		
	return retval;
    }

    /* for each one, stuff temps, and do replace/append */
    for (i = 0; i < n; i++) {
	if ((retval = krb5_encode_princ_contents(context, &contents,
						 entries)))
	    break;

	if ((retval = krb5_encode_princ_dbmkey(context, &key,
					       entries->princ))) {
	    krb5_free_princ_contents(context, &contents);
	    break;
	}
	if (KDBM_STORE(db_ctx, db_ctx->db_dbm_ctx, key, contents, DBM_REPLACE))
	    retval = errno?errno:KRB5_KDB_DB_CORRUPT;

	krb5_free_princ_contents(context, &contents);
	krb5_free_princ_dbmkey(context, &key);
	if (retval)
	    break;
	entries++;			/* bump to next struct */
    }

    (void)krb5_dbm_db_end_update(context);
    (void)krb5_dbm_db_unlock(context);		/* unlock database */
    *nentries = i;
    return(retval);
}

/*
 * delete a principal from the data base.
 * returns number of entries removed
 */

krb5_error_code
krb5_dbm_db_delete_principal(context, searchfor, nentries)
    krb5_context 	  context;
    krb5_const_principal  searchfor;
    int 		* nentries;	/* how many found & deleted */
{
    krb5_error_code 	  retval;
    krb5_db_entry 	  entry;
    krb5_db_context 	* db_ctx;
    datum   		  key, contents, contents2;
    DBM    		* db;
    int			  i;

    if (!k5dbm_inited(context))
	return KRB5_KDB_DBNOTINITED;

    db_ctx = (krb5_db_context *) context->db_context;
    if ((retval = krb5_dbm_db_lock(context, KRB5_LOCKMODE_EXCLUSIVE)))
	return(retval);

    if ((retval = krb5_dbm_db_start_update(context))) {
        (void) krb5_dbm_db_unlock(context);	/* unlock write lock */
	return(retval);
    }

    if ((retval = krb5_encode_princ_dbmkey(context, &key, searchfor)))
	goto cleanup;

    db = db_ctx->db_dbm_ctx;
    contents = KDBM_FETCH(db_ctx, db, key);
    if (contents.dptr == NULL) {
	retval = KRB5_KDB_NOENTRY;
	*nentries = 0;
    } else {
	memset((char *)&entry, 0, sizeof(entry));
	if ((retval = krb5_decode_princ_contents(context, &contents,
						 &entry)))
	    goto cleankey;
	*nentries = 1;
	/* Clear encrypted key contents */
	for (i = 0; i < entry.n_key_data; i++) {
	    if (entry.key_data[i].key_data_length[0]) {
		memset((char *)entry.key_data[i].key_data_contents[0], 0, 
		       entry.key_data[i].key_data_length[0]); 
	    }
	}
	if ((retval = krb5_encode_princ_contents(context, &contents2,
						 &entry)))
	    goto cleancontents;

	if (KDBM_STORE(db_ctx, db, key, contents2, DBM_REPLACE))
	    retval = errno?errno:KRB5_KDB_DB_CORRUPT;
	else {
	    if (KDBM_DELETE(db_ctx, db, key))
		retval = errno?errno:KRB5_KDB_DB_CORRUPT;
	}
	krb5_free_princ_contents(context, &contents2);
    cleancontents:
	krb5_dbe_free_contents(context, &entry);
    cleankey:
	krb5_free_princ_dbmkey(context, &key);
    }

cleanup:
    (void)krb5_dbm_db_end_update(context);
    (void) krb5_dbm_db_unlock(context);	/* unlock write lock */
    return retval;
}

krb5_error_code
krb5_dbm_db_iterate (context, func, func_arg)
    krb5_context context;
    krb5_error_code (*func) PROTOTYPE((krb5_pointer, krb5_db_entry *));
    krb5_pointer func_arg;
{
    datum key, contents;
    krb5_db_entry entries;
    krb5_error_code retval;
    DBM *db;
    krb5_db_context *db_ctx;
    
    if (!k5dbm_inited(context))
	return KRB5_KDB_DBNOTINITED;

    db_ctx = (krb5_db_context *) context->db_context;
    if ((retval = krb5_dbm_db_lock(context, KRB5_LOCKMODE_SHARED)))
	return retval;

    db = db_ctx->db_dbm_ctx;
    for (key = KDBM_FIRSTKEY (db_ctx, db);
	 key.dptr != NULL; key = KDBM_NEXTKEY(db_ctx, db)) {
	contents = KDBM_FETCH (db_ctx, db, key);
	if ((retval = krb5_decode_princ_contents(context, &contents,
						 &entries)))
	    break;
	retval = (*func)(func_arg, &entries);
	krb5_dbe_free_contents(context, &entries);
	if (retval)
	    break;
    }
    (void) krb5_dbm_db_unlock(context);
    return retval;
}

krb5_boolean
krb5_dbm_db_set_lockmode(context, mode)
    krb5_context context;
    krb5_boolean mode;
{
    krb5_boolean old;
    krb5_db_context *db_ctx;

    old = mode;
    if ((db_ctx = (krb5_db_context *) context->db_context)) {
	old = db_ctx->db_nb_locks;
	db_ctx->db_nb_locks = mode;
    }
    return old;
}

/*
 * Set dispatch table.
 */
krb5_error_code
kdb5_db_set_dbops(context, new)
    krb5_context	context;
    kdb5_dispatch_table	*new;
{
    krb5_error_code	kret;
    krb5_db_context	*db_ctx;

    kret = KRB5_KDB_DBINITED;
    if (!k5dbm_inited(context)) {
	if (!(kret = k5dbm_init_context(context))) {
	    db_ctx = (krb5_db_context *) context->db_context;
	    db_ctx->db_dispatch = (new) ? new : &kdb5_default_dispatch;
	}
    }
    return(kret);
}

/*
 * Context serialization operations.
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
    krb5_db_context	*dbctx;

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
    if ((dbctx = (krb5_db_context *) arg)) {
	required = (sizeof(krb5_int32) * 7);
	if (dbctx->db_inited && dbctx->db_dispatch && dbctx->db_name)
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
    krb5_db_context	*dbctx;
    size_t		required;
    krb5_octet		*bp;
    size_t		remain;

    required = 0;
    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    if ((dbctx = (krb5_db_context *) arg)) {
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
    krb5_db_context	*dbctx;
    krb5_int32		ibuf;
    krb5_octet		*bp;
    size_t		remain;
    krb5_int32		iflag;
    krb5_int32		nb_lockmode;
    krb5_int32		lockcount;
    krb5_int32		lockmode;
    krb5_int32		dbnamelen;
    char		*dbname;

    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    dbctx = (krb5_db_context *) NULL;
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
		    dbctx = (krb5_db_context *) tmpctx->db_context;
		    (void) krb5_dbm_db_set_lockmode(tmpctx, 0);
		    if (lockmode)
			kret = krb5_db_lock(tmpctx, lockmode);
		    if (!kret && lockmode)
			dbctx->db_locks_held = lockcount;
		    (void) krb5_dbm_db_set_lockmode(tmpctx, nb_lockmode);
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
		    krb5_dbm_db_fini(tmpctx);
	    }
	    else
		tmpctx->db_context = (void *) NULL;
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


/*
 *
 *	krb5_db_ vectors
 *
 */

krb5_error_code
krb5_db_init(context)
    krb5_context 	  context;
{
    return (krb5_dbm_db_init(context));
}

krb5_error_code
krb5_db_fini(context)
    krb5_context context;
{
    return (krb5_dbm_db_fini(context));
}

krb5_error_code
krb5_db_open_database(context)
    krb5_context context;
{
    return (krb5_dbm_db_open_database(context));
}

krb5_error_code
krb5_db_close_database(context)
    krb5_context context;
{
    return (krb5_dbm_db_close_database(context));
}

krb5_error_code
krb5_db_get_mkey(context, eblock)
    krb5_context 	  context;
    krb5_encrypt_block  **eblock;
{
    return (krb5_dbm_db_get_mkey(context, eblock));
}

krb5_error_code
krb5_db_set_name(context, name)
    krb5_context context;
    char *name;
{
    return (krb5_dbm_db_set_name(context, name));
}

krb5_error_code
krb5_db_get_age(context, db_name, age)
    krb5_context context;
    char *db_name;
    time_t *age;
{
    return (krb5_dbm_db_get_age(context, db_name, age));
}

krb5_error_code
krb5_db_lock(context, mode)
    krb5_context 	  context;
    int 	 	  mode;
{
    return (krb5_dbm_db_lock(context, mode));
}

krb5_error_code
krb5_db_unlock(context)
    krb5_context context;
{
    return (krb5_dbm_db_unlock(context));
}

krb5_error_code
krb5_db_create(context, db_name)
    krb5_context context;
    char *db_name;
{
    return (krb5_dbm_db_create(context, db_name));
}

krb5_error_code
krb5_db_destroy(context, dbname)
    krb5_context context;
	char	*dbname;
{
    return (krb5_dbm_db_destroy(context, dbname));
}

krb5_error_code
krb5_db_rename(context, from, to)
    krb5_context context;
    char *from;
    char *to;
{
    return (krb5_dbm_db_rename(context, from, to));
}

void
krb5_db_free_principal(context, entries, nentries)
    krb5_context context;
    krb5_db_entry *entries;
    int nentries;
{
     krb5_dbm_db_free_principal(context, entries, nentries);
}

krb5_error_code
krb5_db_get_principal(context, searchfor, entries, nentries, more)
    krb5_context context;
krb5_principal searchfor;
krb5_db_entry *entries;		/* filled in */
int *nentries;				/* how much room/how many found */
krb5_boolean *more;			/* are there more? */
{
    return (krb5_dbm_db_get_principal(context, searchfor, entries,
	nentries, more));
}

krb5_error_code
krb5_db_put_principal(context, entries, nentries)
    krb5_context context;
    krb5_db_entry *entries;
    register int *nentries;		/* number of entry structs to update */
{
    return (krb5_dbm_db_put_principal(context, entries, nentries));
}

krb5_error_code
krb5_db_delete_principal(context, searchfor, nentries)
    krb5_context 	  context;
    krb5_principal 	  searchfor;
    int 		* nentries;	/* how many found & deleted */
{
    return (krb5_dbm_db_delete_principal(context, searchfor, nentries));
}

krb5_error_code
krb5_db_iterate (context, func, func_arg)
    krb5_context context;
    krb5_error_code (*func) PROTOTYPE((krb5_pointer, krb5_db_entry *));
    krb5_pointer func_arg;
{
    return (krb5_dbm_db_iterate (context, func, func_arg));
}

krb5_boolean
krb5_db_set_lockmode(context, mode)
    krb5_context context;
    krb5_boolean mode;
{
    return (krb5_dbm_db_set_lockmode(context, mode));
}


