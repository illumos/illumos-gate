/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <k5-int.h>
#include <stdlib.h>
#include <limits.h>
#include <syslog.h>
#include "kdb_log.h"

/*
 * This modules includes all the necessary functions that create and
 * modify the Kerberos principal update and header logs.
 */

#define	getpagesize()	sysconf(_SC_PAGESIZE)

static int		pagesize = 0;

#define	INIT_ULOG(ctx)	log_ctx = ctx->kdblog_context; \
			ulog = log_ctx->ulog
/*
 * Sync update entry to disk.
 */
krb5_error_code
ulog_sync_update(kdb_hlog_t *ulog, kdb_ent_header_t *upd)
{
	ulong_t		start, end, size;
	krb5_error_code	retval;

	if (ulog == NULL)
		return (KRB5_LOG_ERROR);

	if (!pagesize)
		pagesize = getpagesize();

	start = ((ulong_t)upd) & (~(pagesize-1));

	end = (((ulong_t)upd) + ulog->kdb_block +
	    (pagesize-1)) & (~(pagesize-1));

	size = end - start;
	if (retval = msync((caddr_t)start, size, MS_SYNC)) {
		return (retval);
	}

	return (0);
}

/*
 * Sync memory to disk for the update log header.
 */
void
ulog_sync_header(kdb_hlog_t *ulog)
{

	if (!pagesize)
		pagesize = getpagesize();

	if (msync((caddr_t)ulog, pagesize, MS_SYNC)) {
		/*
		 * Couldn't sync to disk, let's panic
		 */
		syslog(LOG_ERR, "ulog_sync_header: could not sync to disk");
		abort();
	}
}

/*
 * Resizes the array elements.  We reinitialize the update log rather than
 * unrolling the the log and copying it over to a temporary log for obvious
 * performance reasons.  Slaves will subsequently do a full resync, but
 * the need for resizing should be very small.
 */
krb5_error_code
ulog_resize(kdb_hlog_t *ulog, uint32_t ulogentries, int ulogfd, uint_t recsize)
{
	uint_t		new_block, new_size;

	if (ulog == NULL)
		return (KRB5_LOG_ERROR);

	new_size = sizeof (kdb_hlog_t);

	new_block = (recsize / ULOG_BLOCK) + 1;
	new_block *= ULOG_BLOCK;

	new_size += ulogentries * new_block;

	if (new_size <= MAXLOGLEN) {
		/*
		 * Reinit log with new block size
		 */
		(void) memset(ulog, 0, sizeof (kdb_hlog_t));

		ulog->kdb_hmagic = KDB_HMAGIC;
		ulog->db_version_num = KDB_VERSION;
		ulog->kdb_state = KDB_STABLE;
		ulog->kdb_block = new_block;

		ulog_sync_header(ulog);

		/*
		 * Time to expand log considering new block size
		 */
		if (lseek(ulogfd, new_size, SEEK_SET) == -1) {
			return (errno);
		}

		if (write(ulogfd, "+", 1) != 1) {
			return (errno);
		}
	} else {
		/*
		 * Can't map into file larger than MAXLOGLEN
		 */
		return (KRB5_LOG_ERROR);
	}

	return (0);
}

/*
 * Adds an entry to the update log.
 * The layout of the update log looks like:
 *
 * header log -> [ update header -> xdr(kdb_incr_update_t) ], ...
 */
krb5_error_code
ulog_add_update(krb5_context context, kdb_incr_update_t *upd)
{
	XDR		xdrs;
	kdbe_time_t	ktime;
	struct timeval	timestamp;
	kdb_ent_header_t *indx_log;
	uint_t		i, recsize;
	ulong_t		upd_size;
	krb5_error_code	retval;
	kdb_sno_t	cur_sno;
	kdb_log_context	*log_ctx;
	kdb_hlog_t	*ulog = NULL;
	uint32_t	ulogentries;
	int		ulogfd;

	INIT_ULOG(context);
	ulogentries = log_ctx->ulogentries;
	ulogfd = log_ctx->ulogfd;

	if (upd == NULL)
		return (KRB5_LOG_ERROR);

	(void) gettimeofday(&timestamp, NULL);
	ktime.seconds = timestamp.tv_sec;
	ktime.useconds = timestamp.tv_usec;

	upd_size = xdr_sizeof((xdrproc_t)xdr_kdb_incr_update_t, upd);

	recsize = sizeof (kdb_ent_header_t) + upd_size;

	if (recsize > ulog->kdb_block) {
		if (retval = ulog_resize(ulog, ulogentries, ulogfd, recsize)) {
			/* Resize element array failed */
			return (retval);
		}
	}

	cur_sno = ulog->kdb_last_sno;

	/*
	 * We need to overflow our sno, replicas will do full
	 * resyncs once they see their sno > than the masters.
	 */
	if (cur_sno == ULONG_MAX)
		cur_sno = 1;
	else
		cur_sno++;

	/*
	 * We squirrel this away for finish_update() to index
	 */
	upd->kdb_entry_sno = cur_sno;

	i = (cur_sno - 1) % ulogentries;

	indx_log = (kdb_ent_header_t *)INDEX(ulog, i);

	(void) memset(indx_log, 0, ulog->kdb_block);

	indx_log->kdb_umagic = KDB_UMAGIC;
	indx_log->kdb_entry_size = upd_size;
	indx_log->kdb_entry_sno = cur_sno;
	indx_log->kdb_time = upd->kdb_time = ktime;
	indx_log->kdb_commit = upd->kdb_commit = FALSE;

	ulog->kdb_state = KDB_UNSTABLE;

	xdrmem_create(&xdrs, (char *)indx_log->entry_data,
	    indx_log->kdb_entry_size, XDR_ENCODE);
	if (!xdr_kdb_incr_update_t(&xdrs, upd))
		return (KRB5_LOG_CONV);

	if (retval = ulog_sync_update(ulog, indx_log))
		return (retval);

	if (ulog->kdb_num < ulogentries)
		ulog->kdb_num++;

	ulog->kdb_last_sno = cur_sno;
	ulog->kdb_last_time = ktime;

	/*
	 * Since this is a circular array, once we circled, kdb_first_sno is
	 * always kdb_entry_sno + 1.
	 */
	if (cur_sno > ulogentries) {
		i = upd->kdb_entry_sno % ulogentries;
		indx_log = (kdb_ent_header_t *)INDEX(ulog, i);
		ulog->kdb_first_sno = indx_log->kdb_entry_sno;
		ulog->kdb_first_time = indx_log->kdb_time;
	} else if (cur_sno == 1) {
		ulog->kdb_first_sno = 1;
		ulog->kdb_first_time = indx_log->kdb_time;
	}

	ulog_sync_header(ulog);

	return (0);
}

/*
 * Mark the log entry as committed and sync the memory mapped log
 * to file.
 */
krb5_error_code
ulog_finish_update(krb5_context context, kdb_incr_update_t *upd)
{
	krb5_error_code		retval;
	kdb_ent_header_t	*indx_log;
	uint_t			i;
	kdb_log_context		*log_ctx;
	kdb_hlog_t		*ulog = NULL;
	uint32_t		ulogentries;

	INIT_ULOG(context);
	ulogentries = log_ctx->ulogentries;

	i = (upd->kdb_entry_sno - 1) % ulogentries;

	indx_log = (kdb_ent_header_t *)INDEX(ulog, i);

	indx_log->kdb_commit = TRUE;

	ulog->kdb_state = KDB_STABLE;

	if (retval = ulog_sync_update(ulog, indx_log))
		return (retval);

	ulog_sync_header(ulog);

	return (0);
}

/*
 * Set the header log details on the slave and sync it to file.
 */
void
ulog_finish_update_slave(kdb_hlog_t *ulog, kdb_last_t lastentry)
{

	ulog->kdb_last_sno = lastentry.last_sno;
	ulog->kdb_last_time = lastentry.last_time;

	ulog_sync_header(ulog);
}

/*
 * Delete an entry to the update log.
 */
krb5_error_code
ulog_delete_update(krb5_context context, kdb_incr_update_t *upd)
{

	upd->kdb_deleted = TRUE;

	return (ulog_add_update(context, upd));
}

/*
 * Used by the slave or master (during ulog_check) to update it's hash db from
 * the incr update log.
 */
krb5_error_code
ulog_replay(krb5_context context, kdb_incr_result_t *incr_ret)
{
	krb5_db_entry		*entry = NULL;
	kdb_incr_update_t	*upd = NULL, *fupd;
	int			i, no_of_updates;
	krb5_error_code		retval;
	krb5_principal		dbprinc = NULL;
	kdb_last_t		errlast;
	char			*dbprincstr = NULL;
	kdb_log_context		*log_ctx;
	kdb_hlog_t		*ulog = NULL;
	bool_t			fini = FALSE;

	INIT_ULOG(context);

	no_of_updates = incr_ret->updates.kdb_ulog_t_len;
	upd = incr_ret->updates.kdb_ulog_t_val;
	fupd = upd;

	/*
	 * We reset last_sno and last_time to 0, if krb5_db_put_principal
	 * or krb5_db_delete_principal fail.
	 */
	errlast.last_sno = (unsigned int)0;
	errlast.last_time.seconds = (unsigned int)0;
	errlast.last_time.useconds = (unsigned int)0;

	if (krb5_db_inited(context)) {
		retval = krb5_db_open(context, NULL,
		    KRB5_KDB_OPEN_RW | KRB5_KDB_SRV_TYPE_ADMIN);
		if (retval != 0)
			goto cleanup;
		fini = TRUE;
	}

	for (i = 0; i < no_of_updates; i++) {
		int nentry = 1;

		if (!upd->kdb_commit)
			continue;

		if (upd->kdb_deleted) {
			dbprincstr = malloc((upd->kdb_princ_name.utf8str_t_len
			    + 1) * sizeof (char));

			if (dbprincstr == NULL) {
				retval = ENOMEM;
				goto cleanup;
			}

			(void) strlcpy(dbprincstr,
			    (char *)upd->kdb_princ_name.utf8str_t_val,
			    (upd->kdb_princ_name.utf8str_t_len + 1));

			if (retval = krb5_parse_name(context, dbprincstr,
			    &dbprinc)) {
				goto cleanup;
			}

			if (dbprincstr)
				free(dbprincstr);

			retval = krb5_db_delete_principal(context,
			    dbprinc, &nentry);

			if (dbprinc)
				krb5_free_principal(context, dbprinc);

			if (retval)
				goto cleanup;
		} else {
			entry = (krb5_db_entry *)malloc(sizeof (krb5_db_entry));

			if (!entry) {
				retval = errno;
				goto cleanup;
			}

			(void) memset(entry, 0, sizeof (krb5_db_entry));

			if (retval = ulog_conv_2dbentry(context, entry, upd, 1))
				goto cleanup;

			retval = krb5_db_put_principal(context, entry,
			    &nentry);

			if (entry) {
				krb5_db_free_principal(context, entry, nentry);
				free(entry);
				entry = NULL;
			}
			if (retval)
				goto cleanup;
		}

		upd++;
	}

cleanup:
	if (fupd)
		ulog_free_entries(fupd, no_of_updates);

	if (log_ctx && (log_ctx->iproprole == IPROP_SLAVE)) {
		if (retval)
			ulog_finish_update_slave(ulog, errlast);
		else
			ulog_finish_update_slave(ulog, incr_ret->lastentry);
	}

	if (fini == TRUE)
		krb5_db_fini(context);

	return (retval);
}

/*
 * Validate the log file and resync any uncommitted update entries
 * to the principal database.
 */
krb5_error_code
ulog_check(krb5_context context, kdb_hlog_t *ulog)
{
	XDR			xdrs;
	krb5_error_code		retval = 0;
	int			i;
	kdb_ent_header_t	*indx_log;
	kdb_incr_update_t	*upd = NULL;
	kdb_incr_result_t	*incr_ret = NULL;

	ulog->kdb_state = KDB_STABLE;

	for (i = 0; i < ulog->kdb_num; i++) {
		indx_log = (kdb_ent_header_t *)INDEX(ulog, i);

		if (indx_log->kdb_umagic != KDB_UMAGIC) {
			/*
			 * Update entry corrupted we should scream and die
			 */
			ulog->kdb_state = KDB_CORRUPT;
			retval = KRB5_LOG_CORRUPT;
			break;
		}

		if (indx_log->kdb_commit == FALSE) {
			ulog->kdb_state = KDB_UNSTABLE;

			incr_ret = (kdb_incr_result_t *)
			    malloc(sizeof (kdb_incr_result_t));
			if (incr_ret == NULL) {
				retval = errno;
				goto error;
			}

			upd = (kdb_incr_update_t *)
			    malloc(sizeof (kdb_incr_update_t));
			if (upd == NULL) {
				retval = errno;
				goto error;
			}

			(void) memset(upd, 0, sizeof (kdb_incr_update_t));
			xdrmem_create(&xdrs, (char *)indx_log->entry_data,
			    indx_log->kdb_entry_size, XDR_DECODE);
			if (!xdr_kdb_incr_update_t(&xdrs, upd)) {
				retval = KRB5_LOG_CONV;
				goto error;
			}

			incr_ret->updates.kdb_ulog_t_len = 1;
			incr_ret->updates.kdb_ulog_t_val = upd;

			upd->kdb_commit = TRUE;

			/*
			 * We don't want to readd this update and just use the
			 * existing update to be propagated later on
			 */
			ulog_set_role(context, IPROP_NULL);
			retval = ulog_replay(context, incr_ret);

			/*
			 * upd was freed by ulog_replay, we NULL
			 * the pointer in case we subsequently break from loop.
			 */
			upd = NULL;
			if (incr_ret) {
				free(incr_ret);
				incr_ret = NULL;
			}
			ulog_set_role(context, IPROP_MASTER);

			if (retval)
				goto error;

			/*
			 * We flag this as committed since this was
			 * the last entry before kadmind crashed, ergo
			 * the slaves have not seen this update before
			 */
			indx_log->kdb_commit = TRUE;
			retval = ulog_sync_update(ulog, indx_log);
			if (retval)
				goto error;

			ulog->kdb_state = KDB_STABLE;
		}
	}

error:
	if (upd)
		ulog_free_entries(upd, 1);

	if (incr_ret)
		free(incr_ret);

	ulog_sync_header(ulog);

	return (retval);
}

/*
 * Map the log file to memory for performance and simplicity.
 *
 * Called by: if iprop_enabled then ulog_map();
 * Assumes that the caller will terminate on ulog_map, hence munmap and
 * closing of the fd are implicitly performed by the caller.
 * Returns 0 on success else failure.
 */
krb5_error_code
ulog_map(krb5_context context, kadm5_config_params *params, int caller)
{
	struct stat	st;
	krb5_error_code	retval;
	uint32_t	ulog_filesize;
	char		logname[MAX_FILENAME];
	kdb_log_context	*log_ctx;
	kdb_hlog_t	*ulog = NULL;
	uint32_t	ulogentries;
	int		ulogfd = -1;

	if ((caller == FKADMIND) || (caller == FKCOMMAND))
		ulogentries = params->iprop_ulogsize;

	ulog_filesize = sizeof (kdb_hlog_t);

	if (strlcpy(logname, params->dbname, MAX_FILENAME) >= MAX_FILENAME)
		return (KRB5_LOG_ERROR);
	if (strlcat(logname, ".ulog", MAX_FILENAME) >= MAX_FILENAME)
		return (KRB5_LOG_ERROR);

	if (stat(logname, &st) == -1) {

		if (caller == FKPROPLOG) {
			/*
			 * File doesn't exist so we exit with kproplog
			 */
			return (errno);
		}

		if ((ulogfd = open(logname, O_RDWR+O_CREAT, 0600)) == -1) {
			return (errno);
		}

		if (lseek(ulogfd, 0L, SEEK_CUR) == -1) {
			return (errno);
		}

		if ((caller == FKADMIND) || (caller == FKCOMMAND))
			ulog_filesize += ulogentries * ULOG_BLOCK;

		if (lseek(ulogfd, ulog_filesize, SEEK_SET) == -1) {
			return (errno);
		}

		if (write(ulogfd, "+", 1) != 1) {
			return (errno);
		}

	} else {

		if ((ulogfd = open(logname, O_RDWR, 0600)) == -1) {
			/*
			 * Can't open existing log file
			 */
			return (errno);
		}
	}

	if (caller == FKPROPLOG) {
		fstat(ulogfd, &st);
		ulog_filesize = st.st_size;

		ulog = (kdb_hlog_t *)mmap(0, ulog_filesize,
		    PROT_READ+PROT_WRITE, MAP_PRIVATE, ulogfd, 0);
	} else {
		/*
		 * else kadmind, kpropd, & kcommands should udpate stores
		 */
		ulog = (kdb_hlog_t *)mmap(0, MAXLOGLEN,
		    PROT_READ+PROT_WRITE, MAP_SHARED, ulogfd, 0);
	}

	if ((int)(ulog) == -1) {
		/*
		 * Can't map update log file to memory
		 */
		return (errno);
	}

	if (!context->kdblog_context) {
		if (!(log_ctx = malloc(sizeof (kdb_log_context))))
			return (errno);
		context->kdblog_context = (void *)log_ctx;
	} else
		log_ctx = context->kdblog_context;
	log_ctx->ulog = ulog;
	log_ctx->ulogentries = ulogentries;
	log_ctx->ulogfd = ulogfd;

	if (ulog->kdb_hmagic != KDB_HMAGIC) {
		if (ulog->kdb_hmagic == 0) {
			/*
			 * New update log
			 */
			(void) memset(ulog, 0, sizeof (kdb_hlog_t));

			ulog->kdb_hmagic = KDB_HMAGIC;
			ulog->db_version_num = KDB_VERSION;
			ulog->kdb_state = KDB_STABLE;
			ulog->kdb_block = ULOG_BLOCK;
			if (!(caller == FKPROPLOG))
				ulog_sync_header(ulog);
		} else {
			return (KRB5_LOG_CORRUPT);
		}
	}

	if (caller == FKADMIND) {
		switch (ulog->kdb_state) {
			case KDB_STABLE:
			case KDB_UNSTABLE:
				/*
				 * Log is currently un/stable, check anyway
				 */
				retval = ulog_check(context, ulog);
				if (retval == KRB5_LOG_CORRUPT) {
					return (retval);
				}
				break;
			case KDB_CORRUPT:
				return (KRB5_LOG_CORRUPT);
			default:
				/*
				 * Invalid db state
				 */
				return (KRB5_LOG_ERROR);
		}
	} else if ((caller == FKPROPLOG) || (caller == FKPROPD)) {
		/*
		 * kproplog and kpropd don't need to do anything else
		 */
		return (0);
	}

	/*
	 * Reinit ulog if the log is being truncated or expanded after
	 * we have circled.
	 */
	if (ulog->kdb_num != ulogentries) {
		if ((ulog->kdb_num != 0) &&
		    ((ulog->kdb_last_sno > ulog->kdb_num) ||
		    (ulog->kdb_num > ulogentries))) {
			(void) memset(ulog, 0, sizeof (kdb_hlog_t));

			ulog->kdb_hmagic = KDB_HMAGIC;
			ulog->db_version_num = KDB_VERSION;
			ulog->kdb_state = KDB_STABLE;
			ulog->kdb_block = ULOG_BLOCK;

			ulog_sync_header(ulog);
		}

		/*
		 * Expand ulog if we have specified a greater size
		 */
		if (ulog->kdb_num < ulogentries) {
			ulog_filesize += ulogentries * ulog->kdb_block;

			if (lseek(ulogfd, ulog_filesize, SEEK_SET) == -1) {
				return (errno);
			}

			if (write(ulogfd, "+", 1) != 1) {
				return (errno);
			}
		}
	}

	return (0);
}

/*
 * Get the last set of updates seen, (last+1) to n is returned.
 */
krb5_error_code
ulog_get_entries(
	krb5_context context,		/* input - krb5 lib config */
	kdb_last_t last,		/* input - slave's last sno */
	kdb_incr_result_t *ulog_handle)	/* output - incr result for slave */
{
	XDR			xdrs;
	kdb_ent_header_t	*indx_log;
	kdb_incr_update_t	*upd;
	uint_t			indx, count, tdiff;
	uint32_t		sno;
	krb5_error_code		retval;
	struct timeval		timestamp;
	kdb_log_context		*log_ctx;
	kdb_hlog_t		*ulog = NULL;
	uint32_t		ulogentries;

	INIT_ULOG(context);
	ulogentries = log_ctx->ulogentries;

	/*
	 * Check to make sure we don't have a corrupt ulog first.
	 */
	if (ulog->kdb_state == KDB_CORRUPT) {
		ulog_handle->ret = UPDATE_ERROR;
		return (KRB5_LOG_CORRUPT);
	}

	gettimeofday(&timestamp, NULL);

	tdiff = timestamp.tv_sec - ulog->kdb_last_time.seconds;
	if (tdiff <= ULOG_IDLE_TIME) {
		ulog_handle->ret = UPDATE_BUSY;
		return (0);
	}

	/*
	 * We need to lock out other processes here, such as kadmin.local,
	 * since we are looking at the last_sno and looking up updates.  So
	 * we can share with other readers.
	 */
	retval = krb5_db_lock(context, KRB5_LOCKMODE_SHARED);
	if (retval)
		return (retval);

	/*
	 * We may have overflowed the update log or we shrunk the log, or
	 * the client's ulog has just been created.
	 */
	if ((last.last_sno > ulog->kdb_last_sno) ||
	    (last.last_sno < ulog->kdb_first_sno) ||
	    (last.last_sno == 0)) {
		ulog_handle->lastentry.last_sno = ulog->kdb_last_sno;
		(void) krb5_db_unlock(context);
		ulog_handle->ret = UPDATE_FULL_RESYNC_NEEDED;
		return (0);
	} else if (last.last_sno <= ulog->kdb_last_sno) {
		sno = last.last_sno;

		indx = (sno - 1) % ulogentries;

		indx_log = (kdb_ent_header_t *)INDEX(ulog, indx);

		/*
		 * Validate the time stamp just to make sure it was the same sno
		 */
		if ((indx_log->kdb_time.seconds == last.last_time.seconds) &&
		    (indx_log->kdb_time.useconds == last.last_time.useconds)) {

			/*
			 * If we have the same sno we return success
			 */
			if (last.last_sno == ulog->kdb_last_sno) {
				(void) krb5_db_unlock(context);
				ulog_handle->ret = UPDATE_NIL;
				return (0);
			}

			count = ulog->kdb_last_sno - sno;

			ulog_handle->updates.kdb_ulog_t_val =
			    (kdb_incr_update_t *)malloc(
			    sizeof (kdb_incr_update_t) * count);

			upd = ulog_handle->updates.kdb_ulog_t_val;

			if (upd == NULL) {
				(void) krb5_db_unlock(context);
				ulog_handle->ret = UPDATE_ERROR;
				return (errno);
			}

			while (sno < ulog->kdb_last_sno) {
				indx = sno % ulogentries;

				indx_log = (kdb_ent_header_t *)
				    INDEX(ulog, indx);

				(void) memset(upd, 0,
				    sizeof (kdb_incr_update_t));
				xdrmem_create(&xdrs,
				    (char *)indx_log->entry_data,
				    indx_log->kdb_entry_size, XDR_DECODE);
				if (!xdr_kdb_incr_update_t(&xdrs, upd)) {
					(void) krb5_db_unlock(context);
					ulog_handle->ret = UPDATE_ERROR;
					return (KRB5_LOG_CONV);
				}
				/*
				 * Mark commitment since we didn't
				 * want to decode and encode the
				 * incr update record the first time.
				 */
				upd->kdb_commit = indx_log->kdb_commit;

				upd++;
				sno++;
			} /* while */

			ulog_handle->updates.kdb_ulog_t_len = count;

			ulog_handle->lastentry.last_sno = ulog->kdb_last_sno;
			ulog_handle->lastentry.last_time.seconds =
			    ulog->kdb_last_time.seconds;
			ulog_handle->lastentry.last_time.useconds =
			    ulog->kdb_last_time.useconds;
			ulog_handle->ret = UPDATE_OK;

			(void) krb5_db_unlock(context);

			return (0);
		} else {
			/*
			 * We have time stamp mismatch or we no longer have
			 * the slave's last sno, so we brute force it
			 */
			(void) krb5_db_unlock(context);
			ulog_handle->ret = UPDATE_FULL_RESYNC_NEEDED;

			return (0);
		}
	}

	/*
	 * Should never get here, return error
	 */
	ulog_handle->ret = UPDATE_ERROR;
	return (KRB5_LOG_ERROR);
}

krb5_error_code
ulog_set_role(krb5_context ctx, iprop_role role)
{
	kdb_log_context	*log_ctx;

	if (!ctx->kdblog_context) {
		if (!(log_ctx = malloc(sizeof (kdb_log_context))))
			return (errno);
		ctx->kdblog_context = (void *)log_ctx;
	} else
		log_ctx = ctx->kdblog_context;

	log_ctx->iproprole = role;

	return (0);
}
