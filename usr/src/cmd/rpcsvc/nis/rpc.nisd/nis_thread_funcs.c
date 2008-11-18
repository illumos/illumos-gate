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


#include <syslog.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <dirent.h>
#include <string.h>
#include <rpcsvc/nis.h>
#include "nis_proc.h"
#include "nis_svc.h"

uint_t	next_refresh;		/* next time to re-load dot file */

/* Track last time we started processing a request */
static struct timeval	last_activity = {0, 0};

/* Max interval between checking number of open fd:s */
#define	FD_CHECK_DEF	(5 * 60)	/* Five minutes */

/*
 * Purge since now minus delta depending on number of open fd:s, in seconds.
 *
 * The array values were chosen to do the following:
 *
 *    Behave like the old code (7200 seconds purge delta) for a very small
 *    number of open fd:s
 *
 *    Give reasonably smooth purge behavior for realistic fd growth rates,
 *    as observed at customer site.
 *
 *    Become aggressive about purging at high numbers of open fd:s, to
 *    reduce the risk of running out of fd:s.
 */
static int	purge_deltas[] = {
			7200, 6900, 6600, 6300, 6000, 5400, 4800, 4200,
			3600, 3000, 1800, 1200,  600, 300,  75, 60
};


/* ARGSUSED1 */
static int
do_count(void *countp, int fd) {
	(*(int *)countp)++;
	return (0);
}

static long
fd_open_count(void) {
	int count = 0;

	(void) fdwalk(do_count, &count);
	return (count);
}

/* servloop_sleep and servloop_wake are protected by the same mutex */
static pthread_cond_t	servloop_sleep = PTHREAD_COND_INITIALIZER;
static time_t		servloop_wake = 0;
static DECLMUTEXLOCK(servloop_sleep);

int
msleep(ulong_t sleeptime) {
	struct timespec	ts;
	struct timeval	tv;
	int		ret;

	(void) gettimeofday(&tv, 0);
	ts.tv_sec = tv.tv_sec + sleeptime/1000;
	ts.tv_nsec = 1000*(tv.tv_usec+1000*(sleeptime%1000));
	if (ts.tv_nsec >= 1000000000) {
		ts.tv_nsec -= 1000000000;
		ts.tv_sec += 1;
	}

	MUTEXLOCK(servloop_sleep, "servloop:msleep lock");
	if (servloop_wake != 0) {
		/* If we're past the servloop_wake time, reset and return */
		if (servloop_wake <= tv.tv_sec) {
			servloop_wake = 0;
			MUTEXUNLOCK(servloop_sleep, "servloop:msleep unlock");
			return (0);
		}
		/* servloop_wake may limit our sleep */
		if (servloop_wake <= ts.tv_sec) {
			ts.tv_sec = servloop_wake;
			ts.tv_nsec = 0;
		}
	}
	ret = pthread_cond_timedwait(&servloop_sleep,
					&servloop_sleep_pmutex, &ts);
	/* Reset servloop_wake if necessary */
	if (servloop_wake != 0) {
		(void) gettimeofday(&tv, 0);
		if (servloop_wake <= tv.tv_sec)
			servloop_wake = 0;
	}
	MUTEXUNLOCK(servloop_sleep, "servloop:msleep unlock");

	return (ret);
}

void
wakeup_servloop(void) {
	(void) pthread_cond_signal(&servloop_sleep);
}

/*
 * Return the update batching timeout.
 */
time_t
updateBatchingTimeout(void) {

	switch (ldapConfig.updateBatching) {
	case upd_none:
		return (0);
	case accumulate:
	case bounded_accumulate:
		return (ldapConfig.updateBatchingTimeout.timeout);
	default:
		return (DIR_IDLE_TIME);
	}
	/* NOTREACHED */
}

/*
 * Establish the time when the servloop next should wake up to check
 * if replicas should be pinged. If we change the wake up time, we
 * always wake up the servloop so that it will take the new wakeup time
 * into account when it goes back to sleep.
 */
void
setPingWakeup(time_t when) {
	int	doWakeup = 0;

	MUTEXLOCK(servloop_sleep, "servloop:set_ping_wakeup lock");
	if (when < servloop_wake || servloop_wake == 0) {
		servloop_wake = when;
		doWakeup = 1;
	}
	MUTEXUNLOCK(servloop_sleep, "servloop:set_ping_wakeup unlock");

	if (doWakeup)
		wakeup_servloop();
}

void
mark_activity(void) {

	static DECLMUTEXLOCK(last_activity);

	MUTEXLOCK(last_activity, "mark_activity(last_activity)");
	(void) gettimeofday(&last_activity, 0);
	MUTEXUNLOCK(last_activity, "mark_activity(last_activity)");
}

void *
servloop(void *varg) {

	long		dtbsize;
	long		last_purge = 0;
	long		fd_check = 0;
	long		fd_check_interval = FD_CHECK_DEF;
	long		purge_delta    = purge_deltas[
			(sizeof (purge_deltas)/sizeof (purge_deltas[0])) - 1];
	long		prev_since;
	long		cur_open_fd;
	struct rlimit	rl;
	struct timeval	now;
	ulong_t		sleeptime = 120*1000;

	/*
	 * get the maximum number of file descriptors for poll
	 */
	getrlimit(RLIMIT_NOFILE, &rl);
	dtbsize = rl.rlim_cur;

	gettimeofday(&now, NULL);
	last_purge = prev_since = now.tv_sec;

	for (;;) {

		/*
		 * Check open fd:s if more than 'fd_check_interval' seconds
		 * since last time.
		 *
		 * XXX: The somewhat complicated code below sets the
		 *	purge_delta depending on the number of open fd:s,
		 *	using linear interpolation in the purge_deltas[]
		 *	array.
		 */
		gettimeofday(&now, NULL);
		if (now.tv_sec - fd_check >= fd_check_interval) {
			long	index;
			int	deltas = (sizeof (purge_deltas)/
					sizeof (purge_deltas[0]));
			cur_open_fd = fd_open_count();
			fd_check = now.tv_sec;
			index = (cur_open_fd-1) * deltas / dtbsize;
			if (index < 0) {
				purge_delta = purge_deltas[0];
			} else if (index < deltas-1) {
				/* Interpolate */
				purge_delta = purge_deltas[index] +
			((cur_open_fd - index*(dtbsize/deltas)) *
			(purge_deltas[index+1]-purge_deltas[index])) /
				(dtbsize/deltas);
			} else {
				purge_delta = purge_deltas[deltas-1];
			}
			fd_check_interval = purge_delta;
			if (fd_check_interval > FD_CHECK_DEF)
				fd_check_interval = FD_CHECK_DEF;
			/*
			 * Run a purge on virtual circuits unused since now
			 * minus purge_delta seconds, if
			 *
			 *   The new purge cutoff would be more recent than
			 *   the one used in the last purge, and
			 *
			 *	We have a fairly large number of fd:s open
			 *	(more than 128, if deltas=16 and dtbsize=1024),
			 *
			 *	or
			 *
			 *	More than 'purge_delta' seconds have passed
			 *	since the last purge.
			 */
			if (now.tv_sec - purge_delta > prev_since &&
		(index > 1 || now.tv_sec - last_purge >= purge_delta)) {
				__svc_nisplus_purge_since(
					now.tv_sec-purge_delta);
				prev_since = now.tv_sec - purge_delta;
				last_purge = now.tv_sec;
			}
		}

		gettimeofday(&now, NULL);
		if (now.tv_sec > next_refresh) {
			next_refresh = __nis_serverRefreshCache();
			syslog(LOG_DEBUG, "nis_main: next_refresh %u",
					next_refresh);
		}

		/* Perform deferred frees */
		__nis_thread_cleanup(__nis_get_tsd());

		(void) msleep(sleeptime);
		if ((last_activity.tv_sec - now.tv_sec) >= sleeptime/1000) {
			/*
			 * No activity while we slept. Remove tables from
			 * standby mode and go back to sleep.
			 */
			(void) db_standby(0);
		}
		check_updaters();
		check_pingers();
		/* the force_checkpoint flag is set by -F or ping -C */
		if (force_checkpoint) {
			force_checkpoint = FALSE;
			/*
			 * Give the local databases a chance to
			 * checkpoint their data.
			 */
			if (verbose)
				syslog(LOG_INFO,
					"Service Checkpoint...");
			checkpoint_db();
			if (checkpoint_log()) {
				if (verbose)
					syslog(LOG_INFO,
					"checkpoint succeeded.");
				need_checkpoint = FALSE;
			} else if (verbose)
				syslog(LOG_INFO, "checkpoint failed.");
		}
	}
	/* Not reached */
}

#define		NO_ENTRY_OBJS	96

void *
callback_thread(void *varg) {

	callback_thread_arg_t	*arg = (callback_thread_arg_t *)varg;
	netobj			cookie;
	int			cbres, queued;
	table_col		*tc;
	nis_object		*cbarray[NO_ENTRY_OBJS];
	nis_object		*d_obj;
	enum clnt_stat		status = RPC_SUCCESS;
	struct timeval		tv = {3600, 0};
	char			tblbuf[NIS_MAXNAMELEN * 2];
	char			*table;
	nis_error		result;
	int			i;
	CLIENT			*cback = NULL;
	ulong_t			flags;
	pthread_t		myself = pthread_self();

	(void) nis_add_callback_id(myself, arg->pname);

	if (verbose)
		syslog(LOG_INFO, "Making callback handle to : %s",
			arg->nserver[0].name);
	if ((strcmp(arg->pname, "nobody") == 0) || (secure_level < 2))
		flags = ZMH_VC;
	else
		flags = ZMH_VC+ZMH_AUTH;

	cback = nis_make_rpchandle(arg->nserver, 1,
				CB_PROG, 1, flags, 16384, 16384);
	/* If we couldn't create a client handle we're hosed */
	if (! cback) {
		syslog(LOG_WARNING, "Unable to create callback.");
		XFREE(arg->fnr);
		free(arg->nserver);
		free(varg);
		nis_delete_callback_id(myself);
		return (0);
	}

	arg->cback = cback;
	arg->cbarg.entries.entries_val = &(cbarray[0]);
	cookie = arg->fnr->cookie;
	cbres = 0;
	queued = 0;
	if (__type_of(arg->ib_obj) == NIS_TABLE_OBJ)
		tc = arg->ib_obj->TA_data.ta_cols.ta_cols_val;
	else
		tc = tbl_prototype.ta_cols.ta_cols_val;

	while ((arg->fnr->status == NIS_SUCCESS) && (!cbres)) {
		if (arg->nm && multival_filter(arg->ib_obj,
				arg->nm, arg->a + arg->na, arg->fnr->obj)) {
			nis_destroy_object(arg->fnr->obj);
		} else if (arg->all_read ||
		    __can_do(NIS_READ_ACC, arg->fnr->obj->zo_access,
					arg->fnr->obj, arg->pname)) {
			cbarray[queued] = arg->fnr->obj;
			queued++;
		} else {
			d_obj = nis_censor_object_attr(arg->fnr->obj, tc,
					arg->pname, arg->na + arg->nm, arg->a);
			if (d_obj) {
				cbarray[queued] = d_obj;
				queued++;
			}
			nis_destroy_object(arg->fnr->obj);
		}
		/*
		 * the object is either already assigned to
		 * cbarray or destroyed.
		 */
		arg->fnr->obj = 0;
		if (queued == NO_ENTRY_OBJS) {
			arg->cbarg.entries.entries_len = NO_ENTRY_OBJS;
			status = clnt_call(arg->cback, CBPROC_RECEIVE,
				xdr_cback_data, (char *)&arg->cbarg,
				xdr_bool, (char *)&cbres, tv);
			if (verbose)
				syslog(LOG_INFO,
				    "list: sent entry, status = %s",
						clnt_sperrno(status));
			for (i = 0; i < NO_ENTRY_OBJS; i++) {
				nis_destroy_object(cbarray[i]);
				cbarray[i] = NULL;
			}
			queued = 0;
			if ((status != RPC_SUCCESS) || cbres) {
				if ((cbres == 0) && verbose) {
					syslog(LOG_ERR,
			"nis_list_svc: callback to %s returned %s",
				arg->cbhostname, clnt_sperrno(status));
				}
				break;
			}
		}
		XFREE(arg->fnr);
		table = internal_table_name(arg->ibr_name, tblbuf);
		arg->fnr = db_nextib(arg->ibr_name, &cookie,
						FN_MANGLE+FN_NORAGS, table);
		/*
		 * Note:  that the db_next_entry function will
		 * free this data. Technically this is an error
		 * but it is convienient.
		 */
		cookie = arg->fnr->cookie;
	}
	if (queued) {
		arg->cbarg.entries.entries_len = queued;
		status = clnt_call(arg->cback, CBPROC_RECEIVE,
				xdr_cback_data, (char *)&arg->cbarg,
				xdr_bool, (char *)&cbres, tv);
		if ((status != RPC_SUCCESS) && verbose)
			syslog(LOG_ERR,
				"nis_list_svc: callback to %s returned %s",
				arg->cbhostname, clnt_sperrno(status));
		for (i = 0; i < queued; i++)
			nis_destroy_object(cbarray[i]);
	}
	tv.tv_sec = 10;
	tv.tv_usec = 0;
	if (status != RPC_SUCCESS) {
		if (status == RPC_AUTHERROR) {
			syslog(LOG_WARNING,
				"Authentication ERROR in talking to %s.",
			    arg->cbhostname);
			auth_destroy(arg->cback->cl_auth);
			arg->cback->cl_auth = authnone_create();
			result = NIS_CLNTAUTH;
		} else {
			syslog(LOG_WARNING,
				"RPC ERROR in talking to %s.",
				arg->cbhostname);
			result = NIS_RPCERROR;
		}
		(void) clnt_call(arg->cback, CBPROC_ERROR,
				    xdr_nis_error, (char *)&result,
				    xdr_void, (char *)(0), tv);
	} else {
		(void) clnt_call(arg->cback, CBPROC_FINISH,
					xdr_void, (char *)(0),
					xdr_void, (char *)(0), tv);
	}
	if (arg->fnr->status == NIS_SUCCESS) {
		if (arg->fnr->obj)
			nis_destroy_object(arg->fnr->obj);
		db_flush(arg->ibr_name, &(arg->fnr->cookie));
	}
	if (arg->ib_obj != 0)
		nis_destroy_object(arg->ib_obj);
	XFREE(arg->fnr);
	auth_destroy(arg->cback->cl_auth);
	clnt_destroy(arg->cback);
	/* Our parent thread allocated this, but it's our job to deallocate */
	free(arg->nserver);
	free(varg);

	nis_delete_callback_id(myself);

	/*
	 * The periodic thread cleanup (or the TSD destructor, if all else
	 * fails) will take care of the loose ends
	 */
	return (0);
}

/* From nis_xx_proc.c */
#define	CB_BUF_SIZE	128

/*
 * Perform the actual dump work on behalf of nis_dump_svc().
 */
void *
dumpsvc_thread(void *varg) {

	dumpsvc_thread_arg_t	*arg = varg;
	__nis_hash_table_mt	tables = NIS_HASH_TABLE_MT_INIT;
	__nis_hash_item_mt	*item;
	int			i, queued_objs;
	nis_fn_result		*fnr;
	netobj			cookie;
	int			cbres = 0;
	char			namebuf[1024];
	int			totlobjs = 0;
	int			skipobjs = 0;
	nis_object		*cbarray[CB_BUF_SIZE];
	struct timeval		tv, go;
	long			boost = 0;
	cback_data		cbarg;
	enum clnt_stat		rstat;
	pthread_t		myself = pthread_self();

	if (arg == 0)
		return (0);

	(void) nis_add_callback_id(myself, arg->pname);

	syslog(LOG_INFO, "nis_dump_svc[%d]: sending full dump of %s to %s",
			pthread_self(), arg->da_dir, arg->pname);

	cbarg.entries.entries_val = cbarray;
	nis_insert_name(arg->da_dir, &tables);
	queued_objs = 0;

	while ((item = __nis_pop_item_mt(&tables)) != 0) {
		strcpy(arg->pname, item->name);
		if (verbose)
			syslog(LOG_INFO, "nis_dump_svc (child) : Dumping '%s'",
								arg->pname);
		fnr = db_firstib(arg->pname, 0, NULL, FN_NOMANGLE+FN_NORAGS,
				NULL);
		cookie = fnr->cookie;
		if (fnr->status == NIS_NOSUCHTABLE) {
			syslog(LOG_INFO,
			    "nis_dump_svc (child): Couldn't read table '%s'",
								arg->pname);
		} else if (fnr->status == NIS_SUCCESS) {
			while (! cbres) {
				if (__type_of(fnr->obj) == NIS_TABLE_OBJ) {
					sprintf(namebuf, "%s.%s",
							fnr->obj->zo_name,
							fnr->obj->zo_domain);
					nis_insert_name(namebuf, &tables);
				}
				if (fnr->obj->zo_oid.mtime > arg->ttime) {
					skipobjs++;
				} else {
					cbarray[queued_objs++] = fnr->obj;
					totlobjs++;
				}
				/*
				 * This won't be true should we skip
				 * recent updates but let's test for
				 * it anyway.
				 */
				if (queued_objs == CB_BUF_SIZE) {
					cbarg.entries.entries_len =
								CB_BUF_SIZE;
					tv.tv_sec = 600 > boost ? 600: boost;
					tv.tv_usec = 0;
					gettimeofday(&go, NULL);
					rstat = clnt_call(arg->cback,
						CBPROC_RECEIVE, xdr_cback_data,
						(char *)&cbarg, xdr_bool,
						(char *)&cbres, tv);
					gettimeofday(&tv, NULL);
					for (i = 0; i < CB_BUF_SIZE; i++)
						nis_destroy_object(cbarray[i]);

					if (rstat != RPC_SUCCESS) {
						syslog(LOG_ERR,
		"nis_dump_svc (child): Callback failed with RPC error %s.",
							clnt_sperrno(rstat));
						auth_destroy(
							arg->cback->cl_auth);
						clnt_destroy(arg->cback);
						free(varg);
						nis_delete_callback_id(myself);
						return (0);
					}
					queued_objs = 0;
					boost = 3 * (tv.tv_sec - go.tv_sec);
				}
				XFREE(fnr);
				fnr = db_nextib(arg->pname, &cookie,
						FN_NORAGS, NULL);
				cookie = fnr->cookie;
				if (fnr->status != NIS_SUCCESS)
					break;
			}
		}
		if (fnr->status == NIS_SUCCESS)
			XFREE(fnr->cookie.n_bytes);
		XFREE(fnr);
		if (queued_objs) {
			cbarg.entries.entries_len = queued_objs;
			if (! cbres) {
				tv.tv_sec = 600 > boost ? 600 : boost;
				tv.tv_usec = 0;
				rstat = clnt_call(arg->cback, CBPROC_RECEIVE,
						xdr_cback_data, (char *)&cbarg,
						xdr_bool, (char *)&cbres, tv);
				if (rstat != RPC_SUCCESS) {
					syslog(LOG_ERR,
		"nis_dump_svc (child): Callback failed with RPC error %s.",
							clnt_sperrno(rstat));
					auth_destroy(arg->cback->cl_auth);
					clnt_destroy(arg->cback);
					free(varg);
					nis_delete_callback_id(myself);
					return (0);
				}
			}
			for (i = 0; i < queued_objs; i++)
				nis_destroy_object(cbarray[i]);

			queued_objs = 0;
		}

		free(item->name);
		free(item);

		boost = 0; /* on to next table */
	}

	syslog(LOG_INFO, "nis_dump_svc[%d]: good dump of %s, %d total objects "
	    "(%d deferred)", pthread_self(), arg->da_dir, totlobjs, skipobjs);
	if (verbose)
		syslog(LOG_INFO, "nis_dump_svc (child): dump complete.");

	tv.tv_sec = 3;
	tv.tv_usec = 0;
	rstat = clnt_call(arg->cback, CBPROC_FINISH, xdr_void, 0, xdr_void, 0,
			tv);
	if (rstat != RPC_SUCCESS && rstat != RPC_TIMEDOUT) {

		/*
		 * Since the callback function handling this FINISH rpc
		 * call does not reply, so we basically ignore it if a
		 * RPC_TIMEDOUT message is returned. Only log other types
		 * of non-successful messages.
		 */
		syslog(LOG_WARNING,
			"nis_dump_svc[%d]: Finish handshake returned %s",
				pthread_self(), clnt_sperrno(rstat));
	}
	auth_destroy(arg->cback->cl_auth);
	clnt_destroy(arg->cback);
	free(varg);

	nis_delete_callback_id(myself);

	return (0);
}
