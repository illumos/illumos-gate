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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <signal.h>
#include <dirent.h>
#include <limits.h>
#include <alloca.h>
#include <unistd.h>
#include <stdio.h>

#include <fmd_string.h>
#include <fmd_alloc.h>
#include <fmd_module.h>
#include <fmd_error.h>
#include <fmd_conf.h>
#include <fmd_dispq.h>
#include <fmd_eventq.h>
#include <fmd_timerq.h>
#include <fmd_subr.h>
#include <fmd_thread.h>
#include <fmd_ustat.h>
#include <fmd_case.h>
#include <fmd_protocol.h>
#include <fmd_buf.h>
#include <fmd_ckpt.h>
#include <fmd_xprt.h>
#include <fmd_topo.h>

#include <fmd.h>

/*
 * Template for per-module statistics installed by fmd on behalf of each active
 * module.  These are used to initialize the per-module mp->mod_stats below.
 * NOTE: FMD_TYPE_STRING statistics should not be used here.  If they are
 * required in the future, the FMD_ADM_MODDSTAT service routine must change.
 */
static const fmd_modstat_t _fmd_modstat_tmpl = {
{
{ "fmd.dispatched", FMD_TYPE_UINT64, "total events dispatched to module" },
{ "fmd.dequeued", FMD_TYPE_UINT64, "total events dequeued by module" },
{ "fmd.prdequeued", FMD_TYPE_UINT64, "protocol events dequeued by module" },
{ "fmd.dropped", FMD_TYPE_UINT64, "total events dropped on queue overflow" },
{ "fmd.wcnt", FMD_TYPE_UINT32, "count of events waiting on queue" },
{ "fmd.wtime", FMD_TYPE_TIME, "total wait time on queue" },
{ "fmd.wlentime", FMD_TYPE_TIME, "total wait length * time product" },
{ "fmd.wlastupdate", FMD_TYPE_TIME, "hrtime of last wait queue update" },
{ "fmd.dtime", FMD_TYPE_TIME, "total processing time after dequeue" },
{ "fmd.dlastupdate", FMD_TYPE_TIME, "hrtime of last event dequeue completion" },
},
{ "fmd.loadtime", FMD_TYPE_TIME, "hrtime at which module was loaded" },
{ "fmd.snaptime", FMD_TYPE_TIME, "hrtime of last statistics snapshot" },
{ "fmd.accepted", FMD_TYPE_UINT64, "total events accepted by module" },
{ "fmd.debugdrop", FMD_TYPE_UINT64, "dropped debug messages" },
{ "fmd.memtotal", FMD_TYPE_SIZE, "total memory allocated by module" },
{ "fmd.memlimit", FMD_TYPE_SIZE, "limit on total memory allocated" },
{ "fmd.buftotal", FMD_TYPE_SIZE, "total buffer space used by module" },
{ "fmd.buflimit", FMD_TYPE_SIZE, "limit on total buffer space" },
{ "fmd.thrtotal", FMD_TYPE_UINT32, "total number of auxiliary threads" },
{ "fmd.thrlimit", FMD_TYPE_UINT32, "limit on number of auxiliary threads" },
{ "fmd.doorthrtotal", FMD_TYPE_UINT32, "total number of door server threads" },
{ "fmd.doorthrlimit", FMD_TYPE_UINT32, "limit on door server threads" },
{ "fmd.caseopen", FMD_TYPE_UINT64, "cases currently open by module" },
{ "fmd.casesolved", FMD_TYPE_UINT64, "total cases solved by module" },
{ "fmd.caseclosed", FMD_TYPE_UINT64, "total cases closed by module" },
{ "fmd.ckptsave", FMD_TYPE_BOOL, "save checkpoints for module" },
{ "fmd.ckptrestore", FMD_TYPE_BOOL, "restore checkpoints for module" },
{ "fmd.ckptzero", FMD_TYPE_BOOL, "zeroed checkpoint at startup" },
{ "fmd.ckptcnt", FMD_TYPE_UINT64, "number of checkpoints taken" },
{ "fmd.ckpttime", FMD_TYPE_TIME, "total checkpoint time" },
{ "fmd.xprtopen", FMD_TYPE_UINT32, "total number of open transports" },
{ "fmd.xprtlimit", FMD_TYPE_UINT32, "limit on number of open transports" },
{ "fmd.xprtqlimit", FMD_TYPE_UINT32, "limit on transport event queue length" },
};

static void
fmd_module_start(void *arg)
{
	fmd_module_t *mp = arg;
	fmd_event_t *ep;
	fmd_xprt_t *xp;

	(void) pthread_mutex_lock(&mp->mod_lock);

	if (mp->mod_ops->mop_init(mp) != 0 || mp->mod_error != 0) {
		if (mp->mod_error == 0)
			mp->mod_error = errno ? errno : EFMD_MOD_INIT;
		goto out;
	}

	if (fmd.d_mod_event != NULL)
		fmd_eventq_insert_at_head(mp->mod_queue, fmd.d_mod_event);

	ASSERT(MUTEX_HELD(&mp->mod_lock));
	mp->mod_flags |= FMD_MOD_INIT;

	(void) pthread_cond_broadcast(&mp->mod_cv);
	(void) pthread_mutex_unlock(&mp->mod_lock);

	/*
	 * If the module opened any transports while executing _fmd_init(),
	 * they are suspended. Now that _fmd_init() is done, wake them up.
	 */
	for (xp = fmd_list_next(&mp->mod_transports);
	    xp != NULL; xp = fmd_list_next(xp))
		fmd_xprt_xresume(xp, FMD_XPRT_ISUSPENDED);

	/*
	 * Wait for events to arrive by checking mod_error and then sleeping in
	 * fmd_eventq_delete().  If a NULL event is returned, the eventq has
	 * been aborted and we continue on to call fini and exit the thread.
	 */
	while ((ep = fmd_eventq_delete(mp->mod_queue)) != NULL) {
		/*
		 * If the module has failed, discard the event without ever
		 * passing it to the module and go back to sleep.
		 */
		if (mp->mod_error != 0) {
			fmd_eventq_done(mp->mod_queue);
			fmd_event_rele(ep);
			continue;
		}

		mp->mod_ops->mop_dispatch(mp, ep);
		fmd_eventq_done(mp->mod_queue);

		/*
		 * Once mop_dispatch() is complete, grab the lock and perform
		 * any event-specific post-processing.  Finally, if necessary,
		 * checkpoint the state of the module after this event.
		 */
		fmd_module_lock(mp);

		if (FMD_EVENT_TYPE(ep) == FMD_EVT_CLOSE)
			fmd_case_delete(FMD_EVENT_DATA(ep));

		fmd_ckpt_save(mp);
		fmd_module_unlock(mp);
		fmd_event_rele(ep);
	}

	if (mp->mod_ops->mop_fini(mp) != 0 && mp->mod_error == 0)
		mp->mod_error = errno ? errno : EFMD_MOD_FINI;

	(void) pthread_mutex_lock(&mp->mod_lock);
	mp->mod_flags |= FMD_MOD_FINI;

out:
	(void) pthread_cond_broadcast(&mp->mod_cv);
	(void) pthread_mutex_unlock(&mp->mod_lock);
}

fmd_module_t *
fmd_module_create(const char *path, const fmd_modops_t *ops)
{
	fmd_module_t *mp = fmd_zalloc(sizeof (fmd_module_t), FMD_SLEEP);

	char buf[PATH_MAX], *p;
	const char *dir;
	uint32_t limit;
	int err;

	(void) strlcpy(buf, fmd_strbasename(path), sizeof (buf));
	if ((p = strrchr(buf, '.')) != NULL && strcmp(p, ".so") == 0)
		*p = '\0'; /* strip trailing .so from any module name */

	(void) pthread_mutex_init(&mp->mod_lock, NULL);
	(void) pthread_cond_init(&mp->mod_cv, NULL);
	(void) pthread_mutex_init(&mp->mod_stats_lock, NULL);

	mp->mod_name = fmd_strdup(buf, FMD_SLEEP);
	mp->mod_path = fmd_strdup(path, FMD_SLEEP);
	mp->mod_ops = ops;
	mp->mod_ustat = fmd_ustat_create();

	(void) fmd_conf_getprop(fmd.d_conf, "ckpt.dir", &dir);
	(void) snprintf(buf, sizeof (buf),
	    "%s/%s/%s", fmd.d_rootdir, dir, mp->mod_name);

	mp->mod_ckpt = fmd_strdup(buf, FMD_SLEEP);

	(void) fmd_conf_getprop(fmd.d_conf, "client.tmrlim", &limit);
	mp->mod_timerids = fmd_idspace_create(mp->mod_name, 1, limit + 1);
	mp->mod_threads = fmd_idspace_create(mp->mod_name, 0, INT_MAX);

	fmd_buf_hash_create(&mp->mod_bufs);
	fmd_serd_hash_create(&mp->mod_serds);

	mp->mod_topo_current = fmd_topo_hold();

	(void) pthread_mutex_lock(&fmd.d_mod_lock);
	fmd_list_append(&fmd.d_mod_list, mp);
	(void) pthread_mutex_unlock(&fmd.d_mod_lock);

	/*
	 * Initialize the module statistics that are kept on its behalf by fmd.
	 * These are set up using a template defined at the top of this file.
	 */
	if ((mp->mod_stats = (fmd_modstat_t *)fmd_ustat_insert(mp->mod_ustat,
	    FMD_USTAT_ALLOC, sizeof (_fmd_modstat_tmpl) / sizeof (fmd_stat_t),
	    (fmd_stat_t *)&_fmd_modstat_tmpl, NULL)) == NULL) {
		fmd_error(EFMD_MOD_INIT, "failed to initialize per-mod stats");
		fmd_module_destroy(mp);
		return (NULL);
	}

	if (nv_alloc_init(&mp->mod_nva_sleep,
	    &fmd_module_nva_ops_sleep, mp) != 0 ||
	    nv_alloc_init(&mp->mod_nva_nosleep,
	    &fmd_module_nva_ops_nosleep, mp) != 0) {
		fmd_error(EFMD_MOD_INIT, "failed to initialize nvlist "
		    "allocation routines");
		fmd_module_destroy(mp);
		return (NULL);
	}

	(void) fmd_conf_getprop(fmd.d_conf, "client.evqlim", &limit);

	mp->mod_queue = fmd_eventq_create(mp,
	    &mp->mod_stats->ms_evqstat, &mp->mod_stats_lock, limit);

	(void) fmd_conf_getprop(fmd.d_conf, "client.memlim",
	    &mp->mod_stats->ms_memlimit.fmds_value.ui64);

	(void) fmd_conf_getprop(fmd.d_conf, "client.buflim",
	    &mp->mod_stats->ms_buflimit.fmds_value.ui64);

	(void) fmd_conf_getprop(fmd.d_conf, "client.thrlim",
	    &mp->mod_stats->ms_thrlimit.fmds_value.ui32);

	(void) fmd_conf_getprop(fmd.d_conf, "client.doorthrlim",
	    &mp->mod_stats->ms_doorthrlimit.fmds_value.ui32);

	(void) fmd_conf_getprop(fmd.d_conf, "client.xprtlim",
	    &mp->mod_stats->ms_xprtlimit.fmds_value.ui32);

	(void) fmd_conf_getprop(fmd.d_conf, "client.xprtqlim",
	    &mp->mod_stats->ms_xprtqlimit.fmds_value.ui32);

	(void) fmd_conf_getprop(fmd.d_conf, "ckpt.save",
	    &mp->mod_stats->ms_ckpt_save.fmds_value.bool);

	(void) fmd_conf_getprop(fmd.d_conf, "ckpt.restore",
	    &mp->mod_stats->ms_ckpt_restore.fmds_value.bool);

	(void) fmd_conf_getprop(fmd.d_conf, "ckpt.zero",
	    &mp->mod_stats->ms_ckpt_zeroed.fmds_value.bool);

	if (mp->mod_stats->ms_ckpt_zeroed.fmds_value.bool)
		fmd_ckpt_delete(mp); /* blow away any pre-existing checkpoint */

	/*
	 * Place a hold on the module and grab the module lock before creating
	 * the module's thread to ensure that it cannot destroy the module and
	 * that it cannot call ops->mop_init() before we're done setting up.
	 * NOTE: from now on, we must use fmd_module_rele() for error paths.
	 */
	fmd_module_hold(mp);
	(void) pthread_mutex_lock(&mp->mod_lock);
	mp->mod_stats->ms_loadtime.fmds_value.ui64 = gethrtime();
	mp->mod_thread = fmd_thread_create(mp, fmd_module_start, mp);

	if (mp->mod_thread == NULL) {
		fmd_error(EFMD_MOD_THR, "failed to create thread for %s", path);
		(void) pthread_mutex_unlock(&mp->mod_lock);
		fmd_module_rele(mp);
		return (NULL);
	}

	/*
	 * At this point our module structure is nearly finished and its thread
	 * is starting execution in fmd_module_start() above, which will begin
	 * by blocking for mod_lock.  We now drop mod_lock and wait for either
	 * FMD_MOD_INIT or mod_error to be set before proceeding.
	 */
	while (!(mp->mod_flags & FMD_MOD_INIT) && mp->mod_error == 0)
		(void) pthread_cond_wait(&mp->mod_cv, &mp->mod_lock);

	/*
	 * If the module has failed to initialize, copy its errno to the errno
	 * of the caller, wait for it to unload, and then destroy it.
	 */
	if (!(mp->mod_flags & FMD_MOD_INIT)) {
		err = mp->mod_error;
		(void) pthread_mutex_unlock(&mp->mod_lock);

		if (err == EFMD_CKPT_INVAL)
			fmd_ckpt_rename(mp); /* move aside bad checkpoint */

		/*
		 * If we're in the background, keep quiet about failure to
		 * load because a handle wasn't registered: this is a module's
		 * way of telling us it didn't want to be loaded for some
		 * reason related to system configuration.  If we're in the
		 * foreground we log this too in order to inform developers.
		 */
		if (fmd.d_fg || err != EFMD_HDL_INIT) {
			fmd_error(EFMD_MOD_INIT, "failed to load %s: %s\n",
			    path, fmd_strerror(err));
		}

		fmd_module_unload(mp);
		fmd_module_rele(mp);

		(void) fmd_set_errno(err);
		return (NULL);
	}

	(void) pthread_cond_broadcast(&mp->mod_cv);
	(void) pthread_mutex_unlock(&mp->mod_lock);

	fmd_dprintf(FMD_DBG_MOD, "loaded module %s\n", mp->mod_name);
	return (mp);
}

static void
fmd_module_untimeout(fmd_idspace_t *ids, id_t id, fmd_module_t *mp)
{
	void *arg = fmd_timerq_remove(fmd.d_timers, ids, id);

	/*
	 * The root module calls fmd_timerq_install() directly and must take
	 * responsibility for any cleanup of timer arguments that is required.
	 * All other modules use fmd_modtimer_t's as the arg data; free them.
	 */
	if (arg != NULL && mp != fmd.d_rmod)
		fmd_free(arg, sizeof (fmd_modtimer_t));
}

void
fmd_module_unload(fmd_module_t *mp)
{
	fmd_modtopo_t *mtp;

	(void) pthread_mutex_lock(&mp->mod_lock);

	if (mp->mod_flags & FMD_MOD_QUIT) {
		(void) pthread_mutex_unlock(&mp->mod_lock);
		return; /* module is already unloading */
	}

	ASSERT(mp->mod_thread != NULL);
	mp->mod_flags |= FMD_MOD_QUIT;

	if (mp->mod_queue != NULL)
		fmd_eventq_abort(mp->mod_queue);

	/*
	 * Wait for the module's thread to stop processing events and call
	 * _fmd_fini() and exit.  We do this by waiting for FMD_MOD_FINI to be
	 * set if INIT was set, and then attempting to join with the thread.
	 */
	while ((mp->mod_flags & (FMD_MOD_INIT | FMD_MOD_FINI)) == FMD_MOD_INIT)
		(void) pthread_cond_wait(&mp->mod_cv, &mp->mod_lock);

	(void) pthread_cond_broadcast(&mp->mod_cv);
	(void) pthread_mutex_unlock(&mp->mod_lock);

	fmd_thread_destroy(mp->mod_thread, FMD_THREAD_JOIN);
	mp->mod_thread = NULL;

	/*
	 * Once the module is no longer active, clean up any data structures
	 * that are only required when the module is loaded.
	 */
	fmd_module_lock(mp);

	if (mp->mod_timerids != NULL) {
		fmd_idspace_apply(mp->mod_timerids,
		    (void (*)())fmd_module_untimeout, mp);

		fmd_idspace_destroy(mp->mod_timerids);
		mp->mod_timerids = NULL;
	}

	if (mp->mod_threads != NULL) {
		fmd_idspace_destroy(mp->mod_threads);
		mp->mod_threads = NULL;
	}

	(void) fmd_buf_hash_destroy(&mp->mod_bufs);
	fmd_serd_hash_destroy(&mp->mod_serds);

	while ((mtp = fmd_list_next(&mp->mod_topolist)) != NULL) {
		fmd_list_delete(&mp->mod_topolist, mtp);
		fmd_topo_rele(mtp->mt_topo);
		fmd_free(mtp, sizeof (fmd_modtopo_t));
	}

	fmd_module_unlock(mp);
	fmd_dprintf(FMD_DBG_MOD, "unloaded module %s\n", mp->mod_name);
}

void
fmd_module_destroy(fmd_module_t *mp)
{
	fmd_conf_formal_t *cfp = mp->mod_argv;
	int i;

	ASSERT(MUTEX_HELD(&mp->mod_lock));

	if (mp->mod_thread != NULL) {
		(void) pthread_mutex_unlock(&mp->mod_lock);
		fmd_module_unload(mp);
		(void) pthread_mutex_lock(&mp->mod_lock);
	}

	ASSERT(mp->mod_thread == NULL);
	ASSERT(mp->mod_refs == 0);

	/*
	 * Once the module's thread is dead, we can safely remove the module
	 * from global visibility and by removing it from d_mod_list.  Any
	 * modhash pointers are already gone by virtue of mod_refs being zero.
	 */
	(void) pthread_mutex_lock(&fmd.d_mod_lock);
	fmd_list_delete(&fmd.d_mod_list, mp);
	(void) pthread_mutex_unlock(&fmd.d_mod_lock);

	if (mp->mod_topo_current != NULL)
		fmd_topo_rele(mp->mod_topo_current);

	if (mp->mod_nva_sleep.nva_ops != NULL)
		nv_alloc_fini(&mp->mod_nva_sleep);
	if (mp->mod_nva_nosleep.nva_ops != NULL)
		nv_alloc_fini(&mp->mod_nva_nosleep);

	/*
	 * Once the module is no longer processing events and no longer visible
	 * through any program data structures, we can free all of its content.
	 */
	if (mp->mod_queue != NULL) {
		fmd_eventq_destroy(mp->mod_queue);
		mp->mod_queue = NULL;
	}

	if (mp->mod_ustat != NULL) {
		(void) pthread_mutex_lock(&mp->mod_stats_lock);
		fmd_ustat_destroy(mp->mod_ustat);
		mp->mod_ustat = NULL;
		mp->mod_stats = NULL;
		(void) pthread_mutex_unlock(&mp->mod_stats_lock);
	}

	for (i = 0; i < mp->mod_dictc; i++)
		fm_dc_closedict(mp->mod_dictv[i]);

	fmd_free(mp->mod_dictv, sizeof (struct fm_dc_handle *) * mp->mod_dictc);

	if (mp->mod_conf != NULL)
		fmd_conf_close(mp->mod_conf);

	for (i = 0; i < mp->mod_argc; i++, cfp++) {
		fmd_strfree((char *)cfp->cf_name);
		fmd_strfree((char *)cfp->cf_default);
	}

	fmd_free(mp->mod_argv, sizeof (fmd_conf_formal_t) * mp->mod_argc);

	fmd_strfree(mp->mod_name);
	fmd_strfree(mp->mod_path);
	fmd_strfree(mp->mod_ckpt);
	nvlist_free(mp->mod_fmri);
	fmd_strfree(mp->mod_vers);

	fmd_free(mp, sizeof (fmd_module_t));
}

/*
 * fmd_module_error() is called after the stack is unwound from a call to
 * fmd_module_abort() to indicate that the module has failed.  The mod_error
 * field is used to hold the error code of the first fatal error to the module.
 * An EFMD_MOD_FAIL event is then created and sent to fmd-self-diagnosis.
 */
static void
fmd_module_error(fmd_module_t *mp, int err)
{
	fmd_event_t *e;
	nvlist_t *nvl;
	char *class;

	ASSERT(MUTEX_HELD(&mp->mod_lock));
	ASSERT(err != 0);

	TRACE((FMD_DBG_MOD, "module aborted: err=%d", err));

	if (mp->mod_error == 0)
		mp->mod_error = err;

	if (mp == fmd.d_self)
		return; /* do not post event if fmd.d_self itself fails */

	/*
	 * Send an error indicating the module has now failed to fmd.d_self.
	 * Since the error causing the failure has already been logged by
	 * fmd_api_xerror(), we do not need to bother logging this event.
	 * It only exists for the purpose of notifying fmd.d_self that it can
	 * close the case associated with this module because mod_error is set.
	 */
	nvl = fmd_protocol_moderror(mp, EFMD_MOD_FAIL, fmd_strerror(err));
	(void) nvlist_lookup_string(nvl, FM_CLASS, &class);
	e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, class);
	fmd_dispq_dispatch(fmd.d_disp, e, class);
}

void
fmd_module_dispatch(fmd_module_t *mp, fmd_event_t *e)
{
	const fmd_hdl_ops_t *ops = mp->mod_info->fmdi_ops;
	fmd_event_impl_t *ep = (fmd_event_impl_t *)e;
	fmd_hdl_t *hdl = (fmd_hdl_t *)mp;
	fmd_modtimer_t *t;
	fmd_topo_t *old_topo;
	volatile int err;

	/*
	 * Before calling the appropriate module callback, enter the module as
	 * if by fmd_module_enter() and establish mod_jmpbuf for any aborts.
	 */
	(void) pthread_mutex_lock(&mp->mod_lock);

	ASSERT(!(mp->mod_flags & FMD_MOD_BUSY));
	mp->mod_flags |= FMD_MOD_BUSY;

	if ((err = setjmp(mp->mod_jmpbuf)) != 0) {
		(void) pthread_mutex_lock(&mp->mod_lock);
		fmd_module_error(mp, err);
	}

	(void) pthread_cond_broadcast(&mp->mod_cv);
	(void) pthread_mutex_unlock(&mp->mod_lock);

	/*
	 * If it's the first time through fmd_module_dispatch(), call the
	 * appropriate module callback based on the event type.  If the call
	 * triggers an fmd_module_abort(), we'll return to setjmp() above with
	 * err set to a non-zero value and then bypass this before exiting.
	 */
	if (err == 0) {
		switch (ep->ev_type) {
		case FMD_EVT_PROTOCOL:
			ops->fmdo_recv(hdl, e, ep->ev_nvl, ep->ev_data);
			break;
		case FMD_EVT_TIMEOUT:
			t = ep->ev_data;
			ASSERT(t->mt_mod == mp);
			ops->fmdo_timeout(hdl, t->mt_id, t->mt_arg);
			break;
		case FMD_EVT_CLOSE:
			ops->fmdo_close(hdl, ep->ev_data);
			break;
		case FMD_EVT_STATS:
			ops->fmdo_stats(hdl);
			fmd_modstat_publish(mp);
			break;
		case FMD_EVT_GC:
			ops->fmdo_gc(hdl);
			break;
		case FMD_EVT_PUBLISH:
			fmd_case_publish(ep->ev_data, FMD_CASE_CURRENT);
			break;
		case FMD_EVT_TOPO:
			/*
			 * Save the pointer to the old topology and update
			 * the pointer with the updated topology.
			 * With this approach, other threads that reference the
			 * topology either
			 *  - finishes with old topology since
			 *	it is released after updating
			 *	mod_topo_current.
			 *  - or is blocked while mod_topo_current is updated.
			 */
			old_topo = mp->mod_topo_current;
			fmd_module_lock(mp);
			mp->mod_topo_current = (fmd_topo_t *)ep->ev_data;
			fmd_topo_addref(mp->mod_topo_current);
			fmd_module_unlock(mp);
			fmd_topo_rele(old_topo);
			ops->fmdo_topo(hdl, mp->mod_topo_current->ft_hdl);
			break;
		}
	}

	fmd_module_exit(mp);
}

int
fmd_module_transport(fmd_module_t *mp, fmd_xprt_t *xp, fmd_event_t *e)
{
	fmd_event_impl_t *ep = (fmd_event_impl_t *)e;
	fmd_hdl_t *hdl = (fmd_hdl_t *)mp;

	ASSERT(ep->ev_type == FMD_EVT_PROTOCOL);
	return (mp->mod_info->fmdi_ops->fmdo_send(hdl, xp, e, ep->ev_nvl));
}

void
fmd_module_timeout(fmd_modtimer_t *t, id_t id, hrtime_t hrt)
{
	fmd_event_t *e;

	t->mt_id = id; /* save id in case we need to delete from eventq */
	e = fmd_event_create(FMD_EVT_TIMEOUT, hrt, NULL, t);
	fmd_eventq_insert_at_time(t->mt_mod->mod_queue, e);
}

/*
 * Garbage collection is initiated by a timer callback once per day or at the
 * request of fmadm.  Purge old SERD entries and send the module a GC event.
 */
void
fmd_module_gc(fmd_module_t *mp)
{
	fmd_hdl_info_t *info;
	fmd_event_t *e;

	if (mp->mod_error != 0)
		return; /* do not do anything if the module has failed */

	fmd_module_lock(mp);

	if ((info = mp->mod_info) != NULL) {
		fmd_serd_hash_apply(&mp->mod_serds, fmd_serd_eng_gc, NULL);
	}

	fmd_module_unlock(mp);

	if (info != NULL) {
		e = fmd_event_create(FMD_EVT_GC, FMD_HRT_NOW, NULL, NULL);
		fmd_eventq_insert_at_head(mp->mod_queue, e);
	}
}

void
fmd_module_trygc(fmd_module_t *mp)
{
	if (fmd_module_trylock(mp)) {
		fmd_serd_hash_apply(&mp->mod_serds, fmd_serd_eng_gc, NULL);
		fmd_module_unlock(mp);
	}
}

int
fmd_module_contains(fmd_module_t *mp, fmd_event_t *ep)
{
	fmd_case_t *cp;
	int rv = 0;

	fmd_module_lock(mp);

	for (cp = fmd_list_next(&mp->mod_cases);
	    cp != NULL; cp = fmd_list_next(cp)) {
		if ((rv = fmd_case_contains(cp, ep)) != 0)
			break;
	}

	if (rv == 0)
		rv = fmd_serd_hash_contains(&mp->mod_serds, ep);

	fmd_module_unlock(mp);
	return (rv);
}

void
fmd_module_setdirty(fmd_module_t *mp)
{
	(void) pthread_mutex_lock(&mp->mod_lock);
	mp->mod_flags |= FMD_MOD_MDIRTY;
	(void) pthread_mutex_unlock(&mp->mod_lock);
}

void
fmd_module_setcdirty(fmd_module_t *mp)
{
	(void) pthread_mutex_lock(&mp->mod_lock);
	mp->mod_flags |= FMD_MOD_CDIRTY;
	(void) pthread_mutex_unlock(&mp->mod_lock);
}

void
fmd_module_clrdirty(fmd_module_t *mp)
{
	fmd_case_t *cp;

	fmd_module_lock(mp);

	if (mp->mod_flags & FMD_MOD_CDIRTY) {
		for (cp = fmd_list_next(&mp->mod_cases);
		    cp != NULL; cp = fmd_list_next(cp))
			fmd_case_clrdirty(cp);
	}

	if (mp->mod_flags & FMD_MOD_MDIRTY) {
		fmd_serd_hash_apply(&mp->mod_serds,
		    fmd_serd_eng_clrdirty, NULL);
		fmd_buf_hash_commit(&mp->mod_bufs);
	}

	(void) pthread_mutex_lock(&mp->mod_lock);
	mp->mod_flags &= ~(FMD_MOD_MDIRTY | FMD_MOD_CDIRTY);
	(void) pthread_mutex_unlock(&mp->mod_lock);

	fmd_module_unlock(mp);
}

void
fmd_module_commit(fmd_module_t *mp)
{
	fmd_case_t *cp;

	ASSERT(fmd_module_locked(mp));

	if (mp->mod_flags & FMD_MOD_CDIRTY) {
		for (cp = fmd_list_next(&mp->mod_cases);
		    cp != NULL; cp = fmd_list_next(cp))
			fmd_case_commit(cp);
	}

	if (mp->mod_flags & FMD_MOD_MDIRTY) {
		fmd_serd_hash_apply(&mp->mod_serds, fmd_serd_eng_commit, NULL);
		fmd_buf_hash_commit(&mp->mod_bufs);
	}

	(void) pthread_mutex_lock(&mp->mod_lock);
	mp->mod_flags &= ~(FMD_MOD_MDIRTY | FMD_MOD_CDIRTY);
	(void) pthread_mutex_unlock(&mp->mod_lock);

	mp->mod_gen++;
}

void
fmd_module_lock(fmd_module_t *mp)
{
	pthread_t self = pthread_self();

	(void) pthread_mutex_lock(&mp->mod_lock);

	while (mp->mod_flags & FMD_MOD_LOCK) {
		if (mp->mod_owner != self)
			(void) pthread_cond_wait(&mp->mod_cv, &mp->mod_lock);
		else
			fmd_panic("recursive module lock of %p\n", (void *)mp);
	}

	mp->mod_owner = self;
	mp->mod_flags |= FMD_MOD_LOCK;

	(void) pthread_cond_broadcast(&mp->mod_cv);
	(void) pthread_mutex_unlock(&mp->mod_lock);
}

void
fmd_module_unlock(fmd_module_t *mp)
{
	(void) pthread_mutex_lock(&mp->mod_lock);

	ASSERT(mp->mod_owner == pthread_self());
	ASSERT(mp->mod_flags & FMD_MOD_LOCK);

	mp->mod_owner = 0;
	mp->mod_flags &= ~FMD_MOD_LOCK;

	(void) pthread_cond_broadcast(&mp->mod_cv);
	(void) pthread_mutex_unlock(&mp->mod_lock);
}

int
fmd_module_trylock(fmd_module_t *mp)
{
	(void) pthread_mutex_lock(&mp->mod_lock);

	if (mp->mod_flags & FMD_MOD_LOCK) {
		(void) pthread_mutex_unlock(&mp->mod_lock);
		return (0);
	}

	mp->mod_owner = pthread_self();
	mp->mod_flags |= FMD_MOD_LOCK;

	(void) pthread_cond_broadcast(&mp->mod_cv);
	(void) pthread_mutex_unlock(&mp->mod_lock);

	return (1);
}

int
fmd_module_locked(fmd_module_t *mp)
{
	return ((mp->mod_flags & FMD_MOD_LOCK) &&
	    mp->mod_owner == pthread_self());
}

int
fmd_module_enter(fmd_module_t *mp, void (*func)(fmd_hdl_t *))
{
	volatile int err;

	(void) pthread_mutex_lock(&mp->mod_lock);

	ASSERT(!(mp->mod_flags & FMD_MOD_BUSY));
	mp->mod_flags |= FMD_MOD_BUSY;

	if ((err = setjmp(mp->mod_jmpbuf)) != 0) {
		(void) pthread_mutex_lock(&mp->mod_lock);
		fmd_module_error(mp, err);
	}

	(void) pthread_cond_broadcast(&mp->mod_cv);
	(void) pthread_mutex_unlock(&mp->mod_lock);

	/*
	 * If it's the first time through fmd_module_enter(), call the provided
	 * function on the module.  If no fmd_module_abort() results, we will
	 * fall through and return zero.  Otherwise we'll longjmp with an err,
	 * return to the setjmp() above, and return the error to our caller.
	 */
	if (err == 0 && func != NULL)
		(*func)((fmd_hdl_t *)mp);

	return (err);
}

void
fmd_module_exit(fmd_module_t *mp)
{
	(void) pthread_mutex_lock(&mp->mod_lock);

	ASSERT(mp->mod_flags & FMD_MOD_BUSY);
	mp->mod_flags &= ~FMD_MOD_BUSY;

	(void) pthread_cond_broadcast(&mp->mod_cv);
	(void) pthread_mutex_unlock(&mp->mod_lock);
}

/*
 * If the client.error policy has been set by a developer, stop or dump core
 * based on the policy; if we stop and are resumed we'll continue and execute
 * the default behavior to discard events in fmd_module_start().  If the caller
 * is the primary module thread, we reach this state by longjmp'ing back to
 * fmd_module_enter(), above.  If the caller is an auxiliary thread, we cancel
 * ourself and arrange for the primary thread to call fmd_module_abort().
 */
void
fmd_module_abort(fmd_module_t *mp, int err)
{
	uint_t policy = FMD_CERROR_UNLOAD;
	pthread_t tid = pthread_self();

	(void) fmd_conf_getprop(fmd.d_conf, "client.error", &policy);

	if (policy == FMD_CERROR_STOP) {
		fmd_error(err, "stopping after %s in client %s (%p)\n",
		    fmd_errclass(err), mp->mod_name, (void *)mp);
		(void) raise(SIGSTOP);
	} else if (policy == FMD_CERROR_ABORT) {
		fmd_panic("aborting due to %s in client %s (%p)\n",
		    fmd_errclass(err), mp->mod_name, (void *)mp);
	}

	/*
	 * If the caller is an auxiliary thread, cancel the current thread.  We
	 * prefer to cancel because it affords developers the option of using
	 * the pthread_cleanup* APIs.  If cancellations have been disabled,
	 * fall through to forcing the current thread to exit.  In either case
	 * we update mod_error (if zero) to enter the failed state.  Once that
	 * is set, further events received by the module will be discarded.
	 *
	 * We also set the FMD_MOD_FAIL bit, indicating an unrecoverable error.
	 * When an auxiliary thread fails, the module is left in a delicate
	 * state where it is likely not able to continue execution (even to
	 * execute its _fmd_fini() routine) because our caller may hold locks
	 * that are private to the module and can no longer be released.  The
	 * FMD_MOD_FAIL bit forces fmd_api_module_lock() to abort if any other
	 * module threads reach an API call, in an attempt to get them to exit.
	 */
	if (tid != mp->mod_thread->thr_tid) {
		(void) pthread_mutex_lock(&mp->mod_lock);

		if (mp->mod_error == 0)
			mp->mod_error = err;

		mp->mod_flags |= FMD_MOD_FAIL;
		(void) pthread_mutex_unlock(&mp->mod_lock);

		(void) pthread_cancel(tid);
		pthread_exit(NULL);
	}

	ASSERT(mp->mod_flags & FMD_MOD_BUSY);
	longjmp(mp->mod_jmpbuf, err);
}

void
fmd_module_hold(fmd_module_t *mp)
{
	(void) pthread_mutex_lock(&mp->mod_lock);

	TRACE((FMD_DBG_MOD, "hold %p (%s/%u)\n",
	    (void *)mp, mp->mod_name, mp->mod_refs));

	mp->mod_refs++;
	ASSERT(mp->mod_refs != 0);

	(void) pthread_mutex_unlock(&mp->mod_lock);
}

void
fmd_module_rele(fmd_module_t *mp)
{
	(void) pthread_mutex_lock(&mp->mod_lock);

	TRACE((FMD_DBG_MOD, "rele %p (%s/%u)\n",
	    (void *)mp, mp->mod_name, mp->mod_refs));

	ASSERT(mp->mod_refs != 0);

	if (--mp->mod_refs == 0)
		fmd_module_destroy(mp);
	else
		(void) pthread_mutex_unlock(&mp->mod_lock);
}

/*
 * Wrapper around libdiagcode's fm_dc_opendict() to load module dictionaries.
 * If the dictionary open is successful, the new dictionary is added to the
 * mod_dictv[] array and mod_codelen is updated with the new maximum length.
 */
int
fmd_module_dc_opendict(fmd_module_t *mp, const char *dict)
{
	struct fm_dc_handle *dcp, **dcv;
	char *dictdir, *dictnam, *p;
	size_t len;

	ASSERT(fmd_module_locked(mp));

	dictnam = strdupa(fmd_strbasename(dict));

	if ((p = strrchr(dictnam, '.')) != NULL &&
	    strcmp(p, ".dict") == 0)
		*p = '\0'; /* eliminate any trailing .dict suffix */

	/*
	 * If 'dict' is an absolute path, dictdir = $rootdir/`dirname dict`
	 * If 'dict' is not an absolute path, dictdir = $dictdir/`dirname dict`
	 */
	if (dict[0] == '/') {
		len = strlen(fmd.d_rootdir) + strlen(dict) + 1;
		dictdir = alloca(len);
		(void) snprintf(dictdir, len, "%s%s", fmd.d_rootdir, dict);
		(void) fmd_strdirname(dictdir);
	} else {
		(void) fmd_conf_getprop(fmd.d_conf, "dictdir", &p);
		len = strlen(fmd.d_rootdir) + strlen(p) + strlen(dict) + 3;
		dictdir = alloca(len);
		(void) snprintf(dictdir, len,
		    "%s/%s/%s", fmd.d_rootdir, p, dict);
		(void) fmd_strdirname(dictdir);
	}

	fmd_dprintf(FMD_DBG_MOD, "module %s opening %s -> %s/%s.dict\n",
	    mp->mod_name, dict, dictdir, dictnam);

	if ((dcp = fm_dc_opendict(FM_DC_VERSION, dictdir, dictnam)) == NULL)
		return (-1); /* errno is set for us */

	dcv = fmd_alloc(sizeof (dcp) * (mp->mod_dictc + 1), FMD_SLEEP);
	bcopy(mp->mod_dictv, dcv, sizeof (dcp) * mp->mod_dictc);
	fmd_free(mp->mod_dictv, sizeof (dcp) * mp->mod_dictc);
	mp->mod_dictv = dcv;
	mp->mod_dictv[mp->mod_dictc++] = dcp;

	len = fm_dc_codelen(dcp);
	mp->mod_codelen = MAX(mp->mod_codelen, len);

	return (0);
}

/*
 * Wrapper around libdiagcode's fm_dc_key2code() that examines all the module's
 * dictionaries.  We adhere to the libdiagcode return values and semantics.
 */
int
fmd_module_dc_key2code(fmd_module_t *mp,
    char *const keys[], char *code, size_t codelen)
{
	int i, err;

	for (i = 0; i < mp->mod_dictc; i++) {
		if ((err = fm_dc_key2code(mp->mod_dictv[i], (const char **)keys,
		    code, codelen)) == 0 || errno != ENOMSG)
			return (err);
	}

	return (fmd_set_errno(ENOMSG));
}

fmd_modhash_t *
fmd_modhash_create(void)
{
	fmd_modhash_t *mhp = fmd_alloc(sizeof (fmd_modhash_t), FMD_SLEEP);

	(void) pthread_rwlock_init(&mhp->mh_lock, NULL);
	mhp->mh_hashlen = fmd.d_str_buckets;
	mhp->mh_hash = fmd_zalloc(sizeof (void *) * mhp->mh_hashlen, FMD_SLEEP);
	mhp->mh_nelems = 0;

	return (mhp);
}

void
fmd_modhash_destroy(fmd_modhash_t *mhp)
{
	fmd_module_t *mp, *nmp;
	uint_t i;

	for (i = 0; i < mhp->mh_hashlen; i++) {
		for (mp = mhp->mh_hash[i]; mp != NULL; mp = nmp) {
			nmp = mp->mod_next;
			mp->mod_next = NULL;
			fmd_module_rele(mp);
		}
	}

	fmd_free(mhp->mh_hash, sizeof (void *) * mhp->mh_hashlen);
	(void) pthread_rwlock_destroy(&mhp->mh_lock);
	fmd_free(mhp, sizeof (fmd_modhash_t));
}

static void
fmd_modhash_loaddir(fmd_modhash_t *mhp, const char *dir,
    const fmd_modops_t *ops, const char *suffix)
{
	char path[PATH_MAX];
	struct dirent *dp;
	const char *p;
	DIR *dirp;

	if ((dirp = opendir(dir)) == NULL)
		return; /* failed to open directory; just skip it */

	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_name[0] == '.')
			continue; /* skip "." and ".." */

		p = strrchr(dp->d_name, '.');

		if (p != NULL && strcmp(p, ".conf") == 0)
			continue; /* skip .conf files */

		if (suffix != NULL && (p == NULL || strcmp(p, suffix) != 0))
			continue; /* skip files with the wrong suffix */

		(void) snprintf(path, sizeof (path), "%s/%s", dir, dp->d_name);
		(void) fmd_modhash_load(mhp, path, ops);
	}

	(void) closedir(dirp);
}

void
fmd_modhash_loadall(fmd_modhash_t *mhp, const fmd_conf_path_t *pap,
    const fmd_modops_t *ops, const char *suffix)
{
	int i;

	for (i = 0; i < pap->cpa_argc; i++)
		fmd_modhash_loaddir(mhp, pap->cpa_argv[i], ops, suffix);
}

void
fmd_modhash_apply(fmd_modhash_t *mhp, void (*func)(fmd_module_t *))
{
	fmd_module_t *mp, *np;
	uint_t i;

	(void) pthread_rwlock_rdlock(&mhp->mh_lock);

	for (i = 0; i < mhp->mh_hashlen; i++) {
		for (mp = mhp->mh_hash[i]; mp != NULL; mp = np) {
			np = mp->mod_next;
			func(mp);
		}
	}

	(void) pthread_rwlock_unlock(&mhp->mh_lock);
}

void
fmd_modhash_tryapply(fmd_modhash_t *mhp, void (*func)(fmd_module_t *))
{
	fmd_module_t *mp, *np;
	uint_t i;

	if (mhp == NULL || pthread_rwlock_tryrdlock(&mhp->mh_lock) != 0)
		return; /* not initialized or couldn't grab lock */

	for (i = 0; i < mhp->mh_hashlen; i++) {
		for (mp = mhp->mh_hash[i]; mp != NULL; mp = np) {
			np = mp->mod_next;
			func(mp);
		}
	}

	(void) pthread_rwlock_unlock(&mhp->mh_lock);
}

void
fmd_modhash_dispatch(fmd_modhash_t *mhp, fmd_event_t *ep)
{
	fmd_module_t *mp;
	uint_t i;

	fmd_event_hold(ep);
	(void) pthread_rwlock_rdlock(&mhp->mh_lock);

	for (i = 0; i < mhp->mh_hashlen; i++) {
		for (mp = mhp->mh_hash[i]; mp != NULL; mp = mp->mod_next) {
			/*
			 * If FMD_MOD_INIT is set but MOD_FINI, MOD_QUIT, and
			 * mod_error are all zero, then the module is active:
			 * enqueue the event in the corresponding event queue.
			 */
			(void) pthread_mutex_lock(&mp->mod_lock);

			if ((mp->mod_flags & (FMD_MOD_INIT | FMD_MOD_FINI |
			    FMD_MOD_QUIT)) == FMD_MOD_INIT && !mp->mod_error) {

				/*
				 * If the event we're dispatching is of type
				 * FMD_EVT_TOPO and there are already redundant
				 * FMD_EVT_TOPO events in this module's queue,
				 * then drop those before adding the new one.
				 */
				if (FMD_EVENT_TYPE(ep) == FMD_EVT_TOPO)
					fmd_eventq_drop_topo(mp->mod_queue);

				fmd_eventq_insert_at_time(mp->mod_queue, ep);

			}
			(void) pthread_mutex_unlock(&mp->mod_lock);
		}
	}

	(void) pthread_rwlock_unlock(&mhp->mh_lock);
	fmd_event_rele(ep);
}

fmd_module_t *
fmd_modhash_lookup(fmd_modhash_t *mhp, const char *name)
{
	fmd_module_t *mp;
	uint_t h;

	(void) pthread_rwlock_rdlock(&mhp->mh_lock);
	h = fmd_strhash(name) % mhp->mh_hashlen;

	for (mp = mhp->mh_hash[h]; mp != NULL; mp = mp->mod_next) {
		if (strcmp(name, mp->mod_name) == 0)
			break;
	}

	if (mp != NULL)
		fmd_module_hold(mp);
	else
		(void) fmd_set_errno(EFMD_MOD_NOMOD);

	(void) pthread_rwlock_unlock(&mhp->mh_lock);
	return (mp);
}

fmd_module_t *
fmd_modhash_load(fmd_modhash_t *mhp, const char *path, const fmd_modops_t *ops)
{
	char name[PATH_MAX], *p;
	fmd_module_t *mp;
	int tries = 0;
	uint_t h;

	(void) strlcpy(name, fmd_strbasename(path), sizeof (name));
	if ((p = strrchr(name, '.')) != NULL && strcmp(p, ".so") == 0)
		*p = '\0'; /* strip trailing .so from any module name */

	(void) pthread_rwlock_wrlock(&mhp->mh_lock);
	h = fmd_strhash(name) % mhp->mh_hashlen;

	/*
	 * First check to see if a module is already present in the hash table
	 * for this name.  If so, the module is already loaded: skip it.
	 */
	for (mp = mhp->mh_hash[h]; mp != NULL; mp = mp->mod_next) {
		if (strcmp(name, mp->mod_name) == 0)
			break;
	}

	if (mp != NULL) {
		(void) pthread_rwlock_unlock(&mhp->mh_lock);
		(void) fmd_set_errno(EFMD_MOD_LOADED);
		return (NULL);
	}

	/*
	 * fmd_module_create() will return a held (as if by fmd_module_hold())
	 * module.  We leave this hold in place to correspond to the hash-in.
	 */
	while ((mp = fmd_module_create(path, ops)) == NULL) {
		if (tries++ != 0 || errno != EFMD_CKPT_INVAL) {
			(void) pthread_rwlock_unlock(&mhp->mh_lock);
			return (NULL); /* errno is set for us */
		}
	}

	mp->mod_hash = mhp;
	mp->mod_next = mhp->mh_hash[h];

	mhp->mh_hash[h] = mp;
	mhp->mh_nelems++;

	(void) pthread_rwlock_unlock(&mhp->mh_lock);
	return (mp);
}

int
fmd_modhash_unload(fmd_modhash_t *mhp, const char *name)
{
	fmd_module_t *mp, **pp;
	uint_t h;

	(void) pthread_rwlock_wrlock(&mhp->mh_lock);
	h = fmd_strhash(name) % mhp->mh_hashlen;
	pp = &mhp->mh_hash[h];

	for (mp = *pp; mp != NULL; mp = mp->mod_next) {
		if (strcmp(name, mp->mod_name) == 0)
			break;
		else
			pp = &mp->mod_next;
	}

	if (mp == NULL) {
		(void) pthread_rwlock_unlock(&mhp->mh_lock);
		return (fmd_set_errno(EFMD_MOD_NOMOD));
	}

	*pp = mp->mod_next;
	mp->mod_next = NULL;

	ASSERT(mhp->mh_nelems != 0);
	mhp->mh_nelems--;

	(void) pthread_rwlock_unlock(&mhp->mh_lock);

	fmd_module_unload(mp);
	fmd_module_rele(mp);

	return (0);
}

void
fmd_modstat_publish(fmd_module_t *mp)
{
	(void) pthread_mutex_lock(&mp->mod_lock);

	ASSERT(mp->mod_flags & FMD_MOD_STSUB);
	mp->mod_flags |= FMD_MOD_STPUB;
	(void) pthread_cond_broadcast(&mp->mod_cv);

	while (mp->mod_flags & FMD_MOD_STPUB)
		(void) pthread_cond_wait(&mp->mod_cv, &mp->mod_lock);

	(void) pthread_mutex_unlock(&mp->mod_lock);
}

int
fmd_modstat_snapshot(fmd_module_t *mp, fmd_ustat_snap_t *uss)
{
	fmd_event_t *e;
	int err;

	/*
	 * Grab the module lock and wait for the STSUB bit to be clear.  Then
	 * set it to indicate we are a subscriber and everyone else must wait.
	 */
	(void) pthread_mutex_lock(&mp->mod_lock);

	while (mp->mod_error == 0 && (mp->mod_flags & FMD_MOD_STSUB))
		(void) pthread_cond_wait(&mp->mod_cv, &mp->mod_lock);

	if (mp->mod_error != 0) {
		(void) pthread_mutex_unlock(&mp->mod_lock);
		return (fmd_set_errno(EFMD_HDL_ABORT));
	}

	mp->mod_flags |= FMD_MOD_STSUB;
	(void) pthread_cond_broadcast(&mp->mod_cv);
	(void) pthread_mutex_unlock(&mp->mod_lock);

	/*
	 * Create a stats pseudo-event and dispatch it to the module, forcing
	 * it to next execute its custom snapshot routine (or the empty one).
	 */
	e = fmd_event_create(FMD_EVT_STATS, FMD_HRT_NOW, NULL, NULL);
	fmd_eventq_insert_at_head(mp->mod_queue, e);

	/*
	 * Grab the module lock and then wait on mod_cv for STPUB to be set,
	 * indicating the snapshot routine is completed and the module is idle.
	 */
	(void) pthread_mutex_lock(&mp->mod_lock);

	while (mp->mod_error == 0 && !(mp->mod_flags & FMD_MOD_STPUB)) {
		struct timespec tms;

		(void) pthread_cond_wait(&mp->mod_cv, &mp->mod_lock);
		(void) pthread_mutex_unlock(&mp->mod_lock);
		tms.tv_sec = 0;
		tms.tv_nsec = 10000000;
		(void) nanosleep(&tms, NULL);
		(void) pthread_mutex_lock(&mp->mod_lock);
	}

	if (mp->mod_error != 0) {
		(void) pthread_mutex_unlock(&mp->mod_lock);
		return (fmd_set_errno(EFMD_HDL_ABORT));
	}

	(void) pthread_cond_broadcast(&mp->mod_cv);
	(void) pthread_mutex_unlock(&mp->mod_lock);

	/*
	 * Update ms_snaptime and take the actual snapshot of the various
	 * statistics while the module is quiescent and waiting for us.
	 */
	(void) pthread_mutex_lock(&mp->mod_stats_lock);

	if (mp->mod_stats != NULL) {
		mp->mod_stats->ms_snaptime.fmds_value.ui64 = gethrtime();
		err = fmd_ustat_snapshot(mp->mod_ustat, uss);
	} else
		err = fmd_set_errno(EFMD_HDL_ABORT);

	(void) pthread_mutex_unlock(&mp->mod_stats_lock);

	/*
	 * With the snapshot complete, grab the module lock and clear both
	 * STSUB and STPUB, permitting everyone to wake up and continue.
	 */
	(void) pthread_mutex_lock(&mp->mod_lock);

	ASSERT(mp->mod_flags & FMD_MOD_STSUB);
	ASSERT(mp->mod_flags & FMD_MOD_STPUB);
	mp->mod_flags &= ~(FMD_MOD_STSUB | FMD_MOD_STPUB);

	(void) pthread_cond_broadcast(&mp->mod_cv);
	(void) pthread_mutex_unlock(&mp->mod_lock);

	return (err);
}

struct topo_hdl *
fmd_module_topo_hold(fmd_module_t *mp)
{
	fmd_modtopo_t *mtp;

	ASSERT(fmd_module_locked(mp));

	mtp = fmd_zalloc(sizeof (fmd_modtopo_t), FMD_SLEEP);
	mtp->mt_topo = mp->mod_topo_current;
	fmd_topo_addref(mtp->mt_topo);
	fmd_list_prepend(&mp->mod_topolist, mtp);

	return (mtp->mt_topo->ft_hdl);
}

int
fmd_module_topo_rele(fmd_module_t *mp, struct topo_hdl *hdl)
{
	fmd_modtopo_t *mtp;

	ASSERT(fmd_module_locked(mp));

	for (mtp = fmd_list_next(&mp->mod_topolist); mtp != NULL;
	    mtp = fmd_list_next(mtp)) {
		if (mtp->mt_topo->ft_hdl == hdl)
			break;
	}

	if (mtp == NULL)
		return (-1);

	fmd_list_delete(&mp->mod_topolist, mtp);
	fmd_topo_rele(mtp->mt_topo);
	fmd_free(mtp, sizeof (fmd_modtopo_t));
	return (0);
}
