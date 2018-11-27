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

#include <sys/types.h>
#include <sys/fm/protocol.h>
#include <fm/topo_hc.h>
#include <uuid/uuid.h>

#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <syslog.h>
#include <alloca.h>
#include <stddef.h>
#include <door.h>

#include <fmd_module.h>
#include <fmd_api.h>
#include <fmd_string.h>
#include <fmd_subr.h>
#include <fmd_error.h>
#include <fmd_event.h>
#include <fmd_eventq.h>
#include <fmd_dispq.h>
#include <fmd_timerq.h>
#include <fmd_thread.h>
#include <fmd_ustat.h>
#include <fmd_case.h>
#include <fmd_protocol.h>
#include <fmd_buf.h>
#include <fmd_asru.h>
#include <fmd_fmri.h>
#include <fmd_topo.h>
#include <fmd_ckpt.h>
#include <fmd_xprt.h>

#include <fmd.h>

/*
 * Table of configuration file variable types ops-vector pointers.  We use this
 * to convert from the property description array specified by the module to an
 * array of fmd_conf_formal_t's.  The order of this array must match the order
 * of #define values specified in <fmd_api.h> (i.e. FMD_TYPE_BOOL must be 0).
 * For now, the fmd_conf_list and fmd_conf_path types are not supported as we
 * do not believe modules need them and they would require more complexity.
 */
static const fmd_conf_ops_t *const _fmd_prop_ops[] = {
	&fmd_conf_bool,		/* FMD_TYPE_BOOL */
	&fmd_conf_int32,	/* FMD_TYPE_INT32 */
	&fmd_conf_uint32,	/* FMD_TYPE_UINT32 */
	&fmd_conf_int64,	/* FMD_TYPE_INT64 */
	&fmd_conf_uint64,	/* FMD_TYPE_UINT64 */
	&fmd_conf_string,	/* FMD_TYPE_STRING */
	&fmd_conf_time,		/* FMD_TYPE_TIME */
	&fmd_conf_size,		/* FMD_TYPE_SIZE */
};

static void fmd_api_verror(fmd_module_t *, int, const char *, va_list)
    __NORETURN;
static void fmd_api_error(fmd_module_t *, int, const char *, ...) __NORETURN;

/*
 * fmd_api_vxerror() provides the engine underlying the fmd_hdl_[v]error() API
 * calls and the fmd_api_[v]error() utility routine defined below.  The routine
 * formats the error, optionally associated with a particular errno code 'err',
 * and logs it as an ereport associated with the calling module.  Depending on
 * other optional properties, we also emit a message to stderr and to syslog.
 */
static void
fmd_api_vxerror(fmd_module_t *mp, int err, const char *format, va_list ap)
{
	int raw_err = err;
	nvlist_t *nvl;
	fmd_event_t *e;
	char *class, *msg;
	size_t len1, len2;
	char c;

	/*
	 * fmd_api_vxerror() counts as both an error of class EFMD_MODULE
	 * as well as an instance of 'err' w.r.t. our internal bean counters.
	 */
	(void) pthread_mutex_lock(&fmd.d_err_lock);
	fmd.d_errstats[EFMD_MODULE - EFMD_UNKNOWN].fmds_value.ui64++;

	if (err > EFMD_UNKNOWN && err < EFMD_END)
		fmd.d_errstats[err - EFMD_UNKNOWN].fmds_value.ui64++;

	(void) pthread_mutex_unlock(&fmd.d_err_lock);

	/*
	 * Format the message using vsnprintf().  As usual, if the format has a
	 * newline in it, it is printed alone; otherwise strerror() is added.
	 */
	if (strchr(format, '\n') != NULL)
		err = 0; /* err is not relevant in the message */

	len1 = vsnprintf(&c, 1, format, ap);
	len2 = err != 0 ? snprintf(&c, 1, ": %s\n", fmd_strerror(err)) : 0;

	msg = fmd_alloc(len1 + len2 + 1, FMD_SLEEP);
	(void) vsnprintf(msg, len1 + 1, format, ap);

	if (err != 0) {
		(void) snprintf(&msg[len1], len2 + 1,
		    ": %s\n", fmd_strerror(err));
	}

	/*
	 * Create an error event corresponding to the error, insert it into the
	 * error log, and dispatch it to the fmd-self-diagnosis engine.
	 */
	if (mp != fmd.d_self && (raw_err != EFMD_HDL_ABORT || fmd.d_running)) {
		if ((c = msg[len1 + len2 - 1]) == '\n')
			msg[len1 + len2 - 1] = '\0'; /* strip \n for event */

		nvl = fmd_protocol_moderror(mp, err, msg);

		if (c == '\n')
			msg[len1 + len2 - 1] = c;

		(void) nvlist_lookup_string(nvl, FM_CLASS, &class);
		e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, class);

		(void) pthread_rwlock_rdlock(&fmd.d_log_lock);
		fmd_log_append(fmd.d_errlog, e, NULL);
		(void) pthread_rwlock_unlock(&fmd.d_log_lock);

		fmd_event_transition(e, FMD_EVS_ACCEPTED);
		fmd_event_commit(e);

		fmd_dispq_dispatch(fmd.d_disp, e, class);
	}

	/*
	 * Similar to fmd_vdebug(), if the debugging switches are enabled we
	 * echo the module name and message to stderr and/or syslog.  Unlike
	 * fmd_vdebug(), we also print to stderr if foreground mode is enabled.
	 * We also print the message if a built-in module is aborting before
	 * fmd has detached from its parent (e.g. default transport failure).
	 */
	if (fmd.d_fg || (fmd.d_hdl_dbout & FMD_DBOUT_STDERR) || (
	    raw_err == EFMD_HDL_ABORT && !fmd.d_running)) {
		(void) pthread_mutex_lock(&fmd.d_err_lock);
		(void) fprintf(stderr, "%s: %s: %s",
		    fmd.d_pname, mp->mod_name, msg);
		(void) pthread_mutex_unlock(&fmd.d_err_lock);
	}

	if (fmd.d_hdl_dbout & FMD_DBOUT_SYSLOG) {
		syslog(LOG_ERR | LOG_DAEMON, "%s ERROR: %s: %s",
		    fmd.d_pname, mp->mod_name, msg);
	}

	fmd_free(msg, len1 + len2 + 1);
}

/*PRINTFLIKE3*/
static void
fmd_api_xerror(fmd_module_t *mp, int err, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	fmd_api_vxerror(mp, err, format, ap);
	va_end(ap);
}

/*
 * fmd_api_verror() is a wrapper around fmd_api_vxerror() for API subroutines.
 * It calls fmd_module_unlock() on behalf of its caller, logs the error, and
 * then aborts the API call and the surrounding module entry point by doing an
 * fmd_module_abort(), which longjmps to the place where we entered the module.
 */
static void
fmd_api_verror(fmd_module_t *mp, int err, const char *format, va_list ap)
{
	if (fmd_module_locked(mp))
		fmd_module_unlock(mp);

	fmd_api_vxerror(mp, err, format, ap);
	fmd_module_abort(mp, err);
}

/*PRINTFLIKE3*/
static void
fmd_api_error(fmd_module_t *mp, int err, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	fmd_api_verror(mp, err, format, ap);
	va_end(ap);
}

/*
 * Common code for fmd_api_module_lock() and fmd_api_transport_impl().  This
 * code verifies that the handle is valid and associated with a proper thread.
 */
static fmd_module_t *
fmd_api_module(fmd_hdl_t *hdl)
{
	fmd_thread_t *tp;
	fmd_module_t *mp;

	/*
	 * If our TSD is not present at all, this is either a serious bug or
	 * someone has created a thread behind our back and is using fmd's API.
	 * We can't call fmd_api_error() because we can't be sure that we can
	 * unwind our state back to an enclosing fmd_module_dispatch(), so we
	 * must panic instead.  This is likely a module design or coding error.
	 */
	if ((tp = pthread_getspecific(fmd.d_key)) == NULL) {
		fmd_panic("fmd module api call made using "
		    "client handle %p from unknown thread\n", (void *)hdl);
	}

	/*
	 * If our TSD refers to the root module and is a non-private
	 * door server thread,  then it was created asynchronously at the
	 * request of a module but is using now the module API as an
	 * auxiliary module thread.  We reset tp->thr_mod to the module
	 * handle so it can act as a module thread.
	 *
	 * If more than one module uses non-private doors then the
	 * "client handle is not valid" check below can fail since
	 * door server threads for such doors can service *any*
	 * non-private door.  We use non-private door for legacy sysevent
	 * alone.
	 */
	if (tp->thr_mod == fmd.d_rmod && tp->thr_func == &fmd_door_server)
		tp->thr_mod = (fmd_module_t *)hdl;

	if ((mp = tp->thr_mod) != (fmd_module_t *)hdl) {
		fmd_api_error(mp, EFMD_HDL_INVAL,
		    "client handle %p is not valid\n", (void *)hdl);
	}

	if (mp->mod_flags & FMD_MOD_FAIL) {
		fmd_api_error(mp, EFMD_MOD_FAIL,
		    "module has experienced an unrecoverable error\n");
	}

	return (mp);
}

/*
 * fmd_api_module_lock() is used as a wrapper around fmd_module_lock() and a
 * common prologue to each fmd_api.c routine.  It verifies that the handle is
 * valid and owned by the current server thread, locks the handle, and then
 * verifies that the caller is performing an operation on a registered handle.
 * If any tests fail, the entire API call is aborted by fmd_api_error().
 */
static fmd_module_t *
fmd_api_module_lock(fmd_hdl_t *hdl)
{
	fmd_module_t *mp = fmd_api_module(hdl);

	fmd_module_lock(mp);

	if (mp->mod_info == NULL) {
		fmd_api_error(mp, EFMD_HDL_NOTREG,
		    "client handle %p has not been registered\n", (void *)hdl);
	}

	return (mp);
}

/*
 * Utility function for API entry points that accept fmd_case_t's.  We cast cp
 * to fmd_case_impl_t and check to make sure the case is owned by the caller.
 */
static fmd_case_impl_t *
fmd_api_case_impl(fmd_module_t *mp, fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	if (cip == NULL || cip->ci_mod != mp) {
		fmd_api_error(mp, EFMD_CASE_OWNER,
		    "case %p is invalid or not owned by caller\n", (void *)cip);
	}

	return (cip);
}

/*
 * Utility function for API entry points that accept fmd_xprt_t's.  We cast xp
 * to fmd_transport_t and check to make sure the case is owned by the caller.
 * Note that we could make this check safer by actually walking mp's transport
 * list, but that requires holding the module lock and this routine needs to be
 * MT-hot w.r.t. auxiliary module threads.  Ultimately any loadable module can
 * cause us to crash anyway, so we optimize for scalability over safety here.
 */
static fmd_xprt_impl_t *
fmd_api_transport_impl(fmd_hdl_t *hdl, fmd_xprt_t *xp)
{
	fmd_module_t *mp = fmd_api_module(hdl);
	fmd_xprt_impl_t *xip = (fmd_xprt_impl_t *)xp;

	if (xip == NULL || xip->xi_queue->eq_mod != mp) {
		fmd_api_error(mp, EFMD_XPRT_OWNER,
		    "xprt %p is invalid or not owned by caller\n", (void *)xp);
	}

	return (xip);
}

/*
 * fmd_hdl_register() is the one function which cannot use fmd_api_error() to
 * report errors, because that routine causes the module to abort.  Failure to
 * register is instead handled by having fmd_hdl_register() return an error to
 * the _fmd_init() function and then detecting no registration when it returns.
 * So we use this routine for fmd_hdl_register() error paths instead.
 */
static int
fmd_hdl_register_error(fmd_module_t *mp, int err)
{
	if (fmd_module_locked(mp))
		fmd_module_unlock(mp);

	fmd_api_xerror(mp, err, "failed to register");
	return (fmd_set_errno(err));
}

static void
fmd_hdl_nop(void)
{
	/* empty function for use with unspecified module entry points */
}

int
fmd_hdl_register(fmd_hdl_t *hdl, int version, const fmd_hdl_info_t *mip)
{
	fmd_thread_t *tp = pthread_getspecific(fmd.d_key);
	fmd_module_t *mp = tp->thr_mod;

	const fmd_prop_t *prop;
	const fmd_conf_path_t *pap;
	fmd_conf_formal_t *cfp;
	fmd_hdl_ops_t ops;

	const char *conf = NULL;
	char buf[PATH_MAX];
	int i;

	if (mp != (fmd_module_t *)hdl)
		return (fmd_hdl_register_error(mp, EFMD_HDL_INVAL));

	fmd_module_lock(mp);

	/*
	 * First perform some sanity checks on our input.  The API version must
	 * be supported by FMD and the handle can only be registered once by
	 * the module thread to which we assigned this client handle.  The info
	 * provided for the handle must be valid and have the minimal settings.
	 */
	if (version > FMD_API_VERSION_5)
		return (fmd_hdl_register_error(mp, EFMD_VER_NEW));

	if (version < FMD_API_VERSION_1)
		return (fmd_hdl_register_error(mp, EFMD_VER_OLD));

	if (mp->mod_conf != NULL)
		return (fmd_hdl_register_error(mp, EFMD_HDL_REG));

	if (pthread_self() != mp->mod_thread->thr_tid)
		return (fmd_hdl_register_error(mp, EFMD_HDL_TID));

	if (mip == NULL || mip->fmdi_desc == NULL ||
	    mip->fmdi_vers == NULL || mip->fmdi_ops == NULL)
		return (fmd_hdl_register_error(mp, EFMD_HDL_INFO));

	/*
	 * Copy the module's ops vector into a local variable to account for
	 * changes in the module ABI.  Then if any of the optional entry points
	 * are NULL, set them to nop so we don't have to check before calling.
	 */
	bzero(&ops, sizeof (ops));

	if (version < FMD_API_VERSION_3)
		bcopy(mip->fmdi_ops, &ops, offsetof(fmd_hdl_ops_t, fmdo_send));
	else if (version < FMD_API_VERSION_4)
		bcopy(mip->fmdi_ops, &ops,
		    offsetof(fmd_hdl_ops_t, fmdo_topo));
	else
		bcopy(mip->fmdi_ops, &ops, sizeof (ops));

	if (ops.fmdo_recv == NULL)
		ops.fmdo_recv = (void (*)())fmd_hdl_nop;
	if (ops.fmdo_timeout == NULL)
		ops.fmdo_timeout = (void (*)())fmd_hdl_nop;
	if (ops.fmdo_close == NULL)
		ops.fmdo_close = (void (*)())fmd_hdl_nop;
	if (ops.fmdo_stats == NULL)
		ops.fmdo_stats = (void (*)())fmd_hdl_nop;
	if (ops.fmdo_gc == NULL)
		ops.fmdo_gc = (void (*)())fmd_hdl_nop;
	if (ops.fmdo_send == NULL)
		ops.fmdo_send = (int (*)())fmd_hdl_nop;
	if (ops.fmdo_topo == NULL)
		ops.fmdo_topo = (void (*)())fmd_hdl_nop;

	/*
	 * Make two passes through the property array to initialize the formals
	 * to use for processing the module's .conf file.  In the first pass,
	 * we validate the types and count the number of properties.  In the
	 * second pass we copy the strings and fill in the appropriate ops.
	 */
	for (prop = mip->fmdi_props, i = 0; prop != NULL &&
	    prop->fmdp_name != NULL; prop++, i++) {
		if (prop->fmdp_type >=
		    sizeof (_fmd_prop_ops) / sizeof (_fmd_prop_ops[0])) {
			fmd_api_xerror(mp, EFMD_HDL_PROP,
			    "property %s uses invalid type %u\n",
			    prop->fmdp_name, prop->fmdp_type);
			return (fmd_hdl_register_error(mp, EFMD_HDL_PROP));
		}
	}

	mp->mod_argc = i;
	mp->mod_argv = fmd_zalloc(sizeof (fmd_conf_formal_t) * i, FMD_SLEEP);

	prop = mip->fmdi_props;
	cfp = mp->mod_argv;

	for (i = 0; i < mp->mod_argc; i++, prop++, cfp++) {
		cfp->cf_name = fmd_strdup(prop->fmdp_name, FMD_SLEEP);
		cfp->cf_ops = _fmd_prop_ops[prop->fmdp_type];
		cfp->cf_default = fmd_strdup(prop->fmdp_defv, FMD_SLEEP);
	}

	/*
	 * If this module came from an on-disk file, compute the name of the
	 * corresponding .conf file and parse properties from it if it exists.
	 */
	if (mp->mod_path != NULL) {
		(void) strlcpy(buf, mp->mod_path, sizeof (buf));
		(void) fmd_strdirname(buf);

		(void) strlcat(buf, "/", sizeof (buf));
		(void) strlcat(buf, mp->mod_name, sizeof (buf));
		(void) strlcat(buf, ".conf", sizeof (buf));

		if (access(buf, F_OK) == 0)
			conf = buf;
	}

	if ((mp->mod_conf = fmd_conf_open(conf,
	    mp->mod_argc, mp->mod_argv, 0)) == NULL)
		return (fmd_hdl_register_error(mp, EFMD_MOD_CONF));

	fmd_conf_propagate(fmd.d_conf, mp->mod_conf, mp->mod_name);

	/*
	 * Look up the list of the libdiagcode dictionaries associated with the
	 * module.  If none were specified, use the value from daemon's config.
	 * We only fail if the module specified an explicit dictionary.
	 */
	(void) fmd_conf_getprop(mp->mod_conf, FMD_PROP_DICTIONARIES, &pap);
	if (pap->cpa_argc == 0 && mp->mod_ops == &fmd_bltin_ops)
		(void) fmd_conf_getprop(fmd.d_conf, "self.dict", &pap);

	for (i = 0; i < pap->cpa_argc; i++) {
		if (fmd_module_dc_opendict(mp, pap->cpa_argv[i]) != 0) {
			fmd_api_xerror(mp, errno,
			    "failed to open dictionary %s", pap->cpa_argv[i]);
			return (fmd_hdl_register_error(mp, EFMD_MOD_CONF));
		}
	}

	/*
	 * Make a copy of the handle information and store it in mod_info.  We
	 * do not need to bother copying fmdi_props since they're already read.
	 */
	mp->mod_info = fmd_alloc(sizeof (fmd_hdl_info_t), FMD_SLEEP);
	mp->mod_info->fmdi_desc = fmd_strdup(mip->fmdi_desc, FMD_SLEEP);
	mp->mod_info->fmdi_vers = fmd_strdup(mip->fmdi_vers, FMD_SLEEP);
	mp->mod_info->fmdi_ops = fmd_alloc(sizeof (fmd_hdl_ops_t), FMD_SLEEP);
	bcopy(&ops, (void *)mp->mod_info->fmdi_ops, sizeof (fmd_hdl_ops_t));
	mp->mod_info->fmdi_props = NULL;

	/*
	 * Store a copy of module version in mp for fmd_scheme_fmd_present()
	 */
	if (mp->mod_vers == NULL)
		mp->mod_vers = fmd_strdup(mip->fmdi_vers, FMD_SLEEP);

	/*
	 * Allocate an FMRI representing this module.  We'll use this later
	 * if the module decides to publish any events (e.g. list.suspects).
	 */
	mp->mod_fmri = fmd_protocol_fmri_module(mp);

	/*
	 * Any subscriptions specified in the conf file are now stored in the
	 * corresponding property.  Add all of these to the dispatch queue.
	 */
	(void) fmd_conf_getprop(mp->mod_conf, FMD_PROP_SUBSCRIPTIONS, &pap);

	for (i = 0; i < pap->cpa_argc; i++) {
		fmd_dispq_insert(fmd.d_disp, mp->mod_queue, pap->cpa_argv[i]);
		fmd_xprt_subscribe_all(pap->cpa_argv[i]);
	}

	/*
	 * Unlock the module and restore any pre-existing module checkpoint.
	 * If the checkpoint is missing or corrupt, we just keep going.
	 */
	fmd_module_unlock(mp);
	fmd_ckpt_restore(mp);
	return (0);
}

/*
 * If an auxiliary thread exists for the specified module at unregistration
 * time, send it an asynchronous cancellation to force it to exit and then
 * join with it (we expect this to either succeed quickly or return ESRCH).
 * Once this is complete we can destroy the associated fmd_thread_t data.
 */
static void
fmd_module_thrcancel(fmd_idspace_t *ids, id_t id, fmd_module_t *mp)
{
	fmd_thread_t *tp = fmd_idspace_getspecific(ids, id);

	/*
	 * Door service threads are not cancellable (worse - if they're
	 * waiting in door_return then that is interrupted, but they then spin
	 * endlessly!).  Non-private door service threads are not tracked
	 * in the module thread idspace so it's only private server threads
	 * created via fmd_doorthr_create that we'll encounter.  In most
	 * cases the module _fini should have tidied up (e.g., calling
	 * sysevent_evc_unbind which will cleanup door threads if
	 * sysevent_evc_xsubscribe was used).  One case that does not
	 * clean up is sysev_fini which explicitly does not unbind the
	 * channel, so we must skip any remaining door threads here.
	 */
	if (tp->thr_isdoor) {
		fmd_dprintf(FMD_DBG_MOD, "not cancelling %s private door "
		    "thread %u\n", mp->mod_name, tp->thr_tid);
		fmd_thread_destroy(tp, FMD_THREAD_NOJOIN);
		return;
	}

	fmd_dprintf(FMD_DBG_MOD, "cancelling %s auxiliary thread %u\n",
	    mp->mod_name, tp->thr_tid);

	ASSERT(tp->thr_tid == id);
	(void) pthread_cancel(tp->thr_tid);
	(void) pthread_join(tp->thr_tid, NULL);

	fmd_thread_destroy(tp, FMD_THREAD_NOJOIN);
}

void
fmd_module_unregister(fmd_module_t *mp)
{
	fmd_conf_formal_t *cfp = mp->mod_argv;
	const fmd_conf_path_t *pap;
	fmd_case_t *cp;
	fmd_xprt_t *xp;
	int i;

	TRACE((FMD_DBG_MOD, "unregister %p (%s)", (void *)mp, mp->mod_name));
	ASSERT(fmd_module_locked(mp));

	/*
	 * If any transports are still open, they have send threads that are
	 * using the module handle: shut them down and join with these threads.
	 */
	while ((xp = fmd_list_next(&mp->mod_transports)) != NULL)
		fmd_xprt_destroy(xp);

	/*
	 * If any auxiliary threads exist, they may be using our module handle,
	 * and therefore could cause a fault as soon as we start destroying it.
	 * Module writers should clean up any threads before unregistering: we
	 * forcibly cancel any remaining auxiliary threads before proceeding.
	 */
	fmd_idspace_apply(mp->mod_threads,
	    (void (*)())fmd_module_thrcancel, mp);

	if (mp->mod_error == 0)
		fmd_ckpt_save(mp); /* take one more checkpoint if needed */

	/*
	 * Delete any cases associated with the module (UNSOLVED, SOLVED, or
	 * CLOSE_WAIT) as if fmdo_close() has finished processing them.
	 */
	while ((cp = fmd_list_next(&mp->mod_cases)) != NULL)
		fmd_case_delete(cp);

	fmd_ustat_delete_references(mp->mod_ustat);
	(void) fmd_conf_getprop(mp->mod_conf, FMD_PROP_SUBSCRIPTIONS, &pap);

	for (i = 0; i < pap->cpa_argc; i++) {
		fmd_xprt_unsubscribe_all(pap->cpa_argv[i]);
		fmd_dispq_delete(fmd.d_disp, mp->mod_queue, pap->cpa_argv[i]);
	}

	fmd_conf_close(mp->mod_conf);
	mp->mod_conf = NULL;

	for (i = 0; i < mp->mod_argc; i++, cfp++) {
		fmd_strfree((char *)cfp->cf_name);
		fmd_strfree((char *)cfp->cf_default);
	}

	fmd_free(mp->mod_argv, sizeof (fmd_conf_formal_t) * mp->mod_argc);
	mp->mod_argv = NULL;
	mp->mod_argc = 0;

	nvlist_free(mp->mod_fmri);
	mp->mod_fmri = NULL;

	fmd_strfree((char *)mp->mod_info->fmdi_desc);
	fmd_strfree((char *)mp->mod_info->fmdi_vers);
	fmd_free((void *)mp->mod_info->fmdi_ops, sizeof (fmd_hdl_ops_t));
	fmd_free(mp->mod_info, sizeof (fmd_hdl_info_t));
	mp->mod_info = NULL;

	fmd_eventq_abort(mp->mod_queue);
}

void
fmd_hdl_unregister(fmd_hdl_t *hdl)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_module_unregister(mp);
	fmd_module_unlock(mp);
}

void
fmd_hdl_subscribe(fmd_hdl_t *hdl, const char *class)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);

	if (fmd_conf_setprop(mp->mod_conf,
	    FMD_PROP_SUBSCRIPTIONS, class) == 0) {
		fmd_dispq_insert(fmd.d_disp, mp->mod_queue, class);
		fmd_xprt_subscribe_all(class);
	}

	fmd_module_unlock(mp);
}


void
fmd_hdl_unsubscribe(fmd_hdl_t *hdl, const char *class)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);

	if (fmd_conf_delprop(mp->mod_conf,
	    FMD_PROP_SUBSCRIPTIONS, class) == 0) {
		fmd_xprt_unsubscribe_all(class);
		fmd_dispq_delete(fmd.d_disp, mp->mod_queue, class);
	}

	fmd_module_unlock(mp);
	fmd_eventq_cancel(mp->mod_queue, FMD_EVT_PROTOCOL, (void *)class);
}

void
fmd_hdl_setspecific(fmd_hdl_t *hdl, void *spec)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);

	mp->mod_spec = spec;
	fmd_module_unlock(mp);
}

void *
fmd_hdl_getspecific(fmd_hdl_t *hdl)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	void *spec = mp->mod_spec;

	fmd_module_unlock(mp);
	return (spec);
}

void
fmd_hdl_opendict(fmd_hdl_t *hdl, const char *dict)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	const fmd_conf_path_t *pap;
	int i;

	/*
	 * Update the dictionary property in order to preserve the list of
	 * pathnames and expand any % tokens in the path.  Then retrieve the
	 * new dictionary names from cpa_argv[] and open them one at a time.
	 */
	(void) fmd_conf_setprop(mp->mod_conf, FMD_PROP_DICTIONARIES, dict);
	(void) fmd_conf_getprop(mp->mod_conf, FMD_PROP_DICTIONARIES, &pap);

	ASSERT(pap->cpa_argc > mp->mod_dictc);

	for (i = mp->mod_dictc; i < pap->cpa_argc; i++) {
		if (fmd_module_dc_opendict(mp, pap->cpa_argv[i]) != 0) {
			fmd_api_error(mp, EFMD_MOD_DICT,
			    "failed to open dictionary %s for module %s",
			    pap->cpa_argv[i], mp->mod_name);
		}
	}

	fmd_module_unlock(mp);
}

topo_hdl_t *
fmd_hdl_topo_hold(fmd_hdl_t *hdl, int v)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	topo_hdl_t *thp;

	if (v != TOPO_VERSION) {
		fmd_api_error(mp, EFMD_MOD_TOPO, "libtopo version mismatch: "
		    "fmd version %d != client version %d\n", TOPO_VERSION, v);
	}

	thp = fmd_module_topo_hold(mp);
	ASSERT(thp != NULL);

	fmd_module_unlock(mp);
	return (thp);
}

void
fmd_hdl_topo_rele(fmd_hdl_t *hdl, topo_hdl_t *thp)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);

	if (fmd_module_topo_rele(mp, thp) != 0)
		fmd_api_error(mp, EFMD_MOD_TOPO, "failed to release invalid "
		    "topo handle: %p\n", (void *)thp);

	fmd_module_unlock(mp);
}

static void *
fmd_hdl_alloc_locked(fmd_module_t *mp, size_t size, int flags)
{
	void *data;

	if (mp->mod_stats->ms_memlimit.fmds_value.ui64 -
	    mp->mod_stats->ms_memtotal.fmds_value.ui64 < size) {
		fmd_api_error(mp, EFMD_HDL_NOMEM, "%s's allocation of %lu "
		    "bytes exceeds module memory limit (%llu)\n",
		    mp->mod_name, (ulong_t)size, (u_longlong_t)
		    mp->mod_stats->ms_memtotal.fmds_value.ui64);
	}

	if ((data = fmd_alloc(size, flags)) != NULL)
		mp->mod_stats->ms_memtotal.fmds_value.ui64 += size;

	return (data);
}

void *
fmd_hdl_alloc(fmd_hdl_t *hdl, size_t size, int flags)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	void *data;

	data = fmd_hdl_alloc_locked(mp, size, flags);

	fmd_module_unlock(mp);
	return (data);
}

void *
fmd_hdl_zalloc(fmd_hdl_t *hdl, size_t size, int flags)
{
	void *data = fmd_hdl_alloc(hdl, size, flags);

	if (data != NULL)
		bzero(data, size);

	return (data);
}

static void
fmd_hdl_free_locked(fmd_module_t *mp, void *data, size_t size)
{
	fmd_free(data, size);
	mp->mod_stats->ms_memtotal.fmds_value.ui64 -= size;
}

void
fmd_hdl_free(fmd_hdl_t *hdl, void *data, size_t size)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);

	fmd_hdl_free_locked(mp, data, size);

	fmd_module_unlock(mp);
}

char *
fmd_hdl_strdup(fmd_hdl_t *hdl, const char *s, int flags)
{
	char *p;

	if (s != NULL)
		p = fmd_hdl_alloc(hdl, strlen(s) + 1, flags);
	else
		p = NULL;

	if (p != NULL)
		(void) strcpy(p, s);

	return (p);
}

void
fmd_hdl_strfree(fmd_hdl_t *hdl, char *s)
{
	if (s != NULL)
		fmd_hdl_free(hdl, s, strlen(s) + 1);
}

void
fmd_hdl_vabort(fmd_hdl_t *hdl, const char *format, va_list ap)
{
	fmd_api_verror(fmd_api_module_lock(hdl), EFMD_HDL_ABORT, format, ap);
}

/*PRINTFLIKE2*/
void
fmd_hdl_abort(fmd_hdl_t *hdl, const char *format, ...)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	va_list ap;

	va_start(ap, format);
	fmd_api_verror(mp, EFMD_HDL_ABORT, format, ap);
	va_end(ap);
}

void
fmd_hdl_verror(fmd_hdl_t *hdl, const char *format, va_list ap)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_api_vxerror(mp, errno, format, ap);
	fmd_module_unlock(mp);
}

/*PRINTFLIKE2*/
void
fmd_hdl_error(fmd_hdl_t *hdl, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	fmd_hdl_verror(hdl, format, ap);
	va_end(ap);
}

void
fmd_hdl_vdebug(fmd_hdl_t *hdl, const char *format, va_list ap)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);

	char *msg;
	size_t len;
	char c;

	if (!(fmd.d_hdl_debug)) {
		mp->mod_stats->ms_debugdrop.fmds_value.ui64++;
		fmd_module_unlock(mp);
		return;
	}

	len = vsnprintf(&c, 1, format, ap);

	if ((msg = fmd_alloc(len + 2, FMD_NOSLEEP)) == NULL) {
		mp->mod_stats->ms_debugdrop.fmds_value.ui64++;
		fmd_module_unlock(mp);
		return;
	}

	(void) vsnprintf(msg, len + 1, format, ap);

	if (msg[len - 1] != '\n')
		(void) strcpy(&msg[len], "\n");

	if (fmd.d_hdl_dbout & FMD_DBOUT_STDERR) {
		(void) pthread_mutex_lock(&fmd.d_err_lock);
		(void) fprintf(stderr, "%s DEBUG: %s: %s",
		    fmd.d_pname, mp->mod_name, msg);
		(void) pthread_mutex_unlock(&fmd.d_err_lock);
	}

	if (fmd.d_hdl_dbout & FMD_DBOUT_SYSLOG) {
		syslog(LOG_DEBUG | LOG_DAEMON, "%s DEBUG: %s: %s",
		    fmd.d_pname, mp->mod_name, msg);
	}

	fmd_free(msg, len + 2);
	fmd_module_unlock(mp);
}

/*PRINTFLIKE2*/
void
fmd_hdl_debug(fmd_hdl_t *hdl, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	fmd_hdl_vdebug(hdl, format, ap);
	va_end(ap);
}

int32_t
fmd_prop_get_int32(fmd_hdl_t *hdl, const char *name)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	const fmd_conf_ops_t *ops = fmd_conf_gettype(mp->mod_conf, name);
	int32_t value = 0;

	if (ops == &fmd_conf_bool || ops == &fmd_conf_int32 ||
	    ops == &fmd_conf_uint32)
		(void) fmd_conf_getprop(mp->mod_conf, name, &value);
	else if (ops != NULL) {
		fmd_api_error(mp, EFMD_PROP_TYPE,
		    "property %s is not of int32 type\n", name);
	} else {
		fmd_api_error(mp, EFMD_PROP_DEFN,
		    "property %s is not defined\n", name);
	}

	fmd_module_unlock(mp);
	return (value);
}

int64_t
fmd_prop_get_int64(fmd_hdl_t *hdl, const char *name)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	const fmd_conf_ops_t *ops = fmd_conf_gettype(mp->mod_conf, name);
	int64_t value = 0;

	if (ops == &fmd_conf_int64 || ops == &fmd_conf_uint64 ||
	    ops == &fmd_conf_time || ops == &fmd_conf_size)
		(void) fmd_conf_getprop(mp->mod_conf, name, &value);
	else if (ops != NULL) {
		fmd_api_error(mp, EFMD_PROP_TYPE,
		    "property %s is not of int64 type\n", name);
	} else {
		fmd_api_error(mp, EFMD_PROP_DEFN,
		    "property %s is not defined\n", name);
	}

	fmd_module_unlock(mp);
	return (value);
}

char *
fmd_prop_get_string(fmd_hdl_t *hdl, const char *name)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	const fmd_conf_ops_t *ops = fmd_conf_gettype(mp->mod_conf, name);
	char *value = NULL;
	const char *s;

	if (ops == &fmd_conf_string) {
		(void) fmd_conf_getprop(mp->mod_conf, name, &s);
		value = fmd_strdup(s, FMD_SLEEP);
	} else if (ops != NULL) {
		fmd_api_error(mp, EFMD_PROP_TYPE,
		    "property %s is not of string type\n", name);
	} else {
		fmd_api_error(mp, EFMD_PROP_DEFN,
		    "property %s is not defined\n", name);
	}

	fmd_module_unlock(mp);
	return (value);
}

void
fmd_prop_free_string(fmd_hdl_t *hdl, char *s)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_strfree(s);
	fmd_module_unlock(mp);
}

fmd_stat_t *
fmd_stat_create(fmd_hdl_t *hdl, uint_t flags, uint_t argc, fmd_stat_t *argv)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_stat_t *ep, *sp;

	if (flags & ~FMD_STAT_ALLOC) {
		fmd_api_error(mp, EFMD_STAT_FLAGS,
		    "invalid flags 0x%x passed to fmd_stat_create\n", flags);
	}

	if ((sp = fmd_ustat_insert(mp->mod_ustat,
	    flags | FMD_USTAT_VALIDATE, argc, argv, &ep)) == NULL) {
		fmd_api_error(mp, errno,
		    "failed to publish stat '%s'", ep->fmds_name);
	}

	fmd_module_unlock(mp);
	return (sp);
}

void
fmd_stat_destroy(fmd_hdl_t *hdl, uint_t argc, fmd_stat_t *argv)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_ustat_delete(mp->mod_ustat, argc, argv);
	fmd_module_unlock(mp);
}

void
fmd_stat_setstr(fmd_hdl_t *hdl, fmd_stat_t *sp, const char *s)
{
	char *str = fmd_strdup(s, FMD_SLEEP);
	fmd_module_t *mp = fmd_api_module_lock(hdl);

	if (sp->fmds_type != FMD_TYPE_STRING) {
		fmd_strfree(str);
		fmd_api_error(mp, EFMD_STAT_TYPE,
		    "stat '%s' is not a string\n", sp->fmds_name);
	}

	fmd_strfree(sp->fmds_value.str);
	sp->fmds_value.str = str;

	fmd_module_unlock(mp);
}

fmd_case_t *
fmd_case_open(fmd_hdl_t *hdl, void *data)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_case_t *cp = fmd_case_create(mp, NULL, data);
	fmd_module_unlock(mp);
	return (cp);
}

fmd_case_t *
fmd_case_open_uuid(fmd_hdl_t *hdl, const char *uuidstr, void *data)
{
	fmd_module_t *mp;
	fmd_case_t *cp;
	uint_t uuidlen;
	uuid_t uuid;

	mp = fmd_api_module_lock(hdl);

	(void) fmd_conf_getprop(fmd.d_conf, "uuidlen", &uuidlen);

	if (uuidstr == NULL) {
		fmd_api_error(mp, EFMD_CASE_INVAL, "NULL uuid string\n");
	} else if (strnlen(uuidstr, uuidlen + 1) != uuidlen) {
		fmd_api_error(mp, EFMD_CASE_INVAL, "invalid uuid string: '%s' "
		    "(expected length %d)\n", uuidstr, uuidlen);
	} else if (uuid_parse((char *)uuidstr, uuid) == -1) {
		fmd_api_error(mp, EFMD_CASE_INVAL, "cannot parse uuid string: "
		    "'%s'\n", uuidstr);
	}

	if ((cp = fmd_case_hash_lookup(fmd.d_cases, uuidstr)) == NULL) {
		cp = fmd_case_create(mp, uuidstr, data);
	} else {
		fmd_case_rele(cp);
		cp = NULL;
	}

	fmd_module_unlock(mp);
	return (cp);	/* May be NULL iff case already exists */
}

void
fmd_case_reset(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_case_impl_t *cip = fmd_api_case_impl(mp, cp);

	if (cip->ci_state >= FMD_CASE_SOLVED) {
		fmd_api_error(mp, EFMD_CASE_STATE, "cannot solve %s: "
		    "case is already solved or closed\n", cip->ci_uuid);
	}

	fmd_case_reset_suspects(cp);
	fmd_module_unlock(mp);
}

void
fmd_case_solve(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_case_impl_t *cip = fmd_api_case_impl(mp, cp);

	if (cip->ci_state >= FMD_CASE_SOLVED) {
		fmd_api_error(mp, EFMD_CASE_STATE, "cannot solve %s: "
		    "case is already solved or closed\n", cip->ci_uuid);
	}

	fmd_case_transition(cp, FMD_CASE_SOLVED, FMD_CF_SOLVED);
	fmd_module_unlock(mp);
}

void
fmd_case_close(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);

	(void) fmd_api_case_impl(mp, cp); /* validate 'cp' */
	fmd_case_transition(cp, FMD_CASE_CLOSE_WAIT, FMD_CF_ISOLATED);

	fmd_module_unlock(mp);
}

const char *
fmd_case_uuid(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_case_impl_t *cip = fmd_api_case_impl(mp, cp);
	const char *uuid = cip->ci_uuid;

	fmd_module_unlock(mp);
	return (uuid);
}

fmd_case_t *
fmd_case_uulookup(fmd_hdl_t *hdl, const char *uuid)
{
	fmd_module_t *cmp, *mp = fmd_api_module_lock(hdl);
	fmd_case_t *cp = fmd_case_hash_lookup(fmd.d_cases, uuid);

	if (cp != NULL) {
		cmp = ((fmd_case_impl_t *)cp)->ci_mod;
		fmd_case_rele(cp);
	} else
		cmp = NULL;

	fmd_module_unlock(mp);
	return (cmp == mp ? cp : NULL);
}

void
fmd_case_uuclose(fmd_hdl_t *hdl, const char *uuid)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_case_t *cp = fmd_case_hash_lookup(fmd.d_cases, uuid);

	if (cp != NULL) {
		fmd_case_transition(cp, FMD_CASE_CLOSE_WAIT, FMD_CF_ISOLATED);
		fmd_case_rele(cp);
	}

	fmd_module_unlock(mp);
}

int
fmd_case_uuclosed(fmd_hdl_t *hdl, const char *uuid)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_case_t *cp = fmd_case_hash_lookup(fmd.d_cases, uuid);
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	int rv = FMD_B_TRUE;

	if (cip != NULL) {
		rv = cip->ci_state >= FMD_CASE_CLOSE_WAIT;
		fmd_case_rele(cp);
	}

	fmd_module_unlock(mp);
	return (rv);
}

void
fmd_case_uuresolved(fmd_hdl_t *hdl, const char *uuid)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_case_t *cp = fmd_case_hash_lookup(fmd.d_cases, uuid);

	if (cp != NULL) {
		fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
		/*
		 * For a proxy, we notify the diagnosing side, and then
		 * wait for it to send us back a list.resolved.
		 */
		if (cip->ci_xprt != NULL)
			fmd_xprt_uuresolved(cip->ci_xprt, cip->ci_uuid);
		else
			fmd_case_transition(cp, FMD_CASE_RESOLVED, 0);
		fmd_case_rele(cp);
	}

	fmd_module_unlock(mp);
}

int
fmd_case_uuisresolved(fmd_hdl_t *hdl, const char *uuid)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_case_t *cp = fmd_case_hash_lookup(fmd.d_cases, uuid);
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	int rv = FMD_B_FALSE;

	if (cip != NULL) {
		rv = (cip->ci_state >= FMD_CASE_RESOLVED);
		fmd_case_rele(cp);
	}

	fmd_module_unlock(mp);
	return (rv);
}

static int
fmd_case_instate(fmd_hdl_t *hdl, fmd_case_t *cp, uint_t state)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_case_impl_t *cip = fmd_api_case_impl(mp, cp);
	int rv = cip->ci_state >= state;

	fmd_module_unlock(mp);
	return (rv);
}

int
fmd_case_solved(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	return (fmd_case_instate(hdl, cp, FMD_CASE_SOLVED));
}

int
fmd_case_closed(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	return (fmd_case_instate(hdl, cp, FMD_CASE_CLOSE_WAIT));
}

void
fmd_case_add_ereport(fmd_hdl_t *hdl, fmd_case_t *cp, fmd_event_t *ep)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);

	(void) fmd_api_case_impl(mp, cp); /* validate 'cp' */

	if (fmd_case_insert_event(cp, ep))
		mp->mod_stats->ms_accepted.fmds_value.ui64++;

	fmd_module_unlock(mp);
}

void
fmd_case_add_serd(fmd_hdl_t *hdl, fmd_case_t *cp, const char *name)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_serd_elem_t *sep;
	fmd_serd_eng_t *sgp;

	if ((sgp = fmd_serd_eng_lookup(&mp->mod_serds, name)) == NULL) {
		fmd_api_error(mp, EFMD_SERD_NAME,
		    "failed to add events from serd engine '%s'", name);
	}

	(void) fmd_api_case_impl(mp, cp); /* validate 'cp' */

	for (sep = fmd_list_next(&sgp->sg_list);
	    sep != NULL; sep = fmd_list_next(sep)) {
		if (fmd_case_insert_event(cp, sep->se_event))
			mp->mod_stats->ms_accepted.fmds_value.ui64++;
	}

	fmd_module_unlock(mp);
}

void
fmd_case_add_suspect(fmd_hdl_t *hdl, fmd_case_t *cp, nvlist_t *nvl)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_case_impl_t *cip = fmd_api_case_impl(mp, cp);
	char *class;
	topo_hdl_t *thp;
	int err;
	nvlist_t *rsrc = NULL, *asru_prop = NULL, *asru = NULL, *fru = NULL;
	char *loc = NULL, *serial = NULL;

	if (cip->ci_state >= FMD_CASE_SOLVED) {
		fmd_api_error(mp, EFMD_CASE_STATE, "cannot add suspect to "
		    "%s: case is already solved or closed\n", cip->ci_uuid);
	}

	if (nvlist_lookup_string(nvl, FM_CLASS, &class) != 0 ||
	    class == NULL || *class == '\0') {
		fmd_api_error(mp, EFMD_CASE_EVENT, "cannot add suspect to "
		    "%s: suspect event is missing a class\n", cip->ci_uuid);
	}

	thp = fmd_module_topo_hold(mp);
	(void) nvlist_lookup_nvlist(nvl, FM_FAULT_RESOURCE, &rsrc);
	(void) nvlist_lookup_nvlist(nvl, FM_FAULT_ASRU, &asru);
	(void) nvlist_lookup_nvlist(nvl, FM_FAULT_FRU, &fru);
	if (rsrc != NULL) {
		if (strncmp(class, "defect", 6) == 0) {
			if (asru == NULL && topo_fmri_getprop(thp, rsrc,
			    TOPO_PGROUP_IO, TOPO_IO_MODULE, rsrc,
			    &asru_prop, &err) == 0 &&
			    nvlist_lookup_nvlist(asru_prop, TOPO_PROP_VAL_VAL,
			    &asru) == 0) {
				(void) nvlist_add_nvlist(nvl, FM_FAULT_ASRU,
				    asru);
				nvlist_free(asru_prop);
				(void) nvlist_lookup_nvlist(nvl, FM_FAULT_ASRU,
				    &asru);
			}
		} else {
			if (topo_fmri_asru(thp, rsrc, &asru, &err) == 0) {
				(void) nvlist_remove(nvl, FM_FAULT_ASRU,
				    DATA_TYPE_NVLIST);
				(void) nvlist_add_nvlist(nvl, FM_FAULT_ASRU,
				    asru);
				nvlist_free(asru);
				(void) nvlist_lookup_nvlist(nvl, FM_FAULT_ASRU,
				    &asru);
			}
			if (topo_fmri_fru(thp, rsrc, &fru, &err) == 0) {
				(void) nvlist_remove(nvl, FM_FAULT_FRU,
				    DATA_TYPE_NVLIST);
				(void) nvlist_add_nvlist(nvl, FM_FAULT_FRU,
				    fru);
				nvlist_free(fru);
				(void) nvlist_lookup_nvlist(nvl, FM_FAULT_FRU,
				    &fru);
			}
		}
	}

	/*
	 * Try to find the location label for this resource
	 */
	if (strncmp(class, "defect", 6) != 0) {
		if (fru != NULL)
			(void) topo_fmri_label(thp, fru, &loc, &err);
		else if (rsrc != NULL)
			(void) topo_fmri_label(thp, rsrc, &loc, &err);
		if (loc != NULL) {
			(void) nvlist_remove(nvl, FM_FAULT_LOCATION,
			    DATA_TYPE_STRING);
			(void) nvlist_add_string(nvl, FM_FAULT_LOCATION, loc);
			topo_hdl_strfree(thp, loc);
		}
	}

	/*
	 * In some cases, serial information for the resource will not be
	 * available at enumeration but may instead be available by invoking
	 * a dynamic property method on the FRU.  In order to ensure the serial
	 * number is persisted properly in the ASRU cache, we'll fetch the
	 * property, if it exists, and add it to the resource and fru fmris.
	 * If the DE has not listed a fru in the suspect, see if we can
	 * retrieve the serial from the resource instead.
	 */
	if (fru != NULL) {
		(void) topo_fmri_serial(thp, fru, &serial, &err);
		if (serial != NULL) {
			(void) nvlist_add_string(fru, "serial", serial);
			topo_hdl_strfree(thp, serial);
		}
	}

	err = fmd_module_topo_rele(mp, thp);
	ASSERT(err == 0);

	fmd_case_insert_suspect(cp, nvl);
	fmd_module_unlock(mp);
}

void
fmd_case_setspecific(fmd_hdl_t *hdl, fmd_case_t *cp, void *data)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_case_impl_t *cip = fmd_api_case_impl(mp, cp);

	(void) pthread_mutex_lock(&cip->ci_lock);
	cip->ci_data = data;
	(void) pthread_mutex_unlock(&cip->ci_lock);

	fmd_module_unlock(mp);
}

void *
fmd_case_getspecific(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_case_impl_t *cip = fmd_api_case_impl(mp, cp);
	void *data;

	(void) pthread_mutex_lock(&cip->ci_lock);
	data = cip->ci_data;
	(void) pthread_mutex_unlock(&cip->ci_lock);

	fmd_module_unlock(mp);
	return (data);
}

void
fmd_case_setprincipal(fmd_hdl_t *hdl, fmd_case_t *cp, fmd_event_t *ep)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);

	(void) fmd_api_case_impl(mp, cp); /* validate 'cp' */

	if (fmd_case_insert_principal(cp, ep))
		mp->mod_stats->ms_accepted.fmds_value.ui64++;

	fmd_module_unlock(mp);
}

fmd_event_t *
fmd_case_getprincipal(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_case_impl_t *cip = fmd_api_case_impl(mp, cp);
	fmd_event_t *ep;

	(void) pthread_mutex_lock(&cip->ci_lock);
	ep = cip->ci_principal;
	(void) pthread_mutex_unlock(&cip->ci_lock);

	fmd_module_unlock(mp);
	return (ep);
}

fmd_case_t *
fmd_case_next(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);

	if (cp != NULL)
		cp = fmd_list_next(fmd_api_case_impl(mp, cp));
	else
		cp = fmd_list_next(&mp->mod_cases);

	fmd_module_unlock(mp);
	return (cp);
}

fmd_case_t *
fmd_case_prev(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);

	if (cp != NULL)
		cp = fmd_list_prev(fmd_api_case_impl(mp, cp));
	else
		cp = fmd_list_prev(&mp->mod_cases);

	fmd_module_unlock(mp);
	return (cp);
}

/*
 * Utility function for fmd_buf_* routines.  If a case is specified, use the
 * case's ci_bufs hash; otherwise use the module's global mod_bufs hash.
 */
static fmd_buf_hash_t *
fmd_buf_gethash(fmd_module_t *mp, fmd_case_t *cp)
{
	return (cp ? &fmd_api_case_impl(mp, cp)->ci_bufs : &mp->mod_bufs);
}

void
fmd_buf_create(fmd_hdl_t *hdl, fmd_case_t *cp, const char *name, size_t size)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_buf_hash_t *bhp = fmd_buf_gethash(mp, cp);
	fmd_buf_t *bp = fmd_buf_lookup(bhp, name);

	if (bp == NULL) {
		if (fmd_strbadid(name, FMD_B_TRUE) != NULL || size == 0) {
			fmd_api_error(mp, EFMD_BUF_INVAL, "cannot create '%s' "
			    "(size %lu): %s\n", name, (ulong_t)size,
			    fmd_strerror(EFMD_BUF_INVAL));
		}

		if (mp->mod_stats->ms_buflimit.fmds_value.ui64 -
		    mp->mod_stats->ms_buftotal.fmds_value.ui64 < size) {
			fmd_api_error(mp, EFMD_BUF_LIMIT, "cannot create '%s': "
			    "buf limit exceeded (%llu)\n", name, (u_longlong_t)
			    mp->mod_stats->ms_buflimit.fmds_value.ui64);
		}

		mp->mod_stats->ms_buftotal.fmds_value.ui64 += size;
		bp = fmd_buf_insert(bhp, name, size);

	} else {
		fmd_api_error(mp, EFMD_BUF_EXISTS,
		    "cannot create '%s': buffer already exists\n", name);
	}

	if (cp != NULL)
		fmd_case_setdirty(cp);
	else
		fmd_module_setdirty(mp);

	fmd_module_unlock(mp);
}

void
fmd_buf_destroy(fmd_hdl_t *hdl, fmd_case_t *cp, const char *name)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_buf_hash_t *bhp = fmd_buf_gethash(mp, cp);
	fmd_buf_t *bp = fmd_buf_lookup(bhp, name);

	if (bp != NULL) {
		mp->mod_stats->ms_buftotal.fmds_value.ui64 -= bp->buf_size;
		fmd_buf_delete(bhp, name);

		if (cp != NULL)
			fmd_case_setdirty(cp);
		else
			fmd_module_setdirty(mp);
	}

	fmd_module_unlock(mp);
}

void
fmd_buf_read(fmd_hdl_t *hdl, fmd_case_t *cp,
    const char *name, void *buf, size_t size)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_buf_t *bp = fmd_buf_lookup(fmd_buf_gethash(mp, cp), name);

	if (bp == NULL) {
		fmd_api_error(mp, EFMD_BUF_NOENT, "no buf named '%s' is "
		    "associated with %s\n", name, cp ? "case" : "module");
	}

	bcopy(bp->buf_data, buf, MIN(bp->buf_size, size));
	if (size > bp->buf_size)
		bzero((char *)buf + bp->buf_size, size - bp->buf_size);

	fmd_module_unlock(mp);
}

void
fmd_buf_write(fmd_hdl_t *hdl, fmd_case_t *cp,
    const char *name, const void *buf, size_t size)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_buf_hash_t *bhp = fmd_buf_gethash(mp, cp);
	fmd_buf_t *bp = fmd_buf_lookup(bhp, name);

	if (bp == NULL) {
		if (fmd_strbadid(name, FMD_B_TRUE) != NULL || size == 0) {
			fmd_api_error(mp, EFMD_BUF_INVAL, "cannot write '%s' "
			    "(size %lu): %s\n", name, (ulong_t)size,
			    fmd_strerror(EFMD_BUF_INVAL));
		}

		if (mp->mod_stats->ms_buflimit.fmds_value.ui64 -
		    mp->mod_stats->ms_buftotal.fmds_value.ui64 < size) {
			fmd_api_error(mp, EFMD_BUF_LIMIT, "cannot write '%s': "
			    "buf limit exceeded (%llu)\n", name, (u_longlong_t)
			    mp->mod_stats->ms_buflimit.fmds_value.ui64);
		}

		mp->mod_stats->ms_buftotal.fmds_value.ui64 += size;
		bp = fmd_buf_insert(bhp, name, size);

	} else if (size > bp->buf_size) {
		fmd_api_error(mp, EFMD_BUF_OFLOW,
		    "write to buf '%s' overflows buf size (%lu > %lu)\n",
		    name, (ulong_t)size, (ulong_t)bp->buf_size);
	}

	bcopy(buf, bp->buf_data, MIN(bp->buf_size, size));
	bp->buf_flags |= FMD_BUF_DIRTY;

	if (cp != NULL)
		fmd_case_setdirty(cp);
	else
		fmd_module_setdirty(mp);

	fmd_module_unlock(mp);
}

size_t
fmd_buf_size(fmd_hdl_t *hdl, fmd_case_t *cp, const char *name)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_buf_hash_t *bhp = fmd_buf_gethash(mp, cp);

	fmd_buf_t *bp;
	size_t size;

	if ((bp = fmd_buf_lookup(bhp, name)) != NULL)
		size = bp->buf_size;
	else
		size = 0;

	fmd_module_unlock(mp);
	return (size);
}

void
fmd_serd_create(fmd_hdl_t *hdl, const char *name, uint_t n, hrtime_t t)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);

	if (fmd_serd_eng_lookup(&mp->mod_serds, name) != NULL) {
		fmd_api_error(mp, EFMD_SERD_EXISTS,
		    "failed to create serd engine '%s': %s\n",
		    name, fmd_strerror(EFMD_SERD_EXISTS));
	}

	(void) fmd_serd_eng_insert(&mp->mod_serds, name, n, t);
	fmd_module_setdirty(mp);
	fmd_module_unlock(mp);
}

void
fmd_serd_destroy(fmd_hdl_t *hdl, const char *name)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);

	fmd_serd_eng_delete(&mp->mod_serds, name);
	fmd_module_setdirty(mp);
	fmd_module_unlock(mp);
}

int
fmd_serd_exists(fmd_hdl_t *hdl, const char *name)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	int rv = (fmd_serd_eng_lookup(&mp->mod_serds, name) != NULL);
	fmd_module_unlock(mp);

	return (rv);
}

void
fmd_serd_reset(fmd_hdl_t *hdl, const char *name)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_serd_eng_t *sgp;

	if ((sgp = fmd_serd_eng_lookup(&mp->mod_serds, name)) == NULL) {
		fmd_api_error(mp, EFMD_SERD_NAME,
		    "serd engine '%s' does not exist\n", name);
	}

	fmd_serd_eng_reset(sgp);
	fmd_module_setdirty(mp);
	fmd_module_unlock(mp);
}

int
fmd_serd_record(fmd_hdl_t *hdl, const char *name, fmd_event_t *ep)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_serd_eng_t *sgp;
	int err;

	if ((sgp = fmd_serd_eng_lookup(&mp->mod_serds, name)) == NULL) {
		fmd_api_error(mp, EFMD_SERD_NAME,
		    "failed to add record to serd engine '%s'", name);
	}

	err = fmd_serd_eng_record(sgp, ep);

	if (sgp->sg_flags & FMD_SERD_DIRTY)
		fmd_module_setdirty(mp);

	fmd_module_unlock(mp);
	return (err);
}

int
fmd_serd_fired(fmd_hdl_t *hdl, const char *name)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_serd_eng_t *sgp;
	int err;

	if ((sgp = fmd_serd_eng_lookup(&mp->mod_serds, name)) == NULL) {
		fmd_api_error(mp, EFMD_SERD_NAME,
		    "serd engine '%s' does not exist\n", name);
	}

	err = fmd_serd_eng_fired(sgp);
	fmd_module_unlock(mp);
	return (err);
}

int
fmd_serd_empty(fmd_hdl_t *hdl, const char *name)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_serd_eng_t *sgp;
	int empty;

	if ((sgp = fmd_serd_eng_lookup(&mp->mod_serds, name)) == NULL) {
		fmd_api_error(mp, EFMD_SERD_NAME,
		    "serd engine '%s' does not exist\n", name);
	}

	empty = fmd_serd_eng_empty(sgp);
	fmd_module_unlock(mp);
	return (empty);
}

pthread_t
fmd_thr_create(fmd_hdl_t *hdl, void (*func)(void *), void *arg)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_thread_t *tp;
	pthread_t tid;

	if (mp->mod_stats->ms_thrtotal.fmds_value.ui32 >=
	    mp->mod_stats->ms_thrlimit.fmds_value.ui32) {
		fmd_api_error(mp, EFMD_THR_LIMIT, "%s request to create an "
		    "auxiliary thread exceeds module thread limit (%u)\n",
		    mp->mod_name, mp->mod_stats->ms_thrlimit.fmds_value.ui32);
	}

	if ((tp = fmd_thread_create(mp, func, arg)) == NULL) {
		fmd_api_error(mp, EFMD_THR_CREATE,
		    "failed to create auxiliary thread");
	}

	tid = tp->thr_tid;
	mp->mod_stats->ms_thrtotal.fmds_value.ui32++;
	(void) fmd_idspace_xalloc(mp->mod_threads, tid, tp);

	fmd_module_unlock(mp);
	return (tid);
}

void
fmd_thr_destroy(fmd_hdl_t *hdl, pthread_t tid)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_thread_t *tp;
	int err;

	if (pthread_self() == tid) {
		fmd_api_error(mp, EFMD_THR_INVAL, "auxiliary thread tried to "
		    "destroy itself (tid %u)\n", tid);
	}

	if ((tp = fmd_idspace_getspecific(mp->mod_threads, tid)) == NULL) {
		fmd_api_error(mp, EFMD_THR_INVAL, "auxiliary thread tried to "
		    "destroy an invalid thread (tid %u)\n", tid);
	}

	/*
	 * Wait for the specified thread to exit and then join with it.  Since
	 * the thread may need to make API calls in order to complete its work
	 * we must sleep with the module lock unheld, and then reacquire it.
	 */
	fmd_module_unlock(mp);
	err = pthread_join(tid, NULL);
	mp = fmd_api_module_lock(hdl);

	/*
	 * Since pthread_join() was called without the module lock held, if
	 * multiple callers attempted to destroy the same auxiliary thread
	 * simultaneously, one will succeed and the others will get ESRCH.
	 * Therefore we silently ignore ESRCH but only allow the caller who
	 * succeessfully joined with the auxiliary thread to destroy it.
	 */
	if (err != 0 && err != ESRCH) {
		fmd_api_error(mp, EFMD_THR_JOIN,
		    "failed to join with auxiliary thread %u\n", tid);
	}

	if (err == 0) {
		fmd_thread_destroy(tp, FMD_THREAD_NOJOIN);
		mp->mod_stats->ms_thrtotal.fmds_value.ui32--;
		(void) fmd_idspace_free(mp->mod_threads, tid);
	}

	fmd_module_unlock(mp);
}

void
fmd_thr_signal(fmd_hdl_t *hdl, pthread_t tid)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);

	if (tid != mp->mod_thread->thr_tid &&
	    fmd_idspace_getspecific(mp->mod_threads, tid) == NULL) {
		fmd_api_error(mp, EFMD_THR_INVAL, "tid %u is not a valid "
		    "thread id for module %s\n", tid, mp->mod_name);
	}

	(void) pthread_kill(tid, fmd.d_thr_sig);
	fmd_module_unlock(mp);
}

void
fmd_thr_checkpoint(fmd_hdl_t *hdl)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	pthread_t tid = pthread_self();

	if (tid == mp->mod_thread->thr_tid ||
	    fmd_idspace_getspecific(mp->mod_threads, tid) == NULL) {
		fmd_api_error(mp, EFMD_THR_INVAL, "tid %u is not a valid "
		    "auxiliary thread id for module %s\n", tid, mp->mod_name);
	}

	fmd_ckpt_save(mp);

	fmd_module_unlock(mp);
}

/*ARGSUSED3*/
int
fmd_doorthr_create(door_info_t *dip, void *(*crf)(void *), void *crarg,
    void *cookie)
{
	fmd_thread_t *old_tp, *new_tp;
	fmd_module_t *mp;
	pthread_t tid;

	/*
	 * We're called either during initial door_xcreate or during
	 * a depletion callback.  In both cases the current thread
	 * is already setup so we can retrieve the fmd_thread_t.
	 * If not then we panic.  The new thread will be associated with
	 * the same module as the old.
	 *
	 * If dip == NULL we're being called as part of the
	 * sysevent_bind_subscriber hack - see comments there.
	 */
	if ((old_tp = pthread_getspecific(fmd.d_key)) == NULL)
		fmd_panic("fmd_doorthr_create from unrecognized thread\n");

	mp = old_tp->thr_mod;
	(void) fmd_api_module_lock((fmd_hdl_t *)mp);

	if (dip && mp->mod_stats->ms_doorthrtotal.fmds_value.ui32 >=
	    mp->mod_stats->ms_doorthrlimit.fmds_value.ui32) {
		fmd_module_unlock(mp);
		(void) fmd_dprintf(FMD_DBG_XPRT, "door server %s for %p "
		    "not attemped - at max\n",
		    dip->di_attributes & DOOR_DEPLETION_CB ?
		    "depletion callback" : "startup", (void *)dip);
		return (0);
	}

	if ((new_tp = fmd_doorthread_create(mp, (fmd_thread_f *)(uintptr_t)crf,
	    crarg)) != NULL) {
		tid = new_tp->thr_tid;
		mp->mod_stats->ms_doorthrtotal.fmds_value.ui32++;
		(void) fmd_idspace_xalloc(mp->mod_threads, tid, new_tp);
	}

	fmd_module_unlock(mp);

	if (dip) {
		fmd_dprintf(FMD_DBG_XPRT, "door server startup for %p %s\n",
		    (void *)dip, new_tp ? "successful" : "failed");
	}

	return (new_tp ? 1 : -1);
}

/*ARGSUSED*/
void
fmd_doorthr_setup(void *cookie)
{
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
}

id_t
fmd_timer_install(fmd_hdl_t *hdl, void *arg, fmd_event_t *ep, hrtime_t delta)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_modtimer_t *t;
	id_t id;

	if (delta < 0) {
		fmd_api_error(mp, EFMD_TIMER_INVAL,
		    "timer delta %lld is not a valid interval\n", delta);
	}

	t = fmd_alloc(sizeof (fmd_modtimer_t), FMD_SLEEP);
	t->mt_mod = mp;
	t->mt_arg = arg;
	t->mt_id = -1;

	if ((id = fmd_timerq_install(fmd.d_timers, mp->mod_timerids,
	    (fmd_timer_f *)fmd_module_timeout, t, ep, delta)) == -1) {
		fmd_free(t, sizeof (fmd_modtimer_t));
		fmd_api_error(mp, EFMD_TIMER_LIMIT,
		    "failed to install timer +%lld", delta);
	}

	fmd_module_unlock(mp);
	return (id);
}

void
fmd_timer_remove(fmd_hdl_t *hdl, id_t id)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_modtimer_t *t;

	if (!fmd_idspace_valid(mp->mod_timerids, id)) {
		fmd_api_error(mp, EFMD_TIMER_INVAL,
		    "id %ld is not a valid timer id\n", id);
	}

	/*
	 * If the timer has not fired (t != NULL), remove it from the timer
	 * queue.  If the timer has fired (t == NULL), we could be in one of
	 * two situations: a) we are processing the timer callback or b)
	 * the timer event is on the module queue awaiting dispatch.  For a),
	 * fmd_timerq_remove() will wait for the timer callback function
	 * to complete and queue an event for dispatch.  For a) and b),
	 * we cancel the outstanding timer event from the module's dispatch
	 * queue.
	 */
	if ((t = fmd_timerq_remove(fmd.d_timers, mp->mod_timerids, id)) != NULL)
		fmd_free(t, sizeof (fmd_modtimer_t));
	fmd_module_unlock(mp);

	fmd_eventq_cancel(mp->mod_queue, FMD_EVT_TIMEOUT, (void *)id);
}

static nvlist_t *
fmd_nvl_create_suspect(fmd_hdl_t *hdl, const char *class,
    uint8_t certainty, nvlist_t *asru, nvlist_t *fru, nvlist_t *rsrc,
    const char *pfx, boolean_t chkpfx)
{
	fmd_module_t *mp;
	nvlist_t *nvl;

	mp = fmd_api_module_lock(hdl);
	if (class == NULL || class[0] == '\0' ||
	    chkpfx == B_TRUE && strncmp(class, pfx, strlen(pfx)) != 0)
		fmd_api_error(mp, EFMD_NVL_INVAL, "invalid %s class: '%s'\n",
		    pfx, class ? class : "(empty)");

	nvl = fmd_protocol_fault(class, certainty, asru, fru, rsrc, NULL);

	fmd_module_unlock(mp);

	return (nvl);
}

nvlist_t *
fmd_nvl_create_fault(fmd_hdl_t *hdl, const char *class,
    uint8_t certainty, nvlist_t *asru, nvlist_t *fru, nvlist_t *rsrc)
{
	/*
	 * We can't enforce that callers only specifiy classes matching
	 * fault.* since there are already a number of modules that
	 * use fmd_nvl_create_fault to create a defect event.  Since
	 * fmd_nvl_create_{fault,defect} are equivalent, for now anyway,
	 * no harm is done.  So call fmd_nvl_create_suspect with last
	 * argument B_FALSE.
	 */
	return (fmd_nvl_create_suspect(hdl, class, certainty, asru,
	    fru, rsrc, FM_FAULT_CLASS ".", B_FALSE));
}

nvlist_t *
fmd_nvl_create_defect(fmd_hdl_t *hdl, const char *class,
    uint8_t certainty, nvlist_t *asru, nvlist_t *fru, nvlist_t *rsrc)
{
	return (fmd_nvl_create_suspect(hdl, class, certainty, asru,
	    fru, rsrc, FM_DEFECT_CLASS ".", B_TRUE));
}

const nvlist_t *
fmd_hdl_fmauth(fmd_hdl_t *hdl)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	const nvlist_t *auth;

	auth = (const nvlist_t *)fmd.d_rmod->mod_fmri;

	fmd_module_unlock(mp);

	return (auth);
}

const nvlist_t *
fmd_hdl_modauth(fmd_hdl_t *hdl)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	const nvlist_t *auth;

	auth = (const nvlist_t *)mp->mod_fmri;

	fmd_module_unlock(mp);

	return (auth);
}


int
fmd_nvl_class_match(fmd_hdl_t *hdl, nvlist_t *nvl, const char *pattern)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	char *class;
	int rv;

	rv = (nvl != NULL && nvlist_lookup_string(nvl,
	    FM_CLASS, &class) == 0 && fmd_strmatch(class, pattern));

	fmd_module_unlock(mp);
	return (rv);
}

int
fmd_nvl_fmri_expand(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	int rv;

	if (nvl == NULL) {
		fmd_api_error(mp, EFMD_NVL_INVAL,
		    "invalid nvlist %p\n", (void *)nvl);
	}

	rv = fmd_fmri_expand(nvl);
	fmd_module_unlock(mp);
	return (rv);
}

int
fmd_nvl_fmri_present(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	int rv;

	if (nvl == NULL) {
		fmd_api_error(mp, EFMD_NVL_INVAL,
		    "invalid nvlist %p\n", (void *)nvl);
	}

	rv = fmd_fmri_present(nvl);
	fmd_module_unlock(mp);

	if (rv < 0) {
		fmd_api_error(mp, EFMD_FMRI_OP, "invalid fmri for "
		    "fmd_nvl_fmri_present\n");
	}

	return (rv);
}

int
fmd_nvl_fmri_replaced(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	int rv;

	if (nvl == NULL) {
		fmd_api_error(mp, EFMD_NVL_INVAL,
		    "invalid nvlist %p\n", (void *)nvl);
	}

	rv = fmd_fmri_replaced(nvl);
	fmd_module_unlock(mp);

	return (rv);
}

int
fmd_nvl_fmri_unusable(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	int rv;

	if (nvl == NULL) {
		fmd_api_error(mp, EFMD_NVL_INVAL,
		    "invalid nvlist %p\n", (void *)nvl);
	}

	rv = fmd_fmri_unusable(nvl);
	fmd_module_unlock(mp);

	if (rv < 0) {
		fmd_api_error(mp, EFMD_FMRI_OP, "invalid fmri for "
		    "fmd_nvl_fmri_unusable\n");
	}

	return (rv);
}

int
fmd_nvl_fmri_retire(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	int rv;

	if (nvl == NULL) {
		fmd_api_error(mp, EFMD_NVL_INVAL,
		    "invalid nvlist %p\n", (void *)nvl);
	}

	rv = fmd_fmri_retire(nvl);
	fmd_module_unlock(mp);

	return (rv);
}

int
fmd_nvl_fmri_unretire(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	int rv;

	if (nvl == NULL) {
		fmd_api_error(mp, EFMD_NVL_INVAL,
		    "invalid nvlist %p\n", (void *)nvl);
	}

	rv = fmd_fmri_unretire(nvl);
	fmd_module_unlock(mp);

	return (rv);
}

int
fmd_nvl_fmri_service_state(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	int rv;

	if (nvl == NULL) {
		fmd_api_error(mp, EFMD_NVL_INVAL,
		    "invalid nvlist %p\n", (void *)nvl);
	}

	rv = fmd_fmri_service_state(nvl);
	if (rv < 0)
		rv = fmd_fmri_unusable(nvl) ? FMD_SERVICE_STATE_UNUSABLE :
		    FMD_SERVICE_STATE_OK;
	fmd_module_unlock(mp);

	if (rv < 0) {
		fmd_api_error(mp, EFMD_FMRI_OP, "invalid fmri for "
		    "fmd_nvl_fmri_service_state\n");
	}

	return (rv);
}

typedef struct {
	const char	*class;
	int	*rvp;
} fmd_has_fault_arg_t;

static void
fmd_rsrc_has_fault(fmd_asru_link_t *alp, void *arg)
{
	fmd_has_fault_arg_t *fhfp = (fmd_has_fault_arg_t *)arg;
	char *class;

	if (fhfp->class == NULL) {
		if (alp->al_flags & FMD_ASRU_FAULTY)
			*fhfp->rvp = 1;
	} else {
		if ((alp->al_flags & FMD_ASRU_FAULTY) &&
		    alp->al_event != NULL && nvlist_lookup_string(alp->al_event,
		    FM_CLASS, &class) == 0 && fmd_strmatch(class, fhfp->class))
			*fhfp->rvp = 1;
	}
}

int
fmd_nvl_fmri_has_fault(fmd_hdl_t *hdl, nvlist_t *nvl, int type, char *class)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_asru_hash_t *ahp = fmd.d_asrus;
	int rv = 0;
	char *name;
	int namelen;
	fmd_has_fault_arg_t fhf;

	if (nvl == NULL) {
		fmd_api_error(mp, EFMD_NVL_INVAL,
		    "invalid nvlist %p\n", (void *)nvl);
	}
	if ((namelen = fmd_fmri_nvl2str(nvl, NULL, 0)) == -1)
		fmd_api_error(mp, EFMD_NVL_INVAL,
		    "invalid nvlist: %p\n", (void *)nvl);
	name = fmd_alloc(namelen + 1, FMD_SLEEP);
	if (fmd_fmri_nvl2str(nvl, name, namelen + 1) == -1) {
		if (name != NULL)
			fmd_free(name, namelen + 1);
		fmd_api_error(mp, EFMD_NVL_INVAL,
		    "invalid nvlist: %p\n", (void *)nvl);
	}

	fhf.class = class;
	fhf.rvp = &rv;
	if (type == FMD_HAS_FAULT_RESOURCE)
		fmd_asru_hash_apply_by_rsrc(ahp, name, fmd_rsrc_has_fault,
		    &fhf);
	else if (type == FMD_HAS_FAULT_ASRU)
		fmd_asru_hash_apply_by_asru(ahp, name, fmd_rsrc_has_fault,
		    &fhf);
	else if (type == FMD_HAS_FAULT_FRU)
		fmd_asru_hash_apply_by_fru(ahp, name, fmd_rsrc_has_fault,
		    &fhf);

	if (name != NULL)
		fmd_free(name, namelen + 1);
	fmd_module_unlock(mp);
	return (rv);
}

int
fmd_nvl_fmri_contains(fmd_hdl_t *hdl, nvlist_t *n1, nvlist_t *n2)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	int rv;

	if (n1 == NULL || n2 == NULL) {
		fmd_api_error(mp, EFMD_NVL_INVAL,
		    "invalid nvlist(s): %p, %p\n", (void *)n1, (void *)n2);
	}

	rv = fmd_fmri_contains(n1, n2);
	fmd_module_unlock(mp);

	if (rv < 0) {
		fmd_api_error(mp, EFMD_FMRI_OP, "invalid fmri for "
		    "fmd_nvl_fmri_contains\n");
	}

	return (rv);
}

nvlist_t *
fmd_nvl_fmri_translate(fmd_hdl_t *hdl, nvlist_t *fmri, nvlist_t *auth)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	nvlist_t *xfmri;

	if (fmri == NULL || auth == NULL) {
		fmd_api_error(mp, EFMD_NVL_INVAL,
		    "invalid nvlist(s): %p, %p\n", (void *)fmri, (void *)auth);
	}

	xfmri = fmd_fmri_translate(fmri, auth);
	fmd_module_unlock(mp);
	return (xfmri);
}

static int
fmd_nvl_op_init(nv_alloc_t *ops, va_list ap)
{
	fmd_module_t *mp = va_arg(ap, fmd_module_t *);

	ops->nva_arg = mp;

	return (0);
}

static void *
fmd_nvl_op_alloc_sleep(nv_alloc_t *ops, size_t size)
{
	fmd_module_t *mp = ops->nva_arg;

	return (fmd_hdl_alloc_locked(mp, size, FMD_SLEEP));
}

static void *
fmd_nvl_op_alloc_nosleep(nv_alloc_t *ops, size_t size)
{
	fmd_module_t *mp = ops->nva_arg;

	return (fmd_hdl_alloc_locked(mp, size, FMD_NOSLEEP));
}

static void
fmd_nvl_op_free(nv_alloc_t *ops, void *data, size_t size)
{
	fmd_module_t *mp = ops->nva_arg;

	fmd_hdl_free_locked(mp, data, size);
}

nv_alloc_ops_t fmd_module_nva_ops_sleep = {
	fmd_nvl_op_init,
	NULL,
	fmd_nvl_op_alloc_sleep,
	fmd_nvl_op_free,
	NULL
};

nv_alloc_ops_t fmd_module_nva_ops_nosleep = {
	fmd_nvl_op_init,
	NULL,
	fmd_nvl_op_alloc_nosleep,
	fmd_nvl_op_free,
	NULL
};

nvlist_t *
fmd_nvl_alloc(fmd_hdl_t *hdl, int flags)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	nv_alloc_t *nva;
	nvlist_t *nvl;
	int ret;

	if (flags == FMD_SLEEP)
		nva = &mp->mod_nva_sleep;
	else
		nva = &mp->mod_nva_nosleep;

	ret = nvlist_xalloc(&nvl, NV_UNIQUE_NAME, nva);

	fmd_module_unlock(mp);

	if (ret != 0)
		return (NULL);
	else
		return (nvl);
}

nvlist_t *
fmd_nvl_dup(fmd_hdl_t *hdl, nvlist_t *src, int flags)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	nv_alloc_t *nva;
	nvlist_t *nvl;
	int ret;

	if (flags == FMD_SLEEP)
		nva = &mp->mod_nva_sleep;
	else
		nva = &mp->mod_nva_nosleep;

	ret = nvlist_xdup(src, &nvl, nva);

	fmd_module_unlock(mp);

	if (ret != 0)
		return (NULL);
	else
		return (nvl);
}

/*ARGSUSED*/
void
fmd_repair_fru(fmd_hdl_t *hdl, const char *fmri)
{
	int err;
	fmd_asru_rep_arg_t fara;

	fara.fara_reason = FMD_ASRU_REPAIRED;
	fara.fara_bywhat = FARA_BY_FRU;
	fara.fara_rval = &err;
	fmd_asru_hash_apply_by_fru(fmd.d_asrus, (char *)fmri,
	    fmd_asru_repaired, &fara);
}

/*ARGSUSED*/
int
fmd_repair_asru(fmd_hdl_t *hdl, const char *fmri)
{
	int err = FARA_ERR_RSRCNOTF;
	fmd_asru_rep_arg_t fara;

	fara.fara_reason = FMD_ASRU_REPAIRED;
	fara.fara_rval = &err;
	fara.fara_uuid = NULL;
	fara.fara_bywhat = FARA_BY_ASRU;
	fmd_asru_hash_apply_by_asru(fmd.d_asrus, fmri,
	    fmd_asru_repaired, &fara);
	return (err);
}

int
fmd_event_local(fmd_hdl_t *hdl, fmd_event_t *ep)
{
	if (hdl == NULL || ep == NULL) {
		fmd_api_error(fmd_api_module_lock(hdl), EFMD_EVENT_INVAL,
		    "NULL parameter specified to fmd_event_local\n");
	}

	return (((fmd_event_impl_t *)ep)->ev_flags & FMD_EVF_LOCAL);
}

/*ARGSUSED*/
uint64_t
fmd_event_ena_create(fmd_hdl_t *hdl)
{
	return (fmd_ena());
}

fmd_xprt_t *
fmd_xprt_open(fmd_hdl_t *hdl, uint_t flags, nvlist_t *auth, void *data)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_xprt_t *xp;

	if (flags & ~FMD_XPRT_CMASK) {
		fmd_api_error(mp, EFMD_XPRT_INVAL,
		    "invalid transport flags 0x%x\n", flags);
	}

	if ((flags & FMD_XPRT_RDWR) != FMD_XPRT_RDWR &&
	    (flags & FMD_XPRT_RDWR) != FMD_XPRT_RDONLY) {
		fmd_api_error(mp, EFMD_XPRT_INVAL,
		    "cannot open write-only transport\n");
	}

	if (mp->mod_stats->ms_xprtopen.fmds_value.ui32 >=
	    mp->mod_stats->ms_xprtlimit.fmds_value.ui32) {
		fmd_api_error(mp, EFMD_XPRT_LIMIT, "%s request to create a "
		    "transport exceeds module transport limit (%u)\n",
		    mp->mod_name, mp->mod_stats->ms_xprtlimit.fmds_value.ui32);
	}

	if ((xp = fmd_xprt_create(mp, flags, auth, data)) == NULL)
		fmd_api_error(mp, errno, "cannot create transport");

	fmd_module_unlock(mp);
	return (xp);
}

void
fmd_xprt_close(fmd_hdl_t *hdl, fmd_xprt_t *xp)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_xprt_impl_t *xip = fmd_api_transport_impl(hdl, xp);

	/*
	 * Although this could be supported, it doesn't seem necessary or worth
	 * the trouble.  For now, just detect this and trigger a module abort.
	 * If it is needed, transports should grow reference counts and a new
	 * event type will need to be enqueued for the main thread to reap it.
	 */
	if (xip->xi_thread != NULL &&
	    xip->xi_thread->thr_tid == pthread_self()) {
		fmd_api_error(mp, EFMD_XPRT_INVAL,
		    "fmd_xprt_close() cannot be called from fmdo_send()\n");
	}

	fmd_xprt_destroy(xp);
	fmd_module_unlock(mp);
}

void
fmd_xprt_post(fmd_hdl_t *hdl, fmd_xprt_t *xp, nvlist_t *nvl, hrtime_t hrt)
{
	nv_alloc_t *nva = nvlist_lookup_nv_alloc(nvl);
	fmd_module_t *mp = fmd_api_module(hdl);
	fmd_xprt_impl_t *xip = fmd_api_transport_impl(hdl, xp);
	nvlist_t *tmp;

	/*
	 * If this event was allocated using the module-specific nvlist ops, we
	 * need to create a copy using the standard fmd nvlist ops.  Otherwise,
	 * the event may persist after the module has been unloaded and we'll
	 * die when attempting to free the nvlist.
	 */
	if (nva == &mp->mod_nva_sleep || nva == &mp->mod_nva_nosleep) {
		(void) nvlist_xdup(nvl, &tmp, &fmd.d_nva);
		nvlist_free(nvl);
		nvl = tmp;
	}

	/*
	 * fmd_xprt_recv() must block during startup waiting for fmd to globally
	 * clear FMD_XPRT_DSUSPENDED.  As such, we can't allow it to be called
	 * from a module's _fmd_init() routine, because that would block
	 * fmd from completing initial module loading, resulting in a deadlock.
	 */
	if ((xip->xi_flags & FMD_XPRT_ISUSPENDED) &&
	    (pthread_self() == xip->xi_queue->eq_mod->mod_thread->thr_tid)) {
		fmd_api_error(fmd_api_module_lock(hdl), EFMD_XPRT_INVAL,
		    "fmd_xprt_post() cannot be called from _fmd_init()\n");
	}

	fmd_xprt_recv(xp, nvl, hrt, FMD_B_FALSE);
}

void
fmd_xprt_log(fmd_hdl_t *hdl, fmd_xprt_t *xp, nvlist_t *nvl, hrtime_t hrt)
{
	fmd_xprt_impl_t *xip = fmd_api_transport_impl(hdl, xp);

	/*
	 * fmd_xprt_recv() must block during startup waiting for fmd to globally
	 * clear FMD_XPRT_DSUSPENDED.  As such, we can't allow it to be called
	 * from a module's _fmd_init() routine, because that would block
	 * fmd from completing initial module loading, resulting in a deadlock.
	 */
	if ((xip->xi_flags & FMD_XPRT_ISUSPENDED) &&
	    (pthread_self() == xip->xi_queue->eq_mod->mod_thread->thr_tid)) {
		fmd_api_error(fmd_api_module_lock(hdl), EFMD_XPRT_INVAL,
		    "fmd_xprt_log() cannot be called from _fmd_init()\n");
	}

	fmd_xprt_recv(xp, nvl, hrt, FMD_B_TRUE);
}

void
fmd_xprt_suspend(fmd_hdl_t *hdl, fmd_xprt_t *xp)
{
	(void) fmd_api_transport_impl(hdl, xp); /* validate 'xp' */
	fmd_xprt_xsuspend(xp, FMD_XPRT_SUSPENDED);
}

void
fmd_xprt_resume(fmd_hdl_t *hdl, fmd_xprt_t *xp)
{
	(void) fmd_api_transport_impl(hdl, xp); /* validate 'xp' */
	fmd_xprt_xresume(xp, FMD_XPRT_SUSPENDED);
}

int
fmd_xprt_error(fmd_hdl_t *hdl, fmd_xprt_t *xp)
{
	fmd_xprt_impl_t *xip = fmd_api_transport_impl(hdl, xp);
	return (xip->xi_state == _fmd_xprt_state_err);
}

/*
 * Translate all FMRIs in the specified name-value pair list for the specified
 * FMRI authority, and return a new name-value pair list for the translation.
 * This function is the recursive engine used by fmd_xprt_translate(), below.
 */
static nvlist_t *
fmd_xprt_xtranslate(nvlist_t *nvl, nvlist_t *auth)
{
	uint_t i, j, n;
	nvpair_t *nvp, **nvps;
	uint_t nvpslen = 0;
	char *name;
	size_t namelen = 0;

	nvlist_t **a, **b;
	nvlist_t *l, *r;
	data_type_t type;
	char *s;
	int err;

	(void) nvlist_xdup(nvl, &nvl, &fmd.d_nva);

	/*
	 * Count up the number of name-value pairs in 'nvl' and compute the
	 * maximum length of a name used in this list for use below.
	 */
	for (nvp = nvlist_next_nvpair(nvl, NULL);
	    nvp != NULL; nvp = nvlist_next_nvpair(nvl, nvp), nvpslen++) {
		size_t len = strlen(nvpair_name(nvp));
		namelen = MAX(namelen, len);
	}

	nvps = alloca(sizeof (nvpair_t *) * nvpslen);
	name = alloca(namelen + 1);

	/*
	 * Store a snapshot of the name-value pairs in 'nvl' into nvps[] so
	 * that we can iterate over the original pairs in the loop below while
	 * performing arbitrary insert and delete operations on 'nvl' itself.
	 */
	for (i = 0, nvp = nvlist_next_nvpair(nvl, NULL);
	    nvp != NULL; nvp = nvlist_next_nvpair(nvl, nvp))
		nvps[i++] = nvp;

	/*
	 * Now iterate over the snapshot of the name-value pairs.  If we find a
	 * value that is of type NVLIST or NVLIST_ARRAY, we translate that
	 * object by either calling ourself recursively on it, or calling into
	 * fmd_fmri_translate() if the object is an FMRI.  We then rip out the
	 * original name-value pair and replace it with the translated one.
	 */
	for (i = 0; i < nvpslen; i++) {
		nvp = nvps[i];
		type = nvpair_type(nvp);

		switch (type) {
		case DATA_TYPE_NVLIST_ARRAY:
			if (nvpair_value_nvlist_array(nvp, &a, &n) != 0 ||
			    a == NULL || n == 0)
				continue; /* array is zero-sized; skip it */

			b = fmd_alloc(sizeof (nvlist_t *) * n, FMD_SLEEP);

			/*
			 * If the first array nvlist element looks like an FMRI
			 * then assume the other elements are FMRIs as well.
			 * If any b[j]'s can't be translated, then EINVAL will
			 * be returned from nvlist_add_nvlist_array() below.
			 */
			if (nvlist_lookup_string(*a, FM_FMRI_SCHEME, &s) == 0) {
				for (j = 0; j < n; j++)
					b[j] = fmd_fmri_translate(a[j], auth);
			} else {
				for (j = 0; j < n; j++)
					b[j] = fmd_xprt_xtranslate(a[j], auth);
			}

			(void) strcpy(name, nvpair_name(nvp));
			(void) nvlist_remove(nvl, name, type);
			err = nvlist_add_nvlist_array(nvl, name, b, n);

			for (j = 0; j < n; j++)
				nvlist_free(b[j]);

			fmd_free(b, sizeof (nvlist_t *) * n);

			if (err != 0) {
				nvlist_free(nvl);
				errno = err;
				return (NULL);
			}
			break;

		case DATA_TYPE_NVLIST:
			if (nvpair_value_nvlist(nvp, &l) == 0 &&
			    nvlist_lookup_string(l, FM_FMRI_SCHEME, &s) == 0)
				r = fmd_fmri_translate(l, auth);
			else
				r = fmd_xprt_xtranslate(l, auth);

			if (r == NULL) {
				nvlist_free(nvl);
				return (NULL);
			}

			(void) strcpy(name, nvpair_name(nvp));
			(void) nvlist_remove(nvl, name, type);
			(void) nvlist_add_nvlist(nvl, name, r);

			nvlist_free(r);
			break;
		}
	}

	return (nvl);
}

nvlist_t *
fmd_xprt_translate(fmd_hdl_t *hdl, fmd_xprt_t *xp, fmd_event_t *ep)
{
	fmd_xprt_impl_t *xip = fmd_api_transport_impl(hdl, xp);

	if (xip->xi_auth == NULL) {
		fmd_api_error(fmd_api_module_lock(hdl), EFMD_XPRT_INVAL,
		    "no authority defined for transport %p\n", (void *)xp);
	}

	return (fmd_xprt_xtranslate(FMD_EVENT_NVL(ep), xip->xi_auth));
}

/*ARGSUSED*/
void
fmd_xprt_add_domain(fmd_hdl_t *hdl, nvlist_t *nvl, char *domain)
{
	nvpair_t *nvp, *nvp2;
	nvlist_t *nvl2, *nvl3;
	char *class;

	if (nvl == NULL || domain == NULL)
		return;
	for (nvp = nvlist_next_nvpair(nvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvl, nvp)) {
		if (strcmp(nvpair_name(nvp), FM_CLASS) == 0) {
			(void) nvpair_value_string(nvp, &class);
			if (strcmp(class, FM_LIST_SUSPECT_CLASS) != 0)
				return;
		}
	}
	for (nvp = nvlist_next_nvpair(nvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvl, nvp)) {
		if (strcmp(nvpair_name(nvp), FM_SUSPECT_DE) == 0) {
			(void) nvpair_value_nvlist(nvp, &nvl2);
			for (nvp2 = nvlist_next_nvpair(nvl2, NULL);
			    nvp2 != NULL;
			    nvp2 = nvlist_next_nvpair(nvl2, nvp2)) {
				if (strcmp(nvpair_name(nvp2),
				    FM_FMRI_AUTHORITY) == 0) {
					(void) nvpair_value_nvlist(nvp2, &nvl3);
					(void) nvlist_add_string(nvl3,
					    FM_FMRI_AUTH_DOMAIN, domain);
					break;
				}
			}
			break;
		}
	}
}

void
fmd_xprt_setspecific(fmd_hdl_t *hdl, fmd_xprt_t *xp, void *data)
{
	fmd_api_transport_impl(hdl, xp)->xi_data = data;
}

void *
fmd_xprt_getspecific(fmd_hdl_t *hdl, fmd_xprt_t *xp)
{
	return (fmd_api_transport_impl(hdl, xp)->xi_data);
}
