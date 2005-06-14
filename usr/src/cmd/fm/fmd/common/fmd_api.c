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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/fm/protocol.h>

#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <syslog.h>
#include <alloca.h>

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
#include <fmd_ckpt.h>

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
	if (mp != fmd.d_self) {
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
	 */
	if (fmd.d_fg || (fmd.d_hdl_dbout & FMD_DBOUT_STDERR)) {
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
 * fmd_api_module_lock() is used as a wrapper around fmd_module_lock() and a
 * common prologue to each fmd_api.c routine.  It verifies that the handle is
 * valid and owned by the current server thread, locks the handle, and then
 * verifies that the caller is performing an operation on a registered handle.
 * If any tests fail, the entire API call is aborted by fmd_api_error().
 */
static fmd_module_t *
fmd_api_module_lock(fmd_hdl_t *hdl)
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

	if ((mp = tp->thr_mod) != (fmd_module_t *)hdl) {
		fmd_api_error(mp, EFMD_HDL_INVAL,
		    "client handle %p is not valid\n", (void *)hdl);
	}

	if (mp->mod_flags & FMD_MOD_FAIL) {
		fmd_api_error(mp, EFMD_MOD_FAIL,
		    "module has experienced an unrecoverable error\n");
	}

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
		    "case %p is not owned by caller\n", (void *)cip);
	}

	return (cip);
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
	fmd_hdl_ops_t *ops;

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
	if (version > FMD_API_VERSION_2)
		return (fmd_hdl_register_error(mp, EFMD_VER_NEW));

	if (version < FMD_API_VERSION_1)
		return (fmd_hdl_register_error(mp, EFMD_VER_OLD));

	if (mp->mod_conf != NULL)
		return (fmd_hdl_register_error(mp, EFMD_HDL_REG));

	if (pthread_self() != mp->mod_thread->thr_tid)
		return (fmd_hdl_register_error(mp, EFMD_HDL_TID));

	if (mip == NULL || mip->fmdi_desc == NULL || mip->fmdi_vers == NULL ||
	    mip->fmdi_ops == NULL || mip->fmdi_ops->fmdo_recv == NULL)
		return (fmd_hdl_register_error(mp, EFMD_HDL_INFO));

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
	    mp->mod_argc, mp->mod_argv)) == NULL)
		return (fmd_hdl_register_error(mp, EFMD_MOD_CONF));

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
	ops = (fmd_hdl_ops_t *)mp->mod_info->fmdi_ops;
	mp->mod_info->fmdi_props = NULL;

	/*
	 * Fill in the copy of the module ops.  If any optional entry points
	 * are NULL, set them to nop so we don't have to check before calling.
	 */
	ops->fmdo_recv = mip->fmdi_ops->fmdo_recv ?
	    mip->fmdi_ops->fmdo_recv : (void (*)())fmd_hdl_nop;
	ops->fmdo_timeout = mip->fmdi_ops->fmdo_timeout ?
	    mip->fmdi_ops->fmdo_timeout : (void (*)())fmd_hdl_nop;
	ops->fmdo_close = mip->fmdi_ops->fmdo_close ?
	    mip->fmdi_ops->fmdo_close : (void (*)())fmd_hdl_nop;
	ops->fmdo_stats = mip->fmdi_ops->fmdo_stats ?
	    mip->fmdi_ops->fmdo_stats : (void (*)())fmd_hdl_nop;
	ops->fmdo_stats = mip->fmdi_ops->fmdo_stats ?
	    mip->fmdi_ops->fmdo_stats : (void (*)())fmd_hdl_nop;
	ops->fmdo_gc = mip->fmdi_ops->fmdo_gc ?
	    mip->fmdi_ops->fmdo_gc : (void (*)())fmd_hdl_nop;

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

	for (i = 0; i < pap->cpa_argc; i++)
		fmd_dispq_insert(fmd.d_disp, mp, pap->cpa_argv[i]);

	/*
	 * Unlock the module and restore any pre-existing module checkpoint.
	 * If the checkpoint is missing or corrupt, we just keep going.
	 */
	fmd_module_unlock(mp);
	fmd_ckpt_restore(mp);
	return (0);
}

void
fmd_module_unregister(fmd_module_t *mp)
{
	fmd_conf_formal_t *cfp = mp->mod_argv;
	const fmd_conf_path_t *pap;
	int i;

	TRACE((FMD_DBG_MOD, "unregister %p (%s)", (void *)mp, mp->mod_name));
	ASSERT(fmd_module_locked(mp));

	if (mp->mod_error == 0)
		fmd_ckpt_save(mp); /* take one more checkpoint if needed */

	(void) fmd_conf_getprop(mp->mod_conf, FMD_PROP_SUBSCRIPTIONS, &pap);

	for (i = 0; i < pap->cpa_argc; i++)
		fmd_dispq_delete(fmd.d_disp, mp, pap->cpa_argv[i]);

	if (mp->mod_ustat != NULL) {
		(void) pthread_mutex_lock(&mp->mod_stats_lock);
		fmd_ustat_destroy(mp->mod_ustat);
		mp->mod_ustat = NULL;
		mp->mod_stats = NULL;
		(void) pthread_mutex_unlock(&mp->mod_stats_lock);
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

	if (fmd_conf_setprop(mp->mod_conf, FMD_PROP_SUBSCRIPTIONS, class) == 0)
		fmd_dispq_insert(fmd.d_disp, mp, class);

	fmd_module_unlock(mp);
}

void
fmd_hdl_unsubscribe(fmd_hdl_t *hdl, const char *class)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);

	if (fmd_conf_delprop(mp->mod_conf, FMD_PROP_SUBSCRIPTIONS, class) == 0)
		fmd_dispq_delete(fmd.d_disp, mp, class);

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

void *
fmd_hdl_alloc(fmd_hdl_t *hdl, size_t size, int flags)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
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

void
fmd_hdl_free(fmd_hdl_t *hdl, void *data, size_t size)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);

	fmd_free(data, size);
	mp->mod_stats->ms_memtotal.fmds_value.ui64 -= size;

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
	fmd_case_t *cp = fmd_case_create(mp, data);
	fmd_module_unlock(mp);
	return (cp);
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

	fmd_case_transition(cp, FMD_CASE_SOLVED);
	fmd_module_unlock(mp);
}

void
fmd_case_convict(fmd_hdl_t *hdl, fmd_case_t *cp, nvlist_t *nvl)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_case_impl_t *cip = fmd_api_case_impl(mp, cp);
	fmd_asru_hash_t *ahp = fmd.d_asrus;

	nvlist_t *fmri;
	fmd_asru_t *asru;

	if (cip->ci_state > FMD_CASE_SOLVED) {
		fmd_api_error(mp, EFMD_CASE_STATE, "cannot convict suspect in "
		    "%s: case is already closed\n", cip->ci_uuid);
	}

	if (nvlist_lookup_nvlist(nvl, FM_FAULT_ASRU, &fmri) != 0) {
		fmd_api_error(mp, EFMD_CASE_EVENT, "cannot convict suspect in "
		    "%s: suspect event is missing asru\n", cip->ci_uuid);
	}

	if ((asru = fmd_asru_hash_lookup_nvl(ahp, fmri, FMD_B_TRUE)) == NULL) {
		fmd_api_error(mp, EFMD_CASE_EVENT, "cannot convict suspect in "
		    "%s: %s\n", cip->ci_uuid, fmd_strerror(errno));
	}

	(void) fmd_asru_clrflags(asru, FMD_ASRU_UNUSABLE, cip->ci_uuid, nvl);
	(void) fmd_asru_setflags(asru, FMD_ASRU_FAULTY, cip->ci_uuid, nvl);

	fmd_asru_hash_release(ahp, asru);
	fmd_module_unlock(mp);
}

void
fmd_case_close(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);

	(void) fmd_api_case_impl(mp, cp); /* validate 'cp' */
	fmd_case_transition(cp, FMD_CASE_CLOSED);

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
fmd_case_uuconvict(fmd_hdl_t *hdl, const char *uuid, nvlist_t *nvl)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_case_t *cp = fmd_case_hash_lookup(fmd.d_cases, uuid);
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_asru_hash_t *ahp = fmd.d_asrus;

	nvlist_t *fmri;
	fmd_asru_t *asru;

	if (cp == NULL) {
		fmd_api_error(mp, EFMD_CASE_INVAL,
		    "cannot convict suspect in %s", uuid);
	}

	if (cip->ci_state > FMD_CASE_SOLVED) {
		fmd_case_rele(cp);
		fmd_api_error(mp, EFMD_CASE_STATE, "cannot convict suspect in "
		    "%s: case is already closed\n", uuid);
	}

	if (nvlist_lookup_nvlist(nvl, FM_FAULT_ASRU, &fmri) != 0) {
		fmd_case_rele(cp);
		fmd_api_error(mp, EFMD_CASE_EVENT, "cannot convict suspect in "
		    "%s: suspect event is missing asru\n", uuid);
	}

	if ((asru = fmd_asru_hash_lookup_nvl(ahp, fmri, FMD_B_TRUE)) == NULL) {
		fmd_case_rele(cp);
		fmd_api_error(mp, EFMD_CASE_EVENT, "cannot convict suspect in "
		    "%s: %s\n", uuid, fmd_strerror(errno));
	}

	(void) fmd_asru_clrflags(asru, FMD_ASRU_UNUSABLE, cip->ci_uuid, nvl);
	(void) fmd_asru_setflags(asru, FMD_ASRU_FAULTY, cip->ci_uuid, nvl);

	fmd_asru_hash_release(ahp, asru);
	fmd_case_rele(cp);
	fmd_module_unlock(mp);
}

void
fmd_case_uuclose(fmd_hdl_t *hdl, const char *uuid)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_case_t *cp = fmd_case_hash_lookup(fmd.d_cases, uuid);

	if (cp == NULL)
		fmd_api_error(mp, EFMD_CASE_INVAL, "cannot close %s", uuid);

	fmd_case_transition(cp, FMD_CASE_CLOSED);
	fmd_case_rele(cp);
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
		rv = cip->ci_state >= FMD_CASE_CLOSED;
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
	return (fmd_case_instate(hdl, cp, FMD_CASE_CLOSED));
}

void
fmd_case_add_ereport(fmd_hdl_t *hdl, fmd_case_t *cp, fmd_event_t *ep)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);

	(void) fmd_api_case_impl(mp, cp); /* validate 'cp' */
	fmd_case_insert_event(cp, ep);
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
	    sep != NULL; sep = fmd_list_next(sep))
		fmd_case_insert_event(cp, sep->se_event);

	mp->mod_stats->ms_accepted.fmds_value.ui64 += sgp->sg_count;
	fmd_module_unlock(mp);
}

void
fmd_case_add_suspect(fmd_hdl_t *hdl, fmd_case_t *cp, nvlist_t *nvl)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	fmd_case_impl_t *cip = fmd_api_case_impl(mp, cp);
	char *class;

	if (cip->ci_state >= FMD_CASE_SOLVED) {
		fmd_api_error(mp, EFMD_CASE_STATE, "cannot add suspect to "
		    "%s: case is already solved or closed\n", cip->ci_uuid);
	}

	if (nvlist_lookup_string(nvl, FM_CLASS, &class) != 0 ||
	    class == NULL || *class == '\0') {
		fmd_api_error(mp, EFMD_CASE_EVENT, "cannot add suspect to "
		    "%s: suspect event is missing a class\n", cip->ci_uuid);
	}

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
	fmd_case_insert_principal(cp, ep);
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

	if (pthread_self() != mp->mod_thread->thr_tid) {
		fmd_api_error(mp, EFMD_THR_INVAL, "auxiliary thread tried to "
		    "create another auxiliary thread\n");
	}

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

	t = fmd_timerq_remove(fmd.d_timers, mp->mod_timerids, id);
	fmd_module_unlock(mp);

	if (t != NULL) {
		fmd_eventq_cancel(mp->mod_queue, FMD_EVT_TIMEOUT, t);
		fmd_free(t, sizeof (fmd_modtimer_t));
	}
}

nvlist_t *
fmd_nvl_create_fault(fmd_hdl_t *hdl, const char *class,
    uint8_t certainty, nvlist_t *asru, nvlist_t *fru, nvlist_t *rsrc)
{
	fmd_module_t *mp = fmd_api_module_lock(hdl);
	nvlist_t *nvl;

	if (class == NULL || class[0] == '\0')
		fmd_api_error(mp, EFMD_NVL_INVAL, "invalid fault class\n");

	nvl = fmd_protocol_fault(class, certainty, asru, fru, rsrc);
	fmd_module_unlock(mp);
	return (nvl);
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
