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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/isa_defs.h>
#include <sys/systeminfo.h>
#include <sys/scsi/generic/smp_frames.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <dlfcn.h>
#include <limits.h>
#include <pthread.h>
#include <synch.h>

#include <scsi/libsmp.h>
#include "smp_impl.h"

static pthread_mutex_t _libsmp_lock = PTHREAD_MUTEX_INITIALIZER;
static smp_engine_t *_libsmp_engines;
static int _libsmp_refcnt;

static boolean_t _libsmp_engine_dlclose;

static void
smp_engine_free(smp_engine_t *ep)
{
	if (ep == NULL)
		return;

	smp_free(ep->se_name);
	smp_free(ep);
}

static void
smp_engine_destroy(smp_engine_t *ep)
{
	smp_engine_t **pp;

	ASSERT(MUTEX_HELD(&_libsmp_lock));

	if (ep->se_fini != NULL)
		ep->se_fini(ep);

	if (_libsmp_engine_dlclose)
		(void) dlclose(ep->se_object);

	ASSERT(ep->se_refcnt == 0);
	for (pp = &_libsmp_engines; *pp != NULL; pp = &((*pp)->se_next))
		if (*pp == ep)
			break;

	if (*pp != NULL)
		*pp = (*pp)->se_next;

	smp_engine_free(ep);
}

void
smp_engine_init(void)
{
	(void) pthread_mutex_lock(&_libsmp_lock);
	++_libsmp_refcnt;
	(void) pthread_mutex_unlock(&_libsmp_lock);
}

void
smp_engine_fini(void)
{
	smp_engine_t *ep;

	(void) pthread_mutex_lock(&_libsmp_lock);
	ASSERT(_libsmp_refcnt > 0);
	if (--_libsmp_refcnt == 0) {
		while (_libsmp_engines != NULL) {
			ep = _libsmp_engines;
			_libsmp_engines = ep->se_next;
			smp_engine_destroy(ep);
		}
	}
	(void) pthread_mutex_unlock(&_libsmp_lock);
}

static int
smp_engine_loadone(const char *path)
{
	smp_engine_t *ep;
	void *obj;

	ASSERT(MUTEX_HELD(&_libsmp_lock));

	if ((obj = dlopen(path, RTLD_PARENT | RTLD_LOCAL | RTLD_LAZY)) == NULL)
		return (smp_set_errno(ESMP_NOENGINE));

	if ((ep = smp_zalloc(sizeof (smp_engine_t))) == NULL) {
		(void) dlclose(obj);
		return (-1);
	}

	ep->se_object = obj;
	ep->se_init = (int (*)())dlsym(obj, "_smp_init");
	ep->se_fini = (void (*)())dlsym(obj, "_smp_fini");

	if (ep->se_init == NULL) {
		smp_engine_free(ep);
		return (smp_set_errno(ESMP_BADENGINE));
	}

	if (ep->se_init(ep) != 0) {
		smp_engine_free(ep);
		return (-1);
	}

	return (0);
}

int
smp_engine_register(smp_engine_t *ep, int version,
    const smp_engine_config_t *ecp)
{
	ASSERT(MUTEX_HELD(&_libsmp_lock));

	if (version != LIBSMP_ENGINE_VERSION)
		return (smp_set_errno(ESMP_VERSION));

	ep->se_ops = ecp->sec_ops;
	ep->se_name = smp_strdup(ecp->sec_name);

	if (ep->se_name == NULL)
		return (-1);

	ep->se_next = _libsmp_engines;
	_libsmp_engines = ep;

	return (0);
}

static smp_engine_t *
smp_engine_hold_cached(const char *name)
{
	smp_engine_t *ep;

	ASSERT(MUTEX_HELD(&_libsmp_lock));

	for (ep = _libsmp_engines; ep != NULL; ep = ep->se_next) {
		if (strcmp(ep->se_name, name) == 0) {
			++ep->se_refcnt;
			return (ep);
		}
	}

	(void) smp_set_errno(ESMP_NOENGINE);
	return (NULL);
}

static smp_engine_t *
smp_engine_hold(const char *name)
{
	smp_engine_t *ep;
	const char *pluginpath, *p, *q;
	char pluginroot[PATH_MAX];
	char path[PATH_MAX];
	char isa[257];

	(void) pthread_mutex_lock(&_libsmp_lock);
	ep = smp_engine_hold_cached(name);
	if (ep != NULL) {
		(void) pthread_mutex_unlock(&_libsmp_lock);
		return (ep);
	}

#if defined(_LP64)
	if (sysinfo(SI_ARCHITECTURE_64, isa, sizeof (isa)) < 0)
		isa[0] = '\0';
#else
	isa[0] = '\0';
#endif

	if ((pluginpath = getenv("SMP_PLUGINPATH")) == NULL)
		pluginpath = LIBSMP_DEFAULT_PLUGINDIR;

	_libsmp_engine_dlclose = (getenv("SMP_NODLCLOSE") == NULL);

	for (p = pluginpath; p != NULL; p = q) {
		if ((q = strchr(p, ':')) != NULL) {
			ptrdiff_t len = q - p;
			(void) strncpy(pluginroot, p, len);
			pluginroot[len] = '\0';
			while (*q == ':')
				++q;
			if (*q == '\0')
				q = NULL;
			if (len == 0)
				continue;
		} else {
			(void) strcpy(pluginroot, p);
		}

		if (pluginroot[0] != '/')
			continue;

		(void) snprintf(path, PATH_MAX, "%s/%s/%s/%s%s",
		    pluginroot, LIBSMP_PLUGIN_ENGINE,
		    isa, name, LIBSMP_PLUGIN_EXT);

		if (smp_engine_loadone(path) == 0) {
			ep = smp_engine_hold_cached(name);
			(void) pthread_mutex_unlock(&_libsmp_lock);
			return (ep);
		}
	}

	return (NULL);
}

static void
smp_engine_rele(smp_engine_t *ep)
{
	(void) pthread_mutex_lock(&_libsmp_lock);
	ASSERT(ep->se_refcnt > 0);
	--ep->se_refcnt;
	(void) pthread_mutex_unlock(&_libsmp_lock);
}

static void
smp_parse_mtbf(const char *envvar, uint_t *intp)
{
	const char *strval;
	int intval;

	if ((strval = getenv(envvar)) != NULL &&
	    (intval = atoi(strval)) > 0) {
		srand48(gethrtime());
		*intp = intval;
	}
}

smp_target_t *
smp_open(const smp_target_def_t *tdp)
{
	smp_engine_t *ep;
	smp_target_t *tp;
	void *private;
	const char *engine;

	if ((engine = tdp->std_engine) == NULL) {
		if ((engine = getenv("LIBSMP_DEFAULT_ENGINE")) == NULL)
			engine = LIBSMP_DEFAULT_ENGINE;
	}

	if ((ep = smp_engine_hold(engine)) == NULL)
		return (NULL);

	if ((tp = smp_zalloc(sizeof (smp_target_t))) == NULL) {
		smp_engine_rele(ep);
		return (NULL);
	}

	if ((private = ep->se_ops->seo_open(tdp->std_def)) == NULL) {
		smp_engine_rele(ep);
		smp_free(tp);
		return (NULL);
	}

	smp_parse_mtbf("LIBSMP_MTBF_REQUEST", &tp->st_mtbf_request);
	smp_parse_mtbf("LIBSMP_MTBF_RESPONSE", &tp->st_mtbf_response);

	tp->st_engine = ep;
	tp->st_priv = private;

	if (smp_plugin_load(tp) != 0) {
		smp_close(tp);
		return (NULL);
	}

	return (tp);
}

void
smp_target_name(const smp_target_t *tp, char *buf, size_t len)
{
	tp->st_engine->se_ops->seo_target_name(tp->st_priv, buf, len);
}

uint64_t
smp_target_addr(const smp_target_t *tp)
{
	return (tp->st_engine->se_ops->seo_target_addr(tp->st_priv));
}

const char *
smp_target_vendor(const smp_target_t *tp)
{
	return (tp->st_vendor);
}

const char *
smp_target_product(const smp_target_t *tp)
{
	return (tp->st_product);
}

const char *
smp_target_revision(const smp_target_t *tp)
{
	return (tp->st_revision);
}

const char *
smp_target_component_vendor(const smp_target_t *tp)
{
	return (tp->st_component_vendor);
}

uint16_t
smp_target_component_id(const smp_target_t *tp)
{
	return (tp->st_component_id);
}

uint8_t
smp_target_component_revision(const smp_target_t *tp)
{
	return (tp->st_component_revision);
}

uint_t
smp_target_getcap(const smp_target_t *tp)
{
	uint_t cap = 0;

	if (tp->st_repgen.srgr_long_response)
		cap |= SMP_TARGET_C_LONG_RESP;

	if (tp->st_repgen.srgr_zoning_supported)
		cap |= SMP_TARGET_C_ZONING;

	if (tp->st_repgen.srgr_number_of_zone_grps == SMP_ZONE_GROUPS_256)
		cap |= SMP_TARGET_C_ZG_256;

	return (cap);
}

void
smp_target_set_change_count(smp_target_t *tp, uint16_t cc)
{
	tp->st_change_count = cc;
}

uint16_t
smp_target_get_change_count(const smp_target_t *tp)
{
	return (tp->st_change_count);
}

void
smp_close(smp_target_t *tp)
{
	smp_free(tp->st_vendor);
	smp_free(tp->st_product);
	smp_free(tp->st_revision);
	smp_free(tp->st_component_vendor);

	smp_plugin_unload(tp);

	tp->st_engine->se_ops->seo_close(tp->st_priv);
	smp_engine_rele(tp->st_engine);

	smp_free(tp);
}

/*
 * Set the timeout in seconds for this action.  If no timeout is specified
 * or if the timeout is set to 0, an implementation-specific timeout will be
 * used (which may vary based on the target, command or other variables).
 * Not all engines support all timeout values.  Setting the timeout to a value
 * not supported by the engine will cause engine-defined behavior when the
 * action is executed.
 */
void
smp_action_set_timeout(smp_action_t *ap, uint32_t timeout)
{
	ap->sa_timeout = timeout;
}

/*
 * Obtain the timeout setting for this action.
 */
uint32_t
smp_action_get_timeout(const smp_action_t *ap)
{
	return (ap->sa_timeout);
}

const smp_function_def_t *
smp_action_get_function_def(const smp_action_t *ap)
{
	return (ap->sa_def);
}

/*
 * Obtain the user-requested request allocation size.  Note that the
 * interpretation of this is function-dependent.
 */
size_t
smp_action_get_rqsd(const smp_action_t *ap)
{
	return (ap->sa_request_rqsd);
}

/*
 * Obtains the address and amount of space allocated for the portion of the
 * request data that lies between the header (if any) and the CRC.
 */
void
smp_action_get_request(const smp_action_t *ap, void **reqp, size_t *dlenp)
{
	if (reqp != NULL) {
		if (ap->sa_request_data_off >= 0) {
			*reqp = ap->sa_request + ap->sa_request_data_off;
		} else {
			*reqp = NULL;
		}
	}

	if (dlenp != NULL)
		*dlenp = ap->sa_request_alloc_len -
		    (ap->sa_request_data_off + sizeof (smp_crc_t));
}

/*
 * Obtains the address and amount of valid response data (that part of the
 * response frame, if any, that lies between the header and the CRC).  The
 * result, if any, is also returned in the location pointed to by result.
 */
void
smp_action_get_response(const smp_action_t *ap, smp_result_t *resultp,
    void **respp, size_t *dlenp)
{
	if (resultp != NULL)
		*resultp = ap->sa_result;

	if (respp != NULL)
		*respp = (ap->sa_response_data_len > 0) ?
		    (ap->sa_response + ap->sa_response_data_off) : NULL;

	if (dlenp != NULL)
		*dlenp = ap->sa_response_data_len;
}

/*
 * Obtains the entire request frame and the amount of space allocated for it.
 * This is intended only for use by plugins; front-end consumers should use
 * smp_action_get_request() instead.
 */
void
smp_action_get_request_frame(const smp_action_t *ap, void **reqp, size_t *alenp)
{
	if (reqp != NULL)
		*reqp = ap->sa_request;

	if (alenp != NULL)
		*alenp = ap->sa_request_alloc_len;
}

/*
 * Obtains the entire response frame and the amount of space allocated for it.
 * This is intended only for use by plugins; front-end consumers should use
 * smp_action_get_response() instead.
 */
void
smp_action_get_response_frame(const smp_action_t *ap,
    void **respp, size_t *lenp)
{
	if (respp != NULL)
		*respp = ap->sa_response;

	if (lenp != NULL) {
		if (ap->sa_flags & SMP_ACTION_F_EXEC)
			*lenp = ap->sa_response_engine_len;
		else
			*lenp = ap->sa_response_alloc_len;
	}
}

/*
 * Set the total response frame length as determined by the engine.  This
 * should never be called by consumers or plugins other than engines.
 */
void
smp_action_set_response_len(smp_action_t *ap, size_t elen)
{
	ap->sa_response_engine_len = elen;
}

void
smp_action_set_result(smp_action_t *ap, smp_result_t result)
{
	ap->sa_result = result;
}

/*
 * Allocate an action object.  The object will contain a request buffer
 * to hold the frame to be transmitted to the target, a response buffer
 * for the frame to be received from it, and auxiliary private information.
 *
 * For the request, callers may specify:
 *
 * - An externally-allocated buffer and its size in bytes, or
 * - NULL and a function-specific size descriptor, or
 *
 * Note that for some functions, the size descriptor may be 0, indicating that
 * a default buffer length will be used.  It is the caller's responsibility
 * to correctly interpret function-specific buffer lengths.  See appropriate
 * plugin documentation for information on buffer sizes and buffer content
 * interpretation.
 *
 * For the response, callers may specify:
 *
 * - An externally-allocated buffer and its size in bytes, or
 * - NULL and 0, to use a guaranteed-sufficient buffer.
 *
 * If an invalid request size descriptor is provided, or a preallocated
 * buffer is provided and it is insufficiently large, this function will
 * fail with ESMP_RANGE.
 *
 * Callers are discouraged from allocating their own buffers and must be
 * aware of the consequences of specifying non-default lengths.
 */
smp_action_t *
smp_action_xalloc(smp_function_t fn, smp_target_t *tp,
    void *rq, size_t rqsd, void *rs, size_t rslen)
{
	smp_plugin_t *pp;
	const smp_function_def_t *dp = NULL;
	smp_action_t *ap;
	uint_t cap;
	size_t rqlen, len;
	uint8_t *alloc;
	int i;

	cap = smp_target_getcap(tp);

	for (pp = tp->st_plugin_first; pp != NULL; pp = pp->sp_next) {
		if (pp->sp_functions == NULL)
			continue;

		for (i = 0; pp->sp_functions[i].sfd_rq_len != NULL; i++) {
			dp = &pp->sp_functions[i];
			if (dp->sfd_function == fn &&
			    ((cap & dp->sfd_capmask) == dp->sfd_capset))
				break;
		}
	}

	if (dp == NULL) {
		(void) smp_set_errno(ESMP_BADFUNC);
		return (NULL);
	}

	if (rq == NULL) {
		if ((rqlen = dp->sfd_rq_len(rqsd, tp)) == 0)
			return (NULL);
	} else if (rqlen < SMP_REQ_MINLEN) {
		(void) smp_set_errno(ESMP_RANGE);
		return (NULL);
	}

	if (rs == NULL) {
		rslen = 1020 + SMP_RESP_MINLEN;
	} else if (rslen < SMP_RESP_MINLEN) {
		(void) smp_set_errno(ESMP_RANGE);
		return (NULL);
	}

	len = offsetof(smp_action_t, sa_buf[0]);
	if (rq == NULL)
		len += rqlen;
	if (rs == NULL)
		len += rslen;

	if ((ap = smp_zalloc(len)) == NULL)
		return (NULL);

	ap->sa_def = dp;
	alloc = ap->sa_buf;

	if (rq == NULL) {
		ap->sa_request = alloc;
		alloc += rqlen;
	}
	ap->sa_request_alloc_len = rqlen;

	if (rs == NULL) {
		ap->sa_response = alloc;
		alloc += rslen;
	}
	ap->sa_response_alloc_len = rslen;

	ASSERT(alloc - (uint8_t *)ap == len);

	ap->sa_request_data_off = dp->sfd_rq_dataoff(ap, tp);
	ap->sa_flags |= SMP_ACTION_F_OFFSET;

	return (ap);
}

/*
 * Simplified action allocator.  All buffers are allocated for the
 * caller.  The request buffer size will be based on the function-specific
 * interpretation of the rqsize parameter.  The response buffer size will be
 * a function-specific value sufficiently large to capture any response.
 */
smp_action_t *
smp_action_alloc(smp_function_t fn, smp_target_t *tp, size_t rqsd)
{
	return (smp_action_xalloc(fn, tp, NULL, rqsd, NULL, 0));
}

void
smp_action_free(smp_action_t *ap)
{
	if (ap == NULL)
		return;

	smp_free(ap);
}

/*
 * For testing purposes, we allow data to be corrupted via an environment
 * variable setting.  This helps ensure that higher level software can cope with
 * arbitrarily broken targets.  The mtbf value represents the number of bytes we
 * will see, on average, in between each failure.  Therefore, for each N bytes,
 * we would expect to see (N / mtbf) bytes of corruption.
 */
static void
smp_inject_errors(void *data, size_t len, uint_t mtbf)
{
	char *buf = data;
	double prob;
	size_t index;

	if (len == 0)
		return;

	prob = (double)len / mtbf;

	while (prob > 1) {
		index = lrand48() % len;
		buf[index] = (lrand48() % 256);
		prob -= 1;
	}

	if (drand48() <= prob) {
		index = lrand48() % len;
		buf[index] = (lrand48() % 256);
	}
}

int
smp_exec(smp_action_t *ap, smp_target_t *tp)
{
	const smp_function_def_t *dp;
	int ret;

	dp = ap->sa_def;
	dp->sfd_rq_setframe(ap, tp);

	if (tp->st_mtbf_request != 0) {
		smp_inject_errors(ap->sa_request, ap->sa_request_alloc_len,
		    tp->st_mtbf_request);
	}

	ret = tp->st_engine->se_ops->seo_exec(tp->st_priv, ap);

	if (ret == 0 && tp->st_mtbf_response != 0) {
		smp_inject_errors(ap->sa_response, ap->sa_response_engine_len,
		    tp->st_mtbf_response);
	}

	if (ret != 0)
		return (ret);

	ap->sa_flags |= SMP_ACTION_F_EXEC;

	/*
	 * Obtain the data length and offset from the underlying plugins.
	 * Then offer the plugins the opportunity to set any parameters in the
	 * target to reflect state observed in the response.
	 */
	ap->sa_response_data_len = dp->sfd_rs_datalen(ap, tp);
	ap->sa_response_data_off = dp->sfd_rs_dataoff(ap, tp);
	dp->sfd_rs_getparams(ap, tp);

	ap->sa_flags |= SMP_ACTION_F_DECODE;

	return (0);
}
