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

/*
 * Simple-minded raw event publication from user context.  See extensive
 * comments in libfmevent.h.  These interfaces remain Project Private -
 * they have to evolve before rollout to Public levels.
 *
 * Events are dispatched synchronously using the GPEC sysevent mechanism.
 * The caller context must therefore be one in which a sysevent_evc_publish
 * (and possibly sysevent_evc_bind if not already bound) is safe.  We will
 * also allocate and manipulate nvlists.
 *
 * Since we use GPEC, which has no least privilege awareness, these interfaces
 * will only work for would-be producers running as root.
 *
 * There is no event rate throttling applied, so we rely on producers
 * to throttle themselves.  A future refinement should apply mandatory
 * but tuneable throttling on a per-producer basis.  In this first version
 * the only throttle is the publication event queue depth - we'll drop
 * events when the queue is full.
 *
 * We can publish over four channels, for privileged/non-privileged and
 * high/low priority.  Since only privileged producers will work now
 * (see above) we hardcode priv == B_TRUE and so only two channels are
 * actually used, separating higher and lower value streams from privileged
 * producers.
 */

#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <atomic.h>
#include <errno.h>
#include <pthread.h>
#include <strings.h>

#include "fmev_impl.h"

static struct {
	const char *name;		/* channel name */
	evchan_t *binding;		/* GPEC binding, once bound */
	const uint32_t flags;		/* flags to use in binding */
} chaninfo[] = {
	{ FMEV_CHAN_USER_NOPRIV_LV, NULL, 0 },
	{ FMEV_CHAN_USER_NOPRIV_HV, NULL, 0 },
	{ FMEV_CHAN_USER_PRIV_LV, NULL, EVCH_HOLD_PEND_INDEF },
	{ FMEV_CHAN_USER_PRIV_HV, NULL, EVCH_HOLD_PEND_INDEF}
};

#define	CHANIDX(priv, pri) (2 * ((priv) != 0) + (pri == FMEV_HIPRI))

#define	CHAN_NAME(priv, pri) (chaninfo[CHANIDX(priv, pri)].name)
#define	CHAN_BINDING(priv, pri) (chaninfo[CHANIDX(priv, pri)].binding)
#define	CHAN_FLAGS(priv, pri) (chaninfo[CHANIDX(priv, pri)].flags)

/*
 * Called after fork in the new child.  We clear the cached event
 * channel bindings which are only valid in the process that created
 * them.
 */
static void
clear_bindings(void)
{
	int i;

	for (i = 0; i < sizeof (chaninfo) / sizeof chaninfo[0]; i++)
		chaninfo[i].binding = NULL;
}

#pragma init(_fmev_publish_init)

static void
_fmev_publish_init(void)
{
	(void) pthread_atfork(NULL, NULL, clear_bindings);
}

static evchan_t *
bind_channel(boolean_t priv, fmev_pri_t pri)
{
	evchan_t **evcpp = &CHAN_BINDING(priv, pri);
	evchan_t *evc;

	if (*evcpp != NULL)
		return (*evcpp);

	if (sysevent_evc_bind(CHAN_NAME(priv, pri), &evc,
	    EVCH_CREAT | CHAN_FLAGS(priv, pri)) != 0)
		return (NULL);

	if (atomic_cas_ptr(evcpp, NULL, evc) != NULL)
		(void) sysevent_evc_unbind(evc);

	return (*evcpp);
}

static fmev_err_t
vrfy_ruleset(const char *ruleset)
{
	if (ruleset != NULL &&
	    strnlen(ruleset, FMEV_MAX_RULESET_LEN) == FMEV_MAX_RULESET_LEN)
		return (FMEVERR_STRING2BIG);

	return (FMEV_OK);

}

static fmev_err_t
vrfy_class(const char *class)
{
	if (class == NULL || *class == '\0')
		return (FMEVERR_API);

	if (strnlen(class, FMEV_PUB_MAXCLASSLEN) == FMEV_PUB_MAXCLASSLEN)
		return (FMEVERR_STRING2BIG);

	return (FMEV_OK);
}

static fmev_err_t
vrfy_subclass(const char *subclass)
{
	if (subclass == NULL || *subclass == '\0')
		return (FMEVERR_API);

	if (strnlen(subclass, FMEV_PUB_MAXSUBCLASSLEN) ==
	    FMEV_PUB_MAXSUBCLASSLEN)
		return (FMEVERR_STRING2BIG);

	return (FMEV_OK);
}

static fmev_err_t
vrfy_pri(fmev_pri_t pri)
{
	return (pri == FMEV_LOPRI || pri == FMEV_HIPRI ?
	    FMEV_OK : FMEVERR_API);
}

const char *
fmev_pri_string(fmev_pri_t pri)
{
	static const char *pristr[] = { "low", "high" };

	if (vrfy_pri(pri) != FMEV_OK)
		return (NULL);

	return (pristr[pri - FMEV_LOPRI]);
}

static fmev_err_t
vrfy(const char **rulesetp, const char **classp, const char **subclassp,
    fmev_pri_t *prip)
{
	fmev_err_t rc = FMEV_OK;

	if (rulesetp && (rc = vrfy_ruleset(*rulesetp)) != FMEV_OK)
		return (rc);

	if (classp && (rc = vrfy_class(*classp)) != FMEV_OK ||
	    subclassp && (rc = vrfy_subclass(*subclassp)) != FMEV_OK ||
	    prip && (rc = vrfy_pri(*prip)) != FMEV_OK)
		return (rc);

	return (FMEV_OK);
}

uint_t fmev_va2nvl_maxtuples = 100;

fmev_err_t
va2nvl(nvlist_t **nvlp, va_list ap, uint_t ntuples)
{
	nvlist_t *nvl = NULL;
	uint_t processed = 0;
	char *name;

	if (ntuples == 0)
		return (FMEVERR_INTERNAL);

	if ((name = va_arg(ap, char *)) == NULL || name == FMEV_ARG_TERM)
		return (FMEVERR_VARARGS_MALFORMED);

	if (ntuples > fmev_va2nvl_maxtuples)
		return (FMEVERR_VARARGS_TOOLONG);

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0)
		return (FMEVERR_ALLOC);

	while (name != NULL && name != FMEV_ARG_TERM && processed <= ntuples) {
		data_type_t type;
		int err, nelem;

		type = va_arg(ap, data_type_t);

		switch (type) {
		case DATA_TYPE_BYTE:
			err = nvlist_add_byte(nvl, name,
			    va_arg(ap, uint_t));
			break;
		case DATA_TYPE_BYTE_ARRAY:
			nelem = va_arg(ap, int);
			err = nvlist_add_byte_array(nvl, name,
			    va_arg(ap, uchar_t *), nelem);
			break;
		case DATA_TYPE_BOOLEAN_VALUE:
			err = nvlist_add_boolean_value(nvl, name,
			    va_arg(ap, boolean_t));
			break;
		case DATA_TYPE_BOOLEAN_ARRAY:
			nelem = va_arg(ap, int);
			err = nvlist_add_boolean_array(nvl, name,
			    va_arg(ap, boolean_t *), nelem);
			break;
		case DATA_TYPE_INT8:
			err = nvlist_add_int8(nvl, name,
			    va_arg(ap, int));
			break;
		case DATA_TYPE_INT8_ARRAY:
			nelem = va_arg(ap, int);
			err = nvlist_add_int8_array(nvl, name,
			    va_arg(ap, int8_t *), nelem);
			break;
		case DATA_TYPE_UINT8:
			err = nvlist_add_uint8(nvl, name,
			    va_arg(ap, uint_t));
			break;
		case DATA_TYPE_UINT8_ARRAY:
			nelem = va_arg(ap, int);
			err = nvlist_add_uint8_array(nvl, name,
			    va_arg(ap, uint8_t *), nelem);
			break;
		case DATA_TYPE_INT16:
			err = nvlist_add_int16(nvl, name,
			    va_arg(ap, int));
			break;
		case DATA_TYPE_INT16_ARRAY:
			nelem = va_arg(ap, int);
			err = nvlist_add_int16_array(nvl, name,
			    va_arg(ap, int16_t *), nelem);
			break;
		case DATA_TYPE_UINT16:
			err = nvlist_add_uint16(nvl, name,
			    va_arg(ap, uint_t));
			break;
		case DATA_TYPE_UINT16_ARRAY:
			nelem = va_arg(ap, int);
			err = nvlist_add_uint16_array(nvl, name,
			    va_arg(ap, uint16_t *), nelem);
			break;
		case DATA_TYPE_INT32:
			err = nvlist_add_int32(nvl, name,
			    va_arg(ap, int32_t));
			break;
		case DATA_TYPE_INT32_ARRAY:
			nelem = va_arg(ap, int);
			err = nvlist_add_int32_array(nvl, name,
			    va_arg(ap, int32_t *), nelem);
			break;
		case DATA_TYPE_UINT32:
			err = nvlist_add_uint32(nvl, name,
			    va_arg(ap, uint32_t));
			break;
		case DATA_TYPE_UINT32_ARRAY:
			nelem = va_arg(ap, int);
			err = nvlist_add_uint32_array(nvl, name,
			    va_arg(ap, uint32_t *), nelem);
			break;
		case DATA_TYPE_INT64:
			err = nvlist_add_int64(nvl, name,
			    va_arg(ap, int64_t));
			break;
		case DATA_TYPE_INT64_ARRAY:
			nelem = va_arg(ap, int);
			err = nvlist_add_int64_array(nvl, name,
			    va_arg(ap, int64_t *), nelem);
			break;
		case DATA_TYPE_UINT64:
			err = nvlist_add_uint64(nvl, name,
			    va_arg(ap, uint64_t));
			break;
		case DATA_TYPE_UINT64_ARRAY:
			nelem = va_arg(ap, int);
			err = nvlist_add_uint64_array(nvl, name,
			    va_arg(ap, uint64_t *), nelem);
			break;
		case DATA_TYPE_STRING:
			err = nvlist_add_string(nvl, name,
			    va_arg(ap, char *));
			break;
		case DATA_TYPE_STRING_ARRAY:
			nelem = va_arg(ap, int);
			err = nvlist_add_string_array(nvl, name,
			    va_arg(ap, char **), nelem);
			break;
		case DATA_TYPE_NVLIST:
			err = nvlist_add_nvlist(nvl, name,
			    va_arg(ap, nvlist_t *));
			break;
		case DATA_TYPE_NVLIST_ARRAY:
			nelem = va_arg(ap, int);
			err = nvlist_add_nvlist_array(nvl, name,
			    va_arg(ap, nvlist_t **), nelem);
			break;
		case DATA_TYPE_HRTIME:
			err = nvlist_add_hrtime(nvl, name,
			    va_arg(ap, hrtime_t));
			break;
		case DATA_TYPE_DOUBLE:
			err = nvlist_add_double(nvl, name,
			    va_arg(ap, double));
			break;
		default:
			err = EINVAL;
		}

		if (err)
			break;	/* terminate on first error */

		processed++;
		name = va_arg(ap, char *);
	}

	if (name != FMEV_ARG_TERM || processed != ntuples) {
		*nvlp = NULL;
		nvlist_free(nvl);
		return (FMEVERR_VARARGS_MALFORMED);
	}

	*nvlp = nvl;
	return (FMEV_SUCCESS);
}

static fmev_err_t
do_publish(const char *file, const char *func, int64_t line,
    const char *ruleset, const char *class, const char *subclass,
    fmev_pri_t pri, nvlist_t *nvl, uint_t ntuples, va_list ap)
{
	fmev_err_t rc = FMEVERR_INTERNAL;
	boolean_t priv = B_TRUE;
	nvlist_t *tmpnvl = NULL;
	nvlist_t *pub;
	evchan_t *evc;

	if (nvl) {
		ASSERT(ntuples == 0);

		/*
		 * Enforce NV_UNIQUE_NAME
		 */
		if ((nvlist_nvflag(nvl) & NV_UNIQUE_NAME) != NV_UNIQUE_NAME)
			return (FMEVERR_NVLIST);

		pub = nvl;

	} else if (ntuples != 0) {
		fmev_err_t err;

		err = va2nvl(&tmpnvl, ap, ntuples);
		if (err != FMEV_SUCCESS)
			return (err);

		pub = tmpnvl;
	} else {
		/*
		 * Even if the caller has no tuples to publish (just an event
		 * class and subclass), we are going to add some detector
		 * information so we need some nvlist.
		 */
		if (nvlist_alloc(&tmpnvl, NV_UNIQUE_NAME, 0) != 0)
			return (FMEVERR_ALLOC);

		pub = tmpnvl;
	}

	evc = bind_channel(priv, pri);

	if (evc == NULL) {
		rc = FMEVERR_INTERNAL;
		goto done;
	}


	/*
	 * Add detector information
	 */
	if (file && nvlist_add_string(pub, "__fmev_file", file) != 0 ||
	    func && nvlist_add_string(pub, "__fmev_func", func) != 0 ||
	    line != -1 && nvlist_add_int64(pub, "__fmev_line", line) != 0 ||
	    nvlist_add_int32(pub, "__fmev_pid", getpid()) != 0 ||
	    nvlist_add_string(pub, "__fmev_execname", getexecname()) != 0) {
		rc = FMEVERR_ALLOC;
		goto done;
	}

	if (ruleset == NULL)
		ruleset = FMEV_RULESET_DEFAULT;

	/*
	 * We abuse the GPEC publication arguments as follows:
	 *
	 * GPEC argument	Our usage
	 * -------------------- -----------------
	 * const char *class	Raw class
	 * const char *subclass	Raw subclass
	 * const char *vendor	Ruleset name
	 * const char *pub_name	Unused
	 * nvlist_t *attr_list	Event attributes
	 */
	rc = (sysevent_evc_publish(evc, class, subclass, ruleset, "",
	    pub, EVCH_NOSLEEP) == 0) ? FMEV_SUCCESS : FMEVERR_TRANSPORT;

done:
	/* Free a passed in nvlist iff success */
	if (rc == FMEV_SUCCESS)
		nvlist_free(nvl);

	nvlist_free(tmpnvl);

	return (rc);
}

fmev_err_t
_i_fmev_publish_nvl(
    const char *file, const char *func, int64_t line,
    const char *ruleset, const char *class, const char *subclass,
    fmev_pri_t pri, nvlist_t *attr)
{
	fmev_err_t rc;

	if ((rc = vrfy(&ruleset, &class, &subclass, &pri)) != FMEV_OK)
		return (rc);		/* any attr not freed */

	return (do_publish(file, func, line,
	    ruleset, class, subclass,
	    pri, attr, 0, NULL));	/* any attr freed iff success */
}

fmev_err_t
_i_fmev_publish(
    const char *file, const char *func, int64_t line,
    const char *ruleset, const char *class, const char *subclass,
    fmev_pri_t pri,
    uint_t ntuples, ...)
{
	va_list ap;
	fmev_err_t rc;

	if ((rc = vrfy(&ruleset, &class, &subclass, &pri)) != FMEV_OK)
		return (rc);

	if (ntuples != 0)
		va_start(ap, ntuples);

	rc = do_publish(file, func, line,
	    ruleset, class, subclass,
	    pri, NULL, ntuples, ap);

	if (ntuples != 0)
		va_end(ap);

	return (rc);
}


#pragma	weak fmev_publish = _fmev_publish
#pragma	weak fmev_rspublish = _fmev_rspublish

static fmev_err_t
_fmev_publish(const char *class, const char *subclass, fmev_pri_t pri,
    uint_t ntuples, ...)
{
	fmev_err_t rc;
	va_list ap;

	if ((rc = vrfy(NULL, &class, &subclass, &pri)) != FMEV_OK)
		return (rc);

	if (ntuples != 0)
		va_start(ap, ntuples);

	rc = do_publish(NULL, NULL, -1,
	    FMEV_RULESET_DEFAULT, class, subclass,
	    pri, NULL, ntuples, ap);

	if (ntuples != 0)
		va_end(ap);

	return (rc);
}

static fmev_err_t
_fmev_rspublish(const char *ruleset, const char *class, const char *subclass,
    fmev_pri_t pri, uint_t ntuples, ...)
{
	fmev_err_t rc;
	va_list ap;

	if ((rc = vrfy(&ruleset, &class, &subclass, &pri)) != FMEV_OK)
		return (rc);

	if (ntuples != 0)
		va_start(ap, ntuples);

	rc = do_publish(NULL, NULL, -1,
	    ruleset, class, subclass,
	    pri, NULL, ntuples, ap);

	if (ntuples != 0)
		va_end(ap);

	return (rc);
}
