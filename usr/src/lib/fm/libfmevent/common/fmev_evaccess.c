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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Subscription event access interfaces.
 */

#include <sys/types.h>
#include <limits.h>
#include <atomic.h>
#include <libsysevent.h>
#include <umem.h>
#include <fm/libfmevent.h>
#include <sys/fm/protocol.h>

#include "fmev_impl.h"

#define	API_ENTERV1(iep) \
	((void) fmev_api_enter(fmev_shdl_cmn(((iep)->ei_hdl)), \
	LIBFMEVENT_VERSION_1))

typedef struct {
	uint32_t ei_magic;		/* _FMEVMAGIC */
	volatile uint32_t ei_refcnt;	/* reference count */
	fmev_shdl_t ei_hdl;		/* handle received on */
	nvlist_t *ei_nvl;		/* (duped) sysevent attribute list */
	uint64_t ei_fmtime[2];		/* embedded protocol event time */
} fmev_impl_t;

#define	FMEV2IMPL(ev)	((fmev_impl_t *)(ev))
#define	IMPL2FMEV(iep)	((fmev_t)(iep))

#define	_FMEVMAGIC	0x466d4576	/* "FmEv" */

#define	EVENT_VALID(iep) ((iep)->ei_magic == _FMEVMAGIC && \
	(iep)->ei_refcnt > 0 && fmev_shdl_valid((iep)->ei_hdl))

#define	FM_TIME_SEC	0
#define	FM_TIME_NSEC	1

/*
 * Transform a received sysevent_t into an fmev_t.
 */

uint64_t fmev_bad_attr, fmev_bad_tod, fmev_bad_class;

fmev_t
fmev_sysev2fmev(fmev_shdl_t hdl, sysevent_t *sep, char **clsp, nvlist_t **nvlp)
{
	fmev_impl_t *iep;
	uint64_t *tod;
	uint_t nelem;

	if ((iep = fmev_shdl_alloc(hdl, sizeof (*iep))) == NULL)
		return (NULL);

	/*
	 * sysevent_get_attr_list duplicates the nvlist - we free it
	 * in fmev_free when the reference count hits zero.
	 */
	if (sysevent_get_attr_list(sep, &iep->ei_nvl) != 0) {
		fmev_shdl_free(hdl, iep, sizeof (*iep));
		fmev_bad_attr++;
		return (NULL);
	}

	*nvlp = iep->ei_nvl;

	if (nvlist_lookup_string(iep->ei_nvl, FM_CLASS, clsp) != 0) {
		nvlist_free(iep->ei_nvl);
		fmev_shdl_free(hdl, iep, sizeof (*iep));
		fmev_bad_class++;
		return (NULL);
	}

	if (nvlist_lookup_uint64_array(iep->ei_nvl, "__tod", &tod,
	    &nelem) != 0 || nelem != 2) {
		nvlist_free(iep->ei_nvl);
		fmev_shdl_free(hdl, iep, sizeof (*iep));
		fmev_bad_tod++;
		return (NULL);
	}

	iep->ei_fmtime[FM_TIME_SEC] = tod[0];
	iep->ei_fmtime[FM_TIME_NSEC] = tod[1];

	/*
	 * Now remove the fmd-private __tod and __ttl members.
	 */
	(void) nvlist_remove_all(iep->ei_nvl, "__tod");
	(void) nvlist_remove_all(iep->ei_nvl, "__ttl");

	iep->ei_magic = _FMEVMAGIC;
	iep->ei_hdl = hdl;
	iep->ei_refcnt = 1;
	ASSERT(EVENT_VALID(iep));

	return (IMPL2FMEV(iep));
}

static void
fmev_free(fmev_impl_t *iep)
{
	ASSERT(iep->ei_refcnt == 0);

	nvlist_free(iep->ei_nvl);
	fmev_shdl_free(iep->ei_hdl, iep, sizeof (*iep));
}

void
fmev_hold(fmev_t ev)
{
	fmev_impl_t *iep = FMEV2IMPL(ev);

	ASSERT(EVENT_VALID(iep));

	API_ENTERV1(iep);

	atomic_inc_32(&iep->ei_refcnt);
}

void
fmev_rele(fmev_t ev)
{
	fmev_impl_t *iep = FMEV2IMPL(ev);

	ASSERT(EVENT_VALID(iep));

	API_ENTERV1(iep);

	if (atomic_dec_32_nv(&iep->ei_refcnt) == 0)
		fmev_free(iep);
}

fmev_t
fmev_dup(fmev_t ev)
{
	fmev_impl_t *iep = FMEV2IMPL(ev);
	fmev_impl_t *cp;

	ASSERT(EVENT_VALID(iep));

	API_ENTERV1(iep);

	if (ev == NULL) {
		(void) fmev_seterr(FMEVERR_API);
		return (NULL);
	}

	if ((cp = fmev_shdl_alloc(iep->ei_hdl, sizeof (*iep))) == NULL) {
		(void) fmev_seterr(FMEVERR_ALLOC);
		return (NULL);
	}

	if (nvlist_dup(iep->ei_nvl, &cp->ei_nvl, 0) != 0) {
		fmev_shdl_free(iep->ei_hdl, cp, sizeof (*cp));
		(void) fmev_seterr(FMEVERR_ALLOC);
		return (NULL);
	}

	cp->ei_magic = _FMEVMAGIC;
	cp->ei_hdl = iep->ei_hdl;
	cp->ei_refcnt = 1;
	return (IMPL2FMEV(cp));
}

nvlist_t *
fmev_attr_list(fmev_t ev)
{
	fmev_impl_t *iep = FMEV2IMPL(ev);

	ASSERT(EVENT_VALID(iep));

	API_ENTERV1(iep);

	if (ev == NULL) {
		(void) fmev_seterr(FMEVERR_API);
		return (NULL);
	} else if (iep->ei_nvl == NULL) {
		(void) fmev_seterr(FMEVERR_MALFORMED_EVENT);
		return (NULL);
	}

	return (iep->ei_nvl);
}

const char *
fmev_class(fmev_t ev)
{
	fmev_impl_t *iep = FMEV2IMPL(ev);
	const char *class;

	ASSERT(EVENT_VALID(iep));

	API_ENTERV1(iep);

	if (ev == NULL) {
		(void) fmev_seterr(FMEVERR_API);
		return ("");
	}

	if (nvlist_lookup_string(iep->ei_nvl, FM_CLASS, (char **)&class) != 0 ||
	    *class == '\0') {
		(void) fmev_seterr(FMEVERR_MALFORMED_EVENT);
		return ("");
	}

	return (class);
}

fmev_err_t
fmev_timespec(fmev_t ev, struct timespec *tp)
{
	fmev_impl_t *iep = FMEV2IMPL(ev);
	uint64_t timetlimit;

	ASSERT(EVENT_VALID(iep));
	API_ENTERV1(iep);

#ifdef	_LP64
	timetlimit = INT64_MAX;
#else
	timetlimit = INT32_MAX;
#endif

	if (iep->ei_fmtime[FM_TIME_SEC] > timetlimit)
		return (FMEVERR_OVERFLOW);

	tp->tv_sec = (time_t)iep->ei_fmtime[FM_TIME_SEC];
	tp->tv_nsec = (long)iep->ei_fmtime[FM_TIME_NSEC];

	return (FMEV_SUCCESS);
}

uint64_t
fmev_time_sec(fmev_t ev)
{
	return (FMEV2IMPL(ev)->ei_fmtime[FM_TIME_SEC]);
}

uint64_t
fmev_time_nsec(fmev_t ev)
{
	return (FMEV2IMPL(ev)->ei_fmtime[FM_TIME_NSEC]);
}

struct tm *
fmev_localtime(fmev_t ev, struct tm *tm)
{
	time_t seconds;

	seconds = (time_t)fmev_time_sec(ev);
	return (localtime_r(&seconds, tm));
}
