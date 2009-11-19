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
#include <pthread.h>
#include <umem.h>
#include <fm/libfmevent.h>

#include "fmev_impl.h"

static pthread_key_t fmev_tsdkey = PTHREAD_ONCE_KEY_NP;
static int key_inited;

/*
 * Thread and handle specific data.
 */
struct fmev_tsd {
	fmev_err_t ts_lasterr;
};

static void
fmev_tsd_destructor(void *data)
{
	umem_free(data, sizeof (struct fmev_tsd));
}

/*
 * Called only from fmev_shdl_init.  Check we are opening a valid version
 * of the ABI.
 */
int
fmev_api_init(struct fmev_hdl_cmn *hc)
{
	if (!fmev_api_enter(NULL, 0))
		return (0);
	/*
	 * We implement only version 1 of the ABI at this point.
	 */
	if (hc->hc_api_vers != LIBFMEVENT_VERSION_1) {
		if (key_inited)
			(void) fmev_seterr(FMEVERR_VERSION_MISMATCH);
		return (0);
	}

	return (1);
}

/*
 * On entry to other libfmevent API members we call fmev_api_enter.
 * Some thread-specific data is used to keep a per-thread error value.
 * The version opened must be no greater than the latest version but can
 * be older.  The ver_intro is the api version at which the interface
 * was added - the caller must have opened at least this version.
 */
int
fmev_api_enter(struct fmev_hdl_cmn *hc, uint32_t ver_intro)
{
	struct fmev_tsd *tsd;

	/* Initialize key on first visit */
	if (!key_inited) {
		(void) pthread_key_create_once_np(&fmev_tsdkey,
		    fmev_tsd_destructor);
		key_inited = 1;
	}

	/*
	 * Allocate TSD for error value for this thread.  It is only
	 * freed if/when the thread exits.
	 */
	if ((tsd = pthread_getspecific(fmev_tsdkey)) == NULL) {
		if ((tsd = umem_alloc(sizeof (*tsd), UMEM_DEFAULT)) == NULL ||
		    pthread_setspecific(fmev_tsdkey, (const void *)tsd) != 0) {
			if (tsd)
				umem_free(tsd, sizeof (*tsd));
			return (0);	/* no error set, but what can we do */
		}
	}

	tsd->ts_lasterr = 0;

	if (hc == NULL) {
		return (1);
	}

	/* Enforce version adherence. */
	if (ver_intro > hc->hc_api_vers ||
	    hc->hc_api_vers > LIBFMEVENT_VERSION_LATEST ||
	    ver_intro > LIBFMEVENT_VERSION_LATEST) {
		tsd->ts_lasterr = FMEVERR_VERSION_MISMATCH;
		return (0);
	}

	return (1);
}

/*
 * Called on any fmev_shdl_fini.  Free the TSD for this thread.  If this
 * thread makes other API calls for other open handles, or opens a new
 * handle, then TSD will be allocated again in fmev_api_enter.
 */
void
fmev_api_freetsd(void)
{
	struct fmev_tsd *tsd;

	if ((tsd = pthread_getspecific(fmev_tsdkey)) != NULL) {
		(void) pthread_setspecific(fmev_tsdkey, NULL);
		fmev_tsd_destructor((void *)tsd);
	}
}

/*
 * To return an error condition an API member first sets the error type
 * with a call to fmev_seterr and then returns NULL or whatever it wants.
 * The caller can then retrieve the per-thread error type using fmev_errno
 * or format it with fmev_strerr.
 */
fmev_err_t
fmev_seterr(fmev_err_t error)
{
	struct fmev_tsd *tsd;

	ASSERT(key_inited);

	if ((tsd = pthread_getspecific(fmev_tsdkey)) != NULL)
		tsd->ts_lasterr = error;

	return (error);
}

/*
 * fmev_errno is a macro defined in terms of the following function.  It
 * can be used to dereference the last error value on the current thread;
 * it must not be used to assign to fmev_errno.
 */

const fmev_err_t apierr = FMEVERR_API;
const fmev_err_t unknownerr = FMEVERR_UNKNOWN;

const fmev_err_t *
__fmev_errno(void)
{
	struct fmev_tsd *tsd;

	if (!key_inited)
		return (&apierr);

	if ((tsd = pthread_getspecific(fmev_tsdkey)) == NULL)
		return (&unknownerr);

	return ((const fmev_err_t *)&tsd->ts_lasterr);
}
