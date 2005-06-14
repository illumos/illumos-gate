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

#include <dt_impl.h>
#include <stddef.h>
#include <errno.h>
#include <assert.h>
#include <time.h>

static const struct {
	int dtslt_option;
	size_t dtslt_offs;
} _dtrace_sleeptab[] = {
	{ DTRACEOPT_STATUSRATE, offsetof(dtrace_hdl_t, dt_laststatus) },
	{ DTRACEOPT_AGGRATE, offsetof(dtrace_hdl_t, dt_lastagg) },
	{ DTRACEOPT_SWITCHRATE, offsetof(dtrace_hdl_t, dt_lastswitch) },
	{ DTRACEOPT_MAX, 0 }
};

void
dtrace_sleep(dtrace_hdl_t *dtp)
{
	dt_proc_hash_t *dph = dtp->dt_procs;
	dtrace_optval_t policy = dtp->dt_options[DTRACEOPT_BUFPOLICY];
	dt_proc_t *dpr;

	hrtime_t earliest = INT64_MAX;
	struct timespec tv;
	hrtime_t now;
	int i;

	for (i = 0; _dtrace_sleeptab[i].dtslt_option < DTRACEOPT_MAX; i++) {
		uintptr_t a = (uintptr_t)dtp + _dtrace_sleeptab[i].dtslt_offs;
		int opt = _dtrace_sleeptab[i].dtslt_option;
		dtrace_optval_t interval = dtp->dt_options[opt];

		/*
		 * If the buffering policy is set to anything other than
		 * "switch", we ignore the aggrate and switchrate -- they're
		 * meaningless.
		 */
		if (policy != DTRACEOPT_BUFPOLICY_SWITCH &&
		    _dtrace_sleeptab[i].dtslt_option != DTRACEOPT_STATUSRATE)
			continue;

		if (*((hrtime_t *)a) + interval < earliest)
			earliest = *((hrtime_t *)a) + interval;
	}

	(void) pthread_mutex_lock(&dph->dph_lock);

	now = gethrtime();

	if (earliest < now) {
		(void) pthread_mutex_unlock(&dph->dph_lock);
		return; /* sleep duration has already past */
	}

	tv.tv_sec = (earliest - now) / NANOSEC;
	tv.tv_nsec = (earliest - now) % NANOSEC;

	/*
	 * Wait for either 'tv' nanoseconds to pass or to receive notification
	 * that a process is in an interesting state.  Regardless of why we
	 * awaken, iterate over any pending notifications and process them.
	 */
	(void) pthread_cond_reltimedwait_np(&dph->dph_cv, &dph->dph_lock, &tv);

	while ((dpr = dph->dph_notify) != NULL) {
		dph->dph_notify = dpr->dpr_notify;
		dpr->dpr_notify = NULL;

		if (dtp->dt_prochdlr != NULL)
			dtp->dt_prochdlr(dpr->dpr_proc, dtp->dt_procarg);
	}

	(void) pthread_mutex_unlock(&dph->dph_lock);
}

int
dtrace_status(dtrace_hdl_t *dtp)
{
	int gen = dtp->dt_statusgen;
	dtrace_optval_t interval = dtp->dt_options[DTRACEOPT_STATUSRATE];
	hrtime_t now = gethrtime();

	if (!dtp->dt_active)
		return (DTRACE_STATUS_NONE);

	if (dtp->dt_stopped)
		return (DTRACE_STATUS_STOPPED);

	if (dtp->dt_laststatus != 0) {
		if (now - dtp->dt_laststatus < interval)
			return (DTRACE_STATUS_NONE);

		dtp->dt_laststatus += interval;
	} else {
		dtp->dt_laststatus = now;
	}

	if (dt_ioctl(dtp, DTRACEIOC_STATUS, &dtp->dt_status[gen]) == -1)
		return (dt_set_errno(dtp, errno));

	dtp->dt_statusgen ^= 1;

	if (dt_handle_status(dtp, &dtp->dt_status[dtp->dt_statusgen],
	    &dtp->dt_status[gen]) == -1)
		return (-1);

	if (dtp->dt_status[gen].dtst_exiting) {
		if (!dtp->dt_stopped)
			(void) dtrace_stop(dtp);

		return (DTRACE_STATUS_EXITED);
	}

	if (dtp->dt_status[gen].dtst_filled == 0)
		return (DTRACE_STATUS_OKAY);

	if (dtp->dt_options[DTRACEOPT_BUFPOLICY] != DTRACEOPT_BUFPOLICY_FILL)
		return (DTRACE_STATUS_OKAY);

	if (!dtp->dt_stopped) {
		if (dtrace_stop(dtp) == -1)
			return (-1);
	}

	return (DTRACE_STATUS_FILLED);
}

dtrace_workstatus_t
dtrace_work(dtrace_hdl_t *dtp, FILE *fp,
    dtrace_consume_probe_f *pfunc, dtrace_consume_rec_f *rfunc, void *arg)
{
	int status = dtrace_status(dtp);
	dtrace_optval_t policy = dtp->dt_options[DTRACEOPT_BUFPOLICY];
	dtrace_workstatus_t rval;

	switch (status) {
	case DTRACE_STATUS_EXITED:
	case DTRACE_STATUS_FILLED:
	case DTRACE_STATUS_STOPPED:
		/*
		 * Tracing is stopped.  We now want to force dtrace_consume()
		 * and dtrace_aggregate_snap() to proceed, regardless of
		 * switchrate and aggrate.  We do this by clearing the times.
		 */
		dtp->dt_lastswitch = 0;
		dtp->dt_lastagg = 0;
		rval = DTRACE_WORKSTATUS_DONE;
		break;

	case DTRACE_STATUS_NONE:
	case DTRACE_STATUS_OKAY:
		rval = DTRACE_WORKSTATUS_OKAY;
		break;

	case -1:
		return (DTRACE_WORKSTATUS_ERROR);
	}

	if ((status == DTRACE_STATUS_NONE || status == DTRACE_STATUS_OKAY) &&
	    policy != DTRACEOPT_BUFPOLICY_SWITCH) {
		/*
		 * There either isn't any status or things are fine -- and
		 * this is a "ring" or "fill" buffer.  We don't want to consume
		 * any of the trace data or snapshot the aggregations; we just
		 * return.
		 */
		assert(rval == DTRACE_WORKSTATUS_OKAY);
		return (rval);
	}

	if (dtrace_aggregate_snap(dtp) == -1)
		return (DTRACE_WORKSTATUS_ERROR);

	if (dtrace_consume(dtp, fp, pfunc, rfunc, arg) == -1)
		return (DTRACE_WORKSTATUS_ERROR);

	return (rval);
}
