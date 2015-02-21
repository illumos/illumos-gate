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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>

#include <ucontext.h>
#include <strings.h>
#include <stdio.h>
#include <errno.h>

#include <fmd_trace.h>
#include <fmd_alloc.h>
#include <fmd_subr.h>
#include <fmd_conf.h>
#include <fmd.h>

fmd_tracebuf_t *
fmd_trace_create(void)
{
	fmd_tracebuf_t *tbp = fmd_zalloc(sizeof (fmd_tracebuf_t), FMD_SLEEP);
	size_t bufsize;

	(void) fmd_conf_getprop(fmd.d_conf, "trace.frames", &tbp->tb_frames);
	(void) fmd_conf_getprop(fmd.d_conf, "trace.recs", &tbp->tb_recs);

	/*
	 * We require 8-byte alignment of fmd_tracerec_t to store hrtime_t's.
	 * Since the trailing flexible array member is of type uintptr_t, we
	 * may need to allocate an additional element if we are compiling
	 * 32-bit; otherwise uintptr_t is 8 bytes so any value of tb_frames is
	 * acceptable.
	 *
	 * tb_frames includes the first element, whose size is reflected in
	 * sizeof (fmd_tracerec_t).  Therefore, if fmd_tracerec_t's size is
	 * 0 mod 8, we must be sure the total number of frames is odd.
	 * Otherwise, we need at least one extra frame, so the total count
	 * must be even.  This will continue to work even if the sizes or
	 * types of other fmd_tracerec_t members are changed.
	 */
#ifdef _ILP32
	/*CONSTCOND*/
	if (sizeof (fmd_tracerec_t) % sizeof (hrtime_t) == 0)
		tbp->tb_frames = (tbp->tb_frames & ~1UL) + 1;
	else
		tbp->tb_frames = P2ROUNDUP(tbp->tb_frames, 2);
#endif
	tbp->tb_size = sizeof (fmd_tracerec_t) +
	    sizeof (uintptr_t) * (MAX(tbp->tb_frames, 1) - 1);

	bufsize = tbp->tb_size * tbp->tb_recs;

	tbp->tb_buf = fmd_zalloc(bufsize, FMD_SLEEP);
	tbp->tb_end = (void *)((uintptr_t)tbp->tb_buf + bufsize - tbp->tb_size);
	tbp->tb_ptr = tbp->tb_buf;

	return (tbp);
}

void
fmd_trace_destroy(fmd_tracebuf_t *tbp)
{
	fmd_free(tbp->tb_buf, tbp->tb_size * tbp->tb_recs);
	fmd_free(tbp, sizeof (fmd_tracebuf_t));
}

/*
 * Callback for walkcontext(3C) to store the stack trace.  We use tr_tag below
 * to store the maximum value of depth that is permitted so we can use it here.
 */
/*ARGSUSED*/
static int
fmd_trace_frame(uintptr_t pc, int sig, fmd_tracerec_t *trp)
{
	trp->tr_stack[trp->tr_depth++] = pc;
	return (trp->tr_depth >= trp->tr_tag);
}

/*ARGSUSED*/
fmd_tracerec_t *
fmd_trace_none(fmd_tracebuf_t *tbp, uint_t tag, const char *format, va_list ap)
{
	return (NULL);
}

fmd_tracerec_t *
fmd_trace_lite(fmd_tracebuf_t *tbp, uint_t tag, const char *format, va_list ap)
{
	hrtime_t time = gethrtime();
	fmd_tracerec_t *trp = tbp->tb_ptr;
	char *p;

	if (tbp->tb_depth++ != 0) {
		tbp->tb_depth--;
		return (NULL);
	}

	trp->tr_time = time;
	trp->tr_file = NULL;
	trp->tr_line = 0;
	trp->tr_errno = (tag == FMD_DBG_ERR) ? errno : 0;
	trp->tr_tag = fmd_ntz32(tag);

	(void) vsnprintf(trp->tr_msg, sizeof (trp->tr_msg), format, ap);
	p = &trp->tr_msg[strlen(trp->tr_msg)];
	if (p > trp->tr_msg && p[-1] == '\n')
		p[-1] = '\0';

	if (tbp->tb_ptr != tbp->tb_end)
		tbp->tb_ptr = (void *)((uintptr_t)tbp->tb_ptr + tbp->tb_size);
	else
		tbp->tb_ptr = tbp->tb_buf;

	tbp->tb_depth--;
	return (trp);
}

fmd_tracerec_t *
fmd_trace_full(fmd_tracebuf_t *tbp, uint_t tag, const char *format, va_list ap)
{
	hrtime_t time = gethrtime();
	fmd_tracerec_t *trp = tbp->tb_ptr;
	ucontext_t uc;
	char *p;

	if (tbp->tb_depth++ != 0) {
		tbp->tb_depth--;
		return (NULL);
	}

	(void) getcontext(&uc);
	trp->tr_depth = 0;
	trp->tr_tag = tbp->tb_frames; /* for use by fmd_trace_frame() */
	(void) walkcontext(&uc, (int (*)())fmd_trace_frame, trp);

	trp->tr_time = time;
	trp->tr_file = NULL;
	trp->tr_line = 0;
	trp->tr_errno = (tag == FMD_DBG_ERR) ? errno : 0;
	trp->tr_tag = fmd_ntz32(tag);

	if (fmd.d_fmd_debug & FMD_DBG_TRACE)
		fmd_vdprintf(tag, format, ap);

	(void) vsnprintf(trp->tr_msg, sizeof (trp->tr_msg), format, ap);
	p = &trp->tr_msg[strlen(trp->tr_msg)];
	if (p > trp->tr_msg && p[-1] == '\n')
		p[-1] = '\0';

	if (tbp->tb_ptr != tbp->tb_end)
		tbp->tb_ptr = (void *)((uintptr_t)tbp->tb_ptr + tbp->tb_size);
	else
		tbp->tb_ptr = tbp->tb_buf;

	tbp->tb_depth--;
	return (trp);
}
