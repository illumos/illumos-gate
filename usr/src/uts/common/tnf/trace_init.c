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
 * Copyright 1994-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Includes
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/debug.h>
#include <sys/tnf.h>
#include <sys/thread.h>
#include <sys/dtrace.h>

#include "tnf_buf.h"
#include "tnf_types.h"
#include "tnf_trace.h"

#ifndef NPROBE

/*
 * Globals
 */

size_t tnf_trace_file_size = TNF_TRACE_FILE_DEFAULT;

/*
 * tnf_trace_on
 */
void
tnf_trace_on(void)
{
	TNFW_B_UNSET_STOPPED(tnfw_b_state);
	tnf_tracing_active = 1;
	dtrace_vtime_enable_tnf();
	/* Enable system call tracing for all processes */
	set_all_proc_sys();
}

/*
 * tnf_trace_off
 */
void
tnf_trace_off(void)
{
	TNFW_B_SET_STOPPED(tnfw_b_state);
	dtrace_vtime_disable_tnf();
	tnf_tracing_active = 0;
	/* System call tracing is automatically disabled */
}

/*
 * tnf_trace_init
 * 	Not reentrant: only called from tnf_allocbuf(), which is
 *	single-threaded.
 */
void
tnf_trace_init(void)
{
	int stopped;
	tnf_ops_t *ops;

	ASSERT(tnf_buf != NULL);
	ASSERT(!tnf_tracing_active);

	stopped = tnfw_b_state & TNFW_B_STOPPED;

	/*
	 * Initialize the buffer
	 */
	tnfw_b_init_buffer(tnf_buf, tnf_trace_file_size);

	/*
	 * Mark allocator running (not stopped). Luckily,
	 * tnf_trace_alloc() first checks tnf_tracing_active, so no
	 * trace data will be written.
	 */
	tnfw_b_state = TNFW_B_RUNNING;

	/*
	 * 1195835: Write out some tags now.  The stopped bit needs
	 * to be clear while we do this.
	 */
	/* LINTED pointer cast may result in improper alignment */
	if ((ops = (tnf_ops_t *)curthread->t_tnf_tpdp) != NULL) {
		tnf_tag_data_t	*tag;
		TNFW_B_POS	*pos;

		ASSERT(!LOCK_HELD(&ops->busy));
		LOCK_INIT_HELD(&ops->busy); /* XXX save a call */

		tag = TAG_DATA(tnf_struct_type);
		(void) tag->tag_desc(ops, tag);
		tag = TAG_DATA(tnf_probe_type);
		(void) tag->tag_desc(ops, tag);
		tag = TAG_DATA(tnf_kernel_schedule);
		(void) tag->tag_desc(ops, tag);

		pos = &ops->wcb.tnfw_w_tag_pos;
		TNFW_B_COMMIT(pos);
		pos = &ops->wcb.tnfw_w_pos;
		TNFW_B_ROLLBACK(pos);

		LOCK_INIT_CLEAR(&ops->busy); /* XXX save a call */
	}

	/* Restore stopped bit */
	tnfw_b_state |= stopped;
}

#endif /* NPROBE */
