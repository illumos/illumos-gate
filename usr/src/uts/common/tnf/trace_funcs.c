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
 *	Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Includes
 */
#include <sys/param.h>
#include <sys/time.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/tnf.h>

#include "tnf_buf.h"
#include "tnf_types.h"
#include "tnf_trace.h"

/*
 * Defines
 */

#define	ENCODED_TAG(tag, tagarg) 		\
	((tag) | ((tagarg) & 0xfffc) | TNF_REF32_T_PAIR)

/*
 * CAUTION: halfword_accessible assumes that the pointer is to a reclaimable
 *		block - i.e. negative offsets have a 0 in high bit
 */
#define	HALFWORD_ACCESSIBLE(x) 			\
	((((x) & 0xffff8000) == 0) || (((x) & 0xffff8000) == 0x7fff8000))

/*
 * Check that x can be encoded in tagarg slot
 * Same as above, but operates on ints (no space bit)
 */
#define	TAGARG_CHECK(x)				\
	(((x) < 32767) && ((x) > -32768))

/*
 * Check that hit 32 bits of hrtime are zero
 */
#define	TIME_CHECK(x) 			\
	(((x) >> 32) == 0)

/*
 * CAUTION: Use the following macro only when doing a self relative pointer
 *		to a target in the same block
 */
#define	PTR_DIFF(item, ref)			\
	((tnf_ref32_t)((tnf_record_p)(item) - (tnf_record_p)(ref)))

/*
 * Typedefs
 */

typedef struct {
	tnf_probe_event_t		probe_event;
	tnf_time_delta_t		time_delta;
} probe_event_prototype_t;

/*
 * Declarations
 */

/*
 * tnf_trace_alloc
 * 	the probe allocation function
 */

void *
tnf_trace_alloc(tnf_ops_t *ops, tnf_probe_control_t *probe_p,
    tnf_probe_setup_t *set_p)
{
	TNFW_B_WCB		*wcb;
	uintptr_t 		probe_index;
	tnf_record_p		sched_record_p;
	tnf_reference_t 	sched_offset, tag_disp;
	tnf_block_header_t	*block;
	tnf_uint32_t		shift;
	probe_event_prototype_t *buffer;
	hrtime_t 		curr_time, time_diff;
	tnf_schedule_t		*sched;
	tnf_ref32_t		*fwd_p;
	size_t			size, asize;

	/*
	 * Check the "tracing active" flag after setting the busy bit;
	 * this avoids a race in which we check the "tracing active"
	 * flag, then it gets turned off, and the buffer gets
	 * deallocated, before we've set the busy bit.
	 */
	if (!lock_try(&ops->busy)) /* atomic op flushes WB */
		return (NULL);
	if (!tnf_tracing_active)
		goto null_ret;

	/*
	 * Write probe tag if needed
	 */
	probe_index = probe_p->index;
	if (probe_index == 0) {
		if ((probe_index = tnf_probe_tag(ops, probe_p)) == 0)
			goto null_ret;
	}

	/*
	 * Determine how much memory is required
	 */
	size = probe_p->tnf_event_size;
	asize = size + sizeof (tnf_ref32_t); /* one fwd ptr */

	if (PROBE_IS_FILE_PTR(probe_index))
		/* common case - probe_index is a file ptr */
		/* LINTED assignment of 64-bit integer to 32-bit integer */
		tag_disp = probe_index & PROBE_INDEX_LOW_MASK;
	else
		/* rare case -- get an extra fwd ptr */
		asize += sizeof (tnf_ref32_t);

	/*
	 * Allocate memory
	 */
	wcb = &ops->wcb;
	/* LINTED assignment of 64-bit integer to 16-bit integer */
	TNFW_B_ALLOC(wcb, asize, buffer, probe_event_prototype_t *);
	if (buffer == NULL)
		goto null_ret;

	/* LINTED pointer cast may result in improper alignment */
	fwd_p = (tnf_ref32_t *)((char *)buffer + size);

	/*
	 * Check if the probe tag needs more work
	 */
	if (!PROBE_IS_FILE_PTR(probe_index)) {
		/* use up first fwd ptr */
		/* LINTED assignment of 64-bit integer to 32-bit integer */
		*fwd_p = TNF_REF32_MAKE_PERMANENT(
			(tnf_record_p)probe_index - tnf_buf);
		/* LINTED cast from 64-bit integer to 32-bit integer */
		tag_disp = PTR_DIFF(fwd_p, buffer);
		tag_disp |= TNF_TAG16_T_REL;
		tag_disp = tag_disp << TNF_REF32_TAG16_SHIFT;
		fwd_p++;
	}

	/*
	 * Get timestamp
	 */
	curr_time = gethrtime();

	/*
	 * Write schedule record if needed
	 */
	sched = &ops->schedule;

	/* LINTED pointer cast */
	shift = ((tnf_buf_file_header_t *)tnf_buf)->com.file_log_size;
	block = (tnf_block_header_t *)((uintptr_t)buffer & TNF_BLOCK_MASK);

	if ((sched_record_p = sched->record_p) == NULL)
		/* No record written yet */
		goto new_schedule;

	/*
	 * Note: Don't bother about space bit here, because we'll
	 * only use bits 15:2 anyway
	 */
#if defined(_LP64)
	/* LINTED  assignment of 64-bit integer to 32-bit integer */
	sched_offset = ((sched->record_gen - block->generation) << shift) +
		(sched_record_p - (caddr_t)buffer);
#else
	sched_offset = ((sched->record_gen - block->generation) << shift) +
		(sched_record_p - (caddr_t)buffer);
#endif
	if (!TAGARG_CHECK(sched_offset))
		/* Record too far away to reference */
		goto new_schedule;

	time_diff = curr_time - sched->time_base;
	if (!TIME_CHECK(time_diff))
		/* Time delta can't fit in 32 bits */
		goto new_schedule;

	if (sched->cpuid != CPU->cpu_id)
		/* CPU information is invalid */
		goto new_schedule;

	/*
	 * Can reuse existing schedule record
	 * Since we did not allocate any more space, can giveback
	 */
#if defined(_LP64)
	/* LINTED warning: assignment of 64-bit integer to 16-bit integer */
	TNFW_B_GIVEBACK(wcb, fwd_p);
#else
	TNFW_B_GIVEBACK(wcb, fwd_p);
#endif

good_ret:
	/*
	 * Store return params and two common event members, return buffer
	 */
	set_p->tpd_p = ops;
	set_p->buffer_p = buffer;
	set_p->probe_p = probe_p;
	buffer->probe_event = ENCODED_TAG(tag_disp, sched_offset);
#if defined(_LP64)
	/* LINTED assignment of 64-bit integer to 32-bit integer */
	buffer->time_delta = tnf_time_delta(ops, (unsigned long)time_diff,
	    &buffer->probe_time_delta);
#else
	buffer->time_delta = tnf_time_delta(ops, (unsigned long)time_diff,
		&buffer->probe_time_delta);
#endif
	return (buffer);

new_schedule:
	/*
	 * Write a new schedule record for this thread
	 */
	sched->cpuid = CPU->cpu_id;
	sched->time_base = curr_time;
	time_diff = 0;
	if ((sched_record_p = tnf_kernel_schedule(ops, sched)) != NULL) {
		/* use one of the extra alloced words for the forwarding ptr */
#if defined(_LP64)
		/* LINTED assignment of 64-bit integer to 32-bit integer */
		*fwd_p = TNF_REF32_MAKE_RECLAIMABLE(
			((sched->record_gen - block->generation) << shift) +
			    /* LINTED */
			    (sched_record_p - (tnf_record_p)fwd_p));
		/* LINTED cast from 64-bit integer to 32-bit integer */
		sched_offset = PTR_DIFF(fwd_p, buffer);
#else
		*fwd_p = TNF_REF32_MAKE_RECLAIMABLE(
			((sched->record_gen - block->generation) << shift) +
			(sched_record_p - (tnf_record_p)fwd_p));
		sched_offset = PTR_DIFF(fwd_p, buffer);
#endif
	} else {
		/* Allocation failed (tracing may have been stopped) */
		sched_offset = 0;
		*fwd_p = TNF_NULL;
	}
	goto good_ret;

null_ret:
	/*
	 * Clear busy flag and return null
	 */
	LOCK_INIT_CLEAR(&ops->busy);	/* XXX save a call */
	return (NULL);
}

/*
 * tnf_trace_commit
 */
void
tnf_trace_commit(tnf_probe_setup_t *set_p)
{
	tnf_ops_t	*ops;
	TNFW_B_WCB	*wcb;
	TNFW_B_POS 	*pos;

	ops = set_p->tpd_p;
	wcb = &ops->wcb;

	/* commit reusable bytes */
	pos = &wcb->tnfw_w_pos;
	TNFW_B_COMMIT(pos);

	/* commit tag bytes */
	pos = &wcb->tnfw_w_tag_pos;
	TNFW_B_COMMIT(pos);

	/* clear busy flag */
	LOCK_INIT_CLEAR(&ops->busy);	/* XXX save a call */
}

/*
 * tnf_trace_rollback
 */
void
tnf_trace_rollback(tnf_probe_setup_t *set_p)
{
	tnf_ops_t	*ops;
	TNFW_B_WCB	*wcb;
	TNFW_B_POS 	*pos;

	ops = set_p->tpd_p;
	wcb = &ops->wcb;

	/* rollback data bytes */
	pos = &wcb->tnfw_w_pos;
	TNFW_B_ROLLBACK(pos);

	/* commit tag bytes */
	pos = &wcb->tnfw_w_tag_pos;
	TNFW_B_COMMIT(pos);

	/* zap schedule record, since it is in uncommitted store */
	ops->schedule.record_p = NULL;

	/* clear busy flag */
	LOCK_INIT_CLEAR(&ops->busy);	/* XXX save a call */
}

/*
 * tnf_allocate
 *	exported interface for allocating trace memory
 */

void *
tnf_allocate(tnf_ops_t *ops, size_t size)
{
	return (tnfw_b_alloc(&ops->wcb, size, ops->mode));
}
