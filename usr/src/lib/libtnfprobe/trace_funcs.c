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

#ifndef DEBUG
#define	NDEBUG	1
#endif

#include <assert.h>
#include <limits.h>
#include <values.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "tnf_trace.h"

/*
 * Defines
 */

#define	ASSERT(expr)	assert(expr)

#define	ENCODED_TAG(tag, tagarg) 		\
	(((tag) | ((tagarg) & 0xfffc)) | TNF_REF32_T_PAIR)

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
 * Check that hi 32 bits of hrtime are zero
 */
#define	TIME_CHECK(x)				\
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
 * tnf_trace_alloc
 * 	the probe allocation function
 */

#define	IS_NEWBLOCK(blockArray, dataBuffer) \
	    (((caddr_t)&blockArray[1]) == (caddr_t)dataBuffer)

void *
tnf_trace_alloc(tnf_ops_t *ops, tnf_probe_control_t *probe_p,
    tnf_probe_setup_t *set_p)
{
	TNFW_B_WCB		*wcb;
	volatile char 		*file_start;
	uintptr_t		probe_index;
	tnf_record_p		sched_record_p;
	tnf_reference_t		sched_offset, tag_disp;
	tnf_block_header_t	*block;
	tnf_uint32_t		shift;
	probe_event_prototype_t *buffer;
	hrtime_t 		curr_time, time_diff;
	tnf_schedule_t		*sched;
	tnf_ref32_t		*fwd_p;
	ulong_t			size, asize;
#if defined(DEBUG) || defined(VERYVERBOSE)
	char tmp_buf[512];
#endif

	ASSERT(ops != NULL);

	/* check if already in a probe */
	if (ops->busy)
		return (NULL);
	ops->busy = 1;


#ifdef VERYVERBOSE
	sprintf(tmp_buf, "tnf_trace_alloc: begin\n");
	(void) write(2, tmp_buf, strlen(tmp_buf));
#endif

	/*
	 * CAUTION: Ordering of function calls in this file is critical because
	 * we call TNFW_B_GIVEBACK. Between the time we allocate space for the
	 * event and call TNFW_B_GIVEBACK there can be no other allocations!!
	 */

	/*
	 * Write probe tag if needed
	 */
	probe_index = probe_p->index;
#ifdef VERYVERBOSE
	sprintf(tmp_buf, "tnf_trace_alloc: (1) probe_index=%p\n", probe_index);
	(void) write(2, tmp_buf, strlen(tmp_buf));
#endif
	if (probe_index == 0) {
	    if ((probe_index = tnf_probe_tag(ops, probe_p)) == 0) {
#ifdef VERYVERBOSE
	    sprintf(tmp_buf, "tnf_trace_alloc: (2) probe_index=%p\n",
		    probe_index);
	    (void) write(2, tmp_buf, strlen(tmp_buf));
	    sprintf(tmp_buf, "tnf_trace_alloc: goto null_ret\n");
	    (void) write(2, tmp_buf, strlen(tmp_buf));
	    fflush(stderr);
	    sleep(2);
#endif
	    goto null_ret;
	    }
#ifdef VERYVERBOSE
	    sprintf(tmp_buf, "tnf_trace_alloc: (3) probe_index=%p\n",
		probe_index);
	    (void) write(2, tmp_buf, strlen(tmp_buf));
	    fflush(stderr);
#endif
	}
	/*
	 * Determine how much memory is required
	 */
	size = probe_p->tnf_event_size;
	asize = size + sizeof (tnf_ref32_t);	/* one fwd ptr */

	if (PROBE_IS_FILE_PTR(probe_index)) {
		/* common case - probe_index is a file ptr */
		tag_disp = probe_index & PROBE_INDEX_LOW_MASK;
	} else {
		/* rare case -- get an extra fwd ptr */
		asize += sizeof (tnf_ref32_t);
	}

	/*
	 * Allocate memory
	 */
	wcb = &(ops->wcb);

#ifdef _TNF_VERBOSE
	sprintf(tmp_buf, "tnf_trace_alloc, wcb=%p\n", wcb);
	(void) write(2, tmp_buf, strlen(tmp_buf));
#endif

	buffer = ops->alloc(wcb, asize, ops->mode);

#ifdef _TNF_VERBOSE
	sprintf(tmp_buf, "tnf_trace_alloc, buffer=%p\n", buffer);
	(void) write(2, tmp_buf, strlen(tmp_buf));
#endif
	if (buffer == NULL)
		goto null_ret;

	/* LINTED pointer cast may result in improper alignment */
	fwd_p = (tnf_ref32_t *) ((char *)(buffer) + size);

#ifdef _TNF_VERBOSE
	sprintf(tmp_buf, "tnf_trace_alloc, fwd_pr=%p\n", fwd_p);
	(void) write(2, tmp_buf, strlen(tmp_buf));
#endif

	/* set file_start after calling alloc because it allocs the file */
	file_start = _tnfw_b_control->tnf_buffer;

	/* Check if the probe tag needs more work */
	if (!PROBE_IS_FILE_PTR(probe_index)) {
		/* LINTED use up first fwd ptr */
		*fwd_p = TNF_REF32_MAKE_PERMANENT(
		/* LINTED ptr subtraction */
			(tnf_record_p)probe_index - (tnf_record_p) file_start);
		/* LINTED ptr subtraction */
		tag_disp = PTR_DIFF(fwd_p, buffer);
		ASSERT(TAGARG_CHECK(tag_disp));
		tag_disp |= TNF_TAG16_T_REL;
		tag_disp = tag_disp << TNF_REF32_TAG16_SHIFT;
		fwd_p++;
	}

	/*
	 * Get timestamp
	 */
	curr_time = gethrtime();

	/*
	 * initialize and write schedule record if needed
	 * watch out for sched->record_p - it has to be checked after alloc is
	 * called for the event, because it could be side effected by alloc
	 * if a fork happened.  Pre-requisite to our algorithm - if a fork
	 * happens all other threads have to be quiescent i.e. not in a probe.
	 */
	sched = &(ops->schedule);

#ifdef _TNF_VERBOSE
	sprintf(tmp_buf, "tnf_trace_alloc, sched=%p\n", sched);
	(void) write(2, tmp_buf, strlen(tmp_buf));
#endif

	/* LINTED pointer cast */
	shift = ((tnf_buf_file_header_t *)file_start)->com.file_log_size;
	block = (tnf_block_header_t *)((ulong_t)buffer & TNF_BLOCK_MASK);

	if ((sched_record_p = sched->record_p) == NULL ||
	    IS_NEWBLOCK(block, buffer)) {
		/* No record written yet */
		goto new_schedule;
	}

	/*
	 * Note: Don't bother about space bit here, because we'll
	 * only use bits 15:2 anyway
	 */
	sched_offset = ((sched->record_gen - block->generation) << shift) +
		/* LINTED - ptr subtraction */
		(uint_t) (sched_record_p - (caddr_t)buffer);

	if (!TAGARG_CHECK(sched_offset))
		/* Record too far away to reference */
		goto new_schedule;

	time_diff = curr_time - sched->time_base;
	if (!TIME_CHECK(time_diff))
		/* Time delta can't fit in 32 bits */
		goto new_schedule;

	/*
	 * Can reuse existing schedule record
	 * Since we did not allocate any more space, can giveback
	 */
	/* LINTED - GIVEBACK returns a pointer subtraction */
	TNFW_B_GIVEBACK(wcb, fwd_p);

good_ret:
	/*
	 * Store return params and two common event members, return buffer
	 */
	set_p->tpd_p = ops;
	set_p->buffer_p = buffer;
	set_p->probe_p = probe_p;
	buffer->probe_event = ENCODED_TAG(tag_disp, sched_offset);
	/* LINTED - TIME_CHECK already passed, see above */
	buffer->time_delta = tnf_time_delta(ops, (unsigned long)time_diff,
	    &buffer->probe_time_delta);
	return (buffer);

new_schedule:
	/*
	 * Write a new schedule record for this thread
	 */
#ifdef VERYVERBOSE
	sprintf(tmp_buf, "	tnf_trace_alloc: initializing "
				"new schedule record\n");
	(void) write(2, tmp_buf, strlen(tmp_buf));
#endif
	_tnf_sched_init(sched, curr_time);
	time_diff = 0;
	if ((sched_record_p = tnf_schedule_write(ops, sched)) != NULL) {
		/* use one of the extra alloced words for the forwarding ptr */
		/* LINTED - ptr subtraction */
		*fwd_p = TNF_REF32_MAKE_RECLAIMABLE(
			((sched->record_gen - block->generation) << shift) +
			(sched_record_p - (tnf_record_p)fwd_p));
		/* LINTED - ptr subtraction */
		sched_offset = PTR_DIFF(fwd_p, buffer);
		ASSERT(TAGARG_CHECK(sched_offset));
	} else {
		/* Allocation failed (tracing may have been stopped) */
		sched_offset = 0;
		*fwd_p = TNF_NULL;
	}
	goto good_ret;

null_ret:
	/*
	 * reset re-entrancy protector, because tnf_trace_end() will
	 * not be called
	 */
#ifdef VERYVERBOSE
	sprintf(tmp_buf, "tnf_trace_alloc: null return\n");
	(void) write(2, tmp_buf, strlen(tmp_buf));
#endif
	ops->busy = 0;
	return (NULL);
}

/*
 * tnf_trace_end
 *	the last (usually only) function in the list of probe functions
 */
void
tnf_trace_end(tnf_probe_setup_t *set_p)
{
#ifdef VERYVERBOSE
	char tmp_buf[512];

	sprintf(tmp_buf, "tnf_trace_end: \n");
	(void) write(2, tmp_buf, strlen(tmp_buf));
#endif

	(set_p->probe_p->commit_func)(set_p);
	set_p->tpd_p->busy = 0;
}

/*
 * tnf_trace_commit
 *	a probe commit function that really commits trace data
 */
void
tnf_trace_commit(tnf_probe_setup_t *set_p)
{
#ifdef VERYVERBOSE
	char tmp_buf[512];

	sprintf(tmp_buf, "tnf_trace_commit: \n\n");
	(void) write(2, tmp_buf, strlen(tmp_buf));
#endif
	(void) set_p->tpd_p->commit(&(set_p->tpd_p->wcb));

	return;

}

/*
 * tnf_trace_rollback
 *	a probe commit function that unrolls trace data
 */
void
tnf_trace_rollback(tnf_probe_setup_t *set_p)
{
#ifdef VERYVERBOSE
	char tmp_buf[512];

	sprintf(tmp_buf, "tnf_trace_rollback: \n\n");
	(void) write(2, tmp_buf, strlen(tmp_buf));
#endif
	(void) set_p->tpd_p->rollback(&(set_p->tpd_p->wcb));

	return;

}

/*
 * tnf_allocate
 *	exported interface for allocating trace memory
 */

void *
tnf_allocate(tnf_ops_t *ops, size_t size)
{
	void *retval;
	char tmp_buf[512];

#ifdef _TNF_VERBOSE
	sprintf(tmp_buf, "tnf_allocate\n");
	(void) write(2, tmp_buf, strlen(tmp_buf));
#endif

	retval = ops->alloc(&(ops->wcb), size, ops->mode);

#ifdef _TNF_VERBOSE
	sprintf(tmp_buf, "tnf_allocate, retval=%p\n", retval);
	(void) write(2, tmp_buf, strlen(tmp_buf));
#endif

	return (retval);
}
