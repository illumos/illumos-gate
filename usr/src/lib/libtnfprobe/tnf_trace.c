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

#ifndef DEBUG
#define	NDEBUG	1
#endif

#include <stdlib.h>
#include <string.h>
#include <tnf/com.h>
#include <tnf/writer.h>
#include <tnf/probe.h>
#include <assert.h>

#include "tnf_types.h"
#include "tnf_trace.h"

#ifdef TNFWB_DEBUG
#ifdef _KERNEL
#error TNFWB_DEBUG
#else  /* _KERNEL */
#include <stdio.h>
#include <thread.h>
#endif /* _KERNEL */
#endif /* TNFW_DEBUG */


/*
 * Defines
 */

#ifdef _KERNEL
#define	TNF_ASSERT(expr)	ASSERT(expr)
#else
#define	TNF_ASSERT(expr)	assert(expr)
#endif

/*
 * New properties need for tracing
 */

static tnf_tag_data_t	**derived_tagarg_properties[] = {
	&TAG_DATA(tnf_derived),
	&TAG_DATA(tnf_tag_arg),
	0
};

static tnf_tag_data_t	***derived_tagarg_properties_ptr =
					derived_tagarg_properties;

/*
 * New derived types for probes
 */

TNF_STD_DERIVED_TAG(tnf_probe_event, tnf_tag,
		derived_tagarg_properties_ptr, TNF_OPAQUE);

TNF_STD_DERIVED_TAG(tnf_time_base, tnf_int64,
		tnf_derived_properties, TNF_INT64);

TNF_STD_DERIVED_TAG(tnf_time_delta, tnf_uint32,
		tnf_derived_properties, TNF_UINT32);

TNF_STD_DERIVED_TAG(tnf_pid, tnf_int32,
		tnf_derived_properties, TNF_INT32);

TNF_STD_DERIVED_TAG(tnf_lwpid, tnf_uint32,
		tnf_derived_properties, TNF_UINT32);

/*
 * Schedule records -CAUTION- keep in sync with tnf_internal.h
 * Note that tnf_schedule_prototype_t has different sizes for
 * kernel and user.
 */

static char	*user_schedule_slot_names[] = {
	TNF_N_TAG,
	TNF_N_TID,
	TNF_N_LWPID,
	TNF_N_PID,
	TNF_N_TIME_BASE,
	0};

static tnf_tag_data_t	**user_schedule_slots[] = {
	&TAG_DATA(tnf_tag),		/* tag			*/
	&TAG_DATA(tnf_uint32),		/* tid XXX		*/
	&TAG_DATA(tnf_lwpid),		/* lwpid 		*/
	&TAG_DATA(tnf_pid),		/* pid 			*/
	&TAG_DATA(tnf_time_base),	/* time_base 		*/
	0};

TNF_STD_STRUCT_TAG(tnf_sched_rec,
		user_schedule_slots,
		user_schedule_slot_names,
		sizeof (tnf_schedule_prototype_t));

/*
 * Probe type record (metatag)
 */

static tnf_tag_data_t	**probe_type_slots[] = {
	&TAG_DATA(tnf_tag),
	&TAG_DATA(tnf_name),
	&TAG_DATA(tnf_properties),
	&TAG_DATA(tnf_slot_types),
	&TAG_DATA(tnf_type_size),
	&TAG_DATA(tnf_slot_names),
	&TAG_DATA(tnf_string),  	/* detail */
	0};

TNF_STRUCT_TAG(tnf_probe_type,
		tnf_type_properties,
		probe_type_slots,
		0,
		sizeof (tnf_probe_prototype_t));

/*
 * export all tags
 */

TAG_EXPORT(tnf_probe_event);
TAG_EXPORT(tnf_time_base);
TAG_EXPORT(tnf_time_delta);
TAG_EXPORT(tnf_pid);
TAG_EXPORT(tnf_lwpid);

TAG_EXPORT(tnf_sched_rec);
TAG_EXPORT(tnf_probe_type);

/*
 * Write a schedule record
 * Can only be written in reusable data space.
 */

tnf_record_p
tnf_schedule_write(tnf_ops_t *ops, tnf_schedule_t *sched)
{
	tnf_tag_data_t *metatag_data;
	tnf_record_p metatag_index;
	tnf_schedule_prototype_t *buffer;

#ifdef _TNF_VERBOSE
	fprintf(stderr, "tnf_schedule_write: \n");
#endif
	/* Cannot be called when writing into tag space */
	TNF_ASSERT(ops->mode == TNF_ALLOC_REUSABLE);
	ALLOC(ops, sizeof (*buffer), buffer, sched->record_p, ops->mode);

	metatag_data = TAG_DATA(tnf_sched_rec);

	metatag_index = metatag_data->tag_index ?
		metatag_data->tag_index :
		metatag_data->tag_desc(ops, metatag_data);

	ASSIGN(buffer,	tag, 		metatag_index);
	/* LINTED - tid is 32 bits */
	ASSIGN2(buffer, tid, 		sched->tid,		uint32);
	/* LINTED - lwpid is 32 bits */
	ASSIGN(buffer,	lwpid, 		sched->lwpid);
	/* LINTED - pid is 32 bits */
	ASSIGN(buffer,	pid, 		sched->pid);
	ASSIGN(buffer,	time_base, 	sched->time_base);

	/*
	 * Remember schedule record generation number so the distance
	 * in virtual space can be calculated from an event record
	 */
	sched->record_gen = ((tnf_block_header_t *)
	    ((uintptr_t)buffer & TNF_BLOCK_MASK))->generation;
	/* Cannot have been written into tag space */
	TNF_ASSERT(sched->record_gen != TNF_TAG_GENERATION_NUM);

	return ((tnf_record_p) buffer);
}
