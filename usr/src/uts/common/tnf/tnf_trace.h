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

#ifndef _TNF_TRACE_H
#define	_TNF_TRACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/tnf_probe.h>
#include <sys/thread.h>
#include <sys/processor.h>

#include "tnf_buf.h"
#include "tnf_types.h"

/*
 * Minimum and default size of trace file
 */

#define	TNF_TRACE_FILE_MIN	(128 * 1024)
#define	TNF_TRACE_FILE_DEFAULT	(1 * 1024 * 1024)

/*
 * Specification of index field of probe control block
 */

#define	PROBE_INDEX_TYPE_MASK	0x3
#define	PROBE_INDEX_MEM_PTR	0x0	/* index is a normal memory ptr */
#define	PROBE_INDEX_FILE_PTR	0x1	/* index is a file abs ptr */
#define	PROBE_INDEX_LOW_MASK	0xffff0000
#define	PROBE_INDEX_SHIFT	16

#define	PROBE_IS_FILE_PTR(x)	\
	(((x) & PROBE_INDEX_TYPE_MASK) == PROBE_INDEX_FILE_PTR)

#define	ATTR_SEPARATOR		';'
#define	VAL_SEPARATOR		' '

/*
 * Flags in proc struct
 */
#define	PROC_F_FILTER	0x1

#define	PROC_IS_FILTER(pp)	((pp)->p_tnf_flags & PROC_F_FILTER)
#define	PROC_FILTER_SET(pp)	((pp)->p_tnf_flags |= PROC_F_FILTER)
#define	PROC_FILTER_CLR(pp)	((pp)->p_tnf_flags &= ~PROC_F_FILTER)

/*
 * In-memory scheduling info, maintained per thread
 */

typedef struct {
	tnf_record_p		record_p;
	tnf_uint32_t		record_gen;
	hrtime_t		time_base;
	processorid_t		cpuid;
} tnf_schedule_t;

/*
 * Per-thread tracing operations and state
 */

struct _tnf_ops {
	char		mode;		/* allocation mode */
	tnf_byte_lock_t	busy;		/* currently in a probe */
	TNFW_B_WCB	wcb;		/* write control info */
	tnf_schedule_t	schedule;	/* scheduling info */
};

/*
 * File layout of a kernel schedule record
 */

typedef struct {
	tnf_tag_t		tag;
	tnf_kthread_id_t	tid;
	tnf_lwpid_t		lwpid;
	tnf_pid_t		pid;
	/*
	 * time base should be on a double word boundary to avoid pads
	 */
	tnf_time_base_t		time_base;
	tnf_cpuid_t		cpuid;
} tnf_schedule_prototype_t;

/*
 * File layout of a probe (event tag) record
 */

typedef struct {
	tnf_tag_t		tag;
	tnf_name_t		name;
	tnf_properties_t	properties;
	tnf_slot_types_t	slot_types;
	tnf_type_size_t		type_size;
	tnf_slot_names_t	slot_names;
	tnf_string_t		string;	/* XXX detail */
} tnf_probe_prototype_t;

/*
 * Tag data variables
 */

extern tnf_tag_data_t	*tnf_probe_type_tag_data;
extern tnf_tag_data_t	*tnf_kernel_schedule_tag_data;

/*
 *
 */

extern size_t tnf_trace_file_size;

/*
 * Function prototypes
 */

/* Encoder functions */

tnf_record_p tnf_kernel_schedule(tnf_ops_t *, tnf_schedule_t *);
uintptr_t tnf_probe_tag(tnf_ops_t *, tnf_probe_control_t *);

/* Trace functions */

void *tnf_trace_alloc(tnf_ops_t *, tnf_probe_control_t *, tnf_probe_setup_t *);

void tnf_trace_commit(tnf_probe_setup_t *);
void tnf_trace_rollback(tnf_probe_setup_t *);

/* Trace control functions */

void tnf_trace_init(void);
void tnf_trace_on(void);
void tnf_trace_off(void);

#endif /* _TNF_TRACE_H */
