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
 *      Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#ifndef _TNF_TRACE_H
#define	_TNF_TRACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <tnf/probe.h>
#include "tnf_buf.h"
#include "tnf_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Size of a TNF buffer block
 */

#define	TNF_BLOCK_SIZE 	512
#define	TNF_BLOCK_MASK	~(TNF_BLOCK_SIZE - 1)

/*
 * Size of TNF file directory area
 */

#define	TNF_DIRECTORY_SIZE	(1 << 16)

/*
 * specification of index field of probe control block
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

typedef struct {
	tnf_record_p		record_p;
	tnf_uint32_t		record_gen;
	unsigned long		tid;
	unsigned long		lwpid;
	long			pid;
	hrtime_t		time_base;
} tnf_schedule_t;

typedef struct {
	tnf_tag_t		tag;
	tnf_uint32_t		tid;
	tnf_uint32_t		lwpid;
	pid_t			pid;
	/*
	 * time base should be on a double word boundary to avoid pads
	 */
	tnf_longlong_t	time_base;
} tnf_schedule_prototype_t;

typedef struct {
	tnf_tag_t		tag;
	tnf_name_t		name;
	tnf_properties_t	properties;
	tnf_slot_types_t	slot_types;
	tnf_type_size_t		type_size;
	tnf_slot_names_t	slot_names;
	tnf_string_t		string;
} tnf_probe_prototype_t;

/*
 * TNF output ops
 */

/*
 * Data structure that is the glue between the tnf layer and the buffering
 * layer.
 */
struct _tnf_ops {
	/* fields needed by TNF writing layer */
	enum tnf_alloc_mode mode;
	void * (*alloc)(TNFW_B_WCB *, size_t, enum tnf_alloc_mode);
	TNFW_B_STATUS (*commit)(TNFW_B_WCB *);
	TNFW_B_STATUS (*rollback)(TNFW_B_WCB *);
	TNFW_B_WCB wcb;
	/* fields needed by tracing allocation and final function */
	int			busy;
	tnf_schedule_t		schedule;
};

/*
 * Tag data variables
 */
extern tnf_tag_data_t	*tnf_probe_type_tag_data;
extern tnf_tag_data_t	*tnf_sched_rec_tag_data;

tnf_record_p 	tnf_schedule_write(tnf_ops_t *ops, tnf_schedule_t *sched);
uintptr_t 	tnf_probe_tag(tnf_ops_t *ops, tnf_probe_control_t *probe);
void		_tnf_sched_init(tnf_schedule_t *, hrtime_t);
int 		_tnf_trace_initialize(void);
void 		_tnf_fork_thread_setup(void);

extern char tnf_trace_file_name[];

/* PROJECT PRIVATE interfaces between prex and libtnfprobe */

void *tnf_trace_alloc(tnf_ops_t *, tnf_probe_control_t *, tnf_probe_setup_t *);

void tnf_trace_end(tnf_probe_setup_t *);

void tnf_trace_commit(tnf_probe_setup_t *);

void tnf_trace_rollback(tnf_probe_setup_t *);

void tnf_probe_debug(tnf_probe_setup_t *);

#ifdef __cplusplus
}
#endif

#endif /* _TNF_TRACE_H */
