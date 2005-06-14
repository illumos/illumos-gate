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
 * Copyright 1999-2001, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_RSM_RSMAPI_COMMON_H
#define	_SYS_RSM_RSMAPI_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/rsm/rsm_common.h>

/*
 * Applications must provide a handle for each region of local memory
 * specified in the scatter/gather list used for an rsm_memseg_putv
 * rsm_memseg_getv operation.
 */
struct __rsm_localmemory_handle;
typedef struct __rsm_localmemory_handle *rsm_localmemory_handle_t;

struct __rsmapi_controller_handle;
typedef struct __rsmapi_controller_handle *rsmapi_controller_handle_t;

typedef struct {
	uint_t	attr_direct_access_sizes;
	uint_t	attr_atomic_sizes;
	size_t	attr_page_size;
	size_t	attr_max_export_segment_size;
	size_t	attr_tot_export_segment_size;
	ulong_t	attr_max_export_segments;
	size_t	attr_max_import_map_size;
	size_t	attr_tot_import_map_size;
	ulong_t	attr_max_import_segments;
} rsmapi_controller_attr_t;

typedef struct {
	rsm_node_id_t	 ae_node;	/* node id allowed access */
	rsm_permission_t ae_permission;	/* permissions for node */
} rsmapi_access_entry_t;

typedef struct {
	void		*seg;
	uint16_t 	gnum;
	void 		*privdata;
}rsmapi_barrier_t;

/*
 * The scatter/gather list contains a pointer (iovec) to an io vector array.
 * Each array element is of type rsm_io_vect_t
 */

typedef struct {
	int				io_type;
	union {
		rsm_localmemory_handle_t	handle;
		caddr_t				vaddr;
	} local;
	size_t					local_offset;
	size_t					remote_offset;
	size_t					transfer_length;
} rsm_iovec_t;

typedef struct {
	rsm_node_id_t			local_nodeid;
	ulong_t				io_request_count;
	ulong_t				io_residual_count;
	uint_t				flags;
	rsm_memseg_import_handle_t	remote_handle;
	rsm_iovec_t			*iovec;
} rsm_scat_gath_t;

/* scatter/gather I/O  types */
#define	RSM_HANDLE_TYPE	0x01
#define	RSM_VA_TYPE	0x02

/*
 * The following macro can be used to indicate that rebind and unbind is
 * allowed for an exported segment. This flag is used during the export
 * segment creation.
 */
#define	RSM_ALLOW_REBIND	0x01

/*
 * This new flag will be used in rsm_memseg_export_create
 * to control blocking/noblocking resource allocation
 * from RSMAPI layer/interface
 */

#define	RSM_CREATE_SEG_DONTWAIT	0x02

/*
 * The bits in the flags field in the scatter gather structure can be
 * initialized using the following macros. An RSM_SIGPOST_NO_ACCUMULATE
 * flag can be ored into the flags value to indicate that when an implicit
 * signal post is being done, the events are not to be accumulated.
 * This flag is defined below.
 */
#define	RSM_IMPLICIT_SIGPOST	0x01

/*
 * The following macro can be used as the flags argument in
 * rsm_intr_signal_post to indicate that the events should not be
 * accumulated and then serviced individually. The default value of the
 * flags argument for the rsm_intr_signal_post is 0, which indicates that
 * the events are accumulated and serviced individually.
 * It is important to note here that the value of this macro is 0x02 and
 * should not be changed without checking for consistency of use in the
 * rsm_memseg_import_getv and rsm_memseg_import_putv calls for an implicit
 * signal post.
 */
#define	RSM_SIGPOST_NO_ACCUMULATE	0x02

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_RSM_RSMAPI_COMMON_H */
