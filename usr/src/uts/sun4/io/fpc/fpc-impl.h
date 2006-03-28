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

#ifndef	_FPC_IMPL_H
#define	_FPC_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* Hide what's behind the platform-specific handle from the common files. */
typedef struct __fire_perfreg_handle_t *fire_perfreg_handle_t;

#define	IS_READ		B_FALSE
#define	IS_WRITE	B_TRUE

typedef struct {
	char		*name;
	kmutex_t	mutex;
	void		*plat_data_p;
} node_data_t;

/* Functions exported by platform specific file. */

extern int fpc_platform_check();
extern int fpc_platform_module_init(dev_info_t *dip);
extern int fpc_platform_node_init(dev_info_t *dip, int *avail);
extern void fpc_platform_node_fini(void *arg);
extern void fpc_platform_module_fini(dev_info_t *dip);
extern fire_perfreg_handle_t fpc_get_perfreg_handle(int devnum);
extern int fpc_free_counter_handle(fire_perfreg_handle_t);
extern int fpc_event_io(fire_perfreg_handle_t handle, fire_perfcnt_t group,
    uint64_t *event, boolean_t is_write);
extern int fpc_counter_io(fire_perfreg_handle_t handle, fire_perfcnt_t group,
    int counter_index, uint64_t *value, boolean_t is_write);

/* Functions exported by common file. */
extern void fpc_common_node_setup(dev_info_t *dip, int *index_p);
extern char *fpc_get_dev_name_by_number(int index);
extern void *fpc_get_platform_data_by_number(int index);
extern int fpc_set_platform_data_by_number(int index, void *data);

#ifdef	__cplusplus
}
#endif

#endif	/* _FPC_IMPL_H */
