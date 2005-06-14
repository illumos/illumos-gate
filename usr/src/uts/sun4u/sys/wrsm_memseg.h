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

#ifndef _WRSM_MEMSEG_H
#define	_WRSM_MEMSEG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * stuff exported by the RSMPI memseg module
 */

#include <sys/rsm/rsmpi.h>
#include <sys/wrsm_transport.h>

#ifdef	__cplusplus
extern "C" {
#endif


void wrsm_memseg_init(void);
void wrsm_memseg_fini(void);
void wrsm_memseg_network_init(wrsm_network_t *);
void wrsm_memseg_network_fini(wrsm_network_t *);
void wrsm_memseg_node_init(wrsm_node_t *);
void wrsm_memseg_node_fini(wrsm_node_t *);
void *wrsm_alloc(size_t, int);
void wrsm_free(void *, size_t);

int wrsmrsm_seg_create(rsm_controller_handle_t controller,
    rsm_memseg_export_handle_t *memsegp,
    size_t size, uint_t flags, rsm_memory_local_t *memory,
    rsm_resource_callback_t callback,
    rsm_resource_callback_arg_t callback_arg);

int wrsmrsm_seg_destroy(rsm_memseg_export_handle_t handle);

int wrsmrsm_bind(rsm_memseg_export_handle_t memseg,
    off_t offset,
    rsm_memory_local_t *memory,
    rsm_resource_callback_t callback,
    rsm_resource_callback_arg_t callback_arg);

int wrsmrsm_unbind(rsm_memseg_export_handle_t memseg, off_t offset,
    size_t length);

int wrsmrsm_rebind(rsm_memseg_export_handle_t memseg, off_t offset,
    rsm_memory_local_t *memory, rsm_resource_callback_t callback,
    rsm_resource_callback_arg_t callback_arg);

int wrsmrsm_publish(rsm_memseg_export_handle_t memseg,
    rsm_access_entry_t access_list[],
    uint_t access_list_length,
    rsm_memseg_id_t segid,
    rsm_resource_callback_t callback,
    rsm_resource_callback_arg_t callback_arg);

int wrsmrsm_unpublish(rsm_memseg_export_handle_t memseg);

int wrsmrsm_republish(rsm_memseg_export_handle_t memseg,
    rsm_access_entry_t access_list[], uint_t access_list_length,
    rsm_resource_callback_t callback, rsm_resource_callback_arg_t callback_arg);

int wrsmrsm_connect(rsm_controller_handle_t controller,
    rsm_addr_t addr, rsm_memseg_id_t segid,
    rsm_memseg_import_handle_t *im_memseg);

int wrsmrsm_disconnect(rsm_memseg_import_handle_t im_memseg);

int wrsmrsm_map(rsm_memseg_import_handle_t im_memseg, off_t offset,
    size_t len, size_t *map_len, dev_info_t **dipp, uint_t *dev_register,
    off_t *dev_offset, rsm_resource_callback_t callback,
    rsm_resource_callback_arg_t arg);

int wrsmrsm_unmap(rsm_memseg_import_handle_t im_memseg);

int wrsmrsm_put(rsm_memseg_import_handle_t im_memseg, off_t offset,
    void *datap, size_t length);
int wrsmrsm_put8(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint8_t *data, ulong_t rep_cnt, boolean_t byte_swap);
int wrsmrsm_put16(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint16_t *data, ulong_t rep_cnt, boolean_t byte_swap);
int wrsmrsm_put32(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint32_t *data, ulong_t rep_cnt, boolean_t byte_swap);
int wrsmrsm_put64(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint64_t *data, ulong_t rep_cnt, boolean_t byte_swap);

int wrsmrsm_get(rsm_memseg_import_handle_t im_memseg, off_t offset,
    void *datap, size_t length);
int wrsmrsm_get8(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint8_t *datap, ulong_t rep_cnt, boolean_t byte_swap);
int wrsmrsm_get16(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint16_t *datap, ulong_t rep_cnt, boolean_t byte_swap);
int wrsmrsm_get32(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint32_t *datap, ulong_t rep_cnt, boolean_t byte_swap);
int wrsmrsm_get64(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint64_t *datap, ulong_t rep_cnt, boolean_t byte_swap);


void wrsm_free_exportsegs(wrsm_network_t *network);
void wrsm_free_importsegs(wrsm_network_t *network);

/* for controller kstat */
typedef struct memseg_stat_data {
	uint_t export_count;
	uint_t import_count;
	uint_t export_published;
	uint_t export_connected;
	uint_t bytes_bound;
} wrsm_memseg_stat_data_t;

void wrsm_memseg_stat(wrsm_network_t *network, wrsm_memseg_stat_data_t *data);

typedef struct wrsm_memseg_evt_args {
	wrsm_network_t *network;
	wrsm_message_t msg;
} wrsm_memseg_evt_args_t;

/*
 * event functions for delivering incoming remote messages asynchronously
 */
boolean_t wrsm_memseg_msg_hdlr(wrsm_network_t *network, wrsm_message_t *msg);
void wrsm_connect_msg_evt(void *arg);
void wrsm_smallputmap_msg_evt(void *arg);
void wrsm_barriermap_msg_evt(void *arg);
void wrsm_segmap_msg_evt(void *arg);
void wrsm_disconnect_msg_evt(void *arg);
void wrsm_unpublish_msg_evt(void *arg);
void wrsm_access_msg_evt(void *arg);

#ifdef	__cplusplus
}
#endif

#endif /* _WRSM_MEMSEG_H */
