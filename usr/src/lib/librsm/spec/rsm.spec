#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/librsm/spec/rsm.spec

function	rsm_get_controller
declaration	int rsm_get_controller(char *name, rsmapi_controller_handle_t *controller)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_get_controller_attr
declaration	int rsm_get_controller_attr(rsmapi_controller_handle_t chdl, rsmapi_controller_attr_t *attr)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_release_controller
declaration	int rsm_release_controller(rsmapi_controller_handle_t controller)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_export_create
declaration	int rsm_memseg_export_create(rsmapi_controller_handle_t controller, rsm_memseg_export_handle_t *memseg, void *vaddr, size_t length, uint_t flags);
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_export_destroy
declaration	int rsm_memseg_export_destroy(rsm_memseg_export_handle_t memseg)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_export_rebind
declaration	int rsm_memseg_export_rebind(rsm_memseg_export_handle_t memseg, void *vaddr, offset_t off, size_t length)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_export_publish
declaration	int rsm_memseg_export_publish(rsm_memseg_export_handle_t memseg, rsm_memseg_id_t *segment_id, rsmapi_access_entry_t access_list[], uint_t access_list_length)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_export_unpublish
declaration	int rsm_memseg_export_unpublish(rsm_memseg_export_handle_t memseg)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_export_republish
declaration	int rsm_memseg_export_republish(rsm_memseg_export_handle_t memseg, rsmapi_access_entry_t access_list[], uint_t access_list_length)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_connect
declaration	int rsm_memseg_import_connect(rsmapi_controller_handle_t controller, rsm_node_id_t node_id, rsm_memseg_id_t segment_id, rsm_permission_t perm, rsm_memseg_import_handle_t *im_memseg)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_disconnect
declaration	int rsm_memseg_import_disconnect(rsm_memseg_import_handle_t im_memseg)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_get8
declaration	int rsm_memseg_import_get8(rsm_memseg_import_handle_t im_memseg, off_t offset, uint8_t *datap, ulong_t rep_cnt)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_get16
declaration	int rsm_memseg_import_get16(rsm_memseg_import_handle_t im_memseg, off_t offset, uint16_t *datap, ulong_t rep_cnt)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_get32
declaration	int rsm_memseg_import_get32(rsm_memseg_import_handle_t im_memseg, off_t offset, uint32_t *datap, ulong_t rep_cnt)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_get64
declaration	int rsm_memseg_import_get64(rsm_memseg_import_handle_t im_memseg, off_t offset, uint64_t *datap, ulong_t rep_cnt)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_get
declaration	int rsm_memseg_import_get(rsm_memseg_import_handle_t im_memseg, off_t offset, void *dst_addr, size_t length)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_getv
declaration	int rsm_memseg_import_getv(rsm_scat_gath_t *)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_put8
declaration	int rsm_memseg_import_put8(rsm_memseg_import_handle_t im_memseg, off_t offset, uint8_t *datap, ulong_t rep_cnt) 
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_put16
declaration	int rsm_memseg_import_put16(rsm_memseg_import_handle_t im_memseg, off_t offset, uint16_t *datap, ulong_t rep_cnt)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_put32
declaration	int rsm_memseg_import_put32(rsm_memseg_import_handle_t im_memseg, off_t offset, uint32_t *datap, ulong_t rep_cnt)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_put64
declaration	int rsm_memseg_import_put64(rsm_memseg_import_handle_t im_memseg, off_t offset, uint64_t *datap, ulong_t rep_cnt)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_put
declaration	int rsm_memseg_import_put(rsm_memseg_import_handle_t im_memseg, off_t offset, void *src_addr, size_t length)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_putv
declaration	int rsm_memseg_import_putv(rsm_scat_gath_t *)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_map
declaration	int rsm_memseg_import_map(rsm_memseg_import_handle_t im_memseg, void **address, rsm_attribute_t attr, rsm_permission_t perm, off_t offset, size_t length)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_unmap
declaration	int rsm_memseg_import_unmap(rsm_memseg_import_handle_t im_memseg)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_init_barrier
declaration	int rsm_memseg_import_init_barrier(rsm_memseg_import_handle_t im_memseg, rsm_barrier_type_t type, rsmapi_barrier_t *barrier)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_open_barrier
declaration	int rsm_memseg_import_open_barrier(rsmapi_barrier_t *barrier);
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_close_barrier
declaration	int rsm_memseg_import_close_barrier(rsmapi_barrier_t *barrier);
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_order_barrier
declaration	int rsm_memseg_import_order_barrier(rsmapi_barrier_t *barrier)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_destroy_barrier
declaration	int rsm_memseg_import_destroy_barrier(rsmapi_barrier_t *barrier)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_get_mode
declaration	int rsm_memseg_import_get_mode(rsm_memseg_import_handle_t im_memseg, rsm_barrier_mode_t *mode)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_import_set_mode
declaration	int rsm_memseg_import_set_mode(rsm_memseg_import_handle_t im_memseg, rsm_barrier_mode_t mode)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_intr_signal_post
declaration	int rsm_intr_signal_post(void * im_memseg, uint_t flags)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_intr_signal_wait
declaration	int rsm_intr_signal_wait(void * im_memseg, int timeout)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_get_pollfd
declaration	int rsm_memseg_get_pollfd(void *, struct pollfd *)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_memseg_release_pollfd
declaration	int rsm_memseg_release_pollfd(void *)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_get_interconnect_topology
declaration	int rsm_get_interconnect_topology(rsm_topology_t **)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_free_interconnect_topology
declaration	void rsm_free_interconnect_topology(rsm_topology_t *)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_create_localmemory_handle
declaration	int rsm_create_localmemory_handle(rsmapi_controller_handle_t, rsm_localmemory_handle_t *, caddr_t, size_t)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_free_localmemory_handle
declaration	int rsm_free_localmemory_handle(rsmapi_controller_handle_t, rsm_localmemory_handle_t)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end		

function	rsm_get_segmentid_range
declaration	int rsm_get_segmentid_range(const char *, rsm_memseg_id_t *, uint32_t *)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end

function	rsm_intr_signal_wait_pollfd
declaration	int rsm_intr_signal_wait_pollfd(struct pollfd [], nfds_t, int, int *)
include		<rsmapi.h>
arch		all
version		SUNWprivate_1.1
end

function	_rsm_get_controller
weak		rsm_get_controller
version		SUNWprivate_1.1
end		

function	_rsm_get_controller_attr
weak		rsm_get_controller_attr
version		SUNWprivate_1.1
end		

function	_rsm_release_controller
weak		rsm_release_controller
version		SUNWprivate_1.1
end		

function	_rsm_memseg_export_create
weak		rsm_memseg_export_create
version		SUNWprivate_1.1
end		

function	_rsm_memseg_export_destroy
weak		rsm_memseg_export_destroy
version		SUNWprivate_1.1
end		

function	_rsm_memseg_export_rebind
weak		rsm_memseg_export_rebind
version		SUNWprivate_1.1
end		

function	_rsm_memseg_export_publish
weak		rsm_memseg_export_publish
version		SUNWprivate_1.1
end		

function	_rsm_memseg_export_unpublish
weak		rsm_memseg_export_unpublish
version		SUNWprivate_1.1
end		

function	_rsm_memseg_export_republish
weak		rsm_memseg_export_republish
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_connect
weak		rsm_memseg_import_connect
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_disconnect
weak		rsm_memseg_import_disconnect
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_get8
weak		rsm_memseg_import_get8
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_get16
weak		rsm_memseg_import_get16
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_get32
weak		rsm_memseg_import_get32
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_get64
weak		rsm_memseg_import_get64
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_get
weak		rsm_memseg_import_get
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_getv
weak		rsm_memseg_import_getv
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_put8
weak		rsm_memseg_import_put8
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_put16
weak		rsm_memseg_import_put16
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_put32
weak		rsm_memseg_import_put32
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_put64
weak		rsm_memseg_import_put64
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_put
weak		rsm_memseg_import_put
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_putv
weak		rsm_memseg_import_putv
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_map
weak		rsm_memseg_import_map
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_unmap
weak		rsm_memseg_import_unmap
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_init_barrier
weak		rsm_memseg_import_init_barrier
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_open_barrier
weak		rsm_memseg_import_open_barrier
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_close_barrier
weak		rsm_memseg_import_close_barrier
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_order_barrier
weak		rsm_memseg_import_order_barrier
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_destroy_barrier
weak		rsm_memseg_import_destroy_barrier
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_get_mode
weak		rsm_memseg_import_get_mode
version		SUNWprivate_1.1
end		

function	_rsm_memseg_import_set_mode
weak		rsm_memseg_import_set_mode
version		SUNWprivate_1.1
end		

function	_rsm_intr_signal_post
weak		rsm_intr_signal_post
version		SUNWprivate_1.1
end		

function	_rsm_intr_signal_wait
weak		rsm_intr_signal_wait
version		SUNWprivate_1.1
end		

function	_rsm_memseg_get_pollfd
weak		rsm_memseg_get_pollfd
version		SUNWprivate_1.1
end		

function	_rsm_memseg_release_pollfd
weak		rsm_memseg_release_pollfd
version		SUNWprivate_1.1
end		

function	_rsm_get_interconnect_topology
weak		rsm_get_interconnect_topology
version		SUNWprivate_1.1
end		

function	_rsm_free_interconnect_topology
weak		rsm_free_interconnect_topology
version		SUNWprivate_1.1
end		

function	_rsm_create_localmemory_handle
weak		rsm_create_localmemory_handle
version		SUNWprivate_1.1
end		

function	_rsm_free_localmemory_handle
weak		rsm_free_localmemory_handle
version		SUNWprivate_1.1
end		

function	_rsm_get_segmentid_range
weak		rsm_get_segmentid_range
version		SUNWprivate_1.1
end

function	_rsm_intr_signal_wait_pollfd
weak		rsm_intr_signal_wait_pollfd
version		SUNWprivate_1.1
end

