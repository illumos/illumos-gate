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
 * Copyright (c) 1998-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sched.h>
#include <errno.h>
#include <strings.h>

#include <rsmapi.h>
#include <sys/rsm/rsmndi.h>
#include <rsmlib_in.h>
#include <sys/rsm/rsm.h>

extern int _rsm_memseg_import_map(rsm_memseg_import_handle_t,
    void **,
    rsm_attribute_t,
    rsm_permission_t,
    off_t, size_t);

extern int _rsm_memseg_import_unmap(rsm_memseg_import_handle_t);

static rsm_ndlib_attr_t _rsm_loopback_attr = {
	B_TRUE,		/* mapping needed for put/get */
	B_TRUE		/* mapping needed for putv/getv */
};

static int
loopback_get8(rsm_memseg_import_handle_t im_memseg, off_t off,
    uint8_t *datap,
    ulong_t rep_cnt,
    boolean_t swap)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	uint8_t *data_addr =
	    (uint8_t *)&seg->rsmseg_vaddr[off - seg->rsmseg_mapoffset];
	uint_t i = 0;
	int	e;

	swap = swap;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_get8: enter\n"));

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_open_barrier(
				(rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	for (i = 0; i < rep_cnt; i++) {
		datap[i] = data_addr[i];
	}

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_close_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_get8: exit\n"));

	return (RSM_SUCCESS);
}

static int
loopback_get16(rsm_memseg_import_handle_t im_memseg, off_t off,
    uint16_t *datap,
    ulong_t rep_cnt,
    boolean_t swap)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	uint16_t *data_addr =
	    /* LINTED */
	    (uint16_t *)&seg->rsmseg_vaddr[off - seg->rsmseg_mapoffset];
	uint_t i = 0;
	int	e;

	swap = swap;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_get16: enter\n"));

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_open_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	for (i = 0; i < rep_cnt; i++) {
		datap[i] = data_addr[i];
	}

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_close_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_get16: exit\n"));

	return (RSM_SUCCESS);
}

static int
loopback_get32(rsm_memseg_import_handle_t im_memseg, off_t off,
    uint32_t *datap,
    ulong_t rep_cnt,
    boolean_t swap)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	uint32_t *data_addr =
	    /* LINTED */
	    (uint32_t *)&seg->rsmseg_vaddr[off - seg->rsmseg_mapoffset];
	uint_t i = 0;
	int	e;

	swap = swap;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_get32: enter\n"));

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_open_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	for (i = 0; i < rep_cnt; i++) {
		datap[i] = data_addr[i];
	}

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_close_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_get32: exit\n"));

	return (RSM_SUCCESS);
}

static int
loopback_get64(rsm_memseg_import_handle_t im_memseg, off_t off,
    uint64_t *datap,
    ulong_t rep_cnt,
    boolean_t swap)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	uint64_t *data_addr =
	    /* LINTED */
	    (uint64_t *)&seg->rsmseg_vaddr[off - seg->rsmseg_mapoffset];
	uint_t i = 0;
	int	e;

	swap = swap;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_get64: enter\n"));

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_open_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	for (i = 0; i < rep_cnt; i++) {
		datap[i] = data_addr[i];
	}

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_close_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_get64: exit\n"));

	return (RSM_SUCCESS);
}

static int
loopback_put8(rsm_memseg_import_handle_t im_memseg, off_t off,
    uint8_t *datap,
    ulong_t rep_cnt,
    boolean_t swap)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	uint8_t *data_addr =
		(uint8_t *)&seg->rsmseg_vaddr[off - seg->rsmseg_mapoffset];
	uint_t i = 0;
	int	e;

	swap = swap;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_put8: enter\n"));

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_open_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	for (i = 0; i < rep_cnt; i++) {
		data_addr[i] = datap[i];
	}

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_close_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_put8: exit\n"));

	return (RSM_SUCCESS);
}

static int
loopback_put16(rsm_memseg_import_handle_t im_memseg, off_t off,
    uint16_t *datap,
    ulong_t rep_cnt,
    boolean_t swap)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	uint16_t *data_addr =
	    /* LINTED */
	    (uint16_t *)&seg->rsmseg_vaddr[off - seg->rsmseg_mapoffset];
	uint_t i = 0;
	int	e;

	swap = swap;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_put16: enter\n"));

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_open_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	for (i = 0; i < rep_cnt; i++) {
		data_addr[i] = datap[i];
	}

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_close_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_put16: exit\n"));

	return (RSM_SUCCESS);
}

static int
loopback_put32(rsm_memseg_import_handle_t im_memseg, off_t off,
    uint32_t *datap,
    ulong_t rep_cnt,
    boolean_t swap)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	uint32_t *data_addr =
	    /* LINTED */
	    (uint32_t *)&seg->rsmseg_vaddr[off - seg->rsmseg_mapoffset];
	uint_t i = 0;
	int	e;

	swap = swap;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_put32: enter\n"));

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_open_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	for (i = 0; i < rep_cnt; i++) {
		data_addr[i] = datap[i];
	}

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_close_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_put32: exit\n"));

	return (RSM_SUCCESS);
}

static int
loopback_put64(rsm_memseg_import_handle_t im_memseg, off_t off,
    uint64_t *datap,
    ulong_t rep_cnt,
    boolean_t swap)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	uint64_t *data_addr =
	    /* LINTED */
	    (uint64_t *)&seg->rsmseg_vaddr[off - seg->rsmseg_mapoffset];
	uint_t i = 0;
	int	e;

	swap = swap;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_put64: enter\n"));

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_open_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	for (i = 0; i < rep_cnt; i++) {
		data_addr[i] = datap[i];
	}

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_close_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_put64: exit\n"));

	return (RSM_SUCCESS);
}

static int
loopback_get(rsm_memseg_import_handle_t im_memseg, off_t offset, void *dst_addr,
    size_t length)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	int	e;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_get: enter\n"));

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_open_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	bcopy(seg->rsmseg_vaddr + offset - seg->rsmseg_mapoffset, dst_addr,
		length);

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_close_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_get: exit\n"));

	return (RSM_SUCCESS);
}


/*
 * Move data to each component of the io vector from the remote segment
 */
int
loopback_getv(rsm_scat_gath_t *sg_io)
{
	rsm_iovec_t	*iovec = sg_io->iovec;
	rsmseg_handle_t *im_seg = (rsmseg_handle_t *)sg_io->remote_handle;
	int i;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_getv: enter\n"));

	/* do the vector data transfer */
	for (i = 0; i < sg_io->io_request_count; i++) {
		(void) bcopy(im_seg->rsmseg_vaddr + iovec->remote_offset,
		    iovec->local.vaddr + iovec->local_offset,
		    iovec->transfer_length);
		iovec++;
	}

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_getv: exit\n"));

	sg_io->io_residual_count = 0;

	return (RSM_SUCCESS);
}

static int
loopback_put(rsm_memseg_import_handle_t im_memseg, off_t offset, void *src_addr,
    size_t length)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	int	e;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_put: enter\n"));

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_open_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	bcopy(src_addr, seg->rsmseg_vaddr + offset - seg->rsmseg_mapoffset,
		length);

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_close_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_put: exit\n"));

	return (RSM_SUCCESS);
}


/*
 * Move data from each component of the io vector to the remote segment
 */
int
loopback_putv(rsm_scat_gath_t *sg_io)
{
	rsm_iovec_t	*iovec = sg_io->iovec;
	rsmseg_handle_t *im_seg = (rsmseg_handle_t *)sg_io->remote_handle;
	int i;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_putv: enter\n"));

	/* do the vector data transfer */
	for (i = 0; i < sg_io->io_request_count; i++) {
		(void) bcopy(iovec->local.vaddr + iovec->local_offset,
		    im_seg->rsmseg_vaddr + iovec->remote_offset,
		    iovec->transfer_length);
		iovec++;
	}

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_putv: exit\n"));

	sg_io->io_residual_count = 0;

	return (RSM_SUCCESS);
}

static int
loopback_create_handle(rsmapi_controller_handle_t controller,
    rsm_localmemory_handle_t *local_handle,
    caddr_t vaddr, size_t len)
{

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_create_handle: enter\n"));

	controller = controller;
	len = len;

	*local_handle = (rsm_localmemory_handle_t)vaddr;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_create_handle: exit\n"));

	return (RSM_SUCCESS);
}

static int
loopback_free_handle(rsm_localmemory_handle_t handle)
{

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_free_handle: enter\n"));

	handle = handle;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_free_handle: exit\n"));

	return (RSM_SUCCESS);
}


	/*
	 * import side memory segment operations (barriers):
	 */
static int
loopback_init_barrier(rsm_memseg_import_handle_t im_memseg,
    rsm_barrier_type_t type,
    rsm_barrier_handle_t barrier)
{

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_init_barrier: enter\n"));

	type = type; im_memseg = im_memseg; barrier = barrier;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_init_barrier: exit\n"));

	return (RSM_SUCCESS);
}

static int
loopback_open_barrier(rsm_barrier_handle_t barrier)
{

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_open_barrier: enter\n"));

	barrier = barrier;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_open_barrier: exit\n"));

	return (RSM_SUCCESS);
}

static int
loopback_order_barrier(rsm_barrier_handle_t barrier)
{

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_order_barrier: enter\n"));

	barrier = barrier;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_order_barrier: exit\n"));

	return (RSM_SUCCESS);
}

static int
loopback_close_barrier(rsm_barrier_handle_t barrier)
{

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_close_barrier: enter\n"));

	barrier = barrier;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_close_barrier: exit\n"));

	return (RSM_SUCCESS);
}

static int
loopback_destroy_barrier(rsm_barrier_handle_t barrier)
{

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_destroy_barrier: enter\n"));

	barrier = barrier;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_destroy_barrier: exit\n"));

	return (RSM_SUCCESS);
}

static int
loopback_get_lib_attr(rsm_ndlib_attr_t **libattrp)
{

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_get_lib_attr: enter\n"));

	*libattrp = &_rsm_loopback_attr;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "loopback_get_lib_attr: exit\n"));

	return (RSM_SUCCESS);
}
/*
 * If an entry is NULL, the parent will fill it out with its entry point.
 */
void
__rsmloopback_init_ops(rsm_segops_t *segops)
{

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "__rsmloopback_init_ops: enter\n"));

	segops->rsm_memseg_import_get8 = loopback_get8;
	segops->rsm_memseg_import_get16 = loopback_get16;
	segops->rsm_memseg_import_get32 = loopback_get32;
	segops->rsm_memseg_import_get64 = loopback_get64;

	segops->rsm_memseg_import_put8 = loopback_put8;
	segops->rsm_memseg_import_put16 = loopback_put16;
	segops->rsm_memseg_import_put32 = loopback_put32;
	segops->rsm_memseg_import_put64 = loopback_put64;

	segops->rsm_memseg_import_put = loopback_put;
	segops->rsm_memseg_import_get = loopback_get;

	segops->rsm_memseg_import_putv = loopback_putv;
	segops->rsm_memseg_import_getv = loopback_getv;

	segops->rsm_create_localmemory_handle = loopback_create_handle;
	segops->rsm_free_localmemory_handle = loopback_free_handle;

	segops->rsm_memseg_import_init_barrier = loopback_init_barrier;
	segops->rsm_memseg_import_open_barrier = loopback_open_barrier;
	segops->rsm_memseg_import_order_barrier = loopback_order_barrier;
	segops->rsm_memseg_import_close_barrier = loopback_close_barrier;
	segops->rsm_memseg_import_destroy_barrier = loopback_destroy_barrier;

	segops->rsm_get_lib_attr = loopback_get_lib_attr;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "__rsmloopback_init_ops: exit\n"));

}
