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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <malloc.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sched.h>

#include <rsmapi.h>
#include <sys/rsm/rsmndi.h>
#include <rsmlib_in.h>
#include <sys/rsm/rsm.h>

/* lint -w2 */

extern rsm_node_id_t rsm_local_nodeid;
extern int loopback_getv(rsm_scat_gath_t *);
extern int loopback_putv(rsm_scat_gath_t *);

static rsm_ndlib_attr_t _rsm_genlib_attr = {
	B_TRUE,		/* mapping needed for put/get */
	B_FALSE		/* mapping needed for putv/getv */
};

static int
__rsm_import_connect(
    rsmapi_controller_handle_t controller, rsm_node_id_t node_id,
    rsm_memseg_id_t segment_id, rsm_permission_t perm,
    rsm_memseg_import_handle_t *im_memseg) {

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_import_connect: enter\n"));

	controller = controller;
	node_id = node_id;
	segment_id = segment_id;
	perm = perm;
	im_memseg = im_memseg;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_import_connect: exit\n"));

	return (RSM_SUCCESS);
}

static int
__rsm_import_disconnect(rsm_memseg_import_handle_t im_memseg) {

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_import_disconnect: enter\n"));

	im_memseg = im_memseg;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_import_disconnect: exit\n"));

	return (RSM_SUCCESS);
}

/*
 * XXX: one day we ought to rewrite this stuff based on 64byte atomic access.
 * We can have a new ops vector that makes that assumption.
 */

static int
__rsm_get8x8(rsm_memseg_import_handle_t im_memseg, off_t off,
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

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_import_get8x8: enter\n"));

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

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_import_get8x8: exit\n"));

	return (RSM_SUCCESS);
}

static int
__rsm_get16x16(rsm_memseg_import_handle_t im_memseg, off_t off,
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

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_import_get16x16: enter\n"));

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

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_import_get16x16: exit\n"));

	return (RSM_SUCCESS);
}

static int
__rsm_get32x32(rsm_memseg_import_handle_t im_memseg, off_t off,
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

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_import_get32x32: enter\n"));

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

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_import_get32x32: exit\n"));

	return (RSM_SUCCESS);
}

static int
__rsm_get64x64(rsm_memseg_import_handle_t im_memseg, off_t off,
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

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_import_get64x64: enter\n"));

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

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_import_get64x64: exit\n"));

	return (RSM_SUCCESS);
}

	/*
	 * import side memory segment operations (write access functions):
	 */

/*
 * XXX: Each one of the following cases ought to be a separate function loaded
 * into a segment access ops vector. We determine the correct function at
 * segment connect time. When a new controller is register, we can decode
 * it's direct_access_size attribute and load the correct function. For
 * loop back we need to create a special ops vector that bypasses all of
 * this stuff.
 *
 * XXX: We need to create a special interrupt queue for the library to handle
 * partial writes in the remote process.
 */
static int
__rsm_put8x8(rsm_memseg_import_handle_t im_memseg, off_t off,
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

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_put8x8: enter\n"));

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

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_put8x8: exit\n"));

	return (RSM_SUCCESS);
}

static int
__rsm_put16x16(rsm_memseg_import_handle_t im_memseg, off_t off,
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

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_put16x16: enter\n"));

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

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_put16x16: exit\n"));

	return (RSM_SUCCESS);
}

static int
__rsm_put32x32(rsm_memseg_import_handle_t im_memseg, off_t off,
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

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_put32x32: enter\n"));

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

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_put32x32: exit\n"));

	return (RSM_SUCCESS);
}

static int
__rsm_put64x64(rsm_memseg_import_handle_t im_memseg, off_t off,
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

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_put64x64: enter\n"));

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

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_put64x64: exit\n"));

	return (RSM_SUCCESS);
}

static int
__rsm_get(rsm_memseg_import_handle_t im_memseg, off_t offset, void *dst_addr,
    size_t length)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	int		e;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_get: enter\n"));

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_open_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	(void) bcopy(seg->rsmseg_vaddr + offset - seg->rsmseg_mapoffset,
	    dst_addr, length);

	if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
		e = seg->rsmseg_ops->rsm_memseg_import_close_barrier(
		    (rsm_barrier_handle_t)seg->rsmseg_barrier);
		if (e != RSM_SUCCESS) {
			return (e);
		}
	}

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_get: exit\n"));

	return (RSM_SUCCESS);
}

static int
__rsm_getv(rsm_scat_gath_t *sg_io)
{
	rsm_iovec_t 	*iovec = sg_io->iovec;
	rsmka_iovec_t	ka_iovec_arr[RSM_MAX_IOVLEN];
	rsmka_iovec_t	*ka_iovec, *ka_iovec_start;
	rsmka_iovec_t	l_iovec_arr[RSM_MAX_IOVLEN];
	rsmka_iovec_t	*l_iovec, *l_iovec_start;
	rsmseg_handle_t *im_seg_hndl = (rsmseg_handle_t *)sg_io->remote_handle;
	rsmseg_handle_t *seg_hndl;
	int iovec_size = sizeof (rsmka_iovec_t) * sg_io->io_request_count;
	int e, i;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_getv: enter\n"));

	/*
	 * Use loopback for single node operations.
	 * replace local handles with virtual addresses
	 */

	if (im_seg_hndl->rsmseg_nodeid == rsm_local_nodeid) {
		/*
		 * To use the loopback optimization map the segment
		 * here implicitly.
		 */
		if (im_seg_hndl->rsmseg_state == IMPORT_CONNECT) {
			caddr_t	va;
			va = mmap(NULL, im_seg_hndl->rsmseg_size,
			    PROT_READ|PROT_WRITE,
			    MAP_SHARED|MAP_NORESERVE,
			    im_seg_hndl->rsmseg_fd, 0);

			if (va == MAP_FAILED) {
				DBPRINTF((RSM_LIBRARY, RSM_ERR,
				    "implicit map failed:%d\n", errno));
				if (errno == EINVAL)
					return (RSMERR_BAD_MEM_ALIGNMENT);
				else if (errno == ENOMEM || errno == ENXIO ||
				    errno == EOVERFLOW)
					return (RSMERR_BAD_LENGTH);
				else if (errno == EAGAIN)
					return (RSMERR_INSUFFICIENT_RESOURCES);
				else
					return (errno);
			}

			im_seg_hndl->rsmseg_vaddr = va;
			im_seg_hndl->rsmseg_maplen = im_seg_hndl->rsmseg_size;
			im_seg_hndl->rsmseg_mapoffset = 0;
			im_seg_hndl->rsmseg_state = IMPORT_MAP;
			im_seg_hndl->rsmseg_flags |= RSM_IMPLICIT_MAP;
		}

		if (sg_io->io_request_count > RSM_MAX_IOVLEN)
			l_iovec_start = l_iovec = malloc(iovec_size);
		else
			l_iovec_start = l_iovec = l_iovec_arr;

		bcopy((caddr_t)iovec, (caddr_t)l_iovec, iovec_size);
		for (i = 0; i < sg_io->io_request_count; i++) {
			if (l_iovec->io_type == RSM_HANDLE_TYPE) {
				/* Get the surrogate export segment handle */
				seg_hndl = (rsmseg_handle_t *)
				    l_iovec->local.handle;
				l_iovec->local.vaddr = seg_hndl->rsmseg_vaddr;
				l_iovec->io_type = RSM_VA_TYPE;
			}
			l_iovec++;
		}
		sg_io->iovec = (rsm_iovec_t *)l_iovec_start;
		e = loopback_getv(sg_io);
		sg_io->iovec = iovec;
		if (sg_io->io_request_count > RSM_MAX_IOVLEN)
			free(l_iovec_start);
		DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
		    "__rsm_getv: exit\n"));
		return (e);
	}

	/* for the Kernel Agent, replace local handles with segment ids */
	if (sg_io->io_request_count > RSM_MAX_IOVLEN)
		ka_iovec_start = ka_iovec = malloc(iovec_size);
	else
		ka_iovec_start = ka_iovec = ka_iovec_arr;

	bcopy((caddr_t)iovec, (caddr_t)ka_iovec, iovec_size);
	for (i = 0; i < sg_io->io_request_count; i++) {
		if (ka_iovec->io_type == RSM_HANDLE_TYPE) {
			seg_hndl = (rsmseg_handle_t *)ka_iovec->local.handle;
			ka_iovec->local.segid = seg_hndl->rsmseg_keyid;
		}
		ka_iovec++;
	}

	sg_io->iovec = (rsm_iovec_t *)ka_iovec_start;
	e = ioctl(im_seg_hndl->rsmseg_fd, RSM_IOCTL_GETV, sg_io);
	sg_io->iovec = iovec;

	if (sg_io->io_request_count > RSM_MAX_IOVLEN)
		free(ka_iovec_start);

	if (e < 0) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    " RSM_IOCTL_GETV failed\n"));
		return (errno);
	}

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_getv: exit\n"));

	return (RSM_SUCCESS);
}


static int
__rsm_put(rsm_memseg_import_handle_t im_memseg, off_t offset, void *src_addr,
    size_t length)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	int		e;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_put: enter\n"));

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

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_put: exit\n"));

	return (RSM_SUCCESS);
}

static int
__rsm_putv(rsm_scat_gath_t *sg_io)
{
	rsm_iovec_t 	*iovec = sg_io->iovec;
	rsmka_iovec_t	ka_iovec_arr[RSM_MAX_IOVLEN];
	rsmka_iovec_t	*ka_iovec, *ka_iovec_start;
	rsmka_iovec_t	l_iovec_arr[RSM_MAX_IOVLEN];
	rsmka_iovec_t	*l_iovec, *l_iovec_start;
	rsmseg_handle_t *im_seg_hndl = (rsmseg_handle_t *)sg_io->remote_handle;
	rsmseg_handle_t *seg_hndl;
	int iovec_size = sizeof (rsmka_iovec_t) * sg_io->io_request_count;
	int e, i;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_putv: enter\n"));

	/*
	 * Use loopback for single node operations.
	 * replace local handles with virtual addresses
	 */

	if (im_seg_hndl->rsmseg_nodeid == rsm_local_nodeid) {
		/*
		 * To use the loopback optimization map the segment
		 * here implicitly.
		 */
		if (im_seg_hndl->rsmseg_state == IMPORT_CONNECT) {
			caddr_t	va;
			va = mmap(NULL, im_seg_hndl->rsmseg_size,
			    PROT_READ|PROT_WRITE,
			    MAP_SHARED|MAP_NORESERVE,
			    im_seg_hndl->rsmseg_fd, 0);

			if (va == MAP_FAILED) {
				DBPRINTF((RSM_LIBRARY, RSM_ERR,
				    "implicit map failed:%d\n", errno));
				if (errno == EINVAL)
					return (RSMERR_BAD_MEM_ALIGNMENT);
				else if (errno == ENOMEM || errno == ENXIO ||
				    errno == EOVERFLOW)
					return (RSMERR_BAD_LENGTH);
				else if (errno == EAGAIN)
					return (RSMERR_INSUFFICIENT_RESOURCES);
				else
					return (errno);
			}
			im_seg_hndl->rsmseg_vaddr = va;
			im_seg_hndl->rsmseg_maplen = im_seg_hndl->rsmseg_size;
			im_seg_hndl->rsmseg_mapoffset = 0;
			im_seg_hndl->rsmseg_state = IMPORT_MAP;
			im_seg_hndl->rsmseg_flags |= RSM_IMPLICIT_MAP;
		}

		if (sg_io->io_request_count > RSM_MAX_IOVLEN)
			l_iovec_start = l_iovec = malloc(iovec_size);
		else
			l_iovec_start = l_iovec = l_iovec_arr;

		bcopy((caddr_t)iovec, (caddr_t)l_iovec, iovec_size);
		for (i = 0; i < sg_io->io_request_count; i++) {
			if (l_iovec->io_type == RSM_HANDLE_TYPE) {
				/* Get the surrogate export segment handle */
				seg_hndl = (rsmseg_handle_t *)
				    l_iovec->local.handle;
				l_iovec->local.vaddr = seg_hndl->rsmseg_vaddr;
				l_iovec->io_type = RSM_VA_TYPE;
			}
			l_iovec++;
		}
		sg_io->iovec = (rsm_iovec_t *)l_iovec_start;
		e = loopback_putv(sg_io);
		sg_io->iovec = iovec;

		if (sg_io->io_request_count > RSM_MAX_IOVLEN)
			free(l_iovec_start);

		DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
		    "__rsm_putv: exit\n"));


		return (e);
	}

	/* for the Kernel Agent, replace local handles with segment ids */
	if (sg_io->io_request_count > RSM_MAX_IOVLEN)
		ka_iovec_start = ka_iovec = malloc(iovec_size);
	else
		ka_iovec_start = ka_iovec = ka_iovec_arr;

	bcopy((caddr_t)iovec, (caddr_t)ka_iovec, iovec_size);

	for (i = 0; i < sg_io->io_request_count; i++) {
		if (ka_iovec->io_type == RSM_HANDLE_TYPE) {
			seg_hndl = (rsmseg_handle_t *)ka_iovec->local.handle;
			ka_iovec->local.segid = seg_hndl->rsmseg_keyid;
		}
		ka_iovec++;
	}

	sg_io->iovec = (rsm_iovec_t *)ka_iovec_start;
	e = ioctl(im_seg_hndl->rsmseg_fd, RSM_IOCTL_PUTV, sg_io);
	sg_io->iovec = iovec;

	if (sg_io->io_request_count > RSM_MAX_IOVLEN)
		free(ka_iovec_start);

	if (e < 0) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    " RSM_IOCTL_PUTV failed\n"));
		return (errno);
	}

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_putv: exit\n"));

	return (RSM_SUCCESS);
}

	/*
	 * import side memory segment operations (barriers):
	 */
static int
__rsm_memseg_import_init_barrier(rsm_memseg_import_handle_t im_memseg,
    rsm_barrier_type_t type,
    rsm_barrier_handle_t barrier)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	rsmgenbar_handle_t *bar = (rsmgenbar_handle_t *)barrier;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    ""
	    "__rsm_memseg_import_init_barrier: enter\n"));

	type = type;

	if (!seg) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid segment handle\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}
	if (!bar) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid barrier handle\n"));
		return (RSMERR_BAD_BARRIER_PTR);
	}

	/* XXX: fix later. We only support span-of-node barriers */

	bar->rsmgenbar_data = (rsm_barrier_t *)malloc(sizeof (rsm_barrier_t));
	if (bar->rsmgenbar_data == NULL) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "not enough memory\n"));
		return (RSMERR_INSUFFICIENT_MEM);
	}
	bar->rsmgenbar_seg = seg;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_memseg_import_init_barrier: exit\n"));

	return (RSM_SUCCESS);
}

static int
__rsm_memseg_import_open_barrier(rsm_barrier_handle_t barrier)
{
	rsmgenbar_handle_t *bar = (rsmgenbar_handle_t *)barrier;
	rsmseg_handle_t *seg;
	rsm_ioctlmsg_t msg;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_memseg_import_open_barrier: enter\n"));

	if (!bar) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid barrier pointer\n"));
		return (RSMERR_BAD_BARRIER_PTR);
	}

	if ((seg = bar->rsmgenbar_seg) == 0) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "uninitialized barrier\n"));
		return (RSMERR_BARRIER_UNINITIALIZED);
	}

/* lint -save -e718 -e746 */
	msg.bar = *(bar->rsmgenbar_data);
	if (ioctl(seg->rsmseg_fd,
	    RSM_IOCTL_BAR_OPEN, &msg) < 0) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    " RSM_IOCTL_BAR_OPEN failed\n"));
/* lint -restore */
		return (RSMERR_BARRIER_OPEN_FAILED);
	}

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_memseg_import_open_barrier: exit\n"));

	return (RSM_SUCCESS);
}

static int
__rsm_memseg_import_order_barrier(rsm_barrier_handle_t barrier)
{
	rsmgenbar_handle_t *bar = (rsmgenbar_handle_t *)barrier;
	rsmseg_handle_t *seg;
	rsm_ioctlmsg_t msg;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_memseg_import_order_barrier: enter\n"));

	if (!bar) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid barrier\n"));
		return (RSMERR_BAD_BARRIER_PTR);
	}
	if ((seg = bar->rsmgenbar_seg) == 0) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "uninitialized barrier\n"));
		return (RSMERR_BARRIER_UNINITIALIZED);
	}

	msg.bar = *(bar->rsmgenbar_data);
	if (ioctl(seg->rsmseg_fd, RSM_IOCTL_BAR_ORDER, &msg) < 0) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "RSM_IOCTL_BAR_ORDER failed\n"));
		return (RSMERR_BARRIER_FAILURE);
	}

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_memseg_import_order_barrier: exit\n"));

	return (RSM_SUCCESS);
}

static int
__rsm_memseg_import_close_barrier(rsm_barrier_handle_t barrier)
{
	rsmgenbar_handle_t *bar = (rsmgenbar_handle_t *)barrier;
	rsmseg_handle_t *seg;
	rsm_ioctlmsg_t msg;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_memseg_import_close_barrier: enter\n"));

	if (!bar) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid barrier\n"));
		return (RSMERR_BAD_BARRIER_PTR);
	}
	if ((seg = bar->rsmgenbar_seg) == 0) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "uninitialized barrier\n"));
		return (RSMERR_BARRIER_UNINITIALIZED);
	}

	msg.bar = *(bar->rsmgenbar_data);
	if (ioctl(seg->rsmseg_fd, RSM_IOCTL_BAR_CLOSE, &msg) < 0) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    " RSM_IOCTL_BAR_CLOSE failed\n"));
		return (RSMERR_BARRIER_FAILURE);
	}

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_memseg_import_close_barrier: exit\n"));

	return (RSM_SUCCESS);
}

static int
__rsm_memseg_import_destroy_barrier(rsm_barrier_handle_t barrier)
{
	rsmgenbar_handle_t *bar = (rsmgenbar_handle_t *)barrier;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_memseg_import_destroy_barrier: enter\n"));

	if (!bar) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid barrier\n"));
		return (RSMERR_BAD_BARRIER_PTR);
	}

	free((void *) bar->rsmgenbar_data);

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_memseg_import_destroy_barrier: exit\n"));

	return (RSM_SUCCESS);
}

/* lint -w1 */
static int
__rsm_memseg_import_get_mode(rsm_memseg_import_handle_t im_memseg,
    rsm_barrier_mode_t *mode)
{
	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_memseg_import_get_mode: enter\n"));

	im_memseg = im_memseg; mode = mode;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_memseg_import_get_mode: exit\n"));

	return (RSM_SUCCESS);
}
static int
__rsm_memseg_import_set_mode(rsm_memseg_import_handle_t im_memseg,
				rsm_barrier_mode_t mode)
{
	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_memseg_import_set_mode: enter\n"));

	im_memseg = im_memseg; mode = mode;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_memseg_import_set_mode: exit\n"));

	return (RSM_SUCCESS);
}

static int
__rsm_create_memory_handle(rsmapi_controller_handle_t controller,
    rsm_localmemory_handle_t *local_hndl_p,
    caddr_t local_va, size_t len)
{
	rsm_memseg_export_handle_t memseg;
	rsmapi_access_entry_t	acl[1];
	rsm_memseg_id_t segid = 0;
	size_t size;
	int e;


	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_create_memory_handle: enter\n"));

	/*
	 * create a surrogate segment (local memory will be locked down).
	 */
	size =  roundup(len, PAGESIZE);
	e = rsm_memseg_export_create(controller, &memseg,
	    (void *)local_va, size,
	    RSM_ALLOW_REBIND);
	if (e != RSM_SUCCESS) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "export create failed\n"));
		return (e);
	}

	/*
	 * Publish the segment to the local node only.  If the segment
	 * length is very large then don't publish to the adapter driver
	 * because that will consume too much DVMA space - this is indicated
	 * to the Kernel Agent using null permissions.  DVMA binding will
	 * be done when the RDMA is set up.
	 */
	acl[0].ae_node = rsm_local_nodeid;
	if (len > RSM_MAX_HANDLE_DVMA)
		acl[0].ae_permission = 0;
	else
		acl[0].ae_permission = RSM_PERM_RDWR;

	e = rsm_memseg_export_publish(memseg, &segid, acl, 1);
	if (e != RSM_SUCCESS) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "export publish failed\n"));
		rsm_memseg_export_destroy(memseg);
		return (e);
	}

	/* Use the surrogate seghandle as the local memory handle */
	*local_hndl_p = (rsm_localmemory_handle_t)memseg;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_create_memory_handle: exit\n"));

	return (e);
}

static int
__rsm_free_memory_handle(rsm_localmemory_handle_t local_handle)
{
	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_free_memory_handle: enter\n"));

	rsm_memseg_export_destroy((rsm_memseg_export_handle_t)local_handle);

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_free_memory_handle: exit\n"));

	return (RSM_SUCCESS);
}

static int
__rsm_get_lib_attr(rsm_ndlib_attr_t **libattrp)
{

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_get_lib_attr: enter\n"));

	*libattrp = &_rsm_genlib_attr;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_get_lib_attr: exit\n"));

	return (RSM_SUCCESS);
}

static int
__rsm_closedevice(rsmapi_controller_handle_t cntr_handle)
{

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_closedevice: enter\n"));

	cntr_handle = cntr_handle;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsm_closedevice: exit\n"));

	return (RSM_SUCCESS);
}

void
__rsmdefault_setops(rsm_segops_t *segops)
{

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsmdefault_setops: enter\n"));

	if (segops->rsm_memseg_import_connect == NULL) {
		segops->rsm_memseg_import_connect = __rsm_import_connect;
	}
	if (segops->rsm_memseg_import_disconnect == NULL) {
		segops->rsm_memseg_import_disconnect = __rsm_import_disconnect;
	}

	if (segops->rsm_memseg_import_get8 == NULL) {
		segops->rsm_memseg_import_get8 = __rsm_get8x8;
	}
	if (segops->rsm_memseg_import_get16 == NULL) {
		segops->rsm_memseg_import_get16 = __rsm_get16x16;
	}
	if (segops->rsm_memseg_import_get32 == NULL) {
		segops->rsm_memseg_import_get32 = __rsm_get32x32;
	}
	if (segops->rsm_memseg_import_get64 == NULL) {
		segops->rsm_memseg_import_get64 = __rsm_get64x64;
	}
	if (segops->rsm_memseg_import_get == NULL) {
		segops->rsm_memseg_import_get = __rsm_get;
	}

	if (segops->rsm_memseg_import_put8 == NULL) {
		segops->rsm_memseg_import_put8 = __rsm_put8x8;
	}
	if (segops->rsm_memseg_import_put16 == NULL) {
		segops->rsm_memseg_import_put16 = __rsm_put16x16;
	}
	if (segops->rsm_memseg_import_put32 == NULL) {
		segops->rsm_memseg_import_put32 = __rsm_put32x32;
	}
	if (segops->rsm_memseg_import_put64 == NULL) {
		segops->rsm_memseg_import_put64 = __rsm_put64x64;
	}
	if (segops->rsm_memseg_import_put == NULL) {
		segops->rsm_memseg_import_put = __rsm_put;
	}

	if (segops->rsm_memseg_import_putv == NULL) {
		segops->rsm_memseg_import_putv = __rsm_putv;
	}

	if (segops->rsm_memseg_import_getv == NULL) {
		segops->rsm_memseg_import_getv = __rsm_getv;
	}

	if (segops->rsm_create_localmemory_handle == NULL) {
		segops->rsm_create_localmemory_handle =
		    __rsm_create_memory_handle;
	}

	if (segops->rsm_free_localmemory_handle == NULL) {
		segops->rsm_free_localmemory_handle =
		    __rsm_free_memory_handle;
	}

	/* XXX: Need to support barrier functions */
	if (segops->rsm_memseg_import_init_barrier == NULL) {
		segops->rsm_memseg_import_init_barrier =
		    __rsm_memseg_import_init_barrier;
	}
	if (segops->rsm_memseg_import_open_barrier == NULL) {
		segops->rsm_memseg_import_open_barrier =
		    __rsm_memseg_import_open_barrier;
	}
	if (segops->rsm_memseg_import_order_barrier == NULL) {
		segops->rsm_memseg_import_order_barrier =
		    __rsm_memseg_import_order_barrier;
	}
	if (segops->rsm_memseg_import_close_barrier == NULL) {
		segops->rsm_memseg_import_close_barrier =
		    __rsm_memseg_import_close_barrier;
	}
	if (segops->rsm_memseg_import_destroy_barrier == NULL) {
		segops->rsm_memseg_import_destroy_barrier =
		    __rsm_memseg_import_destroy_barrier;
	}

	if (segops->rsm_memseg_import_get_mode == NULL) {
		segops->rsm_memseg_import_get_mode =
		    __rsm_memseg_import_get_mode;
	}
	if (segops->rsm_memseg_import_set_mode == NULL) {
		segops->rsm_memseg_import_set_mode =
		    __rsm_memseg_import_set_mode;
	}

	if (segops->rsm_get_lib_attr == NULL) {
		segops->rsm_get_lib_attr =
		    __rsm_get_lib_attr;
	}

	if (segops->rsm_closedevice == NULL) {
		segops->rsm_closedevice =
		    __rsm_closedevice;
	}


	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "__rsmdefault_setops: exit\n"));

}
