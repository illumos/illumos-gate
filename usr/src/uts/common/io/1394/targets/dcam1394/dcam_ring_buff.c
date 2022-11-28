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

/*
 * dcam_ring_buff.c
 *
 * dcam1394 driver.  Video frame ring buffer support.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ddidmareq.h>
#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/cmn_err.h>

#include <sys/1394/targets/dcam1394/dcam.h>

/*
 * ring_buff_create
 *
 *  - alloc ring_buff_t structure
 *  - init ring_buff's num_buffs, buff_num_bytes, num_read_ptrs,
 *        read_ptr_pos
 *  - alloc (num buffs) entries in ring_buff's buff_info_array_p
 *
 *  - for each buff
 *     - alloc DMA handle; store DMA handle in buff's buff_info_array_p
 *     - alloc mem for DMA transfer; store base addr, data access handle
 *           in buff's  buff_info_array_p entry
 *     - bind alloc'ed mem to DMA handle; store assoc info in buff's
 *           buff_info_array_p entry
 */
ring_buff_t *
ring_buff_create(dcam_state_t *softc_p, size_t num_buffs,
    size_t buff_num_bytes)
{
	buff_info_t *buff_info_p;
	size_t buff;
	int i, rc;
	ring_buff_t *ring_buff_p;
	size_t num_bytes;

	num_bytes = sizeof (ring_buff_t);

	ring_buff_p = (ring_buff_t *)kmem_alloc(num_bytes, KM_SLEEP);

	ring_buff_p->num_buffs		= num_buffs;
	ring_buff_p->buff_num_bytes	= buff_num_bytes;
	ring_buff_p->write_ptr_pos	= 0;
	ring_buff_p->num_read_ptrs	= 0;
	ring_buff_p->read_ptr_incr_val	= 1;

	for (i = 0; i < MAX_NUM_READ_PTRS; i++) {
		ring_buff_p->read_ptr_pos[i] = (size_t)-1;
	}

	num_bytes = num_buffs * sizeof (buff_info_t);

	ring_buff_p->buff_info_array_p =
	    (buff_info_t *)kmem_alloc(num_bytes, KM_SLEEP);

	for (buff = 0; buff < num_buffs; buff++) {

		buff_info_p = &(ring_buff_p->buff_info_array_p[buff]);

		if ((ddi_dma_alloc_handle(
		    softc_p->dip,
		    &softc_p->attachinfo.dma_attr,
		    DDI_DMA_DONTWAIT,
		    NULL,
		    &(buff_info_p->dma_handle))) != DDI_SUCCESS) {
			ring_buff_free(softc_p, ring_buff_p);
			return (NULL);
		}

		if (ddi_dma_mem_alloc(
		    buff_info_p->dma_handle,
		    buff_num_bytes,
		    &softc_p->attachinfo.acc_attr,
		    DDI_DMA_STREAMING,
		    DDI_DMA_DONTWAIT,
		    (caddr_t)NULL,
		    &(buff_info_p->kaddr_p),
		    &(buff_info_p->real_len),
		    &(buff_info_p->data_acc_handle)) != DDI_SUCCESS) {
			ring_buff_free(softc_p, ring_buff_p);

			/*
			 *  Print a warning, this triggered the bug
			 *  report #4423667.  This call can fail if
			 *  the memory tests are being run in sunvts.
			 *  The fact is, this code is doing the right
			 *  thing.  I added an error message, so that
			 *  future occurrences can be dealt with directly.
			 *  This is not a bug... The vmem test in sunvts
			 *  can eat up all swap/virtual memory.
			 */
			cmn_err(CE_WARN,
			    "ddi_dma_mem_alloc() failed in ring_buff_create(),"\
			    " insufficient memory resources.\n");
			return (NULL);
		}

		rc = ddi_dma_addr_bind_handle(
		    buff_info_p->dma_handle,
		    (struct as *)NULL,
		    (caddr_t)buff_info_p->kaddr_p,
		    buff_info_p->real_len,
		    DDI_DMA_RDWR | DDI_DMA_STREAMING,
		    DDI_DMA_DONTWAIT,
		    NULL,
		    &buff_info_p->dma_cookie,
		    &buff_info_p->dma_cookie_count);

		if (rc != DDI_DMA_MAPPED) {
			ring_buff_free(softc_p, ring_buff_p);
			return (NULL);
		}
	}

	return (ring_buff_p);
}


/*
 * ring_buff_free
 */
void
ring_buff_free(dcam_state_t *softc_p, ring_buff_t  *ring_buff_p)
{
	buff_info_t *buff_info_p;
	int i;

	if (ring_buff_p == NULL) {
		softc_p->ring_buff_p = NULL;
		return;
	}

	if (ring_buff_p->buff_info_array_p != NULL) {
		for (i = 0; i < ring_buff_p->num_buffs; i++) {

			buff_info_p = &(ring_buff_p->buff_info_array_p[i]);

			(void) ddi_dma_unbind_handle(buff_info_p->dma_handle);
			ddi_dma_mem_free(&buff_info_p->data_acc_handle);
			ddi_dma_free_handle(&buff_info_p->dma_handle);
		}

		kmem_free(ring_buff_p->buff_info_array_p,
		    ring_buff_p->num_buffs * sizeof (buff_info_t));
	}

	kmem_free(ring_buff_p, sizeof (ring_buff_t));

	softc_p->ring_buff_p = NULL;
}


/*
 * ring_buff_read_ptr_add
 */
int
ring_buff_read_ptr_add(ring_buff_t *ring_buff_p)
{
	int i;
	int read_ptr_id;

	read_ptr_id = -1;

	for (i = 0; i < MAX_NUM_READ_PTRS; i++) {

		if (ring_buff_p->read_ptr_pos[i] == -1) {
			ring_buff_p->read_ptr_pos[i] = 0;
			read_ptr_id = i;
			break;
		}
	}

	return (read_ptr_id);
}


/*
 * ring_buff_read_ptr_remove
 */
int
ring_buff_read_ptr_remove(ring_buff_t *ring_buff_p, int read_ptr_id)
{
	ring_buff_p->read_ptr_pos[read_ptr_id] = (size_t)-1;

	return (0);
}


/*
 * ring_buff_read_ptr_buff_get
 *
 * Return pointer to buffer that a read pointer associated with the
 * ring buffer is pointing to.
 */
buff_info_t *
ring_buff_read_ptr_buff_get(ring_buff_t *ring_buff_p, int read_ptr_id)
{
	size_t		read_ptr_pos;
	buff_info_t	*buff_info_p;

	read_ptr_pos = ring_buff_p->read_ptr_pos[read_ptr_id];
	buff_info_p  = &(ring_buff_p->buff_info_array_p[read_ptr_pos]);

	return (buff_info_p);
}


/*
 * ring_buff_read_ptr_pos_get
 */
size_t
ring_buff_read_ptr_pos_get(ring_buff_t *ring_buff_p, int read_ptr_id)
{
	return (ring_buff_p->read_ptr_pos[read_ptr_id]);
}


/*
 * ring_buff_read_ptr_incr
 */
void
ring_buff_read_ptr_incr(ring_buff_t *ring_buff_p, int read_ptr_id)
{
	size_t read_ptr_pos;
#if defined(_ADDL_RING_BUFF_CHECK)
	size_t lrp, lwp; /* linear read, write positions */
#endif	/* _ADDL_RING_BUFFER_CHECK */

	/*
	 * increment the read pointer based on read_ptr_incr_val
	 * which can vary from 1 to 10
	 */

	/* get current read pointer pos */
	read_ptr_pos = ring_buff_p->read_ptr_pos[read_ptr_id];

	ring_buff_p->read_ptr_pos[read_ptr_id] =
	    (read_ptr_pos + 1) % ring_buff_p->num_buffs;

#if defined(_ADDL_RING_BUFF_CHECK)
	if ((read_ptr_pos == 0) && (ring_buff_p->write_ptr_pos == 0)) {
		return;
	}

	if (read_ptr_pos < ring_buff_p->write_ptr_pos) {

		/* calculate new read pointer position */
		if ((read_ptr_pos + ring_buff_p->read_ptr_incr_val) <
		    ring_buff_p->write_ptr_pos) {

			/* there is still some valid frame data */
			ring_buff_p->read_ptr_pos[read_ptr_id] =
			    (read_ptr_pos +
			    ring_buff_p->read_ptr_incr_val) %
			    ring_buff_p->num_buffs;
		} else {
			/*
			 * we have skipped beyond available frame
			 * data, so the buffer is empty
			 */
			ring_buff_p->read_ptr_pos[read_ptr_id] =
			    ring_buff_p->write_ptr_pos;
		}
	} else {
		/*
		 * since read pointer is ahead of write pointer,
		 * it becomes easier to check for new read
		 * pointer position if we pretend that our data
		 * buffer is linear instead of circular
		 */

		lrp = read_ptr_pos + ring_buff_p->read_ptr_incr_val;
		lwp = ring_buff_p->num_buffs +
		    ring_buff_p->write_ptr_pos;

		if (lrp < lwp) {
			/* there is still some valid frame data */
			ring_buff_p->read_ptr_pos[read_ptr_id] =
			    (read_ptr_pos +
			    ring_buff_p->read_ptr_incr_val) %
			    ring_buff_p->num_buffs;
		} else {
			/*
			 * we have skipped beyond available
			 * frame  data, so the buffer is empty
			 */
			ring_buff_p->read_ptr_pos[read_ptr_id] =
			    ring_buff_p->write_ptr_pos;
		}
	}
#endif	/* _ADDL_RING_BUFF_CHECK */
}


/*
 * ring_buff_write_ptr_pos_get
 */
size_t
ring_buff_write_ptr_pos_get(ring_buff_t *ring_buff_p)
{
	return (ring_buff_p->write_ptr_pos);
}


/*
 * ring_buff_write_ptr_incr
 */
void
ring_buff_write_ptr_incr(ring_buff_t *ring_buff_p)
{
	size_t write_ptr_pos;

	write_ptr_pos = ring_buff_p->write_ptr_pos;

	ring_buff_p->write_ptr_pos =
	    ((write_ptr_pos + 1) % ring_buff_p->num_buffs);
}
