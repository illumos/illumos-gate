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
 * hci1394_q.c
 *    This code decouples some of the OpenHCI async descriptor logic/structures
 *    from the async processing.  The goal was to combine as much of the
 *    duplicate code as possible for the different type of async transfers
 *    without going too overboard.
 *
 *    There are two parts to the Q, the descriptor buffer and the data buffer.
 *    For the most part, data to be transmitted and data which is received go
 *    in the data buffers.  The information of where to get the data and put
 *    the data reside in the descriptor buffers. There are exceptions to this.
 */


#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/note.h>

#include <sys/1394/adapters/hci1394.h>


static int hci1394_q_reserve(hci1394_q_buf_t *qbuf, uint_t size,
    uint32_t *io_addr);
static void hci1394_q_unreserve(hci1394_q_buf_t *qbuf);
static void hci1394_q_buf_setup(hci1394_q_buf_t *qbuf);
static void hci1394_q_reset(hci1394_q_handle_t q_handle);
static void hci1394_q_next_buf(hci1394_q_buf_t *qbuf);

static void hci1394_q_at_write_OLI(hci1394_q_handle_t q_handle,
    hci1394_q_buf_t *qbuf, hci1394_q_cmd_t *cmd, hci1394_basic_pkt_t *hdr,
    uint_t hdrsize);
static void hci1394_q_at_write_OMI(hci1394_q_handle_t q_handle,
    hci1394_q_buf_t *qbuf, hci1394_q_cmd_t *cmd, hci1394_basic_pkt_t *hdr,
    uint_t hdrsize);
static void hci1394_q_at_write_OL(hci1394_q_handle_t q_handle,
    hci1394_q_buf_t *qbuf, hci1394_q_cmd_t *cmd, uint32_t io_addr,
    uint_t datasize);
static void hci1394_q_at_rep_put8(hci1394_q_buf_t *qbuf, hci1394_q_cmd_t *cmd,
    uint8_t *data, uint_t datasize);
static void hci1394_q_at_copy_from_mblk(hci1394_q_buf_t *qbuf,
    hci1394_q_cmd_t *cmd, h1394_mblk_t *mblk);

static void hci1394_q_ar_write_IM(hci1394_q_handle_t q_handle,
    hci1394_q_buf_t *qbuf, uint32_t io_addr, uint_t datasize);

_NOTE(SCHEME_PROTECTS_DATA("unique", msgb))

/*
 * hci1394_q_init()
 *    Initialize a Q.  A Q consists of a descriptor buffer and a data buffer and
 *    can be either an AT or AR Q. hci1394_q_init() returns a handle which
 *    should be used for the reset of the hci1394_q_* calls.
 */
int
hci1394_q_init(hci1394_drvinfo_t *drvinfo,
    hci1394_ohci_handle_t ohci_handle, hci1394_q_info_t *qinfo,
    hci1394_q_handle_t *q_handle)
{
	hci1394_q_buf_t *desc;
	hci1394_q_buf_t *data;
	hci1394_buf_parms_t parms;
	hci1394_q_t *q;
	int status;
	int index;


	ASSERT(drvinfo != NULL);
	ASSERT(qinfo != NULL);
	ASSERT(q_handle != NULL);

	/*
	 * allocate the memory to track this Q.  Initialize the internal Q
	 * structure.
	 */
	q = kmem_alloc(sizeof (hci1394_q_t), KM_SLEEP);
	q->q_drvinfo = drvinfo;
	q->q_info = *qinfo;
	q->q_ohci = ohci_handle;
	mutex_init(&q->q_mutex, NULL, MUTEX_DRIVER, drvinfo->di_iblock_cookie);
	desc = &q->q_desc;
	data = &q->q_data;

	/*
	 * Allocate the Descriptor buffer.
	 *
	 * XXX - Only want 1 cookie for now. Change this to OHCI_MAX_COOKIE
	 * after we have tested the multiple cookie code on x86.
	 */
	parms.bp_length = qinfo->qi_desc_size;
	parms.bp_max_cookies = 1;
	parms.bp_alignment = 16;
	status = hci1394_buf_alloc(drvinfo, &parms, &desc->qb_buf,
	    &desc->qb_buf_handle);
	if (status != DDI_SUCCESS) {
		mutex_destroy(&q->q_mutex);
		kmem_free(q, sizeof (hci1394_q_t));
		*q_handle = NULL;
		return (DDI_FAILURE);
	}

	/* Copy in buffer cookies into our local cookie array */
	desc->qb_cookie[0] = desc->qb_buf.bi_cookie;
	for (index = 1; index < desc->qb_buf.bi_cookie_count; index++) {
		ddi_dma_nextcookie(desc->qb_buf.bi_dma_handle,
		    &desc->qb_buf.bi_cookie);
		desc->qb_cookie[index] = desc->qb_buf.bi_cookie;
	}

	/*
	 * Allocate the Data buffer.
	 *
	 * XXX - Only want 1 cookie for now. Change this to OHCI_MAX_COOKIE
	 * after we have tested the multiple cookie code on x86.
	 */
	parms.bp_length = qinfo->qi_data_size;
	parms.bp_max_cookies = 1;
	parms.bp_alignment = 16;
	status = hci1394_buf_alloc(drvinfo, &parms, &data->qb_buf,
	    &data->qb_buf_handle);
	if (status != DDI_SUCCESS) {
		/* Free the allocated Descriptor buffer */
		hci1394_buf_free(&desc->qb_buf_handle);

		mutex_destroy(&q->q_mutex);
		kmem_free(q, sizeof (hci1394_q_t));
		*q_handle = NULL;
		return (DDI_FAILURE);
	}

	/*
	 * We must have at least 2 ARQ data buffers, If we only have one, we
	 * will artificially create 2. We must have 2 so that we always have a
	 * descriptor with free data space to write AR data to. When one is
	 * empty, it will take us a bit to get a new descriptor back into the
	 * chain.
	 */
	if ((qinfo->qi_mode == HCI1394_ARQ) &&
	    (data->qb_buf.bi_cookie_count == 1)) {
		data->qb_buf.bi_cookie_count = 2;
		data->qb_cookie[0] = data->qb_buf.bi_cookie;
		data->qb_cookie[0].dmac_size /= 2;
		data->qb_cookie[1] = data->qb_cookie[0];
		data->qb_cookie[1].dmac_laddress =
		    data->qb_cookie[0].dmac_laddress +
		    data->qb_cookie[0].dmac_size;
		data->qb_cookie[1].dmac_address =
		    data->qb_cookie[0].dmac_address +
		    data->qb_cookie[0].dmac_size;

	/* We have more than 1 cookie or we are an AT Q */
	} else {
		/* Copy in buffer cookies into our local cookie array */
		data->qb_cookie[0] = data->qb_buf.bi_cookie;
		for (index = 1; index < data->qb_buf.bi_cookie_count; index++) {
			ddi_dma_nextcookie(data->qb_buf.bi_dma_handle,
			    &data->qb_buf.bi_cookie);
			data->qb_cookie[index] = data->qb_buf.bi_cookie;
		}
	}

	/* The top and bottom of the Q are only set once */
	desc->qb_ptrs.qp_top = desc->qb_buf.bi_kaddr;
	desc->qb_ptrs.qp_bottom = desc->qb_buf.bi_kaddr +
	    desc->qb_buf.bi_real_length - 1;
	data->qb_ptrs.qp_top = data->qb_buf.bi_kaddr;
	data->qb_ptrs.qp_bottom = data->qb_buf.bi_kaddr +
	    data->qb_buf.bi_real_length - 1;

	/*
	 * reset the Q pointers to their original settings.  Setup IM
	 * descriptors if this is an AR Q.
	 */
	hci1394_q_reset(q);

	/* if this is an AT Q, create a queued list for the AT descriptors */
	if (qinfo->qi_mode == HCI1394_ATQ) {
		hci1394_tlist_init(drvinfo, NULL, &q->q_queued_list);
	}

	*q_handle = q;

	return (DDI_SUCCESS);
}


/*
 * hci1394_q_fini()
 *    Cleanup after a successful hci1394_q_init(). Notice that a pointer to the
 *    handle is used for the parameter.  fini() will set your handle to NULL
 *    before returning.
 */
void
hci1394_q_fini(hci1394_q_handle_t *q_handle)
{
	hci1394_q_t *q;

	ASSERT(q_handle != NULL);

	q = *q_handle;
	if (q->q_info.qi_mode == HCI1394_ATQ) {
		hci1394_tlist_fini(&q->q_queued_list);
	}
	mutex_destroy(&q->q_mutex);
	hci1394_buf_free(&q->q_desc.qb_buf_handle);
	hci1394_buf_free(&q->q_data.qb_buf_handle);
	kmem_free(q, sizeof (hci1394_q_t));
	*q_handle = NULL;
}


/*
 * hci1394_q_buf_setup()
 *    Initialization of buffer pointers which are present in both the descriptor
 *    buffer and data buffer (No reason to duplicate the code)
 */
static void
hci1394_q_buf_setup(hci1394_q_buf_t *qbuf)
{
	ASSERT(qbuf != NULL);

	/* start with the first cookie */
	qbuf->qb_ptrs.qp_current_buf = 0;
	qbuf->qb_ptrs.qp_begin = qbuf->qb_ptrs.qp_top;
	qbuf->qb_ptrs.qp_end = qbuf->qb_ptrs.qp_begin +
	    qbuf->qb_cookie[qbuf->qb_ptrs.qp_current_buf].dmac_size - 1;
	qbuf->qb_ptrs.qp_current = qbuf->qb_ptrs.qp_begin;
	qbuf->qb_ptrs.qp_offset = 0;

	/*
	 * The free_buf and free pointer will change everytime an ACK (of some
	 * type) is processed.  Free is the last byte in the last cookie.
	 */
	qbuf->qb_ptrs.qp_free_buf = qbuf->qb_buf.bi_cookie_count - 1;
	qbuf->qb_ptrs.qp_free = qbuf->qb_ptrs.qp_bottom;

	/*
	 * Start with no space to write descriptors.  We first need to call
	 * hci1394_q_reserve() before calling hci1394_q_at_write_O*().
	 */
	qbuf->qb_ptrs.qp_resv_size = 0;
}


/*
 * hci1394_q_reset()
 *    Resets the buffers to an initial state.  This should be called during
 *    attach and resume.
 */
static void
hci1394_q_reset(hci1394_q_handle_t q_handle)
{
	hci1394_q_buf_t *desc;
	hci1394_q_buf_t *data;
	int index;

	ASSERT(q_handle != NULL);

	mutex_enter(&q_handle->q_mutex);
	desc = &q_handle->q_desc;
	data = &q_handle->q_data;

	hci1394_q_buf_setup(desc);
	hci1394_q_buf_setup(data);

	/* DMA starts off stopped, no previous descriptor to link from */
	q_handle->q_dma_running = B_FALSE;
	q_handle->q_block_cnt = 0;
	q_handle->q_previous = NULL;

	/* If this is an AR Q, setup IM's for the data buffers that we have */
	if (q_handle->q_info.qi_mode == HCI1394_ARQ) {
		/*
		 * This points to where to find the first IM descriptor.  Since
		 * we just reset the pointers in hci1394_q_buf_setup(), the
		 * first IM we write below will be found at the top of the Q.
		 */
		q_handle->q_head = desc->qb_ptrs.qp_top;

		for (index = 0; index < data->qb_buf.bi_cookie_count; index++) {
			hci1394_q_ar_write_IM(q_handle, desc,
			    data->qb_cookie[index].dmac_address,
			    data->qb_cookie[index].dmac_size);
		}

		/*
		 * The space left in the current IM is the size of the buffer.
		 * The current buffer is the first buffer added to the AR Q.
		 */
		q_handle->q_space_left = data->qb_cookie[0].dmac_size;
	}

	mutex_exit(&q_handle->q_mutex);
}


/*
 * hci1394_q_resume()
 *    This is called during a resume (after a successful suspend). Currently
 *    we only call reset.  Since this is not a time critical function, we will
 *    leave this as a separate function to increase readability.
 */
void
hci1394_q_resume(hci1394_q_handle_t q_handle)
{
	ASSERT(q_handle != NULL);
	hci1394_q_reset(q_handle);
}


/*
 * hci1394_q_stop()
 *    This call informs us that a DMA engine has been stopped.  It does not
 *    perform the actual stop. We need to know this so that when we add a
 *    new descriptor, we do a start instead of a wake.
 */
void
hci1394_q_stop(hci1394_q_handle_t q_handle)
{
	ASSERT(q_handle != NULL);
	mutex_enter(&q_handle->q_mutex);
	q_handle->q_dma_running = B_FALSE;
	mutex_exit(&q_handle->q_mutex);
}


/*
 * hci1394_q_reserve()
 *    Reserve space in the AT descriptor or data buffer. This ensures that we
 *    can get a contiguous buffer. Descriptors have to be in a contiguous
 *    buffer. Data does not have to be in a contiguous buffer but we do this to
 *    reduce complexity. For systems with small page sizes (e.g. x86), this
 *    could result in inefficient use of the data buffers when sending large
 *    data blocks (this only applies to non-physical block write ATREQs and
 *    block read ATRESP). Since it looks like most protocols that use large data
 *    blocks (like SPB-2), use physical transfers to do this (due to their
 *    efficiency), this will probably not be a real world problem.  If it turns
 *    out to be a problem, the options are to force a single cookie for the data
 *    buffer, allow multiple cookies and have a larger data space, or change the
 *    data code to use a OMI, OM, OL descriptor sequence (instead of OMI, OL).
 */
static int
hci1394_q_reserve(hci1394_q_buf_t *qbuf, uint_t size, uint32_t *io_addr)
{
	uint_t aligned_size;


	ASSERT(qbuf != NULL);

	/* Save backup of pointers in case we have to unreserve */
	qbuf->qb_backup_ptrs = qbuf->qb_ptrs;

	/*
	 * Make sure all alloc's are quadlet aligned. The data doesn't have to
	 * be, so we will force it to be.
	 */
	aligned_size = HCI1394_ALIGN_QUAD(size);

	/*
	 * if the free pointer is in the current buffer and the free pointer
	 * is below the current pointer (i.e. has not wrapped around)
	 */
	if ((qbuf->qb_ptrs.qp_current_buf == qbuf->qb_ptrs.qp_free_buf) &&
	    (qbuf->qb_ptrs.qp_free >= qbuf->qb_ptrs.qp_current)) {
		/*
		 * The free pointer is in this buffer below the current pointer.
		 * Check to see if we have enough free space left.
		 */
		if ((qbuf->qb_ptrs.qp_current + aligned_size) <=
		    qbuf->qb_ptrs.qp_free) {
			/* Setup up our reserved size, return the IO address */
			qbuf->qb_ptrs.qp_resv_size = aligned_size;
			*io_addr = (uint32_t)(qbuf->qb_cookie[
			    qbuf->qb_ptrs.qp_current_buf].dmac_address +
			    qbuf->qb_ptrs.qp_offset);

		/*
		 * The free pointer is in this buffer below the current pointer.
		 * We do not have enough free space for the alloc. Return
		 * failure.
		 */
		} else {
			qbuf->qb_ptrs.qp_resv_size = 0;
			return (DDI_FAILURE);
		}

	/*
	 * If there is not enough room to fit in the current buffer (not
	 * including wrap around), we will go to the next buffer and check
	 * there. If we only have one buffer (i.e. one cookie), we will end up
	 * staying at the current buffer and wrapping the address back to the
	 * top.
	 */
	} else if ((qbuf->qb_ptrs.qp_current + aligned_size) >
	    qbuf->qb_ptrs.qp_end) {
		/* Go to the next buffer (or the top of ours for one cookie) */
		hci1394_q_next_buf(qbuf);

		/* If the free pointer is in the new current buffer */
		if (qbuf->qb_ptrs.qp_current_buf == qbuf->qb_ptrs.qp_free_buf) {
			/*
			 * The free pointer is in this buffer. If we do not have
			 * enough free space for the alloc. Return failure.
			 */
			if ((qbuf->qb_ptrs.qp_current + aligned_size) >
			    qbuf->qb_ptrs.qp_free) {
				qbuf->qb_ptrs.qp_resv_size = 0;
				return (DDI_FAILURE);
			/*
			 * The free pointer is in this buffer. We have enough
			 * free space left.
			 */
			} else {
				/*
				 * Setup up our reserved size, return the IO
				 * address
				 */
				qbuf->qb_ptrs.qp_resv_size = aligned_size;
				*io_addr = (uint32_t)(qbuf->qb_cookie[
				    qbuf->qb_ptrs.qp_current_buf].dmac_address +
				    qbuf->qb_ptrs.qp_offset);
			}

		/*
		 * We switched buffers and the free pointer is still in another
		 * buffer. We have sufficient space in this buffer for the alloc
		 * after changing buffers.
		 */
		} else {
			/* Setup up our reserved size, return the IO address */
			qbuf->qb_ptrs.qp_resv_size = aligned_size;
			*io_addr = (uint32_t)(qbuf->qb_cookie[
			    qbuf->qb_ptrs.qp_current_buf].dmac_address +
			    qbuf->qb_ptrs.qp_offset);
		}
	/*
	 * The free pointer is in another buffer. We have sufficient space in
	 * this buffer for the alloc.
	 */
	} else {
		/* Setup up our reserved size, return the IO address */
		qbuf->qb_ptrs.qp_resv_size = aligned_size;
		*io_addr = (uint32_t)(qbuf->qb_cookie[
		    qbuf->qb_ptrs.qp_current_buf].dmac_address +
		    qbuf->qb_ptrs.qp_offset);
	}

	return (DDI_SUCCESS);
}

/*
 * hci1394_q_unreserve()
 *    Set the buffer pointer to what they were before hci1394_reserve().  This
 *    will be called when we encounter errors during hci1394_q_at*().
 */
static void
hci1394_q_unreserve(hci1394_q_buf_t *qbuf)
{
	ASSERT(qbuf != NULL);

	/* Go back to pointer setting before the reserve */
	qbuf->qb_ptrs = qbuf->qb_backup_ptrs;
}


/*
 * hci1394_q_next_buf()
 *    Set our current buffer to the next cookie.  If we only have one cookie, we
 *    will go back to the top of our buffer.
 */
void
hci1394_q_next_buf(hci1394_q_buf_t *qbuf)
{
	ASSERT(qbuf != NULL);

	/*
	 * go to the next cookie, if we are >= the cookie count, go back to the
	 * first cookie.
	 */
	qbuf->qb_ptrs.qp_current_buf++;
	if (qbuf->qb_ptrs.qp_current_buf >= qbuf->qb_buf.bi_cookie_count) {
		qbuf->qb_ptrs.qp_current_buf = 0;
	}

	/* adjust the begin, end, current, and offset pointers */
	qbuf->qb_ptrs.qp_begin = qbuf->qb_ptrs.qp_end + 1;
	if (qbuf->qb_ptrs.qp_begin > qbuf->qb_ptrs.qp_bottom) {
		qbuf->qb_ptrs.qp_begin = qbuf->qb_ptrs.qp_top;
	}
	qbuf->qb_ptrs.qp_end = qbuf->qb_ptrs.qp_begin +
	    qbuf->qb_cookie[qbuf->qb_ptrs.qp_current_buf].dmac_size - 1;
	qbuf->qb_ptrs.qp_current = qbuf->qb_ptrs.qp_begin;
	qbuf->qb_ptrs.qp_offset = 0;
}


/*
 * hci1394_q_at()
 *    Place an AT command that does NOT need the data buffer into the DMA chain.
 *    Some examples of this are quadlet read/write, PHY packets, ATREQ Block
 *    Read, and ATRESP block write. result is only valid on failure.
 */
int
hci1394_q_at(hci1394_q_handle_t q_handle, hci1394_q_cmd_t *cmd,
    hci1394_basic_pkt_t *hdr, uint_t hdrsize, int *result)
{
	int status;
	uint32_t ioaddr;


	ASSERT(q_handle != NULL);
	ASSERT(cmd != NULL);
	ASSERT(hdr != NULL);

	mutex_enter(&q_handle->q_mutex);

	/*
	 * Check the HAL state and generation when the AT Q is locked.  This
	 * will make sure that we get all the commands when we flush the Q's
	 * during a reset or shutdown.
	 */
	if ((hci1394_state(q_handle->q_drvinfo) != HCI1394_NORMAL) ||
	    (hci1394_ohci_current_busgen(q_handle->q_ohci) !=
	    cmd->qc_generation)) {
		*result = H1394_STATUS_INVALID_BUSGEN;
		mutex_exit(&q_handle->q_mutex);
		return (DDI_FAILURE);
	}

	/* save away the argument to pass up when this command completes */
	cmd->qc_node.tln_addr = cmd;

	/* we have not written any 16 byte blocks to the descriptor yet */
	q_handle->q_block_cnt = 0;

	/* Reserve space for an OLI in the descriptor buffer */
	status = hci1394_q_reserve(&q_handle->q_desc,
	    sizeof (hci1394_desc_imm_t), &ioaddr);
	if (status != DDI_SUCCESS) {
		*result = H1394_STATUS_NOMORE_SPACE;
		mutex_exit(&q_handle->q_mutex);
		return (DDI_FAILURE);
	}

	/* write the OLI to the descriptor buffer */
	hci1394_q_at_write_OLI(q_handle, &q_handle->q_desc, cmd, hdr, hdrsize);

	/* Add the AT command to the queued list */
	hci1394_tlist_add(q_handle->q_queued_list, &cmd->qc_node);

	mutex_exit(&q_handle->q_mutex);

	return (DDI_SUCCESS);
}


/*
 * XXX - NOTE: POSSIBLE FUTURE OPTIMIZATION
 *    ATREQ Block read and write's that go through software are not very
 *    efficient (one of the reasons to use physical space). A copy is forced
 *    on all block reads due to the design of OpenHCI. Writes do not have this
 *    same restriction.  This design forces a copy for writes too (we always
 *    copy into a data buffer before sending). There are many reasons for this
 *    including complexity reduction.  There is a data size threshold where a
 *    copy is more expensive than mapping the data buffer address (or worse
 *    case a big enough difference where it pays to do it). However, we move
 *    block data around in mblks which means that our data may be scattered
 *    over many buffers.  This adds to the complexity of mapping and setting
 *    up the OpenHCI descriptors.
 *
 *    If someone really needs a speedup on block write ATREQs, my recommendation
 *    would be to add an additional command type at the target interface for a
 *    fast block write.  The target driver would pass a mapped io addr to use.
 *    A function like "hci1394_q_at_with_ioaddr()" could be created which would
 *    be almost an exact copy of hci1394_q_at_with_data() without the
 *    hci1394_q_reserve() and hci1394_q_at_rep_put8() for the data buffer.
 */


/*
 * hci1394_q_at_with_data()
 *    Place an AT command that does need the data buffer into the DMA chain.
 *    The data is passed as a pointer to a kernel virtual address. An example of
 *    this is the lock operations. result is only valid on failure.
 */
int
hci1394_q_at_with_data(hci1394_q_handle_t q_handle, hci1394_q_cmd_t *cmd,
    hci1394_basic_pkt_t *hdr, uint_t hdrsize, uint8_t *data, uint_t datasize,
    int *result)
{
	uint32_t desc_ioaddr;
	uint32_t data_ioaddr;
	int status;


	ASSERT(q_handle != NULL);
	ASSERT(cmd != NULL);
	ASSERT(hdr != NULL);
	ASSERT(data != NULL);

	mutex_enter(&q_handle->q_mutex);

	/*
	 * Check the HAL state and generation when the AT Q is locked.  This
	 * will make sure that we get all the commands when we flush the Q's
	 * during a reset or shutdown.
	 */
	if ((hci1394_state(q_handle->q_drvinfo) != HCI1394_NORMAL) ||
	    (hci1394_ohci_current_busgen(q_handle->q_ohci) !=
	    cmd->qc_generation)) {
		*result = H1394_STATUS_INVALID_BUSGEN;
		mutex_exit(&q_handle->q_mutex);
		return (DDI_FAILURE);
	}

	/* save away the argument to pass up when this command completes */
	cmd->qc_node.tln_addr = cmd;

	/* we have not written any 16 byte blocks to the descriptor yet */
	q_handle->q_block_cnt = 0;

	/* Reserve space for an OMI and OL in the descriptor buffer */
	status = hci1394_q_reserve(&q_handle->q_desc,
	    (sizeof (hci1394_desc_imm_t) + sizeof (hci1394_desc_t)),
	    &desc_ioaddr);
	if (status != DDI_SUCCESS) {
		*result = H1394_STATUS_NOMORE_SPACE;
		mutex_exit(&q_handle->q_mutex);
		return (DDI_FAILURE);
	}

	/* allocate space for data in the data buffer */
	status = hci1394_q_reserve(&q_handle->q_data, datasize, &data_ioaddr);
	if (status != DDI_SUCCESS) {
		*result = H1394_STATUS_NOMORE_SPACE;
		hci1394_q_unreserve(&q_handle->q_desc);
		mutex_exit(&q_handle->q_mutex);
		return (DDI_FAILURE);
	}

	/* Copy data into data buffer */
	hci1394_q_at_rep_put8(&q_handle->q_data, cmd, data, datasize);

	/* write the OMI to the descriptor buffer */
	hci1394_q_at_write_OMI(q_handle, &q_handle->q_desc, cmd, hdr, hdrsize);

	/* write the OL to the descriptor buffer */
	hci1394_q_at_write_OL(q_handle, &q_handle->q_desc, cmd, data_ioaddr,
	    datasize);

	/* Add the AT command to the queued list */
	hci1394_tlist_add(q_handle->q_queued_list, &cmd->qc_node);

	mutex_exit(&q_handle->q_mutex);

	return (DDI_SUCCESS);
}


/*
 * hci1394_q_at_with_mblk()
 *    Place an AT command that does need the data buffer into the DMA chain.
 *    The data is passed in mblk_t(s). Examples of this are a block write
 *    ATREQ and a block read ATRESP. The services layer and the hal use a
 *    private structure (h1394_mblk_t) to keep track of how much of the mblk
 *    to send since we may have to break the transfer up into smaller blocks.
 *    (i.e. a 1MByte block write would go out in 2KByte chunks. result is only
 *    valid on failure.
 */
int
hci1394_q_at_with_mblk(hci1394_q_handle_t q_handle, hci1394_q_cmd_t *cmd,
    hci1394_basic_pkt_t *hdr, uint_t hdrsize, h1394_mblk_t *mblk, int *result)
{
	uint32_t desc_ioaddr;
	uint32_t data_ioaddr;
	int status;


	ASSERT(q_handle != NULL);
	ASSERT(cmd != NULL);
	ASSERT(hdr != NULL);
	ASSERT(mblk != NULL);

	mutex_enter(&q_handle->q_mutex);

	/*
	 * Check the HAL state and generation when the AT Q is locked.  This
	 * will make sure that we get all the commands when we flush the Q's
	 * during a reset or shutdown.
	 */
	if ((hci1394_state(q_handle->q_drvinfo) != HCI1394_NORMAL) ||
	    (hci1394_ohci_current_busgen(q_handle->q_ohci) !=
	    cmd->qc_generation)) {
		*result = H1394_STATUS_INVALID_BUSGEN;
		mutex_exit(&q_handle->q_mutex);
		return (DDI_FAILURE);
	}

	/* save away the argument to pass up when this command completes */
	cmd->qc_node.tln_addr = cmd;

	/* we have not written any 16 byte blocks to the descriptor yet */
	q_handle->q_block_cnt = 0;

	/* Reserve space for an OMI and OL in the descriptor buffer */
	status = hci1394_q_reserve(&q_handle->q_desc,
	    (sizeof (hci1394_desc_imm_t) + sizeof (hci1394_desc_t)),
	    &desc_ioaddr);
	if (status != DDI_SUCCESS) {
		*result = H1394_STATUS_NOMORE_SPACE;
		mutex_exit(&q_handle->q_mutex);
		return (DDI_FAILURE);
	}

	/* Reserve space for data in the data buffer */
	status = hci1394_q_reserve(&q_handle->q_data, mblk->length,
	    &data_ioaddr);
	if (status != DDI_SUCCESS) {
		*result = H1394_STATUS_NOMORE_SPACE;
		hci1394_q_unreserve(&q_handle->q_desc);
		mutex_exit(&q_handle->q_mutex);
		return (DDI_FAILURE);
	}

	/* Copy mblk data into data buffer */
	hci1394_q_at_copy_from_mblk(&q_handle->q_data, cmd, mblk);

	/* write the OMI to the descriptor buffer */
	hci1394_q_at_write_OMI(q_handle, &q_handle->q_desc, cmd, hdr, hdrsize);

	/* write the OL to the descriptor buffer */
	hci1394_q_at_write_OL(q_handle, &q_handle->q_desc, cmd, data_ioaddr,
	    mblk->length);

	/* Add the AT command to the queued list */
	hci1394_tlist_add(q_handle->q_queued_list, &cmd->qc_node);

	mutex_exit(&q_handle->q_mutex);

	return (DDI_SUCCESS);
}


/*
 * hci1394_q_at_next()
 *    Return the next completed AT command in cmd.  If flush_q is true, we will
 *    return the command regardless if it finished or not.  We will flush
 *    during bus reset processing, shutdown, and detach.
 */
void
hci1394_q_at_next(hci1394_q_handle_t q_handle, boolean_t flush_q,
    hci1394_q_cmd_t **cmd)
{
	hci1394_q_buf_t *desc;
	hci1394_q_buf_t *data;
	hci1394_tlist_node_t *node;
	uint32_t cmd_status;


	ASSERT(q_handle != NULL);
	ASSERT(cmd != NULL);

	mutex_enter(&q_handle->q_mutex);

	desc = &q_handle->q_desc;
	data = &q_handle->q_data;

	/* Sync descriptor buffer */
	(void) ddi_dma_sync(desc->qb_buf.bi_dma_handle, 0,
	    desc->qb_buf.bi_length, DDI_DMA_SYNC_FORKERNEL);

	/* Look at the top cmd on the queued list (without removing it) */
	hci1394_tlist_peek(q_handle->q_queued_list, &node);
	if (node == NULL) {
		/* There are no more commands left on the queued list */
		*cmd = NULL;
		mutex_exit(&q_handle->q_mutex);
		return;
	}

	/*
	 * There is a command on the list, read its status and timestamp when
	 * it was sent
	 */
	*cmd = (hci1394_q_cmd_t *)node->tln_addr;
	cmd_status = ddi_get32(desc->qb_buf.bi_handle, (*cmd)->qc_status_addr);
	(*cmd)->qc_timestamp = cmd_status & DESC_ST_TIMESTAMP_MASK;
	cmd_status = HCI1394_DESC_EVT_GET(cmd_status);

	/*
	 * If we are flushing the q (e.g. due to a bus reset), we will return
	 * the command regardless of its completion status. If we are not
	 * flushing the Q and we do not have status on the command (e.g. status
	 * = 0), we are done with this Q for now.
	 */
	if (flush_q == B_FALSE) {
		if (cmd_status == 0) {
			*cmd = NULL;
			mutex_exit(&q_handle->q_mutex);
			return;
		}
	}

	/*
	 * The command completed, remove it from the queued list. There is not
	 * a race condition to delete the node in the list here.  This is the
	 * only place the node will be deleted so we do not need to check the
	 * return status.
	 */
	(void) hci1394_tlist_delete(q_handle->q_queued_list, node);

	/*
	 * Free the space used by the command in the descriptor and data
	 * buffers.
	 */
	desc->qb_ptrs.qp_free_buf = (*cmd)->qc_descriptor_buf;
	desc->qb_ptrs.qp_free = (*cmd)->qc_descriptor_end;
	if ((*cmd)->qc_data_used == B_TRUE) {
		data->qb_ptrs.qp_free_buf = (*cmd)->qc_data_buf;
		data->qb_ptrs.qp_free = (*cmd)->qc_data_end;
	}

	/* return command status */
	(*cmd)->qc_status = cmd_status;

	mutex_exit(&q_handle->q_mutex);
}


/*
 * hci1394_q_at_write_OMI()
 *    Write an OMI descriptor into the AT descriptor buffer passed in as qbuf.
 *    Buffer state information is stored in cmd.  Use the hdr and hdr size for
 *    the additional information attached to an immediate descriptor.
 */
void
hci1394_q_at_write_OMI(hci1394_q_handle_t q_handle, hci1394_q_buf_t *qbuf,
    hci1394_q_cmd_t *cmd, hci1394_basic_pkt_t *hdr, uint_t hdrsize)
{
	hci1394_desc_imm_t *desc;
	uint32_t data;


	ASSERT(qbuf != NULL);
	ASSERT(cmd != NULL);
	ASSERT(hdr != NULL);
	ASSERT(MUTEX_HELD(&q_handle->q_mutex));

	/* The only valid "header" sizes for an OMI are 8 bytes or 16 bytes */
	ASSERT((hdrsize == 8) || (hdrsize == 16));

	/* Make sure enough room for OMI */
	ASSERT(qbuf->qb_ptrs.qp_resv_size >= sizeof (hci1394_desc_imm_t));

	/* Store the offset of the top of this descriptor block */
	qbuf->qb_ptrs.qp_offset = (uint32_t)(qbuf->qb_ptrs.qp_current -
	    qbuf->qb_ptrs.qp_begin);

	/* Setup OpenHCI OMI Header */
	desc = (hci1394_desc_imm_t *)qbuf->qb_ptrs.qp_current;
	data = DESC_AT_OMI | (hdrsize & DESC_HDR_REQCOUNT_MASK);
	ddi_put32(qbuf->qb_buf.bi_handle, &desc->hdr, data);
	ddi_put32(qbuf->qb_buf.bi_handle, &desc->data_addr, 0);
	ddi_put32(qbuf->qb_buf.bi_handle, &desc->branch, 0);
	ddi_put32(qbuf->qb_buf.bi_handle, &desc->status, cmd->qc_timestamp);

	/*
	 * Copy in 1394 header. Size is in bytes, convert it to a 32-bit word
	 * count.
	 */
	ddi_rep_put32(qbuf->qb_buf.bi_handle, &hdr->q1, &desc->q1,
	    hdrsize >> 2, DDI_DEV_AUTOINCR);

	/*
	 * We wrote 2 16 byte blocks in the descriptor buffer, update the count
	 * accordingly.  Update the reserved size and current pointer.
	 */
	q_handle->q_block_cnt += 2;
	qbuf->qb_ptrs.qp_resv_size -= sizeof (hci1394_desc_imm_t);
	qbuf->qb_ptrs.qp_current += sizeof (hci1394_desc_imm_t);
}


/*
 * hci1394_q_at_write_OLI()
 *    Write an OLI descriptor into the AT descriptor buffer passed in as qbuf.
 *    Buffer state information is stored in cmd.  Use the hdr and hdr size for
 *    the additional information attached to an immediate descriptor.
 */
void
hci1394_q_at_write_OLI(hci1394_q_handle_t q_handle, hci1394_q_buf_t *qbuf,
    hci1394_q_cmd_t *cmd, hci1394_basic_pkt_t *hdr, uint_t hdrsize)
{
	hci1394_desc_imm_t *desc;
	uint32_t data;
	uint32_t command_ptr;
	uint32_t tcode;


	ASSERT(qbuf != NULL);
	ASSERT(cmd != NULL);
	ASSERT(hdr != NULL);
	ASSERT(MUTEX_HELD(&q_handle->q_mutex));

	/* The only valid "header" sizes for an OLI are 8, 12, 16 bytes */
	ASSERT((hdrsize == 8) || (hdrsize == 12) || (hdrsize == 16));

	/* make sure enough room for 1 OLI */
	ASSERT(qbuf->qb_ptrs.qp_resv_size >= sizeof (hci1394_desc_imm_t));

	/* Store the offset of the top of this descriptor block */
	qbuf->qb_ptrs.qp_offset = (uint32_t)(qbuf->qb_ptrs.qp_current -
	    qbuf->qb_ptrs.qp_begin);

	/* Setup OpenHCI OLI Header */
	desc = (hci1394_desc_imm_t *)qbuf->qb_ptrs.qp_current;
	data = DESC_AT_OLI | (hdrsize & DESC_HDR_REQCOUNT_MASK);
	ddi_put32(qbuf->qb_buf.bi_handle, &desc->hdr, data);
	ddi_put32(qbuf->qb_buf.bi_handle, &desc->data_addr, 0);
	ddi_put32(qbuf->qb_buf.bi_handle, &desc->branch, 0);
	ddi_put32(qbuf->qb_buf.bi_handle, &desc->status, cmd->qc_timestamp);

	/* Setup 1394 Header */
	tcode = (hdr->q1 & DESC_PKT_TCODE_MASK) >> DESC_PKT_TCODE_SHIFT;
	if ((tcode == IEEE1394_TCODE_WRITE_QUADLET) ||
	    (tcode == IEEE1394_TCODE_READ_QUADLET_RESP)) {
		/*
		 * if the tcode = a quadlet write, move the last quadlet as
		 * 8-bit data.  All data is treated as 8-bit data (even quadlet
		 * reads and writes). Therefore, target drivers MUST take that
		 * into consideration when accessing device registers.
		 */
		ddi_rep_put32(qbuf->qb_buf.bi_handle, &hdr->q1, &desc->q1, 3,
		    DDI_DEV_AUTOINCR);
		ddi_rep_put8(qbuf->qb_buf.bi_handle, (uint8_t *)&hdr->q4,
		    (uint8_t *)&desc->q4, 4, DDI_DEV_AUTOINCR);
	} else {
		ddi_rep_put32(qbuf->qb_buf.bi_handle, &hdr->q1, &desc->q1,
		    hdrsize >> 2, DDI_DEV_AUTOINCR);
	}

	/*
	 * We wrote 2 16 byte blocks in the descriptor buffer, update the count
	 * accordingly.
	 */
	q_handle->q_block_cnt += 2;

	/*
	 * Sync buffer in case DMA engine currently running. This must be done
	 * before writing the command pointer in the previous descriptor.
	 */
	(void) ddi_dma_sync(qbuf->qb_buf.bi_dma_handle, 0,
	    qbuf->qb_buf.bi_length, DDI_DMA_SYNC_FORDEV);

	/* save away the status address for quick access in at_next() */
	cmd->qc_status_addr = &desc->status;

	/*
	 * Setup the command pointer.  This tells the HW where to get the
	 * descriptor we just setup.  This includes the IO address along with
	 * a 4 bit 16 byte block count
	 */
	command_ptr = (uint32_t)((qbuf->qb_cookie[qbuf->qb_ptrs.qp_current_buf
	    ].dmac_address + qbuf->qb_ptrs.qp_offset) | (q_handle->q_block_cnt &
	    DESC_Z_MASK));

	/*
	 * if we previously setup a descriptor, add this new descriptor into
	 * the previous descriptor's "next" pointer.
	 */
	if (q_handle->q_previous != NULL) {
		ddi_put32(qbuf->qb_buf.bi_handle, &q_handle->q_previous->branch,
		    command_ptr);
		/* Sync buffer again, this gets the command pointer */
		(void) ddi_dma_sync(qbuf->qb_buf.bi_dma_handle, 0,
		    qbuf->qb_buf.bi_length, DDI_DMA_SYNC_FORDEV);
	}

	/*
	 * this is now the previous descriptor.  Update the current pointer,
	 * clear the block count and reserved size since this is the end of
	 * this command.
	 */
	q_handle->q_previous = (hci1394_desc_t *)desc;
	qbuf->qb_ptrs.qp_current += sizeof (hci1394_desc_imm_t);
	q_handle->q_block_cnt = 0;
	qbuf->qb_ptrs.qp_resv_size = 0;

	/* save away cleanup info when we are done with the command */
	cmd->qc_descriptor_buf = qbuf->qb_ptrs.qp_current_buf;
	cmd->qc_descriptor_end = qbuf->qb_ptrs.qp_current - 1;

	/* If the DMA is not running, start it */
	if (q_handle->q_dma_running == B_FALSE) {
		q_handle->q_info.qi_start(q_handle->q_info.qi_callback_arg,
		    command_ptr);
		q_handle->q_dma_running = B_TRUE;
	/* the DMA is running, wake it up */
	} else {
		q_handle->q_info.qi_wake(q_handle->q_info.qi_callback_arg);
	}
}


/*
 * hci1394_q_at_write_OL()
 *    Write an OL descriptor into the AT descriptor buffer passed in as qbuf.
 *    Buffer state information is stored in cmd.  The IO address of the data
 *    buffer is passed in io_addr.  Size is the size of the data to be
 *    transferred.
 */
void
hci1394_q_at_write_OL(hci1394_q_handle_t q_handle, hci1394_q_buf_t *qbuf,
    hci1394_q_cmd_t *cmd, uint32_t io_addr, uint_t size)
{
	hci1394_desc_t *desc;
	uint32_t data;
	uint32_t command_ptr;


	ASSERT(q_handle != NULL);
	ASSERT(qbuf != NULL);
	ASSERT(cmd != NULL);
	ASSERT(MUTEX_HELD(&q_handle->q_mutex));

	/* make sure enough room for OL */
	ASSERT(qbuf->qb_ptrs.qp_resv_size >= sizeof (hci1394_desc_t));

	/* Setup OpenHCI OL Header */
	desc = (hci1394_desc_t *)qbuf->qb_ptrs.qp_current;
	data = DESC_AT_OL | (size & DESC_HDR_REQCOUNT_MASK);
	ddi_put32(qbuf->qb_buf.bi_handle, &desc->hdr, data);
	ddi_put32(qbuf->qb_buf.bi_handle, &desc->data_addr, io_addr);
	ddi_put32(qbuf->qb_buf.bi_handle, &desc->branch, 0);
	ddi_put32(qbuf->qb_buf.bi_handle, &desc->status, 0);

	/*
	 * We wrote 1 16 byte block in the descriptor buffer, update the count
	 * accordingly.
	 */
	q_handle->q_block_cnt++;

	/*
	 * Sync buffer in case DMA engine currently running. This must be done
	 * before writing the command pointer in the previous descriptor.
	 */
	(void) ddi_dma_sync(qbuf->qb_buf.bi_dma_handle, 0,
	    qbuf->qb_buf.bi_length, DDI_DMA_SYNC_FORDEV);

	/* save away the status address for quick access in at_next() */
	cmd->qc_status_addr = &desc->status;

	/*
	 * Setup the command pointer.  This tells the HW where to get the
	 * descriptor we just setup.  This includes the IO address along with
	 * a 4 bit 16 byte block count
	 */
	command_ptr = (uint32_t)((qbuf->qb_cookie[qbuf->qb_ptrs.qp_current_buf
	    ].dmac_address + qbuf->qb_ptrs.qp_offset) | (q_handle->q_block_cnt &
	    DESC_Z_MASK));

	/*
	 * if we previously setup a descriptor, add this new descriptor into
	 * the previous descriptor's "next" pointer.
	 */
	if (q_handle->q_previous != NULL) {
		ddi_put32(qbuf->qb_buf.bi_handle, &q_handle->q_previous->branch,
		    command_ptr);
		/* Sync buffer again, this gets the command pointer */
		(void) ddi_dma_sync(qbuf->qb_buf.bi_dma_handle, 0,
		    qbuf->qb_buf.bi_length, DDI_DMA_SYNC_FORDEV);
	}

	/*
	 * this is now the previous descriptor.  Update the current pointer,
	 * clear the block count and reserved size since this is the end of
	 * this command.
	 */
	q_handle->q_previous = desc;
	qbuf->qb_ptrs.qp_current += sizeof (hci1394_desc_t);
	q_handle->q_block_cnt = 0;
	qbuf->qb_ptrs.qp_resv_size = 0;

	/* save away cleanup info when we are done with the command */
	cmd->qc_descriptor_buf = qbuf->qb_ptrs.qp_current_buf;
	cmd->qc_descriptor_end = qbuf->qb_ptrs.qp_current - 1;

	/* If the DMA is not running, start it */
	if (q_handle->q_dma_running == B_FALSE) {
		q_handle->q_info.qi_start(q_handle->q_info.qi_callback_arg,
		    command_ptr);
		q_handle->q_dma_running = B_TRUE;
	/* the DMA is running, wake it up */
	} else {
		q_handle->q_info.qi_wake(q_handle->q_info.qi_callback_arg);
	}
}


/*
 * hci1394_q_at_rep_put8()
 *    Copy a byte stream from a kernel virtual address (data) to a IO mapped
 *    data buffer (qbuf).  Copy datasize bytes.  State information for the
 *    data buffer is kept in cmd.
 */
void
hci1394_q_at_rep_put8(hci1394_q_buf_t *qbuf, hci1394_q_cmd_t *cmd,
    uint8_t *data, uint_t datasize)
{
	ASSERT(qbuf != NULL);
	ASSERT(cmd != NULL);
	ASSERT(data != NULL);

	/* Make sure enough room for data */
	ASSERT(qbuf->qb_ptrs.qp_resv_size >= datasize);

	/* Copy in data into the data buffer */
	ddi_rep_put8(qbuf->qb_buf.bi_handle, data,
	    (uint8_t *)qbuf->qb_ptrs.qp_current, datasize, DDI_DEV_AUTOINCR);

	/* Update the current pointer, offset, and reserved size */
	qbuf->qb_ptrs.qp_current += datasize;
	qbuf->qb_ptrs.qp_offset = (uint32_t)(qbuf->qb_ptrs.qp_current -
	    qbuf->qb_ptrs.qp_begin);
	qbuf->qb_ptrs.qp_resv_size -= datasize;

	/* save away cleanup info when we are done with the command */
	cmd->qc_data_used = B_TRUE;
	cmd->qc_data_buf = qbuf->qb_ptrs.qp_current_buf;
	cmd->qc_data_end = qbuf->qb_ptrs.qp_current - 1;

	/* Sync data buffer */
	(void) ddi_dma_sync(qbuf->qb_buf.bi_dma_handle, 0,
	    qbuf->qb_buf.bi_length, DDI_DMA_SYNC_FORDEV);
}


/*
 * hci1394_q_at_copy_from_mblk()
 *    Copy a byte stream from a mblk(s) to a IO mapped data buffer (qbuf).
 *    Copy mblk->length bytes. The services layer and the hal use a private
 *    structure (h1394_mblk_t) to keep track of how much of the mblk to send
 *    since we may have to break the transfer up into smaller blocks. (i.e. a
 *    1MByte block write would go out in 2KByte chunks. State information for
 *    the data buffer is kept in cmd.
 */
static void
hci1394_q_at_copy_from_mblk(hci1394_q_buf_t *qbuf, hci1394_q_cmd_t *cmd,
    h1394_mblk_t *mblk)
{
	uint_t bytes_left;
	uint_t length;


	ASSERT(qbuf != NULL);
	ASSERT(cmd != NULL);
	ASSERT(mblk != NULL);

	/* We return these variables to the Services Layer when we are done */
	mblk->next_offset = mblk->curr_offset;
	mblk->next_mblk = mblk->curr_mblk;
	bytes_left = mblk->length;

	/* do while there are bytes left to copy */
	do {
		/*
		 * If the entire data portion of the current block transfer is
		 * contained within a single mblk.
		 */
		if ((mblk->next_offset + bytes_left) <=
		    (mblk->next_mblk->b_wptr)) {
			/* Copy the data into the data Q */
			hci1394_q_at_rep_put8(qbuf, cmd,
			    (uint8_t *)mblk->next_offset, bytes_left);

			/* increment the mblk offset */
			mblk->next_offset += bytes_left;

			/* we have no more bytes to put into the buffer */
			bytes_left = 0;

			/*
			 * If our offset is at the end of data in this mblk, go
			 * to the next mblk.
			 */
			if (mblk->next_offset >= mblk->next_mblk->b_wptr) {
				mblk->next_mblk = mblk->next_mblk->b_cont;
				if (mblk->next_mblk != NULL) {
					mblk->next_offset =
					    mblk->next_mblk->b_rptr;
				}
			}

		/*
		 * The data portion of the current block transfer is spread
		 * across two or more mblk's
		 */
		} else {
			/*
			 * Figure out how much data is in this mblk.
			 */
			length = mblk->next_mblk->b_wptr - mblk->next_offset;

			/* Copy the data into the atreq data Q */
			hci1394_q_at_rep_put8(qbuf, cmd,
			    (uint8_t *)mblk->next_offset, length);

			/* update the bytes left count, go to the next mblk */
			bytes_left = bytes_left - length;
			mblk->next_mblk = mblk->next_mblk->b_cont;
			ASSERT(mblk->next_mblk != NULL);
			mblk->next_offset = mblk->next_mblk->b_rptr;
		}
	} while (bytes_left > 0);
}


/*
 * hci1394_q_ar_next()
 *    Return an address to the next received AR packet.  If there are no more
 *    AR packets in the buffer, q_addr will be set to NULL.
 */
void
hci1394_q_ar_next(hci1394_q_handle_t q_handle, uint32_t **q_addr)
{
	hci1394_desc_t *desc;
	hci1394_q_buf_t *descb;
	hci1394_q_buf_t *datab;
	uint32_t residual_count;


	ASSERT(q_handle != NULL);
	ASSERT(q_addr != NULL);

	descb = &q_handle->q_desc;
	datab = &q_handle->q_data;

	/* Sync Descriptor buffer */
	(void) ddi_dma_sync(descb->qb_buf.bi_dma_handle, 0,
	    descb->qb_buf.bi_length, DDI_DMA_SYNC_FORKERNEL);

	/*
	 * Check residual in current IM count vs q_space_left to see if we have
	 * received any more responses
	 */
	desc = (hci1394_desc_t *)q_handle->q_head;
	residual_count = ddi_get32(descb->qb_buf.bi_handle, &desc->status);
	residual_count &= DESC_ST_RESCOUNT_MASK;
	if (residual_count >= q_handle->q_space_left) {
		/* No new packets received */
		*q_addr = NULL;
		return;
	}

	/* Sync Data Q */
	(void) ddi_dma_sync(datab->qb_buf.bi_dma_handle, 0,
	    datab->qb_buf.bi_length, DDI_DMA_SYNC_FORKERNEL);

	/*
	 * We have a new packet, return the address of the start of the
	 * packet.
	 */
	*q_addr = (uint32_t *)datab->qb_ptrs.qp_current;
}


/*
 * hci1394_q_ar_free()
 *    Free the space used by the AR packet at the top of the data buffer. AR
 *    packets are processed in the order that they are received.  This will
 *    free the oldest received packet which has not yet been freed.  size is
 *    how much space the packet takes up.
 */
void
hci1394_q_ar_free(hci1394_q_handle_t q_handle, uint_t size)
{
	hci1394_q_buf_t *descb;
	hci1394_q_buf_t *datab;


	ASSERT(q_handle != NULL);

	descb = &q_handle->q_desc;
	datab = &q_handle->q_data;

	/*
	 * Packet is in multiple buffers. Theoretically a buffer could be broken
	 * in more than two buffers for an ARRESP.  Since the buffers should be
	 * in at least 4K increments this will not happen since the max packet
	 * size is 2KBytes.
	 */
	if ((datab->qb_ptrs.qp_current + size) > datab->qb_ptrs.qp_end) {
		/* Add IM descriptor for used buffer back into Q */
		hci1394_q_ar_write_IM(q_handle, descb,
		    datab->qb_cookie[datab->qb_ptrs.qp_current_buf
		    ].dmac_address,
		    datab->qb_cookie[datab->qb_ptrs.qp_current_buf].dmac_size);

		/* Go to the next buffer */
		hci1394_q_next_buf(datab);

		/* Update next buffers pointers for partial packet */
		size -= q_handle->q_space_left;
		datab->qb_ptrs.qp_current += size;
		q_handle->q_space_left =
		    datab->qb_cookie[datab->qb_ptrs.qp_current_buf].dmac_size -
		    size;

		/* Change the head pointer to the next IM descriptor */
		q_handle->q_head += sizeof (hci1394_desc_t);
		if ((q_handle->q_head + sizeof (hci1394_desc_t)) >
		    (descb->qb_ptrs.qp_bottom + 1)) {
			q_handle->q_head = descb->qb_ptrs.qp_top;
		}

	/* Packet is only in one buffer */
	} else {
		q_handle->q_space_left -= size;
		datab->qb_ptrs.qp_current += size;
	}
}


/*
 * hci1394_q_ar_get32()
 *    Read a quadlet of data regardless if it is in the current buffer or has
 *    wrapped to the top buffer.  If the address passed to this routine is
 *    passed the bottom of the data buffer, this routine will automatically
 *    wrap back to the top of the Q and look in the correct offset from the
 *    top. Copy the data into the kernel virtual address provided.
 */
uint32_t
hci1394_q_ar_get32(hci1394_q_handle_t q_handle, uint32_t *addr)
{
	hci1394_q_buf_t *data;
	uintptr_t new_addr;
	uint32_t data32;


	ASSERT(q_handle != NULL);
	ASSERT(addr != NULL);

	data = &q_handle->q_data;

	/*
	 * if the data has wrapped to the top of the buffer, adjust the address.
	 */
	if ((uintptr_t)addr > (uintptr_t)data->qb_ptrs.qp_bottom) {
		new_addr = (uintptr_t)data->qb_ptrs.qp_top + ((uintptr_t)addr -
		    ((uintptr_t)data->qb_ptrs.qp_bottom + (uintptr_t)1));
		data32 = ddi_get32(data->qb_buf.bi_handle,
		    (uint32_t *)new_addr);

	/* data is before end of buffer */
	} else {
		data32 = ddi_get32(data->qb_buf.bi_handle, addr);
	}

	return (data32);
}


/*
 * hci1394_q_ar_rep_get8()
 *    Read a byte stream of data regardless if it is contiguous or has partially
 *    or fully wrapped to the top buffer.  If the address passed to this routine
 *    is passed the bottom of the data buffer, or address + size is past the
 *    bottom of the data buffer. this routine will automatically wrap back to
 *    the top of the Q and look in the correct offset from the top. Copy the
 *    data into the kernel virtual address provided.
 */
void
hci1394_q_ar_rep_get8(hci1394_q_handle_t q_handle, uint8_t *dest,
    uint8_t *q_addr, uint_t size)
{
	hci1394_q_buf_t *data;
	uintptr_t new_addr;
	uint_t new_size;
	uintptr_t new_dest;


	ASSERT(q_handle != NULL);
	ASSERT(dest != NULL);
	ASSERT(q_addr != NULL);

	data = &q_handle->q_data;

	/*
	 * There are three cases:
	 *   1) All of the data has wrapped.
	 *   2) Some of the data has not wrapped and some has wrapped.
	 *   3) None of the data has wrapped.
	 */

	/* All of the data has wrapped, just adjust the starting address */
	if ((uintptr_t)q_addr > (uintptr_t)data->qb_ptrs.qp_bottom) {
		new_addr = (uintptr_t)data->qb_ptrs.qp_top +
		    ((uintptr_t)q_addr - ((uintptr_t)data->qb_ptrs.qp_bottom +
		    (uintptr_t)1));
		ddi_rep_get8(data->qb_buf.bi_handle, dest, (uint8_t *)new_addr,
		    size, DDI_DEV_AUTOINCR);

	/*
	 * Some of the data has wrapped. Copy the data that hasn't wrapped,
	 * adjust the address, then copy the rest.
	 */
	} else if (((uintptr_t)q_addr + (uintptr_t)size) >
	    ((uintptr_t)data->qb_ptrs.qp_bottom + (uintptr_t)1)) {
		/* Copy first half */
		new_size = (uint_t)(((uintptr_t)data->qb_ptrs.qp_bottom +
		    (uintptr_t)1) - (uintptr_t)q_addr);
		ddi_rep_get8(data->qb_buf.bi_handle, dest, q_addr, new_size,
		    DDI_DEV_AUTOINCR);

		/* copy second half */
		new_dest = (uintptr_t)dest + (uintptr_t)new_size;
		new_size = size - new_size;
		new_addr = (uintptr_t)data->qb_ptrs.qp_top;
		ddi_rep_get8(data->qb_buf.bi_handle, (uint8_t *)new_dest,
		    (uint8_t *)new_addr, new_size, DDI_DEV_AUTOINCR);

	/* None of the data has wrapped */
	} else {
		ddi_rep_get8(data->qb_buf.bi_handle, dest, q_addr, size,
		    DDI_DEV_AUTOINCR);
	}
}


/*
 * hci1394_q_ar_copy_to_mblk()
 *    Read a byte stream of data regardless if it is contiguous or has partially
 *    or fully wrapped to the top buffer.  If the address passed to this routine
 *    is passed the bottom of the data buffer, or address + size is passed the
 *    bottom of the data buffer. this routine will automatically wrap back to
 *    the top of the Q and look in the correct offset from the top. Copy the
 *    data into the mblk provided. The services layer and the hal use a private
 *    structure (h1394_mblk_t) to keep track of how much of the mblk to receive
 *    into since we may have to break the transfer up into smaller blocks.
 *    (i.e. a 1MByte block read would go out in 2KByte requests.
 */
void
hci1394_q_ar_copy_to_mblk(hci1394_q_handle_t q_handle, uint8_t *addr,
    h1394_mblk_t *mblk)
{
	uint8_t *new_addr;
	uint_t bytes_left;
	uint_t length;


	ASSERT(q_handle != NULL);
	ASSERT(addr != NULL);
	ASSERT(mblk != NULL);

	/* We return these variables to the Services Layer when we are done */
	mblk->next_offset = mblk->curr_offset;
	mblk->next_mblk = mblk->curr_mblk;
	bytes_left = mblk->length;

	/* the address we copy from will change as we change mblks */
	new_addr = addr;

	/* do while there are bytes left to copy */
	do {
		/*
		 * If the entire data portion of the current block transfer is
		 * contained within a single mblk.
		 */
		if ((mblk->next_offset + bytes_left) <=
		    (mblk->next_mblk->b_datap->db_lim)) {
			/* Copy the data into the mblk */
			hci1394_q_ar_rep_get8(q_handle,
			    (uint8_t *)mblk->next_offset, new_addr, bytes_left);

			/* increment the offset */
			mblk->next_offset += bytes_left;
			mblk->next_mblk->b_wptr = mblk->next_offset;

			/* we have no more bytes to put into the buffer */
			bytes_left = 0;

			/*
			 * If our offset is at the end of data in this mblk, go
			 * to the next mblk.
			 */
			if (mblk->next_offset >=
			    mblk->next_mblk->b_datap->db_lim) {
				mblk->next_mblk = mblk->next_mblk->b_cont;
				if (mblk->next_mblk != NULL) {
					mblk->next_offset =
					    mblk->next_mblk->b_wptr;
				}
			}

		/*
		 * The data portion of the current block transfer is spread
		 * across two or more mblk's
		 */
		} else {
			/* Figure out how much data is in this mblk */
			length = mblk->next_mblk->b_datap->db_lim -
			    mblk->next_offset;

			/* Copy the data into the mblk */
			hci1394_q_ar_rep_get8(q_handle,
			    (uint8_t *)mblk->next_offset, new_addr, length);
			mblk->next_mblk->b_wptr =
			    mblk->next_mblk->b_datap->db_lim;

			/*
			 * update the bytes left and address to copy from, go
			 * to the next mblk.
			 */
			bytes_left = bytes_left - length;
			new_addr = (uint8_t *)((uintptr_t)new_addr +
			    (uintptr_t)length);
			mblk->next_mblk = mblk->next_mblk->b_cont;
			ASSERT(mblk->next_mblk != NULL);
			mblk->next_offset = mblk->next_mblk->b_wptr;
		}
	} while (bytes_left > 0);
}


/*
 * hci1394_q_ar_write_IM()
 *    Write an IM descriptor into the AR descriptor buffer passed in as qbuf.
 *    The IO address of the data buffer is passed in io_addr.  datasize is the
 *    size of the data data buffer to receive into.
 */
void
hci1394_q_ar_write_IM(hci1394_q_handle_t q_handle, hci1394_q_buf_t *qbuf,
    uint32_t io_addr, uint_t datasize)
{
	hci1394_desc_t *desc;
	uint32_t data;
	uint32_t command_ptr;


	ASSERT(q_handle != NULL);
	ASSERT(qbuf != NULL);

	/* Make sure enough room for IM */
	if ((qbuf->qb_ptrs.qp_current + sizeof (hci1394_desc_t)) >
	    (qbuf->qb_ptrs.qp_bottom + 1)) {
		hci1394_q_next_buf(qbuf);
	} else {
		/* Store the offset of the top of this descriptor block */
		qbuf->qb_ptrs.qp_offset = (uint32_t)(qbuf->qb_ptrs.qp_current -
		    qbuf->qb_ptrs.qp_begin);
	}

	/* Setup OpenHCI IM Header */
	desc = (hci1394_desc_t *)qbuf->qb_ptrs.qp_current;
	data = DESC_AR_IM | (datasize & DESC_HDR_REQCOUNT_MASK);
	ddi_put32(qbuf->qb_buf.bi_handle, &desc->hdr, data);
	ddi_put32(qbuf->qb_buf.bi_handle, &desc->data_addr, io_addr);
	ddi_put32(qbuf->qb_buf.bi_handle, &desc->branch, 0);
	ddi_put32(qbuf->qb_buf.bi_handle, &desc->status, datasize &
	    DESC_ST_RESCOUNT_MASK);

	/*
	 * Sync buffer in case DMA engine currently running. This must be done
	 * before writing the command pointer in the previous descriptor.
	 */
	(void) ddi_dma_sync(qbuf->qb_buf.bi_dma_handle, 0,
	    qbuf->qb_buf.bi_length, DDI_DMA_SYNC_FORDEV);

	/*
	 * Setup the command pointer.  This tells the HW where to get the
	 * descriptor we just setup.  This includes the IO address along with
	 * a 4 bit 16 byte block count.  We only wrote 1 16 byte block.
	 */
	command_ptr = (uint32_t)((qbuf->qb_cookie[qbuf->qb_ptrs.qp_current_buf
	    ].dmac_address + qbuf->qb_ptrs.qp_offset) | 1);

	/*
	 * if we previously setup a descriptor, add this new descriptor into
	 * the previous descriptor's "next" pointer.
	 */
	if (q_handle->q_previous != NULL) {
		ddi_put32(qbuf->qb_buf.bi_handle,
		    &q_handle->q_previous->branch, command_ptr);
		/* Sync buffer again, this gets the command pointer */
		(void) ddi_dma_sync(qbuf->qb_buf.bi_dma_handle, 0,
		    qbuf->qb_buf.bi_length, DDI_DMA_SYNC_FORDEV);
	}

	/* this is the new previous descriptor.  Update the current pointer */
	q_handle->q_previous = desc;
	qbuf->qb_ptrs.qp_current += sizeof (hci1394_desc_t);

	/* If the DMA is not running, start it */
	if (q_handle->q_dma_running == B_FALSE) {
		q_handle->q_info.qi_start(q_handle->q_info.qi_callback_arg,
		    command_ptr);
		q_handle->q_dma_running = B_TRUE;
	/* the DMA is running, wake it up */
	} else {
		q_handle->q_info.qi_wake(q_handle->q_info.qi_callback_arg);
	}
}
