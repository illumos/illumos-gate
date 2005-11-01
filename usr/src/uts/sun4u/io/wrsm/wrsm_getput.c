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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file implements the RSMPI rsm_get* and rsm_put* functions
 * in the Wildcat RSM driver.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/vmsystm.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <vm/seg_kmem.h>
#include <vm/page.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddimapreq.h>

#include <sys/rsm/rsmpi.h>

#include <sys/wrsm_common.h>
#include <sys/wrsm_nc.h>
#include <sys/wrsm_memseg.h>
#include <sys/wrsm_memseg_impl.h>
#include <sys/wrsm_barrier.h>
#include <sys/wci_common.h>
#include <sys/wrsm_intr.h>
#include <sys/wrsm_plugin.h>

#ifdef DEBUG
extern char platform[];


#define	DBG_WARN		0x001
#define	DBG_SMPUT		0x008
#define	DBG_SMPUT_EXTRA		0x080

static uint_t wrsm_getput_debug = DBG_WARN;

#define	DPRINTF(a, b) { if (wrsm_getput_debug & a) wrsmdprintf b; }

#else /* DEBUG */
#define	DPRINTF(a, b) { }
#endif /* DEBUG */


static void
record_error(wrsm_network_t *network, cnodeid_t cnodeid, int err)
{
	wrsm_node_t *node;

	mutex_enter(&network->lock);
	network->memseg->transfer_errors++;
	network->memseg->last_transfer_error = err;
	node = network->nodes[cnodeid];
	if (node) {
		node->memseg->transfer_errors++;
		node->memseg->last_transfer_error = err;
	}
	mutex_exit(&network->lock);
}



/*
 * Send one or more interrupt requests to cause <len> bytes from buffer
 * <buf> be written at offset <offset> into the segment.
 */
static int
small_put(iseginfo_t *iseginfo, off_t offset, uint_t len, caddr_t buf)
{
	wrsm_raw_message_t msgbuf;
	wrsm_smallput_msg_t *msg = (wrsm_smallput_msg_t *)&msgbuf;
	int writesize;
	int put_offset;
	int err;
#ifdef DEBUG
	uint_t smallput_body_size = WRSM_SMALLPUT_BODY_SIZE;
#endif
	DPRINTF(DBG_SMPUT, (CE_CONT, "small_put - segid %d offset 0x%lx "
	    "len %d\n", iseginfo->segid, offset, len));

	/* LINTED */
	ASSERT(WRSM_SMALLPUT_BODY_SIZE == 48);

#ifdef DEBUG
	if (strncmp(platform, "SUNW,Ultra", 10) == 0) {
		DPRINTF(DBG_SMPUT_EXTRA,
		    (CE_CONT, "small put buffer is 8 bytes\n"));
		smallput_body_size = 8;
	} else {
		smallput_body_size = 48;
	}
#endif

	msg->header.sending_cnode = iseginfo->network->cnodeid;

	while (len) {
		/*
		 * Place the data in putdata buffer so that it is long
		 * aligned with respect to the segment offset.  (Note that
		 * the start of the putdata buffer is long aligned.)
		 */
#ifdef DEBUG
		if (len < smallput_body_size)
			writesize = len;
		else
			writesize = smallput_body_size;

		put_offset = offset & WRSM_LONG_MASK;
		if (writesize > (smallput_body_size - put_offset))
			writesize = smallput_body_size - put_offset;
#else
		if (len < WRSM_SMALLPUT_BODY_SIZE)
			writesize = len;
		else
			writesize = WRSM_SMALLPUT_BODY_SIZE;

		put_offset = offset & WRSM_LONG_MASK;
		if (writesize > (WRSM_SMALLPUT_BODY_SIZE - put_offset))
			writesize = WRSM_SMALLPUT_BODY_SIZE - put_offset;
#endif
		msg->header.offset = offset;
		msg->header.len = writesize;
		msg->header.start = put_offset;

		DPRINTF(DBG_SMPUT_EXTRA,
		    (CE_CONT, "len 0x%x offset 0x%lx writesize %d "
		    "put_offset %d msg 0x%p msg-buf-start 0x%p "
		    "put-paddr 0x%lx\n",
		    len, offset, writesize, put_offset, (void *)msg,
		    (void *)&(msg->putdata[put_offset]),
		    va_to_pa(iseginfo->kernel_mapping.small_put_offset)));
		bcopy(buf, &(msg->putdata[put_offset]), writesize);

		err = wrsm_intr_send(iseginfo->network,
		    iseginfo->kernel_mapping.small_put_offset,
		    iseginfo->cnodeid, msg, 0, WRSM_INTR_WAIT_DEFAULT, 0);
		if (err) {
			DPRINTF(DBG_SMPUT_EXTRA,
			    (CE_CONT, "SMALL PUT err is %d", err));
			mutex_enter(&iseginfo->lock);
			iseginfo->transfer_errors++;
			iseginfo->last_transfer_error = RSMERR_BARRIER_FAILURE;
			mutex_exit(&iseginfo->lock);
			return (RSMERR_BARRIER_FAILURE);
		}

		len -= writesize;
		offset += writesize;
		buf += writesize;
	}

	return (RSM_SUCCESS);
}


int
wrsmrsm_put(rsm_memseg_import_handle_t im_memseg, off_t offset, void *datap,
    size_t length)
{
	importseg_t *importseg = (importseg_t *)im_memseg;
	iseginfo_t *iseginfo;
	caddr_t dp = datap;
	uint_t partial_cacheline;
	uint_t num_cachelines;
	int err = RSM_SUCCESS;
	caddr_t segptr;
	rsm_barrier_t barrier;
	wrsm_network_t *network;
	cnodeid_t cnodeid;
	wrsm_raw_message_t msgbuf;
	wrsm_smallput_msg_t *msg = (wrsm_smallput_msg_t *)&msgbuf;
	boolean_t did_small_puts = B_FALSE;

	if ((err = wrsm_lock_importseg(importseg, RW_READER)) !=
	    RSM_SUCCESS) {
		return (err);
	}

	if (importseg->unpublished) {
		rw_exit(&importseg->rw_lock);
		return (RSMERR_CONN_ABORTED);
	}

	iseginfo = importseg->iseginfo;

	if (!(iseginfo->perms & RSM_PERM_WRITE)) {
		rw_exit(&importseg->rw_lock);
		return (RSMERR_PERM_DENIED);
	}

	if (iseginfo->size < (offset + length)) {
		rw_exit(&importseg->rw_lock);
		return (RSMERR_BAD_LENGTH);
	}

	if (length == 0) {
		rw_exit(&importseg->rw_lock);
		return (RSM_SUCCESS);
	}

	if (!importseg->kernel_user) {
		importseg->kernel_user = B_TRUE;
		mutex_enter(&iseginfo->lock);
		if (!iseginfo->kernel_users) {
			err = create_segment_mapping(iseginfo);
			if (err) {
				iseginfo->transfer_errors++;
				iseginfo->last_transfer_error = err;
				mutex_exit(&iseginfo->lock);
				network = iseginfo->network;
				cnodeid = iseginfo->cnodeid;
				rw_exit(&importseg->rw_lock);
				record_error(network, cnodeid, err);
				return (err);
			}
		}
		iseginfo->kernel_users++;
		mutex_exit(&iseginfo->lock);
	}


	if (importseg->barrier_mode == RSM_BARRIER_MODE_IMPLICIT) {
		if ((err = wrsm_open_barrier_region(importseg, &barrier)) !=
		    RSM_SUCCESS) {
			rw_exit(&importseg->rw_lock);
			return (err);
		}
	}

	/*
	 * handle partial line write at start of buffer
	 */
	if (offset & WRSM_CACHELINE_MASK) {
		partial_cacheline = WRSM_CACHELINE_SIZE -
		    (offset & WRSM_CACHELINE_MASK);
		if (partial_cacheline > length)
			partial_cacheline = length;

		did_small_puts = B_TRUE;
		msg->header.offset = 0;
		msg->header.len = 0;
		msg->header.start = 0;
		err = small_put(iseginfo, offset, partial_cacheline, dp);
		if (err) {
			network = iseginfo->network;
			cnodeid = iseginfo->cnodeid;
			rw_exit(&importseg->rw_lock);
			record_error(network, cnodeid, err);

			if (importseg->barrier_mode ==
			    RSM_BARRIER_MODE_IMPLICIT) {
				(void) wrsm_close_barrier(&barrier);
			}
			/*
			 * guarantee that any outstanding small puts have
			 * finished
			 */
			(void) wrsm_intr_send(importseg->iseginfo->network,
			    importseg->iseginfo->kernel_mapping.
			    small_put_offset,
			    importseg->iseginfo->cnodeid,
			    msg, 0, WRSM_INTR_WAIT_DEFAULT, 0);
			return (err);
		}

		length -= partial_cacheline;
		dp += partial_cacheline;
		offset += partial_cacheline;

		if (length == 0) {
			int intr_err;
			/*
			 * this put call is finished
			 */
			rw_exit(&importseg->rw_lock);
			/*
			 * guarantee that any outstanding small
			 * puts have finished
			 */
			if (importseg->barrier_mode ==
			    RSM_BARRIER_MODE_IMPLICIT) {
				err = wrsm_close_barrier(&barrier);
			}
			intr_err = wrsm_intr_send(importseg->iseginfo->network,
			    importseg->iseginfo->kernel_mapping.
			    small_put_offset,
			    importseg->iseginfo->cnodeid,
			    msg, 0, WRSM_INTR_WAIT_DEFAULT, 0);
			/*
			 * Return the barrier error, or if that succeeded,
			 * the send error if there was one.
			 */
			err = err ? err : intr_err;
			return (err);
		}
	}

	/*
	 * handle cacheline sized writes
	 */
	num_cachelines = length >> WRSM_CACHELINE_SHIFT;
	DPRINTF(DBG_SMPUT, (CE_CONT, "putting %d cachelines\n",
	    num_cachelines));
	if (num_cachelines) {
		segptr = iseginfo->kernel_mapping.seg + offset;

		DPRINTF(DBG_SMPUT, (CE_CONT, "doing all at once\n"));
		wrsm_blkwrite(dp, segptr, num_cachelines);

		length -= (num_cachelines * WRSM_CACHELINE_SIZE);
		dp += (num_cachelines * WRSM_CACHELINE_SIZE);
		offset += (num_cachelines * WRSM_CACHELINE_SIZE);
	}

	/*
	 * handle partial line write at end of buffer
	 */
	if (length) {
		did_small_puts = B_TRUE;
		msg->header.offset = 0;
		msg->header.len = 0;
		msg->header.start = 0;
		err = small_put(iseginfo, offset, length, dp);
		if (err) {
			network = iseginfo->network;
			cnodeid = iseginfo->cnodeid;
			rw_exit(&importseg->rw_lock);
			record_error(network, cnodeid, err);

			/*
			 * guarantee that any outstanding small puts have
			 * finished
			 */
			(void) wrsm_intr_send(importseg->iseginfo->network,
			    importseg->iseginfo->kernel_mapping.
			    small_put_offset,
			    importseg->iseginfo->cnodeid,
			    msg, 0, WRSM_INTR_WAIT_DEFAULT, 0);
			if (importseg->barrier_mode ==
			    RSM_BARRIER_MODE_IMPLICIT) {
				(void) wrsm_close_barrier(&barrier);
			}
			return (err);
		}
	}

	rw_exit(&importseg->rw_lock);

	if (did_small_puts) {
		/*
		 * guarantee that any outstanding small puts have finished
		 */
		(void) wrsm_intr_send(importseg->iseginfo->network,
		    importseg->iseginfo->kernel_mapping.small_put_offset,
		    importseg->iseginfo->cnodeid,
		    msg, 0, WRSM_INTR_WAIT_DEFAULT, 0);
	}

	if (importseg->barrier_mode == RSM_BARRIER_MODE_IMPLICIT) {
		err = wrsm_close_barrier(&barrier);
	}

	return (err);
}

/* ARGSUSED */
int
wrsmrsm_put8(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint8_t *datap, ulong_t rep_cnt, boolean_t byte_swap)
{
	/* Since Wildcat is SPARC-only, don't need to worry about byte_swap */
	return (wrsmrsm_put(im_memseg, offset, datap, rep_cnt));
}

/* ARGSUSED */
int
wrsmrsm_put16(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint16_t *datap, ulong_t rep_cnt, boolean_t byte_swap)
{
	/* Check alignment */
	if ((((uint64_t)datap) & 0x1) != 0 ||
	    (((uint64_t)offset) & 0x1) != 0) {
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	/* Since Wildcat is SPARC-only, don't need to worry about byte_swap */
	return (wrsmrsm_put(im_memseg, offset, datap, 2 * rep_cnt));
}

/* ARGSUSED */
int
wrsmrsm_put32(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint32_t *datap, ulong_t rep_cnt, boolean_t byte_swap)
{
	/* Check alignment */
	if ((((uint64_t)datap) & 0x3) != 0 ||
	    (((uint64_t)offset) & 0x3) != 0) {
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	/* Since Wildcat is SPARC-only, don't need to worry about byte_swap */
	return (wrsmrsm_put(im_memseg, offset, datap, 4 * rep_cnt));
}

/* ARGSUSED */
int
wrsmrsm_put64(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint64_t *datap, ulong_t rep_cnt, boolean_t byte_swap)
{
	/* Check alignment */
	if ((((uint64_t)datap) & 0x7) != 0 ||
	    (((uint64_t)offset) & 0x7) != 0) {
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	/* Since Wildcat is SPARC-only, don't need to worry about byte_swap */
	return (wrsmrsm_put(im_memseg, offset, datap, 8 * rep_cnt));
}


static int
small_get(iseginfo_t *iseginfo, off_t offset, uint_t len, caddr_t buf)
{
	wrsm_raw_message_t cachelinebuf;
	caddr_t aligned_cacheline = (caddr_t)&cachelinebuf;
	off_t read_offset;
	uint_t cacheline_offset;
	caddr_t seg;

	DPRINTF(DBG_SMPUT, (CE_CONT, "small_get - segid %d offset 0x%lx "
	    "len %d\n", iseginfo->segid, offset, len));

	cacheline_offset = offset & WRSM_CACHELINE_MASK;
	ASSERT((cacheline_offset + len) <= WRSM_CACHELINE_SIZE);

	seg = iseginfo->kernel_mapping.seg;

	read_offset = offset & ~WRSM_CACHELINE_MASK;
	wrsm_blkread(seg + read_offset, aligned_cacheline, 1);

	bcopy(aligned_cacheline + cacheline_offset, buf, len);
	return (RSM_SUCCESS);
}



int
wrsmrsm_get(rsm_memseg_import_handle_t im_memseg, off_t offset, void *datap,
    size_t length)
{
	importseg_t *importseg = (importseg_t *)im_memseg;
	iseginfo_t *iseginfo;
	caddr_t dp = datap;
	uint_t partial_cacheline;
	uint_t num_cachelines;
	int err;
	caddr_t seg;
	rsm_barrier_t barrier;
	wrsm_network_t *network;
	cnodeid_t cnodeid;

	DPRINTF(DBG_SMPUT, (CE_CONT,
	    "wrsmrsm_get - importseg 0x%p offset 0x%lx len %ld\n",
	    (void *)importseg, offset, length));

	if ((err = wrsm_lock_importseg(importseg, RW_READER)) !=
	    RSM_SUCCESS) {
		return (err);
	}

	iseginfo = importseg->iseginfo;

	if (importseg->unpublished) {
		mutex_enter(&iseginfo->lock);
		iseginfo->transfer_errors++;
		iseginfo->last_transfer_error = RSMERR_CONN_ABORTED;
		mutex_exit(&iseginfo->lock);
		network = iseginfo->network;
		cnodeid = iseginfo->cnodeid;
		rw_exit(&importseg->rw_lock);
		record_error(network, cnodeid, RSMERR_CONN_ABORTED);
		return (RSMERR_CONN_ABORTED);
	}

	if (!importseg->kernel_user) {
		importseg->kernel_user = B_TRUE;
		mutex_enter(&iseginfo->lock);
		if (!iseginfo->kernel_users) {
			err = create_segment_mapping(iseginfo);
			if (err) {
				iseginfo->transfer_errors++;
				iseginfo->last_transfer_error = err;
				mutex_exit(&iseginfo->lock);
				network = iseginfo->network;
				cnodeid = iseginfo->cnodeid;
				rw_exit(&importseg->rw_lock);
				record_error(network, cnodeid, err);
				return (err);
			}
		}
		iseginfo->kernel_users++;
		mutex_exit(&iseginfo->lock);
	}

	if (!(iseginfo->perms & (rsm_permission_t)RSM_PERM_READ)) {
		mutex_enter(&iseginfo->lock);
		iseginfo->transfer_errors++;
		iseginfo->last_transfer_error = RSMERR_PERM_DENIED;
		mutex_exit(&iseginfo->lock);
		network = iseginfo->network;
		cnodeid = iseginfo->cnodeid;
		rw_exit(&importseg->rw_lock);
		record_error(network, cnodeid, RSMERR_PERM_DENIED);
		return (RSMERR_PERM_DENIED);
	}

	if (iseginfo->size < (offset + length)) {
		/* barrier doesn't record this type of error */
		rw_exit(&importseg->rw_lock);
		return (RSMERR_BAD_LENGTH);
	}

	if (length == 0) {
		rw_exit(&importseg->rw_lock);
		return (RSM_SUCCESS);
	}

	if (importseg->barrier_mode == RSM_BARRIER_MODE_IMPLICIT) {
		if ((err = wrsm_open_barrier_region(importseg, &barrier)) !=
		    RSM_SUCCESS) {
			return (err);
		}
	}

	/*
	 * handle partial line read at start of buffer
	 */
	if (offset & WRSM_CACHELINE_MASK) {
		partial_cacheline = WRSM_CACHELINE_SIZE -
		    (offset & WRSM_CACHELINE_MASK);
		if (partial_cacheline > length)
			partial_cacheline = length;

		if ((err = small_get(iseginfo, offset, partial_cacheline, dp))
		    != 0) {
			rw_exit(&importseg->rw_lock);
			if (importseg->barrier_mode ==
			    RSM_BARRIER_MODE_IMPLICIT) {
				(void) wrsm_close_barrier(&barrier);
			}
			return (err);
		}

		length -= partial_cacheline;
		dp += partial_cacheline;
		offset += partial_cacheline;

		if (length == 0) {
			rw_exit(&importseg->rw_lock);
			if (importseg->barrier_mode ==
			    RSM_BARRIER_MODE_IMPLICIT) {
				return (wrsm_close_barrier(&barrier));
			} else {
				return (RSM_SUCCESS);
			}
		}
	}

	/*
	 * handle cacheline sized reads
	 */
	num_cachelines = length >> WRSM_CACHELINE_SHIFT;
	if (num_cachelines) {
		seg = importseg->iseginfo->kernel_mapping.seg + offset;

		DPRINTF(DBG_SMPUT, (CE_CONT,
		    "full cacheline read offset 0x%lx num_cachelines %d\n",
		    offset, num_cachelines));

		wrsm_blkread(
		    seg,
		    dp,
		    num_cachelines);
		length -= (num_cachelines * WRSM_CACHELINE_SIZE);
		dp += (num_cachelines * WRSM_CACHELINE_SIZE);
		offset += (num_cachelines * WRSM_CACHELINE_SIZE);
	}

	/*
	 * handle partial line read at end of buffer
	 */
	if (length) {
		if ((err = small_get(iseginfo, offset, length, dp)) != 0) {
			rw_exit(&importseg->rw_lock);
			if (importseg->barrier_mode ==
			    RSM_BARRIER_MODE_IMPLICIT) {
				(void) wrsm_close_barrier(&barrier);
			}
			return (err);
		}
	}

	rw_exit(&importseg->rw_lock);

	if (importseg->barrier_mode == RSM_BARRIER_MODE_IMPLICIT) {
		err = wrsm_close_barrier(&barrier);
	}

	return (err);
}

/* ARGSUSED */
int
wrsmrsm_get8(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint8_t *datap, ulong_t rep_cnt, boolean_t byte_swap)
{
	/* Since Wildcat is SPARC-only, don't need to worry about byte_swap */
	return (wrsmrsm_get(im_memseg, offset, (void *)datap, rep_cnt));
}

/* ARGSUSED */
int
wrsmrsm_get16(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint16_t *datap, ulong_t rep_cnt, boolean_t byte_swap)
{
	/* Check alignment */
	if ((((uint64_t)datap) & 0x1) != 0 ||
	    (((uint64_t)offset) & 0x1) != 0) {
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	/* Since Wildcat is SPARC-only, don't need to worry about byte_swap */
	return (wrsmrsm_get(im_memseg, offset, (void *)datap, 2 * rep_cnt));
}

/* ARGSUSED */
int
wrsmrsm_get32(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint32_t *datap, ulong_t rep_cnt, boolean_t byte_swap)
{
	/* Check alignment */
	if ((((uint64_t)datap) & 0x3) != 0 ||
	    (((uint64_t)offset) & 0x3) != 0) {
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	/* Since Wildcat is SPARC-only, don't need to worry about byte_swap */
	return (wrsmrsm_get(im_memseg, offset, (void *)datap, 4 * rep_cnt));
}

/* ARGSUSED */
int
wrsmrsm_get64(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint64_t *datap, ulong_t rep_cnt, boolean_t byte_swap)
{
	/* Check alignment */
	if ((((uint64_t)datap) & 0x7) != 0 ||
	    (((uint64_t)offset) & 0x7) != 0) {
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	/* Since Wildcat is SPARC-only, don't need to worry about byte_swap */
	return (wrsmrsm_get(im_memseg, offset, (void *)datap, 8 * rep_cnt));
}

/*
 * Called from wrsm_ioctl() when invoked on a driver instance which
 * has a type of wrsm_rsm_controller and cmd = WRSM_CTLR_PLUGIN_SMALLPUT
 */
/* ARGSUSED */
int
wrsm_smallput_plugin_ioctl(int minor, int cmd, intptr_t arg, int mode,
    cred_t *cred_p, int *rval_p)
{
	wrsm_raw_message_t msgbuf;
	msg_pluginput_args_t pluginmsg;
	msg_pluginput_args32_t pluginmsg32;
	iseginfo_t *iseginfo;
	int err;
	int datamodel;

	wrsm_smallput_msg_t *msg = (wrsm_smallput_msg_t *)&msgbuf;

	DPRINTF(DBG_SMPUT, (CE_CONT, "wrsm_smallput_plugin_ioctl"));


	datamodel = ddi_model_convert_from(mode & FMODELS);
	switch (datamodel) {
	case DDI_MODEL_ILP32:
		if (ddi_copyin((void *)arg,  (char *)&pluginmsg32,
		    sizeof (msg_pluginput_args32_t), mode) != 0) {
			DPRINTF(DBG_SMPUT, (CE_WARN, "wrsm_smallput_plugin_"
			    "ioctl ddi_copyin failed 32 bit "));
			return (EFAULT);
		}
		DPRINTF(DBG_SMPUT, (CE_CONT, "wrsm_smallput_plugin_ioctl 32 "
		    "app. segid %d length %ld cnode %ld",
		    pluginmsg32.segment_id, pluginmsg32.len,
		    pluginmsg32.remote_cnodeid));

		pluginmsg.segment_id = pluginmsg32.segment_id;
		pluginmsg.len = pluginmsg32.len;
		pluginmsg.remote_cnodeid = pluginmsg32.remote_cnodeid;
		pluginmsg.offset = pluginmsg32.offset;

		if (ddi_copyin((void *)(uintptr_t)pluginmsg32.buf, msg->putdata,
		    pluginmsg32.len, mode)
		    != 0) {
			DPRINTF(DBG_SMPUT, (CE_WARN, "wrsm_smallput_plugin_"
			    "ioctl ddicopyin msg buffer failed "));
			return (EFAULT);
		}

		break;
	default:
		if (ddi_copyin((void *)arg,  (char *)&pluginmsg,
		    sizeof (msg_pluginput_args_t), mode) != 0) {
			DPRINTF(DBG_SMPUT, (CE_WARN, "wrsm_smallput_plugin_"
			    "ioctl ddi_copyin failed 64 bit "));
			return (EFAULT);
		}
		DPRINTF(DBG_SMPUT, (CE_CONT, "wrsm_smallput_plugin_ioctl 64 "
		    " bit app. segid %d length %ld cnode %ld",
		    pluginmsg.segment_id, pluginmsg.len,
		    pluginmsg.remote_cnodeid));

		if (ddi_copyin((void *)pluginmsg.buf, msg->putdata,
		    pluginmsg.len, mode)
		    != 0) {
			DPRINTF(DBG_SMPUT, (CE_WARN, "wrsm_smallput_plugin_"
			    "ioctl ddicopyin msg buffer failed "));
			return (EFAULT);
		}

		break;
	}


	/*
	 * Get iseginfo for this controller, cnodeid, and segment_id.
	 * iseginfo is returned locked.
	 */
	err = wrsm_memseg_remote_node_to_iseginfo(minor,
	    (cnodeid_t)pluginmsg.remote_cnodeid, pluginmsg.segment_id,
	    &iseginfo);

	if (err != RSM_SUCCESS) {
		return (err);
	}

	/*
	 * RSM Kernel Agent prevents iseginfo being removed (it holds
	 * an importseg on behalf of the caller), so it is not necessary
	 * to hold iseginfo->lock during the call to small_put().
	 */
	mutex_exit(&iseginfo->lock);

	err = small_put(iseginfo, pluginmsg.offset, pluginmsg.len,
	    (caddr_t)msg->putdata);
	if (err != RSM_SUCCESS) {
		return (EIO);
	}
	/* send 0 length, 0 buf to assure put finished */
	msg->header.offset = 0;
	msg->header.len = 0;
	msg->header.start = 0;
	(void) wrsm_intr_send(iseginfo->network,
	    iseginfo->kernel_mapping.small_put_offset, iseginfo->cnodeid,
	    msg, 0, WRSM_INTR_WAIT_DEFAULT, 0);

	return (0);
}
