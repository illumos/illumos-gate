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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Deimos - cryptographic acceleration based upon Broadcom 582x.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/crypto/dca.h>
#include <sys/atomic.h>

/*
 * Random number implementation.
 */

static int dca_rngstart(dca_t *, dca_request_t *);
static void dca_rngdone(dca_request_t *, int);

static void dca_random_done();
int dca_random_buffer(dca_t *dca, caddr_t buf, int len);
int dca_random_init();
void dca_random_fini();

int
dca_rng(dca_t *dca, uchar_t *buf, size_t len, crypto_req_handle_t req)
{
	dca_request_t	*reqp;
	int		rv;
	crypto_data_t	*data;

	if ((reqp = dca_getreq(dca, MCR2, 1)) == NULL) {
		dca_error(dca, "unable to allocate request for RNG");
		return (CRYPTO_HOST_MEMORY);
	}

	reqp->dr_kcf_req = req;

	data = &reqp->dr_ctx.in_dup;
	data->cd_format = CRYPTO_DATA_RAW;
	data->cd_offset = 0;
	data->cd_length = 0;
	data->cd_raw.iov_base = (char *)buf;
	data->cd_raw.iov_len = len;
	reqp->dr_out = data;
	reqp->dr_in = NULL;

	rv = dca_rngstart(dca, reqp);
	if (rv != CRYPTO_QUEUED) {
		if (reqp->destroy)
			dca_destroyreq(reqp);
		else
			dca_freereq(reqp);
	}
	return (rv);
}

int
dca_rngstart(dca_t *dca, dca_request_t *reqp)
{
	uint16_t	cmd;
	size_t		len;
	uint16_t	chunk;
	crypto_data_t	*out = reqp->dr_out;

	if (dca->dca_flags & DCA_RNGSHA1) {
		reqp->dr_job_stat = DS_RNGSHA1JOBS;
		reqp->dr_byte_stat = DS_RNGSHA1BYTES;
		cmd = CMD_RNGSHA1;
	} else {
		reqp->dr_job_stat = DS_RNGJOBS;
		reqp->dr_byte_stat = DS_RNGBYTES;
		cmd = CMD_RNGDIRECT;
	}

	len = out->cd_raw.iov_len - out->cd_length;
	len = min(len, MAXPACKET & ~0xf);
	chunk = ROUNDUP(len, sizeof (uint32_t));

	if ((len < dca_mindma) ||
	    dca_sgcheck(dca, reqp->dr_out, DCA_SG_WALIGN)) {
		reqp->dr_flags |= DR_SCATTER;
	}

	/* Try to do direct DMA. */
	if (!(reqp->dr_flags & DR_SCATTER)) {
		if (dca_bindchains(reqp, 0, len) != DDI_SUCCESS) {
			return (CRYPTO_DEVICE_ERROR);
		}
	}

	reqp->dr_in_paddr = 0;
	reqp->dr_in_next = 0;
	reqp->dr_in_len = 0;

	/*
	 * Setup for scattering the result back out
	 * Using the pre-mapped buffers to store random numbers. Since the
	 * data buffer is a linked list, we need to transfer its head to MCR
	 */
	if (reqp->dr_flags & DR_SCATTER) {
		reqp->dr_out_paddr = reqp->dr_obuf_head.dc_buffer_paddr;
		reqp->dr_out_next = reqp->dr_obuf_head.dc_next_paddr;
		if (chunk > reqp->dr_obuf_head.dc_buffer_length)
			reqp->dr_out_len = reqp->dr_obuf_head.dc_buffer_length;
		else
			reqp->dr_out_len = chunk;
	}
	reqp->dr_param.dp_rng.dr_chunklen = len;
	reqp->dr_pkt_length = (uint16_t)chunk;
	reqp->dr_callback = dca_rngdone;

	/* write out the context structure */
	PUTCTX16(reqp, CTX_LENGTH, CTX_RNG_LENGTH);
	PUTCTX16(reqp, CTX_CMD, cmd);

	/* schedule the work by doing a submit */
	return (dca_start(dca, reqp, MCR2, 1));
}

void
dca_rngdone(dca_request_t *reqp, int errno)
{
	if (errno == CRYPTO_SUCCESS) {

		if (reqp->dr_flags & DR_SCATTER) {
			(void) ddi_dma_sync(reqp->dr_obuf_dmah, 0,
				reqp->dr_out_len, DDI_DMA_SYNC_FORKERNEL);
			if (dca_check_dma_handle(reqp->dr_dca,
			    reqp->dr_obuf_dmah, DCA_FM_ECLASS_NONE) !=
			    DDI_SUCCESS) {
				reqp->destroy = TRUE;
				errno = CRYPTO_DEVICE_ERROR;
				goto errout;
			}
			errno = dca_scatter(reqp->dr_obuf_kaddr,
			    reqp->dr_out, reqp->dr_param.dp_rng.dr_chunklen, 0);
			if (errno != CRYPTO_SUCCESS) {
				goto errout;
			}
		} else {
			reqp->dr_out->cd_length +=
			    reqp->dr_param.dp_rng.dr_chunklen;
		}

		/*
		 * If there is more to do, then reschedule another
		 * pass.
		 */
		if (reqp->dr_out->cd_length < reqp->dr_out->cd_raw.iov_len) {
			errno = dca_rngstart(reqp->dr_dca, reqp);
			if (errno == CRYPTO_QUEUED) {
				return;
			}
		}
	}

errout:

	if (reqp->dr_kcf_req) {
		/* notify framework that request is completed */
		crypto_op_notification(reqp->dr_kcf_req, errno);
	} else {
		/* For internal random number generation */
		dca_random_done(reqp->dr_dca);
	}

	DBG(NULL, DINTR,
	    "dca_rngdone: returning %d to the kef via crypto_op_notification",
	    errno);
	if (reqp->destroy)
		dca_destroyreq(reqp);
	else
		dca_freereq(reqp);
}

/*
 * This gives a 32k random bytes per buffer. The two buffers will switch back
 * and forth. When a buffer is used up, a request will be submitted to refill
 * this buffer before switching to the other one
 */

#define	RANDOM_BUFFER_SIZE		(1<<15)
#define	DCA_RANDOM_MAX_WAIT		10000

int
dca_random_init(dca_t *dca)
{
	/* Mutex for the local random number pool */
	mutex_init(&dca->dca_random_lock, NULL, MUTEX_DRIVER, NULL);

	if ((dca->dca_buf1 = kmem_alloc(RANDOM_BUFFER_SIZE, KM_SLEEP)) ==
	    NULL) {
		mutex_destroy(&dca->dca_random_lock);
		return (CRYPTO_FAILED);
	}

	if ((dca->dca_buf2 = kmem_alloc(RANDOM_BUFFER_SIZE, KM_SLEEP)) ==
	    NULL) {
		mutex_destroy(&dca->dca_random_lock);
		kmem_free(dca->dca_buf1, RANDOM_BUFFER_SIZE);
		return (CRYPTO_FAILED);
	}

	return (CRYPTO_SUCCESS);
}

void
dca_random_fini(dca_t *dca)
{
	kmem_free(dca->dca_buf1, RANDOM_BUFFER_SIZE);
	kmem_free(dca->dca_buf2, RANDOM_BUFFER_SIZE);
	dca->dca_buf1 = dca->dca_buf2 = dca->dca_buf_ptr = NULL;
	(void) mutex_destroy(&dca->dca_random_lock);
}

int
dca_random_buffer(dca_t *dca, caddr_t buf, int len)
{
	int rv;
	int i, j;
	char *fill_buf;

	mutex_enter(&dca->dca_random_lock);

	if (dca->dca_buf_ptr == NULL) {
		if (dca->dca_buf1 == NULL || dca->dca_buf2 == NULL) {
			mutex_exit(&dca->dca_random_lock);
			return (CRYPTO_FAILED);
		}

		/* Very first time. Let us fill the first buffer */
		if (dca_rng(dca, (uchar_t *)dca->dca_buf1, RANDOM_BUFFER_SIZE,
		    NULL) != CRYPTO_QUEUED) {
			mutex_exit(&dca->dca_random_lock);
			return (CRYPTO_FAILED);
		}

		atomic_or_32(&dca->dca_random_filling, 0x1);

		/* Pretend we are using buffer2 and it is empty */
		dca->dca_buf_ptr = dca->dca_buf2;
		dca->dca_index = RANDOM_BUFFER_SIZE;
	}

	i = 0;
	while (i < len) {
		if (dca->dca_index >= RANDOM_BUFFER_SIZE) {
			j = 0;
			while (dca->dca_random_filling) {
				/* Only wait here at the first time */
				delay(drv_usectohz(100));
				if (j++ >= DCA_RANDOM_MAX_WAIT)
					break;
			}
			DBG(NULL, DENTRY, "dca_random_buffer: j: %d", j);
			if (j > DCA_RANDOM_MAX_WAIT) {
				mutex_exit(&dca->dca_random_lock);
				return (CRYPTO_FAILED);
			}

			/* switch to the other buffer */
			if (dca->dca_buf_ptr == dca->dca_buf1) {
				dca->dca_buf_ptr = dca->dca_buf2;
				fill_buf = dca->dca_buf1;
			} else {
				dca->dca_buf_ptr = dca->dca_buf1;
				fill_buf = dca->dca_buf2;
			}

			atomic_or_32(&dca->dca_random_filling, 0x1);
			dca->dca_index = 0;

			if ((rv = dca_rng(dca, (uchar_t *)fill_buf,
			    RANDOM_BUFFER_SIZE, NULL)) != CRYPTO_QUEUED) {
				mutex_exit(&dca->dca_random_lock);
				return (rv);
			}
		}

		if (dca->dca_buf_ptr[dca->dca_index] != '\0')
			buf[i++] = dca->dca_buf_ptr[dca->dca_index];

		dca->dca_index++;
	}

	mutex_exit(&dca->dca_random_lock);

	DBG(NULL, DENTRY, "dca_random_buffer: i: %d", i);
	return (CRYPTO_SUCCESS);
}

static void
dca_random_done(dca_t *dca)
{
	DBG(NULL, DENTRY, "dca_random_done");
	atomic_and_32(&dca->dca_random_filling, 0x0);
}
