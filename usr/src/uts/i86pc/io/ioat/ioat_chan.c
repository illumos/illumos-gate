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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/modctl.h>
#include <sys/ddi_impldefs.h>
#include <sys/sysmacros.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <sys/mach_mmu.h>
#ifdef __xpv
#include <sys/hypervisor.h>
#endif

#include <sys/ioat.h>


extern ddi_device_acc_attr_t ioat_acc_attr;

/* dma attr for the descriptor rings */
ddi_dma_attr_t ioat_desc_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0x0,			/* dma_attr_addr_lo */
	0xffffffffffffffff,	/* dma_attr_addr_hi */
	0xffffffff,		/* dma_attr_count_max */
	0x1000,			/* dma_attr_align */
	0x1,			/* dma_attr_burstsizes */
	0x1,			/* dma_attr_minxfer */
	0xffffffff,		/* dma_attr_maxxfer */
	0xffffffff,		/* dma_attr_seg */
	0x1,			/* dma_attr_sgllen */
	0x1,			/* dma_attr_granular */
	0x0,			/* dma_attr_flags */
};

/* dma attr for the completion buffers */
ddi_dma_attr_t ioat_cmpl_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0x0,			/* dma_attr_addr_lo */
	0xffffffffffffffff,	/* dma_attr_addr_hi */
	0xffffffff,		/* dma_attr_count_max */
	0x40,			/* dma_attr_align */
	0x1,			/* dma_attr_burstsizes */
	0x1,			/* dma_attr_minxfer */
	0xffffffff,		/* dma_attr_maxxfer */
	0xffffffff,		/* dma_attr_seg */
	0x1,			/* dma_attr_sgllen */
	0x1,			/* dma_attr_granular */
	0x0,			/* dma_attr_flags */
};

static int ioat_completion_alloc(ioat_channel_t channel);
static void ioat_completion_free(ioat_channel_t channel);
static void ioat_channel_start(ioat_channel_t channel);
static void ioat_channel_reset(ioat_channel_t channel);

int ioat_ring_alloc(ioat_channel_t channel, uint_t desc_cnt);
void ioat_ring_free(ioat_channel_t channel);
void ioat_ring_seed(ioat_channel_t channel, ioat_chan_dma_desc_t *desc);
int ioat_ring_reserve(ioat_channel_t channel, ioat_channel_ring_t *ring,
    dcopy_cmd_t cmd);

static void ioat_cmd_post_copy(ioat_channel_ring_t *ring, uint64_t src_addr,
    uint64_t dest_addr, uint32_t size, uint32_t ctrl);
static void ioat_cmd_post_dca(ioat_channel_ring_t *ring, uint32_t dca_id);


/*
 * ioat_channel_init()
 */
int
ioat_channel_init(ioat_state_t *state)
{
	int i;

	/*
	 * initialize each dma channel's state which doesn't change across
	 * channel alloc/free.
	 */
	state->is_chansize = sizeof (struct ioat_channel_s) *
	    state->is_num_channels;
	state->is_channel = kmem_zalloc(state->is_chansize, KM_SLEEP);
	for (i = 0; i < state->is_num_channels; i++) {
		state->is_channel[i].ic_state = state;
		state->is_channel[i].ic_regs = (uint8_t *)
		    ((uintptr_t)state->is_genregs +
		    (uintptr_t)(IOAT_CHANNELREG_OFFSET * (i + 1)));
	}

	/* initial the allocator (from 0 to state->is_num_channels) */
	ioat_rs_init(state, 0, state->is_num_channels, &state->is_channel_rs);

	return (DDI_SUCCESS);
}


/*
 * ioat_channel_fini()
 */
void
ioat_channel_fini(ioat_state_t *state)
{
	ioat_rs_fini(&state->is_channel_rs);
	kmem_free(state->is_channel, state->is_chansize);
}


/*
 * ioat_channel_alloc()
 *   NOTE: We intentionaly don't handle DCOPY_SLEEP (if no channels are
 *	available)
 */
/*ARGSUSED*/
int
ioat_channel_alloc(void *device_private, dcopy_handle_t handle, int flags,
    uint_t size, dcopy_query_channel_t *info, void *channel_private)
{
#define	CHANSTRSIZE	20
	struct ioat_channel_s *channel;
	char chanstr[CHANSTRSIZE];
	ioat_channel_t *chan;
	ioat_state_t *state;
	size_t cmd_size;
	uint_t chan_num;
	uint32_t estat;
	int e;


	state = (ioat_state_t *)device_private;
	chan = (ioat_channel_t *)channel_private;

	/* allocate a H/W channel */
	e = ioat_rs_alloc(state->is_channel_rs, &chan_num);
	if (e != DDI_SUCCESS) {
		return (DCOPY_NORESOURCES);
	}

	channel = &state->is_channel[chan_num];
	channel->ic_inuse = B_TRUE;
	channel->ic_chan_num = chan_num;
	channel->ic_ver = state->is_ver;
	channel->ic_dca_active = B_FALSE;
	channel->ic_channel_state = IOAT_CHANNEL_OK;
	channel->ic_dcopy_handle = handle;

#ifdef	DEBUG
	{
		/* if we're cbv2, verify that the V2 compatibility bit is set */
		uint16_t reg;
		if (channel->ic_ver == IOAT_CBv2) {
			reg = ddi_get16(state->is_reg_handle,
			    (uint16_t *)&channel->ic_regs[IOAT_CHAN_COMP]);
			ASSERT(reg & 0x2);
		}
	}
#endif

	/*
	 * Configure DMA channel
	 *   Channel In Use
	 *   Error Interrupt Enable
	 *   Any Error Abort Enable
	 *   Error Completion Enable
	 */
	ddi_put16(state->is_reg_handle,
	    (uint16_t *)&channel->ic_regs[IOAT_CHAN_CTL], 0x011C);

	/* check channel error register, clear any errors */
	estat = ddi_get32(state->is_reg_handle,
	    (uint32_t *)&channel->ic_regs[IOAT_CHAN_ERR]);
	if (estat != 0) {
#ifdef	DEBUG
		cmn_err(CE_CONT, "cleared errors (0x%x) before channel (%d) "
		    "enable\n", estat, channel->ic_chan_num);
#endif
		ddi_put32(state->is_reg_handle,
		    (uint32_t *)&channel->ic_regs[IOAT_CHAN_ERR], estat);
	}

	/* allocate and initialize the descriptor buf */
	e = ioat_ring_alloc(channel, size);
	if (e != DDI_SUCCESS) {
		goto chinitfail_desc_alloc;
	}

	/* allocate and initialize the completion space */
	e = ioat_completion_alloc(channel);
	if (e != DDI_SUCCESS) {
		goto chinitfail_completion_alloc;
	}

	/* setup kmem_cache for commands */
	cmd_size = sizeof (struct dcopy_cmd_s) +
	    sizeof (struct dcopy_cmd_priv_s) +
	    sizeof (struct ioat_cmd_private_s);
	(void) snprintf(chanstr, CHANSTRSIZE, "ioat%dchan%dcmd",
	    state->is_instance, channel->ic_chan_num);
	channel->ic_cmd_cache = kmem_cache_create(chanstr, cmd_size, 64,
	    NULL, NULL, NULL, NULL, NULL, 0);
	if (channel->ic_cmd_cache == NULL) {
		goto chinitfail_kmem_cache;
	}

	/* start-up the channel */
	ioat_channel_start(channel);

	/* fill in the channel info returned to dcopy */
	info->qc_version = DCOPY_QUERY_CHANNEL_V0;
	info->qc_id = state->is_deviceinfo.di_id;
	info->qc_capabilities = (uint64_t)state->is_capabilities;
	info->qc_channel_size = (uint64_t)size;
	info->qc_chan_num = (uint64_t)channel->ic_chan_num;
	if (channel->ic_ver == IOAT_CBv1) {
		info->qc_dca_supported = B_FALSE;
	} else {
		if (info->qc_capabilities & IOAT_DMACAP_DCA) {
			info->qc_dca_supported = B_TRUE;
		} else {
			info->qc_dca_supported = B_FALSE;
		}
	}

	*chan = channel;

	return (DCOPY_SUCCESS);

chinitfail_kmem_cache:
	ioat_completion_free(channel);
chinitfail_completion_alloc:
	ioat_ring_free(channel);
chinitfail_desc_alloc:
	return (DCOPY_FAILURE);
}


/*
 * ioat_channel_suspend()
 */
/*ARGSUSED*/
void
ioat_channel_suspend(ioat_state_t *state)
{
	/*
	 * normally you would disable interrupts and reset the H/W here. But
	 * since the suspend framework doesn't know who is using us, it may
	 * not suspend their I/O before us.  Since we won't actively be doing
	 * any DMA or interrupts unless someone asks us to, it's safe to not
	 * do anything here.
	 */
}


/*
 * ioat_channel_resume()
 */
int
ioat_channel_resume(ioat_state_t *state)
{
	ioat_channel_ring_t *ring;
	ioat_channel_t channel;
	uint32_t estat;
	int i;


	for (i = 0; i < state->is_num_channels; i++) {
		channel = &state->is_channel[i];
		ring = channel->ic_ring;

		if (!channel->ic_inuse) {
			continue;
		}

		/*
		 * Configure DMA channel
		 *   Channel In Use
		 *   Error Interrupt Enable
		 *   Any Error Abort Enable
		 *   Error Completion Enable
		 */
		ddi_put16(state->is_reg_handle,
		    (uint16_t *)&channel->ic_regs[IOAT_CHAN_CTL], 0x011C);

		/* check channel error register, clear any errors */
		estat = ddi_get32(state->is_reg_handle,
		    (uint32_t *)&channel->ic_regs[IOAT_CHAN_ERR]);
		if (estat != 0) {
#ifdef	DEBUG
			cmn_err(CE_CONT, "cleared errors (0x%x) before channel"
			    " (%d) enable\n", estat, channel->ic_chan_num);
#endif
			ddi_put32(state->is_reg_handle,
			    (uint32_t *)&channel->ic_regs[IOAT_CHAN_ERR],
			    estat);
		}

		/* Re-initialize the ring */
		bzero(ring->cr_desc, channel->ic_desc_alloc_size);
		/* write the physical address into the chain address register */
		if (channel->ic_ver == IOAT_CBv1) {
			ddi_put32(state->is_reg_handle,
			    (uint32_t *)&channel->ic_regs[IOAT_V1_CHAN_ADDR_LO],
			    (uint32_t)(ring->cr_phys_desc & 0xffffffff));
			ddi_put32(state->is_reg_handle,
			    (uint32_t *)&channel->ic_regs[IOAT_V1_CHAN_ADDR_HI],
			    (uint32_t)(ring->cr_phys_desc >> 32));
		} else {
			ASSERT(channel->ic_ver == IOAT_CBv2);
			ddi_put32(state->is_reg_handle,
			    (uint32_t *)&channel->ic_regs[IOAT_V2_CHAN_ADDR_LO],
			    (uint32_t)(ring->cr_phys_desc & 0xffffffff));
			ddi_put32(state->is_reg_handle,
			    (uint32_t *)&channel->ic_regs[IOAT_V2_CHAN_ADDR_HI],
			    (uint32_t)(ring->cr_phys_desc >> 32));
		}

		/* re-initialize the completion buffer */
		bzero((void *)channel->ic_cmpl, channel->ic_cmpl_alloc_size);
		/* write the phys addr into the completion address register */
		ddi_put32(state->is_reg_handle,
		    (uint32_t *)&channel->ic_regs[IOAT_CHAN_CMPL_LO],
		    (uint32_t)(channel->ic_phys_cmpl & 0xffffffff));
		ddi_put32(state->is_reg_handle,
		    (uint32_t *)&channel->ic_regs[IOAT_CHAN_CMPL_HI],
		    (uint32_t)(channel->ic_phys_cmpl >> 32));

		/* start-up the channel */
		ioat_channel_start(channel);

	}

	return (DDI_SUCCESS);
}

/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
void
ioat_channel_quiesce(ioat_state_t *state)
{
	int i;

	/*
	 * Walk through all channels and quiesce
	 */
	for (i = 0; i < state->is_num_channels; i++) {

		ioat_channel_t	channel = state->is_channel + i;

		if (!channel->ic_inuse)
			continue;

		/* disable the interrupts */
		ddi_put16(state->is_reg_handle,
		    (uint16_t *)&channel->ic_regs[IOAT_CHAN_CTL],
		    0x0);

		ioat_channel_reset(channel);
	}
}


/*
 * ioat_channel_free()
 */
void
ioat_channel_free(void *channel_private)
{
	struct ioat_channel_s *channel;
	ioat_channel_t *chan;
	ioat_state_t *state;
	uint_t chan_num;


	chan = (ioat_channel_t *)channel_private;
	channel = *chan;

	state = channel->ic_state;
	chan_num = channel->ic_chan_num;

	/* disable the interrupts */
	ddi_put16(state->is_reg_handle,
	    (uint16_t *)&channel->ic_regs[IOAT_CHAN_CTL], 0x0);

	ioat_channel_reset(channel);

	/* cleanup command cache */
	kmem_cache_destroy(channel->ic_cmd_cache);

	/* clean-up/free-up the completion space and descriptors */
	ioat_completion_free(channel);
	ioat_ring_free(channel);

	channel->ic_inuse = B_FALSE;

	/* free the H/W DMA engine */
	ioat_rs_free(state->is_channel_rs, chan_num);

	*chan = NULL;
}


/*
 * ioat_channel_intr()
 */
void
ioat_channel_intr(ioat_channel_t channel)
{
	ioat_state_t *state;
	uint16_t chanctrl;
	uint32_t chanerr;
	uint32_t status;


	state = channel->ic_state;

	if (channel->ic_ver == IOAT_CBv1) {
		status = ddi_get32(state->is_reg_handle,
		    (uint32_t *)&channel->ic_regs[IOAT_V1_CHAN_STS_LO]);
	} else {
		ASSERT(channel->ic_ver == IOAT_CBv2);
		status = ddi_get32(state->is_reg_handle,
		    (uint32_t *)&channel->ic_regs[IOAT_V2_CHAN_STS_LO]);
	}

	/* if that status isn't ACTIVE or IDLE, the channel has failed */
	if (status & IOAT_CHAN_STS_FAIL_MASK) {
		chanerr = ddi_get32(state->is_reg_handle,
		    (uint32_t *)&channel->ic_regs[IOAT_CHAN_ERR]);
		cmn_err(CE_WARN, "channel(%d) fatal failure! "
		    "chanstat_lo=0x%X; chanerr=0x%X\n",
		    channel->ic_chan_num, status, chanerr);
		channel->ic_channel_state = IOAT_CHANNEL_IN_FAILURE;
		ioat_channel_reset(channel);

		return;
	}

	/*
	 * clear interrupt disable bit if set (it's a RW1C). Read it back to
	 * ensure the write completes.
	 */
	chanctrl = ddi_get16(state->is_reg_handle,
	    (uint16_t *)&channel->ic_regs[IOAT_CHAN_CTL]);
	ddi_put16(state->is_reg_handle,
	    (uint16_t *)&channel->ic_regs[IOAT_CHAN_CTL], chanctrl);
	(void) ddi_get16(state->is_reg_handle,
	    (uint16_t *)&channel->ic_regs[IOAT_CHAN_CTL]);

	/* tell dcopy we have seen a completion on this channel */
	dcopy_device_channel_notify(channel->ic_dcopy_handle, DCOPY_COMPLETION);
}


/*
 * ioat_channel_start()
 */
void
ioat_channel_start(ioat_channel_t channel)
{
	ioat_chan_dma_desc_t desc;

	/* set the first descriptor up as a NULL descriptor */
	bzero(&desc, sizeof (desc));
	desc.dd_size = 0;
	desc.dd_ctrl = IOAT_DESC_CTRL_OP_DMA | IOAT_DESC_DMACTRL_NULL |
	    IOAT_DESC_CTRL_CMPL;
	desc.dd_next_desc = 0x0;

	/* setup the very first descriptor */
	ioat_ring_seed(channel, &desc);
}


/*
 * ioat_channel_reset()
 */
void
ioat_channel_reset(ioat_channel_t channel)
{
	ioat_state_t *state;

	state = channel->ic_state;

	/* hit the reset bit */
	if (channel->ic_ver == IOAT_CBv1) {
		ddi_put8(state->is_reg_handle,
		    &channel->ic_regs[IOAT_V1_CHAN_CMD], 0x20);
	} else {
		ASSERT(channel->ic_ver == IOAT_CBv2);
		ddi_put8(state->is_reg_handle,
		    &channel->ic_regs[IOAT_V2_CHAN_CMD], 0x20);
	}
}


/*
 * ioat_completion_alloc()
 */
int
ioat_completion_alloc(ioat_channel_t channel)
{
	ioat_state_t *state;
	size_t real_length;
	uint_t cookie_cnt;
	int e;


	state = channel->ic_state;

	/*
	 * allocate memory for the completion status, zero it out, and get
	 * the paddr. We'll allocate a physically contiguous cache line.
	 */
	e = ddi_dma_alloc_handle(state->is_dip, &ioat_cmpl_dma_attr,
	    DDI_DMA_SLEEP, NULL, &channel->ic_cmpl_dma_handle);
	if (e != DDI_SUCCESS) {
		goto cmplallocfail_alloc_handle;
	}
	channel->ic_cmpl_alloc_size = 64;
	e = ddi_dma_mem_alloc(channel->ic_cmpl_dma_handle,
	    channel->ic_cmpl_alloc_size, &ioat_acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    (caddr_t *)&channel->ic_cmpl, &real_length,
	    &channel->ic_cmpl_handle);
	if (e != DDI_SUCCESS) {
		goto cmplallocfail_mem_alloc;
	}
	bzero((void *)channel->ic_cmpl, channel->ic_cmpl_alloc_size);
	e = ddi_dma_addr_bind_handle(channel->ic_cmpl_dma_handle, NULL,
	    (caddr_t)channel->ic_cmpl, channel->ic_cmpl_alloc_size,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &channel->ic_cmpl_cookie, &cookie_cnt);
	if (e != DDI_SUCCESS) {
		goto cmplallocfail_addr_bind;
	}
	ASSERT(cookie_cnt == 1);
	ASSERT(channel->ic_cmpl_cookie.dmac_size ==
	    channel->ic_cmpl_alloc_size);
	channel->ic_phys_cmpl = channel->ic_cmpl_cookie.dmac_laddress;

	/* write the physical address into the completion address register */
	ddi_put32(state->is_reg_handle,
	    (uint32_t *)&channel->ic_regs[IOAT_CHAN_CMPL_LO],
	    (uint32_t)(channel->ic_phys_cmpl & 0xffffffff));
	ddi_put32(state->is_reg_handle,
	    (uint32_t *)&channel->ic_regs[IOAT_CHAN_CMPL_HI],
	    (uint32_t)(channel->ic_phys_cmpl >> 32));

	return (DDI_SUCCESS);

cmplallocfail_addr_bind:
	ddi_dma_mem_free(&channel->ic_desc_handle);
cmplallocfail_mem_alloc:
	ddi_dma_free_handle(&channel->ic_desc_dma_handle);
cmplallocfail_alloc_handle:
	return (DDI_FAILURE);
}


/*
 * ioat_completion_free()
 */
void
ioat_completion_free(ioat_channel_t channel)
{
	ioat_state_t *state;

	state = channel->ic_state;

	/* reset the completion address register */
	ddi_put32(state->is_reg_handle,
	    (uint32_t *)&channel->ic_regs[IOAT_CHAN_CMPL_LO], 0x0);
	ddi_put32(state->is_reg_handle,
	    (uint32_t *)&channel->ic_regs[IOAT_CHAN_CMPL_HI], 0x0);

	/* unbind, then free up the memory, dma handle */
	(void) ddi_dma_unbind_handle(channel->ic_cmpl_dma_handle);
	ddi_dma_mem_free(&channel->ic_cmpl_handle);
	ddi_dma_free_handle(&channel->ic_cmpl_dma_handle);
}

/*
 * ioat_ring_alloc()
 */
int
ioat_ring_alloc(ioat_channel_t channel, uint_t desc_cnt)
{
	ioat_channel_ring_t *ring;
	ioat_state_t *state;
	size_t real_length;
	uint_t cookie_cnt;
	int e;


	state = channel->ic_state;

	ring = kmem_zalloc(sizeof (ioat_channel_ring_t), KM_SLEEP);
	channel->ic_ring = ring;
	ring->cr_chan = channel;
	ring->cr_post_cnt = 0;

	mutex_init(&ring->cr_cmpl_mutex, NULL, MUTEX_DRIVER,
	    channel->ic_state->is_iblock_cookie);
	mutex_init(&ring->cr_desc_mutex, NULL, MUTEX_DRIVER,
	    channel->ic_state->is_iblock_cookie);

	/*
	 * allocate memory for the ring, zero it out, and get the paddr.
	 * We'll allocate a physically contiguous chunck of memory  which
	 * simplifies the completion logic.
	 */
	e = ddi_dma_alloc_handle(state->is_dip, &ioat_desc_dma_attr,
	    DDI_DMA_SLEEP, NULL, &channel->ic_desc_dma_handle);
	if (e != DDI_SUCCESS) {
		goto ringallocfail_alloc_handle;
	}
	/*
	 * allocate one extra descriptor so we can simplify the empty/full
	 * logic. Then round that number up to a whole multiple of 4.
	 */
	channel->ic_chan_desc_cnt = ((desc_cnt + 1) + 3) & ~0x3;
	ring->cr_desc_last = channel->ic_chan_desc_cnt - 1;
	channel->ic_desc_alloc_size = channel->ic_chan_desc_cnt *
	    sizeof (ioat_chan_desc_t);
	e = ddi_dma_mem_alloc(channel->ic_desc_dma_handle,
	    channel->ic_desc_alloc_size, &ioat_acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    (caddr_t *)&ring->cr_desc, &real_length, &channel->ic_desc_handle);
	if (e != DDI_SUCCESS) {
		goto ringallocfail_mem_alloc;
	}
	bzero(ring->cr_desc, channel->ic_desc_alloc_size);
	e = ddi_dma_addr_bind_handle(channel->ic_desc_dma_handle, NULL,
	    (caddr_t)ring->cr_desc, channel->ic_desc_alloc_size,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &channel->ic_desc_cookies, &cookie_cnt);
	if (e != DDI_SUCCESS) {
		goto ringallocfail_addr_bind;
	}
	ASSERT(cookie_cnt == 1);
	ASSERT(channel->ic_desc_cookies.dmac_size ==
	    channel->ic_desc_alloc_size);
	ring->cr_phys_desc = channel->ic_desc_cookies.dmac_laddress;

	/* write the physical address into the chain address register */
	if (channel->ic_ver == IOAT_CBv1) {
		ddi_put32(state->is_reg_handle,
		    (uint32_t *)&channel->ic_regs[IOAT_V1_CHAN_ADDR_LO],
		    (uint32_t)(ring->cr_phys_desc & 0xffffffff));
		ddi_put32(state->is_reg_handle,
		    (uint32_t *)&channel->ic_regs[IOAT_V1_CHAN_ADDR_HI],
		    (uint32_t)(ring->cr_phys_desc >> 32));
	} else {
		ASSERT(channel->ic_ver == IOAT_CBv2);
		ddi_put32(state->is_reg_handle,
		    (uint32_t *)&channel->ic_regs[IOAT_V2_CHAN_ADDR_LO],
		    (uint32_t)(ring->cr_phys_desc & 0xffffffff));
		ddi_put32(state->is_reg_handle,
		    (uint32_t *)&channel->ic_regs[IOAT_V2_CHAN_ADDR_HI],
		    (uint32_t)(ring->cr_phys_desc >> 32));
	}

	return (DCOPY_SUCCESS);

ringallocfail_addr_bind:
	ddi_dma_mem_free(&channel->ic_desc_handle);
ringallocfail_mem_alloc:
	ddi_dma_free_handle(&channel->ic_desc_dma_handle);
ringallocfail_alloc_handle:
	mutex_destroy(&ring->cr_desc_mutex);
	mutex_destroy(&ring->cr_cmpl_mutex);
	kmem_free(channel->ic_ring, sizeof (ioat_channel_ring_t));

	return (DCOPY_FAILURE);
}


/*
 * ioat_ring_free()
 */
void
ioat_ring_free(ioat_channel_t channel)
{
	ioat_state_t *state;


	state = channel->ic_state;

	/* reset the chain address register */
	if (channel->ic_ver == IOAT_CBv1) {
		ddi_put32(state->is_reg_handle,
		    (uint32_t *)&channel->ic_regs[IOAT_V1_CHAN_ADDR_LO], 0x0);
		ddi_put32(state->is_reg_handle,
		    (uint32_t *)&channel->ic_regs[IOAT_V1_CHAN_ADDR_HI], 0x0);
	} else {
		ASSERT(channel->ic_ver == IOAT_CBv2);
		ddi_put32(state->is_reg_handle,
		    (uint32_t *)&channel->ic_regs[IOAT_V2_CHAN_ADDR_LO], 0x0);
		ddi_put32(state->is_reg_handle,
		    (uint32_t *)&channel->ic_regs[IOAT_V2_CHAN_ADDR_HI], 0x0);
	}

	/* unbind, then free up the memory, dma handle */
	(void) ddi_dma_unbind_handle(channel->ic_desc_dma_handle);
	ddi_dma_mem_free(&channel->ic_desc_handle);
	ddi_dma_free_handle(&channel->ic_desc_dma_handle);

	mutex_destroy(&channel->ic_ring->cr_desc_mutex);
	mutex_destroy(&channel->ic_ring->cr_cmpl_mutex);
	kmem_free(channel->ic_ring, sizeof (ioat_channel_ring_t));

}


/*
 * ioat_ring_seed()
 *    write the first descriptor in the ring.
 */
void
ioat_ring_seed(ioat_channel_t channel, ioat_chan_dma_desc_t *in_desc)
{
	ioat_channel_ring_t *ring;
	ioat_chan_dma_desc_t *desc;
	ioat_chan_dma_desc_t *prev;
	ioat_state_t *state;


	state = channel->ic_state;
	ring = channel->ic_ring;

	/* init the completion state */
	ring->cr_cmpl_gen = 0x0;
	ring->cr_cmpl_last = 0x0;

	/* write in the descriptor and init the descriptor state */
	ring->cr_post_cnt++;
	channel->ic_ring->cr_desc[0] = *(ioat_chan_desc_t *)in_desc;
	ring->cr_desc_gen = 0;
	ring->cr_desc_prev = 0;
	ring->cr_desc_next = 1;

	if (channel->ic_ver == IOAT_CBv1) {
		/* hit the start bit */
		ddi_put8(state->is_reg_handle,
		    &channel->ic_regs[IOAT_V1_CHAN_CMD], 0x1);
	} else {
		/*
		 * if this is CBv2, link the descriptor to an empty
		 * descriptor
		 */
		ASSERT(ring->cr_chan->ic_ver == IOAT_CBv2);
		desc = (ioat_chan_dma_desc_t *)
		    &ring->cr_desc[ring->cr_desc_next];
		prev = (ioat_chan_dma_desc_t *)
		    &ring->cr_desc[ring->cr_desc_prev];

		desc->dd_ctrl = 0;
		desc->dd_next_desc = 0x0;

		prev->dd_next_desc = ring->cr_phys_desc +
		    (ring->cr_desc_next << 6);

		ddi_put16(state->is_reg_handle,
		    (uint16_t *)&channel->ic_regs[IOAT_V2_CHAN_CNT],
		    (uint16_t)1);
	}

}

/*
 * ioat_ring_loop()
 * Make the ring loop for CB v1
 * This function assume we are in the ring->cr_desc_mutex mutex context
 */
int
ioat_ring_loop(ioat_channel_ring_t *ring, dcopy_cmd_t cmd)
{
	uint64_t count;
	ioat_channel_t channel;
	ioat_chan_dma_desc_t *curr;
	ioat_cmd_private_t *prevpriv;
	ioat_cmd_private_t *currpriv;

	currpriv = NULL;
	channel = ring->cr_chan;
	ASSERT(channel->ic_ver == IOAT_CBv1);

	/*
	 * For each cmd in the command queue, check whether they are continuous
	 * in descriptor ring. Return error if not continuous.
	 */
	for (count = 0, prevpriv = NULL;
	    cmd != NULL && count <= channel->ic_chan_desc_cnt;
	    prevpriv = currpriv) {
		currpriv = cmd->dp_private->pr_device_cmd_private;
		if (prevpriv != NULL &&
		    currpriv->ip_index + 1 != prevpriv->ip_start &&
		    currpriv->ip_index + 1 != prevpriv->ip_start +
		    channel->ic_chan_desc_cnt) {
			/* Non-continuous, other commands get interleaved */
			return (DCOPY_FAILURE);
		}
		if (currpriv->ip_index < currpriv->ip_start) {
			count += channel->ic_chan_desc_cnt
			    + currpriv->ip_index - currpriv->ip_start + 1;
		} else {
			count += currpriv->ip_index - currpriv->ip_start + 1;
		}
		cmd = currpriv->ip_next;
	}
	/*
	 * Check for too many descriptors which would cause wrap around in
	 * descriptor ring. And make sure there is space for cancel operation.
	 */
	if (count >= channel->ic_chan_desc_cnt) {
		return (DCOPY_FAILURE);
	}

	/* Point next descriptor to header of chain. */
	curr = (ioat_chan_dma_desc_t *)&ring->cr_desc[ring->cr_desc_prev];
	curr->dd_next_desc = ring->cr_phys_desc + (currpriv->ip_start << 6);

	/* sync the last desc */
	(void) ddi_dma_sync(channel->ic_desc_dma_handle,
	    ring->cr_desc_prev << 6, 64, DDI_DMA_SYNC_FORDEV);

	return (DCOPY_SUCCESS);
}


/*
 * ioat_cmd_alloc()
 */
int
ioat_cmd_alloc(void *private, int flags, dcopy_cmd_t *cmd)
{
	ioat_cmd_private_t *priv;
	ioat_channel_t channel;
	dcopy_cmd_t oldcmd;
	int kmflag;


	channel = (ioat_channel_t)private;

	if (flags & DCOPY_NOSLEEP) {
		kmflag = KM_NOSLEEP;
	} else {
		kmflag = KM_SLEEP;
	}

	/* save the command passed incase DCOPY_ALLOC_LINK is set */
	oldcmd = *cmd;

	*cmd = kmem_cache_alloc(channel->ic_cmd_cache, kmflag);
	if (*cmd == NULL) {
		return (DCOPY_NORESOURCES);
	}

	/* setup the dcopy and ioat private state pointers */
	(*cmd)->dp_version = DCOPY_CMD_V0;
	(*cmd)->dp_cmd = 0;
	(*cmd)->dp_private = (struct dcopy_cmd_priv_s *)
	    ((uintptr_t)(*cmd) + sizeof (struct dcopy_cmd_s));
	(*cmd)->dp_private->pr_device_cmd_private =
	    (struct ioat_cmd_private_s *)((uintptr_t)(*cmd)->dp_private +
	    sizeof (struct dcopy_cmd_priv_s));

	/*
	 * if DCOPY_ALLOC_LINK is set, link the old command to the new one
	 * just allocated.
	 */
	priv = (*cmd)->dp_private->pr_device_cmd_private;
	if (flags & DCOPY_ALLOC_LINK) {
		priv->ip_next = oldcmd;
	} else {
		priv->ip_next = NULL;
	}

	return (DCOPY_SUCCESS);
}


/*
 * ioat_cmd_free()
 */
void
ioat_cmd_free(void *private, dcopy_cmd_t *cmdp)
{
	ioat_cmd_private_t *priv;
	ioat_channel_t channel;
	dcopy_cmd_t next;
	dcopy_cmd_t cmd;


	channel = (ioat_channel_t)private;
	cmd = *(cmdp);

	/*
	 * free all the commands in the chain (see DCOPY_ALLOC_LINK in
	 * ioat_cmd_alloc() for more info).
	 */
	while (cmd != NULL) {
		priv = cmd->dp_private->pr_device_cmd_private;
		next = priv->ip_next;
		kmem_cache_free(channel->ic_cmd_cache, cmd);
		cmd = next;
	}
	*cmdp = NULL;
}


/*
 * ioat_cmd_post()
 */
int
ioat_cmd_post(void *private, dcopy_cmd_t cmd)
{
	ioat_channel_ring_t *ring;
	ioat_cmd_private_t *priv;
	ioat_channel_t channel;
	ioat_state_t *state;
	uint64_t dest_paddr;
	uint64_t src_paddr;
	uint64_t dest_addr;
	uint32_t dest_size;
	uint64_t src_addr;
	uint32_t src_size;
	size_t xfer_size;
	uint32_t ctrl;
	size_t size;
	int e;


	channel = (ioat_channel_t)private;
	priv = cmd->dp_private->pr_device_cmd_private;

	state = channel->ic_state;
	ring = channel->ic_ring;

	/*
	 * Special support for DCOPY_CMD_LOOP option, only supported on CBv1.
	 * DCOPY_CMD_QUEUE should also be set if DCOPY_CMD_LOOP is set.
	 */
	if ((cmd->dp_flags & DCOPY_CMD_LOOP) &&
	    (channel->ic_ver != IOAT_CBv1 ||
	    (cmd->dp_flags & DCOPY_CMD_QUEUE))) {
		return (DCOPY_FAILURE);
	}

	if ((cmd->dp_flags & DCOPY_CMD_NOWAIT) == 0) {
		mutex_enter(&ring->cr_desc_mutex);

	/*
	 * Try to acquire mutex if NOWAIT flag is set.
	 * Return failure if failed to acquire mutex.
	 */
	} else if (mutex_tryenter(&ring->cr_desc_mutex) == 0) {
		return (DCOPY_FAILURE);
	}

	/* if the channel has had a fatal failure, return failure */
	if (channel->ic_channel_state == IOAT_CHANNEL_IN_FAILURE) {
		mutex_exit(&ring->cr_desc_mutex);
		return (DCOPY_FAILURE);
	}

	/* make sure we have space for the descriptors */
	e = ioat_ring_reserve(channel, ring, cmd);
	if (e != DCOPY_SUCCESS) {
		mutex_exit(&ring->cr_desc_mutex);
		return (DCOPY_NORESOURCES);
	}

	/* if we support DCA, and the DCA flag is set, post a DCA desc */
	if ((channel->ic_ver == IOAT_CBv2) &&
	    (cmd->dp_flags & DCOPY_CMD_DCA)) {
		ioat_cmd_post_dca(ring, cmd->dp_dca_id);
	}

	/*
	 * the dma copy may have to be broken up into multiple descriptors
	 * since we can't cross a page boundary.
	 */
	ASSERT(cmd->dp_version == DCOPY_CMD_V0);
	ASSERT(cmd->dp_cmd == DCOPY_CMD_COPY);
	src_addr = cmd->dp.copy.cc_source;
	dest_addr = cmd->dp.copy.cc_dest;
	size = cmd->dp.copy.cc_size;
	priv->ip_start = ring->cr_desc_next;
	while (size > 0) {
		src_paddr = pa_to_ma(src_addr);
		dest_paddr = pa_to_ma(dest_addr);

		/* adjust for any offset into the page */
		if ((src_addr & PAGEOFFSET) == 0) {
			src_size = PAGESIZE;
		} else {
			src_size = PAGESIZE - (src_addr & PAGEOFFSET);
		}
		if ((dest_addr & PAGEOFFSET) == 0) {
			dest_size = PAGESIZE;
		} else {
			dest_size = PAGESIZE - (dest_addr & PAGEOFFSET);
		}

		/* take the smallest of the three */
		xfer_size = MIN(src_size, dest_size);
		xfer_size = MIN(xfer_size, size);

		/*
		 * if this is the last descriptor, and we are supposed to
		 * generate a completion, generate a completion. same logic
		 * for interrupt.
		 */
		ctrl = 0;
		if (cmd->dp_flags & DCOPY_CMD_NOSRCSNP) {
			ctrl |= IOAT_DESC_CTRL_NOSRCSNP;
		}
		if (cmd->dp_flags & DCOPY_CMD_NODSTSNP) {
			ctrl |= IOAT_DESC_CTRL_NODSTSNP;
		}
		if (xfer_size == size) {
			if (!(cmd->dp_flags & DCOPY_CMD_NOSTAT)) {
				ctrl |= IOAT_DESC_CTRL_CMPL;
			}
			if ((cmd->dp_flags & DCOPY_CMD_INTR)) {
				ctrl |= IOAT_DESC_CTRL_INTR;
			}
		}

		ioat_cmd_post_copy(ring, src_paddr, dest_paddr, xfer_size,
		    ctrl);

		/* go to the next page */
		src_addr += xfer_size;
		dest_addr += xfer_size;
		size -= xfer_size;
	}

	/* save away the state so we can poll on it. */
	priv->ip_generation = ring->cr_desc_gen_prev;
	priv->ip_index = ring->cr_desc_prev;

	/* if queue not defined, tell the DMA engine about it */
	if (!(cmd->dp_flags & DCOPY_CMD_QUEUE)) {
		/*
		 * Link the ring to a loop (currently only for FIPE).
		 */
		if (cmd->dp_flags & DCOPY_CMD_LOOP) {
			e = ioat_ring_loop(ring, cmd);
			if (e != DCOPY_SUCCESS) {
				mutex_exit(&ring->cr_desc_mutex);
				return (DCOPY_FAILURE);
			}
		}

		if (channel->ic_ver == IOAT_CBv1) {
			ddi_put8(state->is_reg_handle,
			    (uint8_t *)&channel->ic_regs[IOAT_V1_CHAN_CMD],
			    0x2);
		} else {
			ASSERT(channel->ic_ver == IOAT_CBv2);
			ddi_put16(state->is_reg_handle,
			    (uint16_t *)&channel->ic_regs[IOAT_V2_CHAN_CNT],
			    (uint16_t)(ring->cr_post_cnt & 0xFFFF));
		}
	}

	mutex_exit(&ring->cr_desc_mutex);

	return (DCOPY_SUCCESS);
}


/*
 * ioat_cmd_post_dca()
 */
static void
ioat_cmd_post_dca(ioat_channel_ring_t *ring, uint32_t dca_id)
{
	ioat_chan_dca_desc_t *saved_prev;
	ioat_chan_dca_desc_t *desc;
	ioat_chan_dca_desc_t *prev;
	ioat_channel_t channel;
	uint64_t next_desc_phys;
	off_t prev_offset;
	off_t next_offset;


	channel = ring->cr_chan;
	desc = (ioat_chan_dca_desc_t *)&ring->cr_desc[ring->cr_desc_next];
	prev = (ioat_chan_dca_desc_t *)&ring->cr_desc[ring->cr_desc_prev];

	/* keep track of the number of descs posted for cbv2 */
	ring->cr_post_cnt++;

	/*
	 * post a context change desriptor. If dca has never been used on
	 * this channel, or if the id doesn't match the last id used on this
	 * channel, set CONTEXT_CHANGE bit and dca id, set dca state to active,
	 * and save away the id we're using.
	 */
	desc->dd_ctrl = IOAT_DESC_CTRL_OP_CNTX;
	desc->dd_next_desc = 0x0;
	if (!channel->ic_dca_active || (channel->ic_dca_current != dca_id)) {
		channel->ic_dca_active = B_TRUE;
		channel->ic_dca_current = dca_id;
		desc->dd_ctrl |= IOAT_DESC_CTRL_CNTX_CHNG;
		desc->dd_cntx = dca_id;
	}

	/*
	 * save next desc and prev offset for when we link the two
	 * descriptors together.
	 */
	saved_prev = prev;
	prev_offset = ring->cr_desc_prev << 6;
	next_offset = ring->cr_desc_next << 6;
	next_desc_phys = ring->cr_phys_desc + next_offset;

	/* save the current desc_next and desc_last for the completion */
	ring->cr_desc_prev = ring->cr_desc_next;
	ring->cr_desc_gen_prev = ring->cr_desc_gen;

	/* increment next/gen so it points to the next free desc */
	ring->cr_desc_next++;
	if (ring->cr_desc_next > ring->cr_desc_last) {
		ring->cr_desc_next = 0;
		ring->cr_desc_gen++;
	}

	/*
	 * if this is CBv2, link the descriptor to an empty descriptor. Since
	 * we always leave on desc empty to detect full, this works out.
	 */
	if (ring->cr_chan->ic_ver == IOAT_CBv2) {
		desc = (ioat_chan_dca_desc_t *)
		    &ring->cr_desc[ring->cr_desc_next];
		prev = (ioat_chan_dca_desc_t *)
		    &ring->cr_desc[ring->cr_desc_prev];
		desc->dd_ctrl = 0;
		desc->dd_next_desc = 0x0;
		(void) ddi_dma_sync(channel->ic_desc_dma_handle,
		    ring->cr_desc_next << 6, 64, DDI_DMA_SYNC_FORDEV);
		prev->dd_next_desc = ring->cr_phys_desc +
		    (ring->cr_desc_next << 6);
	}

	/* Put the descriptors physical address in the previous descriptor */
	/*LINTED:E_TRUE_LOGICAL_EXPR*/
	ASSERT(sizeof (ioat_chan_dca_desc_t) == 64);

	/* sync the current desc */
	(void) ddi_dma_sync(channel->ic_desc_dma_handle, next_offset, 64,
	    DDI_DMA_SYNC_FORDEV);

	/* update the previous desc and sync it too */
	saved_prev->dd_next_desc = next_desc_phys;
	(void) ddi_dma_sync(channel->ic_desc_dma_handle, prev_offset, 64,
	    DDI_DMA_SYNC_FORDEV);
}


/*
 * ioat_cmd_post_copy()
 *
 */
static void
ioat_cmd_post_copy(ioat_channel_ring_t *ring, uint64_t src_addr,
    uint64_t dest_addr, uint32_t size, uint32_t ctrl)
{
	ioat_chan_dma_desc_t *saved_prev;
	ioat_chan_dma_desc_t *desc;
	ioat_chan_dma_desc_t *prev;
	ioat_channel_t channel;
	uint64_t next_desc_phy;
	off_t prev_offset;
	off_t next_offset;


	channel = ring->cr_chan;
	desc = (ioat_chan_dma_desc_t *)&ring->cr_desc[ring->cr_desc_next];
	prev = (ioat_chan_dma_desc_t *)&ring->cr_desc[ring->cr_desc_prev];

	/* keep track of the number of descs posted for cbv2 */
	ring->cr_post_cnt++;

	/* write in the DMA desc */
	desc->dd_ctrl = IOAT_DESC_CTRL_OP_DMA | ctrl;
	desc->dd_size = size;
	desc->dd_src_paddr = src_addr;
	desc->dd_dest_paddr = dest_addr;
	desc->dd_next_desc = 0x0;

	/*
	 * save next desc and prev offset for when we link the two
	 * descriptors together.
	 */
	saved_prev = prev;
	prev_offset = ring->cr_desc_prev << 6;
	next_offset = ring->cr_desc_next << 6;
	next_desc_phy = ring->cr_phys_desc + next_offset;

	/* increment next/gen so it points to the next free desc */
	ring->cr_desc_prev = ring->cr_desc_next;
	ring->cr_desc_gen_prev = ring->cr_desc_gen;

	/* increment next/gen so it points to the next free desc */
	ring->cr_desc_next++;
	if (ring->cr_desc_next > ring->cr_desc_last) {
		ring->cr_desc_next = 0;
		ring->cr_desc_gen++;
	}

	/*
	 * if this is CBv2, link the descriptor to an empty descriptor. Since
	 * we always leave on desc empty to detect full, this works out.
	 */
	if (ring->cr_chan->ic_ver == IOAT_CBv2) {
		desc = (ioat_chan_dma_desc_t *)
		    &ring->cr_desc[ring->cr_desc_next];
		prev = (ioat_chan_dma_desc_t *)
		    &ring->cr_desc[ring->cr_desc_prev];
		desc->dd_size = 0;
		desc->dd_ctrl = 0;
		desc->dd_next_desc = 0x0;
		(void) ddi_dma_sync(channel->ic_desc_dma_handle,
		    ring->cr_desc_next << 6, 64, DDI_DMA_SYNC_FORDEV);
		prev->dd_next_desc = ring->cr_phys_desc +
		    (ring->cr_desc_next << 6);
	}

	/* Put the descriptors physical address in the previous descriptor */
	/*LINTED:E_TRUE_LOGICAL_EXPR*/
	ASSERT(sizeof (ioat_chan_dma_desc_t) == 64);

	/* sync the current desc */
	(void) ddi_dma_sync(channel->ic_desc_dma_handle, next_offset, 64,
	    DDI_DMA_SYNC_FORDEV);

	/* update the previous desc and sync it too */
	saved_prev->dd_next_desc = next_desc_phy;
	(void) ddi_dma_sync(channel->ic_desc_dma_handle, prev_offset, 64,
	    DDI_DMA_SYNC_FORDEV);
}


/*
 * ioat_cmd_poll()
 */
int
ioat_cmd_poll(void *private, dcopy_cmd_t cmd)
{
	ioat_channel_ring_t *ring;
	ioat_cmd_private_t *priv;
	ioat_channel_t channel;
	uint64_t generation;
	uint64_t last_cmpl;

	ASSERT(cmd != NULL);
	channel = (ioat_channel_t)private;
	priv = cmd->dp_private->pr_device_cmd_private;

	ring = channel->ic_ring;
	ASSERT(ring != NULL);

	if ((cmd->dp_flags & DCOPY_CMD_NOWAIT) == 0) {
		mutex_enter(&ring->cr_cmpl_mutex);

	/*
	 * Try to acquire mutex if NOWAIT flag is set.
	 * Return failure if failed to acquire mutex.
	 */
	} else if (mutex_tryenter(&ring->cr_cmpl_mutex) == 0) {
		return (DCOPY_FAILURE);
	}

	/* if the channel had a fatal failure, fail all polls */
	if ((channel->ic_channel_state == IOAT_CHANNEL_IN_FAILURE) ||
	    IOAT_CMPL_FAILED(channel)) {
		mutex_exit(&ring->cr_cmpl_mutex);
		return (DCOPY_FAILURE);
	}

	/*
	 * if the current completion is the same as the last time we read one,
	 * post is still pending, nothing further to do. We track completions
	 * as indexes into the ring since post uses VAs and the H/W returns
	 * PAs. We grab a snapshot of generation and last_cmpl in the mutex.
	 */
	(void) ddi_dma_sync(channel->ic_cmpl_dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORCPU);
	last_cmpl = IOAT_CMPL_INDEX(channel);
	if (last_cmpl != ring->cr_cmpl_last) {
		/*
		 * if we wrapped the ring, increment the generation. Store
		 * the last cmpl. This logic assumes a physically contiguous
		 * ring.
		 */
		if (last_cmpl < ring->cr_cmpl_last) {
			ring->cr_cmpl_gen++;
		}
		ring->cr_cmpl_last = last_cmpl;
		generation = ring->cr_cmpl_gen;

	} else {
		generation = ring->cr_cmpl_gen;
	}

	mutex_exit(&ring->cr_cmpl_mutex);

	/*
	 * if cmd isn't passed in, well return.  Useful for updating the
	 * consumer pointer (ring->cr_cmpl_last).
	 */
	if (cmd->dp_flags & DCOPY_CMD_SYNC) {
		return (DCOPY_PENDING);
	}

	/*
	 * if the post's generation is old, this post has completed. No reason
	 * to go check the last completion. if the generation is the same
	 * and if the post is before or = to the last completion processed,
	 * the post has completed.
	 */
	if (priv->ip_generation < generation) {
		return (DCOPY_COMPLETED);
	} else if ((priv->ip_generation == generation) &&
	    (priv->ip_index <= last_cmpl)) {
		return (DCOPY_COMPLETED);
	}

	return (DCOPY_PENDING);
}


/*
 * ioat_ring_reserve()
 */
int
ioat_ring_reserve(ioat_channel_t channel, ioat_channel_ring_t *ring,
    dcopy_cmd_t cmd)
{
	uint64_t dest_addr;
	uint32_t dest_size;
	uint64_t src_addr;
	uint32_t src_size;
	size_t xfer_size;
	uint64_t desc;
	int num_desc;
	size_t size;
	int i;


	/*
	 * figure out how many descriptors we need. This can include a dca
	 * desc and multiple desc for a dma copy.
	 */
	num_desc = 0;
	if ((channel->ic_ver == IOAT_CBv2) &&
	    (cmd->dp_flags & DCOPY_CMD_DCA)) {
		num_desc++;
	}
	src_addr = cmd->dp.copy.cc_source;
	dest_addr = cmd->dp.copy.cc_dest;
	size = cmd->dp.copy.cc_size;
	while (size > 0) {
		num_desc++;

		/* adjust for any offset into the page */
		if ((src_addr & PAGEOFFSET) == 0) {
			src_size = PAGESIZE;
		} else {
			src_size = PAGESIZE - (src_addr & PAGEOFFSET);
		}
		if ((dest_addr & PAGEOFFSET) == 0) {
			dest_size = PAGESIZE;
		} else {
			dest_size = PAGESIZE - (dest_addr & PAGEOFFSET);
		}

		/* take the smallest of the three */
		xfer_size = MIN(src_size, dest_size);
		xfer_size = MIN(xfer_size, size);

		/* go to the next page */
		src_addr += xfer_size;
		dest_addr += xfer_size;
		size -= xfer_size;
	}

	/* Make sure we have space for these descriptors */
	desc = ring->cr_desc_next;
	for (i = 0; i < num_desc; i++) {

		/*
		 * if this is the last descriptor in the ring, see if the
		 * last completed descriptor is #0.
		 */
		if (desc == ring->cr_desc_last) {
			if (ring->cr_cmpl_last == 0) {
				/*
				 * if we think the ring is full, update where
				 * the H/W really is and check for full again.
				 */
				cmd->dp_flags |= DCOPY_CMD_SYNC;
				(void) ioat_cmd_poll(channel, cmd);
				cmd->dp_flags &= ~DCOPY_CMD_SYNC;
				if (ring->cr_cmpl_last == 0) {
					return (DCOPY_NORESOURCES);
				}
			}

			/*
			 * go to the next descriptor which is zero in this
			 * case.
			 */
			desc = 0;

		/*
		 * if this is not the last descriptor in the ring, see if
		 * the last completion we saw was the next descriptor.
		 */
		} else {
			if ((desc + 1) == ring->cr_cmpl_last) {
				/*
				 * if we think the ring is full, update where
				 * the H/W really is and check for full again.
				 */
				cmd->dp_flags |= DCOPY_CMD_SYNC;
				(void) ioat_cmd_poll(channel, cmd);
				cmd->dp_flags &= ~DCOPY_CMD_SYNC;
				if ((desc + 1) == ring->cr_cmpl_last) {
					return (DCOPY_NORESOURCES);
				}
			}

			/* go to the next descriptor */
			desc++;
		}
	}

	return (DCOPY_SUCCESS);
}
