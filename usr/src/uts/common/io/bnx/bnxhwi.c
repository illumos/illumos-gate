/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2019, Joyent, Inc.
 */

#include "bnx.h"
#include "bnx_mm.h"
#include "bnxsnd.h"
#include "bnxrcv.h"
#include "bnxint.h"
#include "bnxtmr.h"
#include "bnxcfg.h"

void
bnx_update_phy(um_device_t * const umdevice)
{
	lm_status_t lmstatus;
	lm_device_t *lmdevice;

	lmdevice = &(umdevice->lm_dev);

	/* Map 'ndd' parameters to LM struct. */
	bnx_cfg_map_phy(umdevice);

	mutex_enter(&umdevice->os_param.phy_mutex);

	/* Reset, re-program and bring-up phy. */
	lmstatus = lm_init_phy(lmdevice, lmdevice->params.req_medium,
	    lmdevice->params.flow_ctrl_cap, lmdevice->params.selective_autoneg,
	    lmdevice->params.wire_speed, 0);
	if (lmstatus != LM_STATUS_SUCCESS) {
		cmn_err(CE_WARN, "%s: Failed to configure the PHY.",
		    umdevice->dev_name);
	}

	lm_service_phy_int(lmdevice, TRUE);

	mutex_exit(&umdevice->os_param.phy_mutex);
}

ddi_dma_handle_t *
bnx_find_dma_hdl(um_device_t *const umdevice, const void *const virtaddr)
{
	int i;
	ddi_dma_handle_t *dmahdl;

	dmahdl = NULL;
	for (i = 0; i < umdevice->os_param.dma_handles_used; i++) {
		if (umdevice->os_param.dma_virt[i] == virtaddr) {
			dmahdl = &(umdevice->os_param.dma_handle[i]);
		}
	}

	return (dmahdl);
}

static void
bnx_free_lmmem(um_device_t * const umdevice)
{
	int i;
	bnx_memreq_t *memreq;
	ddi_dma_handle_t *dma_handle;
	ddi_acc_handle_t *acc_handle;

	if (umdevice->os_param.dma_handles_used != 0) {
		i = umdevice->os_param.dma_handles_used - 1;

		dma_handle = &(umdevice->os_param.dma_handle[i]);
		acc_handle = &(umdevice->os_param.dma_acc_handle[i]);

		/* Free all shared memory. */
		for (; i >= 0; i--) {
			(void) ddi_dma_unbind_handle(*dma_handle);

			ddi_dma_mem_free(acc_handle);

			ddi_dma_free_handle(dma_handle);

			dma_handle--;
			acc_handle--;
		}

		umdevice->os_param.dma_handles_used = 0;
	}

	if (umdevice->memcnt != 0) {
		/* Free all local memory. */
		for (i = umdevice->memcnt - 1; i >= 0; i--) {
			memreq = &umdevice->memreq[i];

			kmem_free(memreq->addr, memreq->size);

			memreq->addr = NULL;
			memreq->size = 0;
		}

		umdevice->memcnt = 0;
	}
}

int
bnx_hdwr_init(um_device_t *const umdevice)
{
	lm_status_t lmstatus;
	lm_device_t *lmdevice;

	lmdevice = &(umdevice->lm_dev);

	lmstatus = lm_get_dev_info(lmdevice);
	if (lmstatus != LM_STATUS_SUCCESS) {
		cmn_err(CE_WARN, "%s: Failed to get device information.\n",
		    umdevice->dev_name);
		return (-1);
	}

	/*
	 * Initialize the adapter resource.  Mainly allocating memory needed
	 * by the driver, such as packet descriptors, shared memory, etc.
	 */
	lmstatus = lm_init_resc(lmdevice);
	if (lmstatus != LM_STATUS_SUCCESS) {
		cmn_err(CE_WARN, "%s: Failed to allocate device resources.\n",
		    umdevice->dev_name);
		goto error1;
	}

	if (bnx_txpkts_init(umdevice)) {
		goto error1;
	}

	if (bnx_rxpkts_init(umdevice)) {
		goto error2;
	}

	/* Find	the DMA handle associated with the status block memory. */
	umdevice->os_param.status_block_dma_hdl = bnx_find_dma_hdl(umdevice,
	    (void *)(umdevice->lm_dev.vars.status_virt));

	/* Reset the local interrupt event index. */
	umdevice->dev_var.processed_status_idx = 0;

	/* Initialize the receive mask to a sane default. */
	umdevice->dev_var.rx_filter_mask = LM_RX_MASK_ACCEPT_UNICAST |
	    LM_RX_MASK_ACCEPT_BROADCAST;

	return (0);

error2:
	bnx_txpkts_fini(umdevice);

error1:
	bnx_free_lmmem(umdevice);

	return (-1);
}

int
bnx_hdwr_acquire(um_device_t *const umdevice)
{
	lm_status_t lmstatus;
	lm_device_t *lmdevice;

	lmdevice = &(umdevice->lm_dev);

	/* Reset the configuration to the hardware default. */
	bnx_cfg_reset(umdevice);

	/*
	 * A call to lm_reset() implicitly means we are relieving the firmware
	 * of it's responsibility to maintain the device.  The driver assumes
	 * control.  The LM vars.medium field normally gets set with a call to
	 * lm_init_phy(), but this function cannot be called before we assume
	 * control of the device.  If we did, we run the risk of contending
	 * with the firmware for PHY accesses.  Do the next best thing.
	 */
	lmdevice->vars.medium = lm_get_medium(lmdevice);

	/* Map 'ndd' parameters to LM struct. */
	bnx_cfg_map_phy(umdevice);

	/* Bring the chip under driver control. */
	lmstatus = lm_reset(lmdevice, LM_REASON_DRIVER_RESET);
	if (lmstatus != LM_STATUS_SUCCESS) {
		cmn_err(CE_WARN, "%s: Failed to reset chip.\n",
		    umdevice->dev_name);
		return (-1);
	}

	/* Configure the PHY to the requested settings. */
	lmstatus = lm_init_phy(lmdevice, lmdevice->params.req_medium,
	    lmdevice->params.flow_ctrl_cap, lmdevice->params.selective_autoneg,
	    lmdevice->params.wire_speed, 0);
	if (lmstatus != LM_STATUS_SUCCESS) {
		cmn_err(CE_WARN, "%s: Failed to initialize the PHY.",
		    umdevice->dev_name);
	}

	lm_service_phy_int(lmdevice, FALSE); /* force a phy status update */

	umdevice->dev_var.indLink = lmdevice->vars.link_status;
	umdevice->dev_var.indMedium = lmdevice->vars.medium;

	/*
	 * Need to clear TX PATCH scratch register at offset 0x420
	 * to instruct chip to do full TCP checksum calculations.
	 */
	REG_WR_IND(lmdevice, (OFFSETOF(reg_space_t, tpat.tpat_scratch[0]) +
	    0x420), 0);

	FLUSHPOSTEDWRITES(lmdevice);

	umdevice->recv_discards = 0;

	/* Make sure the rx statistics counters are reset. */
	bzero(&(lmdevice->rx_info.stats), sizeof (lm_rx_stats_t));

	/* Post rx buffers to the chip. */
	(void) lm_post_buffers(lmdevice, 0, NULL);

	/* Allow the hardware to accept rx traffic. */
	(void) lm_set_rx_mask(lmdevice, RX_FILTER_USER_IDX0,
	    umdevice->dev_var.rx_filter_mask);

	FLUSHPOSTEDWRITES(lmdevice);

	/* Enable interrupts. */
	bnx_intr_enable(umdevice);

	/* Start the periodic timer. */
	bnx_timer_start(umdevice);

	return (0);
}

void
bnx_hdwr_release(um_device_t *const umdevice)
{
	int reason;
	lm_device_t *lmdevice;

	lmdevice = &(umdevice->lm_dev);

	/* Stop the periodic timer. */
	bnx_timer_stop(umdevice);

	/* Disable interrupts. */
	bnx_intr_disable(umdevice);

	/*
	 * In Solaris when RX traffic is accepted, the system might generate
	 * and attempt to send some TX packets (from within gld_recv() !).
	 * Claiming any TX locks before this point would create a deadlock.
	 * The ISR would be waiting for a lock acquired here that would never
	 * be freed, since we in-turn would be waiting for the ISR to finish
	 * here.  Consequently, we acquire the TX lock as soon as we know that
	 * no TX traffic is a result of RX traffic.
	 */
	rw_enter(&umdevice->os_param.gld_snd_mutex, RW_WRITER);

	/* Set RX mask to stop receiving any further packets */
	(void) lm_set_rx_mask(lmdevice, RX_FILTER_USER_IDX0,
	    LM_RX_MASK_ACCEPT_NONE);

	FLUSHPOSTEDWRITES(lmdevice);

	if (umdevice->dev_var.fw_ver < FW_VER_WITH_UNLOAD_POWER_DOWN) {
		reason = LM_REASON_DRIVER_SHUTDOWN;
	} else {
		reason = LM_REASON_DRIVER_UNLOAD_POWER_DOWN;
	}

	lm_chip_reset(lmdevice, reason);

	FLUSHPOSTEDWRITES(lmdevice);

	/* Reclaim all tx buffers submitted to the hardware. */
	bnx_txpkts_flush(umdevice);

	/* Reclaim all rx buffers submitted to the hardware. */
	bnx_rxpkts_recycle(umdevice);

	rw_exit(&umdevice->os_param.gld_snd_mutex);
}

void
bnx_hdwr_fini(um_device_t *const umdevice)
{
	bnx_rxpkts_fini(umdevice);

	bnx_txpkts_fini(umdevice);

	bnx_free_lmmem(umdevice);
}

static u32_t
compute_crc32(const u8_t *const buf, u32_t buf_size)
{
	u32_t reg;
	u32_t tmp;
	u32_t j;
	u32_t k;

	reg = 0xffffffff;

	for (j = 0; j < buf_size; j++) {
		reg ^= buf[j];

		for (k = 0; k < 8; k++) {
			tmp = reg & 0x01;

			reg >>= 1;

			if (tmp) {
				reg ^= 0xedb88320;
			}
		}
	}

	return (~reg);
}

int
bnx_find_mchash_collision(lm_mc_table_t *mc_table, const uint8_t *const mc_addr)
{
	u32_t cur_bit_pos;
	u32_t tgt_bit_pos;
	u32_t idx;
	u32_t crc32;

	crc32 = compute_crc32(mc_addr, ETHERNET_ADDRESS_SIZE);

	tgt_bit_pos = ~crc32 & 0xff;

	for (idx = 0; idx < mc_table->entry_cnt; idx++) {
		crc32 = compute_crc32(mc_table->addr_arr[idx].mc_addr,
		    ETHERNET_ADDRESS_SIZE);

		/*
		 * The most significant 7 bits of the CRC32 (no inversion),
		 * are used to index into one of the possible 128 bit positions.
		 */
		cur_bit_pos = ~crc32 & 0xff;

		if (tgt_bit_pos == cur_bit_pos) {
			return (idx);
		}
	}

	return (-1);
}



/*
 * Name:	um_send_driver_pulse
 *
 * Input:       ptr to driver structure
 *
 * Return:      none
 *
 * Description: um_send_driver_pulse routine sends heartbeat pulse to firmware.
 */
void
um_send_driver_pulse(um_device_t *const umdevice)
{
	u32_t msg_code;
	u32_t offset;
	lm_device_t *lmdevice;

	lmdevice = &(umdevice->lm_dev);

	offset = lmdevice->hw_info.shmem_base;
	offset += OFFSETOF(shmem_region_t, drv_fw_mb.drv_pulse_mb);

	mutex_enter(&umdevice->os_param.ind_mutex);

	lmdevice->vars.drv_pulse_wr_seq++;

	msg_code = lmdevice->vars.drv_pulse_wr_seq & DRV_PULSE_SEQ_MASK;

	mutex_exit(&umdevice->os_param.ind_mutex);

	if (lmdevice->params.test_mode & TEST_MODE_DRIVER_PULSE_ALWAYS_ALIVE) {
		msg_code |= DRV_PULSE_ALWAYS_ALIVE;
	}

	REG_WR_IND(lmdevice, offset, msg_code);
}
