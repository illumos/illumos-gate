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
 *  Copyright (c) 2002-2005 Neterion, Inc.
 *  All right Reserved.
 *
 *  FileName :    xgehal-device-fp.c
 *
 *  Description:  HAL device object functionality (fast path)
 *
 *  Created:      10 June 2004
 */

#ifdef XGE_DEBUG_FP
#include "xgehal-device.h"
#endif

#include "xgehal-ring.h"
#include "xgehal-fifo.h"

/**
 * xge_hal_device_bar0 - Get BAR0 mapped address.
 * @hldev: HAL device handle.
 *
 * Returns: BAR0 address of the specified device.
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE char *
xge_hal_device_bar0(xge_hal_device_t *hldev)
{
	return hldev->bar0;
}

/**
 * xge_hal_device_isrbar0 - Get BAR0 mapped address.
 * @hldev: HAL device handle.
 *
 * Returns: BAR0 address of the specified device.
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE char *
xge_hal_device_isrbar0(xge_hal_device_t *hldev)
{
	return hldev->isrbar0;
}

/**
 * xge_hal_device_bar1 - Get BAR1 mapped address.
 * @hldev: HAL device handle.
 *
 * Returns: BAR1 address of the specified device.
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE char *
xge_hal_device_bar1(xge_hal_device_t *hldev)
{
	return hldev->bar1;
}

/**
 * xge_hal_device_bar0_set - Set BAR0 mapped address.
 * @hldev: HAL device handle.
 * @bar0: BAR0 mapped address.
 * * Set BAR0 address in the HAL device object.
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE void
xge_hal_device_bar0_set(xge_hal_device_t *hldev, char *bar0)
{
	xge_assert(bar0);
	hldev->bar0 = bar0;
}

/**
 * xge_hal_device_isrbar0_set - Set BAR0 mapped address.
 * @hldev: HAL device handle.
 * @isrbar0: BAR0 mapped address.
 * * Set BAR0 address in the HAL device object.
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE void
xge_hal_device_isrbar0_set(xge_hal_device_t *hldev, char *isrbar0)
{
	xge_assert(isrbar0);
	hldev->isrbar0 = isrbar0;
}

/**
 * xge_hal_device_bar1_set - Set BAR1 mapped address.
 * @hldev: HAL device handle.
 * @channelh: Channel handle.
 * @bar1: BAR1 mapped address.
 *
 * Set BAR1 address for the given channel.
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE void
xge_hal_device_bar1_set(xge_hal_device_t *hldev, xge_hal_channel_h channelh,
		       char *bar1)
{
	xge_hal_fifo_t *fifo = (xge_hal_fifo_t *)channelh;

	xge_assert(bar1);
	xge_assert(fifo);

	/* Initializing the BAR1 address as the start of
	 * the FIFO queue pointer and as a location of FIFO control
	 * word. */
	fifo->hw_pair =
	        (xge_hal_fifo_hw_pair_t *) (bar1 +
		        (fifo->channel.post_qid * XGE_HAL_FIFO_HW_PAIR_OFFSET));
	hldev->bar1 = bar1;
}


/**
 * xge_hal_device_rev - Get Device revision number.
 * @hldev: HAL device handle.
 *
 * Returns: Device revision number
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE int
xge_hal_device_rev(xge_hal_device_t *hldev)
{
        return hldev->revision;
}


/**
 * xge_hal_device_begin_irq - Begin IRQ processing.
 * @hldev: HAL device handle.
 * @reason: "Reason" for the interrupt, the value of Xframe's
 *          general_int_status register.
 *
 * The function performs two actions, It first checks whether (shared IRQ) the
 * interrupt was raised by the device. Next, it masks the device interrupts.
 *
 * Note:
 * xge_hal_device_begin_irq() does not flush MMIO writes through the
 * bridge. Therefore, two back-to-back interrupts are potentially possible.
 * It is the responsibility of the ULD to make sure that only one
 * xge_hal_device_continue_irq() runs at a time.
 *
 * Returns: 0, if the interrupt is not "ours" (note that in this case the
 * device remain enabled).
 * Otherwise, xge_hal_device_begin_irq() returns 64bit general adapter
 * status.
 * See also: xge_hal_device_handle_irq()
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE xge_hal_status_e
xge_hal_device_begin_irq(xge_hal_device_t *hldev, u64 *reason)
{
	u64 val64;
	xge_hal_pci_bar0_t *isrbar0 = (xge_hal_pci_bar0_t *)hldev->isrbar0;

	hldev->stats.sw_dev_info_stats.total_intr_cnt++;

	val64 = xge_os_pio_mem_read64(hldev->pdev,
			      hldev->regh0, &isrbar0->general_int_status);
	if (xge_os_unlikely(!val64)) {
		/* not Xframe interrupt */
		hldev->stats.sw_dev_info_stats.not_traffic_intr_cnt++;
		*reason = 0;
	        return XGE_HAL_ERR_WRONG_IRQ;
	}

	if (xge_os_unlikely(val64 == XGE_HAL_ALL_FOXES)) {
                u64 adapter_status =
                        xge_os_pio_mem_read64(hldev->pdev, hldev->regh0,
					      &isrbar0->adapter_status);
                if (adapter_status == XGE_HAL_ALL_FOXES)  {
	                (void) xge_queue_produce(hldev->queueh,
						 XGE_HAL_EVENT_SLOT_FREEZE,
						 hldev,
						 1,  /* critical: slot freeze */
						 sizeof(u64),
						 (void*)&adapter_status);
			*reason = 0;
			return XGE_HAL_ERR_CRITICAL;
		}
	}

	*reason = val64;

	/* separate fast path, i.e. no errors */
	if (val64 & XGE_HAL_GEN_INTR_RXTRAFFIC) {
		hldev->stats.sw_dev_info_stats.rx_traffic_intr_cnt++;
		return XGE_HAL_OK;
	}
	if (val64 & XGE_HAL_GEN_INTR_TXTRAFFIC) {
		hldev->stats.sw_dev_info_stats.tx_traffic_intr_cnt++;
		return XGE_HAL_OK;
	}

	if (xge_os_unlikely(val64 & XGE_HAL_GEN_INTR_TXPIC)) {
		xge_hal_status_e status;
		status = __hal_device_handle_txpic(hldev, val64);
		if (status != XGE_HAL_OK) {
			return status;
		}
	}

	if (xge_os_unlikely(val64 & XGE_HAL_GEN_INTR_TXDMA)) {
		xge_hal_status_e status;
		status = __hal_device_handle_txdma(hldev, val64);
		if (status != XGE_HAL_OK) {
			return status;
		}
	}

	if (xge_os_unlikely(val64 & XGE_HAL_GEN_INTR_TXMAC)) {
		xge_hal_status_e status;
		status = __hal_device_handle_txmac(hldev, val64);
		if (status != XGE_HAL_OK) {
			return status;
		}
	}

	if (xge_os_unlikely(val64 & XGE_HAL_GEN_INTR_TXXGXS)) {
		xge_hal_status_e status;
		status = __hal_device_handle_txxgxs(hldev, val64);
		if (status != XGE_HAL_OK) {
			return status;
		}
	}

	if (xge_os_unlikely(val64 & XGE_HAL_GEN_INTR_RXPIC)) {
		xge_hal_status_e status;
		status = __hal_device_handle_rxpic(hldev, val64);
		if (status != XGE_HAL_OK) {
			return status;
		}
	}

	if (xge_os_unlikely(val64 & XGE_HAL_GEN_INTR_RXDMA)) {
		xge_hal_status_e status;
		status = __hal_device_handle_rxdma(hldev, val64);
		if (status != XGE_HAL_OK) {
			return status;
		}
	}

	if (xge_os_unlikely(val64 & XGE_HAL_GEN_INTR_RXMAC)) {
		xge_hal_status_e status;
		status = __hal_device_handle_rxmac(hldev, val64);
		if (status != XGE_HAL_OK) {
			return status;
		}
	}

	if (xge_os_unlikely(val64 & XGE_HAL_GEN_INTR_RXXGXS)) {
		xge_hal_status_e status;
		status = __hal_device_handle_rxxgxs(hldev, val64);
		if (status != XGE_HAL_OK) {
			return status;
		}
	}

	if (xge_os_unlikely(val64 & XGE_HAL_GEN_INTR_MC)) {
		xge_hal_status_e status;
		status = __hal_device_handle_mc(hldev, val64);
		if (status != XGE_HAL_OK) {
			return status;
		}
	}

	return XGE_HAL_OK;
}

/**
 * xge_hal_device_clear_rx - Acknowledge (that is, clear) the
 * condition that has caused the RX interrupt.
 * @hldev: HAL device handle.
 *
 * Acknowledge (that is, clear) the condition that has caused
 * the Rx interrupt.
 * See also: xge_hal_device_begin_irq(), xge_hal_device_continue_irq(),
 * xge_hal_device_clear_tx(), xge_hal_device_mask_rx().
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE void
xge_hal_device_clear_rx(xge_hal_device_t *hldev)
{
	xge_hal_pci_bar0_t *isrbar0 = (xge_hal_pci_bar0_t *)hldev->isrbar0;

	xge_os_pio_mem_write64(hldev->pdev, hldev->regh0,
			     0xFFFFFFFFFFFFFFFFULL,
			     &isrbar0->rx_traffic_int);
}

/**
 * xge_hal_device_clear_tx - Acknowledge (that is, clear) the
 * condition that has caused the TX interrupt.
 * @hldev: HAL device handle.
 *
 * Acknowledge (that is, clear) the condition that has caused
 * the Tx interrupt.
 * See also: xge_hal_device_begin_irq(), xge_hal_device_continue_irq(),
 * xge_hal_device_clear_rx(), xge_hal_device_mask_tx().
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE void
xge_hal_device_clear_tx(xge_hal_device_t *hldev)
{
	xge_hal_pci_bar0_t *isrbar0 = (xge_hal_pci_bar0_t *)hldev->isrbar0;

	xge_os_pio_mem_write64(hldev->pdev, hldev->regh0,
			     0xFFFFFFFFFFFFFFFFULL,
			     &isrbar0->tx_traffic_int);
}

/**
 * xge_hal_device_poll_rx_channels - Poll Rx channels for completed
 * descriptors and process the same.
 * @hldev: HAL device handle.
 *
 * The function polls the Rx channels for the completed descriptors and calls
 * the upper-layer driver (ULD) via supplied completion callback.
 *
 * Returns: XGE_HAL_OK, if the polling is completed successful.
 * XGE_HAL_COMPLETIONS_REMAIN: There are still more completed
 * descriptors available which are yet to be processed.
 *
 * See also: xge_hal_device_poll_tx_channels(), xge_hal_device_continue_irq().
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE xge_hal_status_e
xge_hal_device_poll_rx_channels(xge_hal_device_t *hldev)
{
	xge_list_t *item;
	xge_hal_channel_t *channel;
	xge_hal_dtr_h first_dtrh;
	u8 t_code;

	/* for each opened rx channel */
	xge_list_for_each(item, &hldev->ring_channels) {
		channel = xge_container_of(item,
				xge_hal_channel_t, item);

		((xge_hal_ring_t*)channel)->cmpl_cnt = 0;
		if (xge_hal_ring_dtr_next_completed (channel, &first_dtrh,
					&t_code) == XGE_HAL_OK) {
			if (channel->callback(channel, first_dtrh,
				t_code, channel->userdata) != XGE_HAL_OK) {
				return XGE_HAL_COMPLETIONS_REMAIN;
			}
		}
	}

	return XGE_HAL_OK;
}

/**
 * xge_hal_device_poll_tx_channels - Poll Tx channels for completed
 * descriptors and process the same.
 * @hldev: HAL device handle.
 *
 * The function polls the Tx channels for the completed descriptors and calls
 * the upper-layer driver (ULD) via supplied completion callback.
 *
 * Returns: XGE_HAL_OK, if the polling is completed successful.
 * XGE_HAL_COMPLETIONS_REMAIN: There are still more completed
 * descriptors available which are yet to be processed.
 *
 * See also: xge_hal_device_poll_rx_channels(), xge_hal_device_continue_irq().
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE xge_hal_status_e
xge_hal_device_poll_tx_channels(xge_hal_device_t *hldev)
{
	xge_list_t *item;
	xge_hal_channel_t *channel;
	xge_hal_dtr_h first_dtrh;
	u8 t_code;

	/* for each opened tx channel */
	xge_list_for_each(item, &hldev->fifo_channels) {
		channel = xge_container_of(item,
				xge_hal_channel_t, item);

		if (xge_hal_fifo_dtr_next_completed (channel, &first_dtrh,
					&t_code) == XGE_HAL_OK) {
			if (channel->callback(channel, first_dtrh,
				t_code, channel->userdata) != XGE_HAL_OK) {
				return XGE_HAL_COMPLETIONS_REMAIN;
			}
		}
	}

	return XGE_HAL_OK;
}

/**
 * xge_hal_device_mask_tx - Mask Tx interrupts.
 * @hldev: HAL device handle.
 *
 * Mask Tx device interrupts.
 *
 * See also: xge_hal_device_unmask_tx(), xge_hal_device_mask_rx(),
 * xge_hal_device_clear_tx().
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE void
xge_hal_device_mask_tx(xge_hal_device_t *hldev)
{
	xge_hal_pci_bar0_t *isrbar0 = (xge_hal_pci_bar0_t *)hldev->isrbar0;

	xge_os_pio_mem_write64(hldev->pdev, hldev->regh0,
			       0xFFFFFFFFFFFFFFFFULL,
			       &isrbar0->tx_traffic_mask);
}

/**
 * xge_hal_device_mask_rx - Mask Rx interrupts.
 * @hldev: HAL device handle.
 *
 * Mask Rx device interrupts.
 *
 * See also: xge_hal_device_unmask_rx(), xge_hal_device_mask_tx(),
 * xge_hal_device_clear_rx().
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE void
xge_hal_device_mask_rx(xge_hal_device_t *hldev)
{
	xge_hal_pci_bar0_t *isrbar0 = (xge_hal_pci_bar0_t *)hldev->isrbar0;

	xge_os_pio_mem_write64(hldev->pdev, hldev->regh0,
			       0xFFFFFFFFFFFFFFFFULL,
			       &isrbar0->rx_traffic_mask);
}

/**
 * xge_hal_device_mask_all - Mask all device interrupts.
 * @hldev: HAL device handle.
 *
 * Mask all device interrupts.
 *
 * See also: xge_hal_device_unmask_all()
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE void
xge_hal_device_mask_all(xge_hal_device_t *hldev)
{
	xge_hal_pci_bar0_t *isrbar0 = (xge_hal_pci_bar0_t *)hldev->isrbar0;

	xge_os_pio_mem_write64(hldev->pdev, hldev->regh0,
			       0xFFFFFFFFFFFFFFFFULL,
			       &isrbar0->general_int_mask);
}

/**
 * xge_hal_device_unmask_tx - Unmask Tx interrupts.
 * @hldev: HAL device handle.
 *
 * Unmask Tx device interrupts.
 *
 * See also: xge_hal_device_mask_tx(), xge_hal_device_clear_tx().
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE void
xge_hal_device_unmask_tx(xge_hal_device_t *hldev)
{
	xge_hal_pci_bar0_t *isrbar0 = (xge_hal_pci_bar0_t *)hldev->isrbar0;

	xge_os_pio_mem_write64(hldev->pdev, hldev->regh0,
			       0x0ULL,
			       &isrbar0->tx_traffic_mask);
}

/**
 * xge_hal_device_unmask_rx - Unmask Rx interrupts.
 * @hldev: HAL device handle.
 *
 * Unmask Rx device interrupts.
 *
 * See also: xge_hal_device_mask_rx(), xge_hal_device_clear_rx().
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE void
xge_hal_device_unmask_rx(xge_hal_device_t *hldev)
{
	xge_hal_pci_bar0_t *isrbar0 = (xge_hal_pci_bar0_t *)hldev->isrbar0;

	xge_os_pio_mem_write64(hldev->pdev, hldev->regh0,
			       0x0ULL,
			       &isrbar0->rx_traffic_mask);
}

/**
 * xge_hal_device_unmask_all - Unmask all device interrupts.
 * @hldev: HAL device handle.
 *
 * Unmask all device interrupts.
 *
 * See also: xge_hal_device_mask_all()
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE void
xge_hal_device_unmask_all(xge_hal_device_t *hldev)
{
	xge_hal_pci_bar0_t *isrbar0 = (xge_hal_pci_bar0_t *)hldev->isrbar0;

	xge_os_pio_mem_write64(hldev->pdev, hldev->regh0,
			       0x0ULL,
			       &isrbar0->general_int_mask);
}


/**
 * xge_hal_device_continue_irq - Continue handling IRQ: process all
 * completed descriptors.
 * @hldev: HAL device handle.
 *
 * Process completed descriptors and unmask the device interrupts.
 *
 * The xge_hal_device_continue_irq() walks all open channels
 * and calls upper-layer driver (ULD) via supplied completion
 * callback. Note that the completion callback is specified at channel open
 * time, see xge_hal_channel_open().
 *
 * Note that the xge_hal_device_continue_irq is part of the _fast_ path.
 * To optimize the processing, the function does _not_ check for
 * errors and alarms.
 *
 * The latter is done in a polling fashion, via xge_hal_device_poll().
 *
 * Returns: XGE_HAL_OK.
 *
 * See also: xge_hal_device_handle_irq(), xge_hal_device_poll(),
 * xge_hal_ring_dtr_next_completed(),
 * xge_hal_fifo_dtr_next_completed(), xge_hal_channel_callback_f{}.
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE xge_hal_status_e
xge_hal_device_continue_irq(xge_hal_device_t *hldev)
{
	xge_list_t *item;
	xge_hal_channel_t *channel;
	xge_hal_dtr_h first_dtrh;
	int got_rx = 0, got_tx = 0;
	unsigned int isr_polling_cnt = (unsigned int) hldev->config.isr_polling_cnt;
	u8 t_code;

_try_again:

	/* for each opened rx channel */
	xge_list_for_each(item, &hldev->ring_channels) {
		channel = xge_container_of(item,
				xge_hal_channel_t, item);

		((xge_hal_ring_t*)channel)->cmpl_cnt = 0;
		if (xge_hal_ring_dtr_next_completed (channel, &first_dtrh,
					&t_code) == XGE_HAL_OK) {
			channel->callback(channel, first_dtrh,
						t_code, channel->userdata);
			got_rx++;
		}

		if (hldev->terminating)
			return XGE_HAL_OK;

	}

	/* Note.
	 * All interrupts are masked by general_int_status at this point,
	 * i.e. no new interrupts going to be produced by the adapter.
	 * We intentionally do not mask rx/tx interrupts right after
	 * walking to continue processing new descriptors on next
	 * interation if configured. */

	/* for each opened tx channel */
	xge_list_for_each(item, &hldev->fifo_channels) {
		channel = xge_container_of(item,
				xge_hal_channel_t, item);

		if (xge_hal_fifo_dtr_next_completed (channel, &first_dtrh,
					&t_code) == XGE_HAL_OK) {
			channel->callback(channel, first_dtrh,
					t_code, channel->userdata);
			got_tx++;
		}

		if (hldev->terminating)
			return XGE_HAL_OK;

	}

	if (got_rx || got_tx) {
		xge_hal_pci_bar0_t *isrbar0 =
			(xge_hal_pci_bar0_t *)hldev->isrbar0;
		got_tx = got_rx = 0;
		if (isr_polling_cnt--)
			goto _try_again;
		/* to avoid interrupt loss, we force bridge to flush cached
		 * writes, in simple case OSDEP needs to just readl(), some
		 * OSes (e.g. M$ Windows) has special bridge flush API */
		(void) xge_os_flush_bridge(hldev->pdev, hldev->regh0,
				    &isrbar0->general_int_status);
	} else if (isr_polling_cnt == hldev->config.isr_polling_cnt) {
		hldev->stats.sw_dev_info_stats.not_traffic_intr_cnt++;
	}

	return XGE_HAL_OK;
}

/**
 * xge_hal_device_handle_irq - Handle device IRQ.
 * @hldev: HAL device handle.
 *
 * Perform the complete handling of the line interrupt. The function
 * performs two calls.
 * First it uses xge_hal_device_begin_irq() to  check the reason for
 * the interrupt and mask the device interrupts.
 * Second, it calls xge_hal_device_continue_irq() to process all
 * completed descriptors and re-enable the interrupts.
 *
 * Returns: XGE_HAL_OK - success;
 * XGE_HAL_ERR_WRONG_IRQ - (shared) IRQ produced by other device.
 *
 * See also: xge_hal_device_begin_irq(), xge_hal_device_continue_irq().
 */
__HAL_STATIC_DEVICE __HAL_INLINE_DEVICE xge_hal_status_e
xge_hal_device_handle_irq(xge_hal_device_t *hldev)
{
	u64 reason;
	xge_hal_status_e status;

	xge_hal_device_mask_all(hldev);

        status = xge_hal_device_begin_irq(hldev, &reason);
        if (status != XGE_HAL_OK) {
		xge_hal_device_unmask_all(hldev);
	        return status;
	}

	if (reason & XGE_HAL_GEN_INTR_RXTRAFFIC) {
		xge_hal_device_clear_rx(hldev);
	}

        status = xge_hal_device_continue_irq(hldev);

	xge_hal_device_clear_tx(hldev);

	xge_hal_device_unmask_all(hldev);

	return status;
}

#if defined(XGE_HAL_CONFIG_LRO)

/*
 * __hal_tcp_seg_len: Find the tcp seg len.
 * @ip: ip header.
 * @tcp: tcp header.
 * returns: Tcp seg length.
 */
__HAL_STATIC_CHANNEL __HAL_INLINE_CHANNEL u16
__hal_tcp_seg_len(iplro_t *ip, tcplro_t *tcp)
{
	u16 ret;

	ret =  (xge_os_ntohs(ip->tot_len) -
	       ((ip->version_ihl & 0x0F)<<2) -
	       ((tcp->doff_res)>>2));
	return (ret);
}

/*
 * __hal_ip_lro_capable: Finds whether ip is lro capable.
 * @ip: ip header.
 * @ext_info:  descriptor info.
 */
__HAL_STATIC_CHANNEL __HAL_INLINE_CHANNEL xge_hal_status_e
__hal_ip_lro_capable(iplro_t *ip,
		     xge_hal_dtr_info_t *ext_info)
{

#ifdef XGE_LL_DEBUG_DUMP_PKT
		{
			u16 i;
			u8 ch, *iph = (u8 *)ip;

			xge_debug_ring(XGE_TRACE, "Dump Ip:" );
			for (i =0; i < 40; i++) {
				ch = ntohs(*((u8 *)(iph + i)) );
				printf("i:%d %02x, ",i,ch);
			}
		}
#endif

	if (ip->version_ihl != IP_FAST_PATH_HDR_MASK) {
		xge_debug_ring(XGE_ERR, "iphdr !=45 :%d",ip->version_ihl);
		return XGE_HAL_FAIL;
	}

	if (ext_info->proto & XGE_HAL_FRAME_PROTO_IP_FRAGMENTED) {
		xge_debug_ring(XGE_ERR, "IP fragmented");
		return XGE_HAL_FAIL;
	}

	return XGE_HAL_OK;
}

/*
 * __hal_tcp_lro_capable: Finds whether tcp is lro capable.
 * @ip: ip header.
 * @tcp: tcp header.
 */
__HAL_STATIC_CHANNEL __HAL_INLINE_CHANNEL xge_hal_status_e
__hal_tcp_lro_capable(iplro_t *ip, tcplro_t *tcp)
{
#ifdef XGE_LL_DEBUG_DUMP_PKT
		{
			u8 ch;
			u16 i;

			xge_debug_ring(XGE_TRACE, "Dump Tcp:" );
			for (i =0; i < 20; i++) {
				ch = ntohs(*((u8 *)((u8 *)tcp + i)) );
				xge_os_printf("i:%d %02x, ",i,ch);
			}
		}
#endif
	if ((TCP_FAST_PATH_HDR_MASK1 != tcp->doff_res) ||
	    ((TCP_FAST_PATH_HDR_MASK2 != tcp->ctrl) && 
	     (TCP_FAST_PATH_HDR_MASK3 != tcp->ctrl))) { 
		xge_debug_ring(XGE_ERR, "tcphdr not fastpth %02x %02x \n", tcp->doff_res, tcp->ctrl);
		return XGE_HAL_FAIL;
	}

	return XGE_HAL_OK;
}

/*
 * __hal_lro_capable: Finds whether frame is lro capable.
 * @buffer: Ethernet frame.
 * @ip: ip frame.
 * @tcp: tcp frame.
 * @ext_info: Descriptor info.
 * @hldev: Hal context.
 */
__HAL_STATIC_CHANNEL __HAL_INLINE_CHANNEL xge_hal_status_e
__hal_lro_capable( u8 *buffer,
		   iplro_t **ip,
		   tcplro_t **tcp,
		   xge_hal_dtr_info_t *ext_info,
		   xge_hal_device_t *hldev)
{
	u8 ip_off, ip_length;

	if (!(ext_info->proto & XGE_HAL_FRAME_PROTO_TCP)) {
		xge_debug_ring(XGE_ERR, "Cant do lro %d", ext_info->proto);
		return XGE_HAL_FAIL;
	}
#ifdef XGE_LL_DEBUG_DUMP_PKT
		{
			u8 ch;
			u16 i;

			xge_os_printf("Dump Eth:" );
			for (i =0; i < 60; i++) {
				ch = ntohs(*((u8 *)(buffer + i)) );
				xge_os_printf("i:%d %02x, ",i,ch);
			}
		}
#endif

	switch (ext_info->frame) {
	case XGE_HAL_FRAME_TYPE_DIX:
		ip_off = XGE_HAL_HEADER_ETHERNET_II_802_3_SIZE;
		break;
	case XGE_HAL_FRAME_TYPE_LLC:
		ip_off = (XGE_HAL_HEADER_ETHERNET_II_802_3_SIZE +
			  XGE_HAL_HEADER_802_2_SIZE);
		break;
	case XGE_HAL_FRAME_TYPE_SNAP:
		ip_off = (XGE_HAL_HEADER_ETHERNET_II_802_3_SIZE +
			  XGE_HAL_HEADER_SNAP_SIZE);
		break;
	default: // XGE_HAL_FRAME_TYPE_IPX, etc.
		return XGE_HAL_FAIL;
	}


	if (ext_info->proto & XGE_HAL_FRAME_PROTO_VLAN_TAGGED) {
		ip_off += XGE_HAL_HEADER_VLAN_SIZE;
	}

	/* Grab ip, tcp headers */
	*ip = (iplro_t *)((char*)buffer + ip_off);

	ip_length = (u8)((*ip)->version_ihl & 0x0F);
	ip_length = ip_length <<2;
	*tcp = (tcplro_t *)((unsigned long)*ip + ip_length);

	xge_debug_ring(XGE_TRACE, "ip_length:%d ip:%llx tcp:%llx", (int)ip_length,
	(u64)(unsigned long)*ip, (u64)(unsigned long)*tcp);

	return XGE_HAL_OK;

}

/**
 * xge_hal_lro_free - Used to recycle lro memory.
 * @lro: LRO memory.
 * @hldev: Hal device structure.
 *
 */
__HAL_STATIC_CHANNEL __HAL_INLINE_CHANNEL void
xge_hal_lro_free(lro_t *lro, xge_hal_device_t *hldev)
{
	lro->in_use = 0;
#if 1 // For debug.
	xge_os_memzero(lro, sizeof(lro_t));
#endif
}

/*
 * __hal_lro_malloc - Gets LRO from free memory pool.
 * @hldev: Hal device structure.
 */
__HAL_STATIC_CHANNEL __HAL_INLINE_CHANNEL lro_t *
__hal_lro_malloc(xge_hal_device_t *hldev)
{
	hldev->g_lro_pool->in_use = 1;
	return (hldev->g_lro_pool);
}


/*
 * __hal_get_lro_session: Gets matching LRO session or creates one.
 * @buffer: Ethernet frame.
 * @ip: ip header.
 * @tcp: tcp header.
 * @lro: lro pointer
 * @ext_info: Descriptor info.
 * @hldev: Hal context.
 * Note: Current implementation will contain only one LRO session.
 *       Global lro will not exist once more LRO sessions are permitted.
 */
__HAL_STATIC_CHANNEL __HAL_INLINE_CHANNEL xge_hal_status_e
__hal_get_lro_session (u8 *buffer,
		       iplro_t *ip,
		       tcplro_t *tcp,
		       lro_t **lro,
		       xge_hal_dtr_info_t *ext_info,
		       xge_hal_device_t *hldev)
{
	xge_hal_status_e ret;
	lro_t *g_lro;
	int i, free_slot = -1;

	/***********************************************************
	Search in the pool of LROs for the session that matches the incoming
	frame.
	************************************************************/
	*lro = g_lro = NULL; 
	for (i = 0; i < XGE_HAL_MAX_LRO_SESSIONS; i++) {
		g_lro = &hldev->g_lro_pool[i];

		if (!g_lro->in_use) {	
			if (free_slot == -1)
				free_slot = i;
			continue;
		}	

		/* Match Source address field */
		if ((g_lro->ip_hdr->saddr != ip->saddr))
			continue;
			
		/* Match Destination address field */
		if ((g_lro->ip_hdr->daddr != ip->daddr))
			continue;


		/* Match Source Port field */
		if ((g_lro->tcp_hdr->source != tcp->source))
			continue;
	
			
		/* Match Destination Port field */
		if ((g_lro->tcp_hdr->dest != tcp->dest))
			continue;

		*lro = g_lro;

		if (g_lro->tcp_next_seq_num != xge_os_ntohl(tcp->seq)) {
			xge_debug_ring(XGE_ERR, "**retransmit  **"
						"found***");
			return XGE_HAL_INF_LRO_END_2;
		}

		if (XGE_HAL_OK != __hal_ip_lro_capable(ip, ext_info))
			return XGE_HAL_INF_LRO_END_2;

		if (XGE_HAL_OK != __hal_tcp_lro_capable(ip, tcp)) 
			return XGE_HAL_INF_LRO_END_2;

               	/*
		 * The frame is good, in-sequence, can be LRO-ed;
		 * take its (latest) ACK - unless it is a dupack.
		 * Note: to be exact need to check window size as well..
	 	*/
		if (g_lro->tcp_ack_num == tcp->ack_seq &&
		    g_lro->tcp_seq_num == tcp->seq)
			return XGE_HAL_INF_LRO_END_2;

		g_lro->tcp_seq_num = tcp->seq;
		g_lro->tcp_ack_num = tcp->ack_seq;
		g_lro->frags_len += __hal_tcp_seg_len(ip, tcp);

		return XGE_HAL_INF_LRO_CONT;
	}

	if (free_slot == -1)
		return XGE_HAL_INF_LRO_UNCAPABLE;
	
	g_lro = &hldev->g_lro_pool[free_slot];
	if (XGE_HAL_FAIL == __hal_ip_lro_capable(ip, ext_info))
		return XGE_HAL_INF_LRO_UNCAPABLE;

	if (XGE_HAL_FAIL == __hal_tcp_lro_capable(ip, tcp))
		return XGE_HAL_INF_LRO_UNCAPABLE;
		
	*lro = g_lro;
	xge_debug_ring(XGE_TRACE, "Creating lro session.");

	g_lro->in_use		=	1;
	g_lro->ll_hdr		=	buffer;
	g_lro->ip_hdr		=	ip;
	g_lro->tcp_hdr		=	tcp;
	g_lro->tcp_next_seq_num =	__hal_tcp_seg_len(ip, tcp) +
					xge_os_ntohl(tcp->seq);
	g_lro->tcp_seq_num	=	tcp->seq;
	g_lro->tcp_ack_num	=	tcp->ack_seq;
	g_lro->sg_num		=	1;
	g_lro->total_length	=	xge_os_ntohs(ip->tot_len);
	g_lro->frags_len	=	0;
	hldev->stats.sw_dev_info_stats.tot_frms_lroised++;
		hldev->stats.sw_dev_info_stats.tot_lro_sessions++;

	return XGE_HAL_INF_LRO_BEGIN;
}

/*
 * __hal_lro_under_optimal_thresh: Finds whether combined session is optimal.
 * @ip: ip header.
 * @tcp: tcp header.
 * @lro: lro pointer
 * @hldev: Hal context.
 */
__HAL_STATIC_CHANNEL __HAL_INLINE_CHANNEL xge_hal_status_e
__hal_lro_under_optimal_thresh (iplro_t *ip,
			        tcplro_t *tcp,
				lro_t *lro,
				xge_hal_device_t *hldev)
{
	if (!lro) return XGE_HAL_FAIL;

	if ((lro->total_length + __hal_tcp_seg_len(ip, tcp) ) >
	     CONFIG_LRO_MAX_ACCUM_LENGTH) {
		xge_debug_ring(XGE_TRACE, "Max accumulation length exceeded:  max length %d \n", CONFIG_LRO_MAX_ACCUM_LENGTH);
		return XGE_HAL_FAIL;
	}

	if (lro->sg_num == CONFIG_LRO_MAX_SG_NUM) {
		xge_debug_ring(XGE_TRACE, "Max sg count exceeded:  max sg %d \n", CONFIG_LRO_MAX_SG_NUM);
		return XGE_HAL_FAIL;
	}

	return XGE_HAL_OK;
}

/*
 * __hal_collapse_ip_hdr: Collapses ip header.
 * @ip: ip header.
 * @tcp: tcp header.
 * @lro: lro pointer
 * @hldev: Hal context.
 */
__HAL_STATIC_CHANNEL __HAL_INLINE_CHANNEL xge_hal_status_e
__hal_collapse_ip_hdr ( iplro_t *ip,
			tcplro_t *tcp,
			lro_t *lro,
			xge_hal_device_t *hldev)
{

	lro->total_length += __hal_tcp_seg_len(ip, tcp);

	/* May be we have to handle time stamps or more options */

	return XGE_HAL_OK;

}

/*
 * __hal_collapse_tcp_hdr: Collapses tcp header.
 * @ip: ip header.
 * @tcp: tcp header.
 * @lro: lro pointer
 * @hldev: Hal context.
 */
__HAL_STATIC_CHANNEL __HAL_INLINE_CHANNEL xge_hal_status_e
__hal_collapse_tcp_hdr ( iplro_t *ip,
			 tcplro_t *tcp,
			 lro_t *lro,
			 xge_hal_device_t *hldev)
{

	lro->tcp_next_seq_num += __hal_tcp_seg_len(ip, tcp);
	return XGE_HAL_OK;

}

/*
 * __hal_append_lro: Appends new frame to existing LRO session.
 * @ip: ip header.
 * @tcp: tcp header.
 * @seg_len: tcp payload length.
 * @lro: lro pointer
 * @hldev: Hal context.
 */
__HAL_STATIC_CHANNEL __HAL_INLINE_CHANNEL xge_hal_status_e
__hal_append_lro(iplro_t *ip,
		 tcplro_t **tcp,
		 u32 *seg_len,
		 lro_t *lro,
		 xge_hal_device_t *hldev)
{
	__hal_collapse_ip_hdr(ip, *tcp, lro, hldev);
	__hal_collapse_tcp_hdr(ip, *tcp, lro, hldev);
	// Update mbuf chain will be done in ll driver.
	// xge_hal_accumulate_large_rx on success of appending new frame to
	// lro will return to ll driver tcpdata pointer, and tcp payload length.
	// along with return code lro frame appended.

	lro->sg_num++;
	*seg_len = __hal_tcp_seg_len(ip, *tcp);
	*tcp = (tcplro_t *)((unsigned long)*tcp + (((*tcp)->doff_res)>>2));

	return XGE_HAL_OK;

}

/**
 * xge_hal_accumulate_large_rx: LRO a given frame
 * frames
 * @buffer: Ethernet frame.
 * @tcp: tcp header.
 * @seglen: packet length.
 * @p_lro: lro pointer.
 * @ext_info: descriptor info, see xge_hal_dtr_info_t{}.
 * @hldev: HAL device.
 *
 * LRO the newly received frame, i.e. attach it (if possible) to the
 * already accumulated (i.e., already LRO-ed) received frames (if any),
 * to form one super-sized frame for the subsequent processing
 * by the stack.
 */
__HAL_STATIC_CHANNEL __HAL_INLINE_CHANNEL xge_hal_status_e
xge_hal_accumulate_large_rx(u8 *buffer,
			    u8 **tcp,
			    u32 *seglen,
			    lro_t **p_lro,
			    xge_hal_dtr_info_t *ext_info,
			    xge_hal_device_t *hldev)
{
	iplro_t *ip;
	xge_hal_status_e ret;
	lro_t *lro;

	xge_debug_ring(XGE_TRACE, "Entered accumu lro. ");
	if (XGE_HAL_OK != __hal_lro_capable(buffer, &ip, (tcplro_t **)tcp,
					    ext_info, hldev))
		return XGE_HAL_INF_LRO_UNCAPABLE;

	/*
	 * This function shall get matching LRO or else
	 * create one and return it
	 */
        ret = __hal_get_lro_session(buffer, ip,
                                    (tcplro_t *)*tcp,
                                    p_lro, ext_info, hldev);
	xge_debug_ring(XGE_TRACE, "ret from get_lro:%d ",ret);
	lro = *p_lro;
	if (XGE_HAL_INF_LRO_CONT == ret) {
		if (XGE_HAL_OK == __hal_lro_under_optimal_thresh(ip,
				        (tcplro_t *)*tcp, lro, hldev)) {
			__hal_append_lro(ip,(tcplro_t **) tcp, seglen,
			                 lro,
					 hldev);
			hldev->stats.sw_dev_info_stats.tot_frms_lroised++;

			if (lro->sg_num >= CONFIG_LRO_MAX_SG_NUM)
				ret = XGE_HAL_INF_LRO_END_1;

		} else ret = XGE_HAL_INF_LRO_END_2;
	}

	/*
	 * Since its time to flush,
	 * update ip header so that it can be sent up
	 */
	if ((ret == XGE_HAL_INF_LRO_END_1) ||
	    (ret == XGE_HAL_INF_LRO_END_2)) {
		lro->ip_hdr->tot_len = xge_os_htons((*p_lro)->total_length);
		lro->ip_hdr->check = xge_os_htons(0);
		lro->ip_hdr->check =
		        XGE_LL_IP_FAST_CSUM(((u8 *)(lro->ip_hdr)),
		                (lro->ip_hdr->version_ihl & 0x0F));
		lro->tcp_hdr->ack_seq = lro->tcp_ack_num;
	}

	return (ret);
}

/**
 * xge_hal_lro_exist: Returns LRO list head if any.
 * @hldev: Hal context.
 */
__HAL_STATIC_CHANNEL __HAL_INLINE_CHANNEL lro_t *
xge_hal_lro_exist (xge_hal_device_t *hldev)
{

	if (hldev->g_lro_pool->in_use) {
	/* Since its time to flush, Update ip header so that it can be sent up*/
		lro_t *lro;
		lro = hldev->g_lro_pool;
		lro->ip_hdr->tot_len = xge_os_htons(lro->total_length);
		lro->ip_hdr->check = xge_os_htons(0);
		lro->ip_hdr->check = XGE_LL_IP_FAST_CSUM(((u8 *)(lro->ip_hdr)),
		                        (lro->ip_hdr->version_ihl & 0x0F));
		return (hldev->g_lro_pool);
	}

	return NULL;
}
#endif
