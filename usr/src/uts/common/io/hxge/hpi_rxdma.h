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

#ifndef _HPI_RXDMA_H
#define	_HPI_RXDMA_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <hpi.h>
#include <hxge_defs.h>
#include <hxge_pfc.h>
#include <hxge_pfc_hw.h>
#include <hxge_rdc_hw.h>

#define	RXDMA_CFIG2_MBADDR_L_SHIFT	6	/* bit 31:6 */
#define	RXDMA_CFIG2_MBADDR_L_MASK	0x00000000ffffffc0ULL

#define	RBR_CFIG_A_STDADDR_MASK		0x000000000003ffc0ULL
#define	RBR_CFIG_A_STDADDR_BASE_MASK    0x00000ffffffc0000ULL

#define	RCRCFIG_A_STADDR_SHIFT		6	/* bit 18:6 */
#define	RCRCFIG_A_STADDR_MASK		0x000000000007FFC0ULL
#define	RCRCFIG_A_STADDR_BASE_SHIF	19	/* bit 43:19 */
#define	RCRCFIG_A_STADDR_BASE_MASK	0x00000FFFFFF80000ULL
#define	RCRCFIG_A_LEN_SHIF		48	/* bit 63:48 */
#define	RCRCFIG_A_LEN_MASK		0xFFFF000000000000ULL

#define	RCR_FLSH_SHIFT			0	/* RW, bit 0:0 */
#define	RCR_FLSH_SET			0x0000000000000001ULL
#define	RCR_FLSH_MASK			0x0000000000000001ULL

#define	RBR_CFIG_A_LEN_SHIFT		48	/* bits 63:48 */
#define	RBR_CFIG_A_LEN_MASK		0xFFFF000000000000ULL

/*
 * Buffer block descriptor
 */
typedef struct _rx_desc_t {
	uint32_t	block_addr;
} rx_desc_t, *p_rx_desc_t;

typedef enum _bsize {
	SIZE_0B = 0x0,
	SIZE_64B,
	SIZE_128B,
	SIZE_192B,
	SIZE_256B,
	SIZE_512B,
	SIZE_1KB,
	SIZE_2KB,
	SIZE_4KB,
	SIZE_8KB,
	SIZE_16KB,
	SIZE_32KB
} bsize_t;

typedef struct _rdc_desc_cfg_t {
	uint8_t mbox_enable;		/* Enable full (18b) header */
	uint8_t full_hdr;		/* Enable full (18b) header */
	uint8_t offset;			/* 64 byte offsets */
	uint8_t valid2;			/* size 2 is valid */
	bsize_t size2;			/* Size 2 length */
	uint8_t valid1;			/* size 1 is valid */
	bsize_t size1;			/* Size 1 length */
	uint8_t valid0;			/* size 0 is valid */
	bsize_t size0;			/* Size 1 length */
	bsize_t page_size;		/* Page or buffer Size */
	uint8_t	rcr_timeout_enable;
	uint8_t	rcr_timeout;
	uint16_t rcr_threshold;
	uint16_t rcr_len;		/* RBR Descriptor size (entries) */
	uint16_t rbr_len;		/* RBR Descriptor size (entries) */
	uint64_t mbox_addr;		/* Mailbox Address */
	uint64_t rcr_addr;		/* RCR Address */
	uint64_t rbr_addr;		/* RBB Address */
} rdc_desc_cfg_t;


/*
 * Register offset (0x800 bytes for each channel) for receive ring registers.
 */
#define	HXGE_RXDMA_OFFSET(x, v, channel) (x + \
		(!v ? DMC_OFFSET(channel) : \
		    RDMC_PIOVADDR_OFFSET(channel)))

#define	RXDMA_REG_READ64(handle, reg, channel, data_p) {\
	HXGE_REG_RD64(handle, (HXGE_RXDMA_OFFSET(reg, handle.is_vraddr,\
		channel)), (data_p))\
}

#define	RXDMA_REG_READ32(handle, reg, channel, data_p) \
	HXGE_REG_RD32(handle, (HXGE_RXDMA_OFFSET(reg, handle.is_vraddr,\
		channel)), (data_p))

#define	RXDMA_REG_WRITE64(handle, reg, channel, data) {\
	HXGE_REG_WR64(handle, (HXGE_RXDMA_OFFSET(reg, handle.is_vraddr,\
		channel)), (data))\
}

/*
 * RX HPI error codes
 */
#define	RXDMA_ER_ST			(RXDMA_BLK_ID << HPI_BLOCK_ID_SHIFT)
#define	RXDMA_ID_SHIFT(n)		(n << HPI_PORT_CHAN_SHIFT)

#define	HPI_RXDMA_ERROR			RXDMA_ER_ST

#define	HPI_RXDMA_SW_PARAM_ERROR	(HPI_RXDMA_ERROR | 0x40)
#define	HPI_RXDMA_HW_ERROR		(HPI_RXDMA_ERROR | 0x80)

#define	HPI_RXDMA_RDC_INVALID		(HPI_RXDMA_ERROR | CHANNEL_INVALID)
#define	HPI_RXDMA_RESET_ERR		(HPI_RXDMA_HW_ERROR | RESET_FAILED)
#define	HPI_RXDMA_BUFSZIE_INVALID	(HPI_RXDMA_SW_PARAM_ERROR | 0x0000b)
#define	HPI_RXDMA_RBRSZIE_INVALID	(HPI_RXDMA_SW_PARAM_ERROR | 0x0000c)
#define	HPI_RXDMA_RCRSZIE_INVALID	(HPI_RXDMA_SW_PARAM_ERROR | 0x0000d)

#define	HPI_RXDMA_CHANNEL_INVALID(n)	(RXDMA_ID_SHIFT(n) |	\
					HPI_RXDMA_ERROR | CHANNEL_INVALID)
#define	HPI_RXDMA_OPCODE_INVALID(n)	(RXDMA_ID_SHIFT(n) |	\
					HPI_RXDMA_ERROR | OPCODE_INVALID)

#define	HPI_RXDMA_ERROR_ENCODE(err, rdc)	\
	(RXDMA_ID_SHIFT(rdc) | RXDMA_ER_ST | err)

#define	RXDMA_CHANNEL_VALID(rdc) \
	((rdc < HXGE_MAX_RDCS))

#define	RXDMA_BUFF_OFFSET_VALID(offset) \
	((offset == SW_OFFSET_NO_OFFSET) || \
	    (offset == SW_OFFSET_64) || \
	    (offset == SW_OFFSET_128))

#define	RXDMA_RCR_TO_VALID(tov) ((tov) && (tov < 64))
#define	RXDMA_RCR_THRESH_VALID(thresh) ((thresh <= 0x8000))

#define	hpi_rxdma_rdc_rcr_flush(handle, rdc) \
	RXDMA_REG_WRITE64(handle, RDC_RCR_FLUSH, rdc, \
		    (RCR_FLSH_SET << RCR_FLSH_SHIFT))
#define	hpi_rxdma_rdc_rbr_kick(handle, rdc, num_buffers) \
	RXDMA_REG_WRITE64(handle, RDC_RBR_KICK, rdc, num_buffers)

hpi_status_t hpi_rxdma_cfg_rdc_wait_for_qst(hpi_handle_t handle, uint8_t rdc);
hpi_status_t hpi_rxdma_cfg_rdc_ring(hpi_handle_t handle, uint8_t rdc,
    rdc_desc_cfg_t *rdc_desc_params);
hpi_status_t hpi_rxdma_cfg_clock_div_set(hpi_handle_t handle, uint16_t count);
hpi_status_t hpi_rxdma_cfg_logical_page_handle(hpi_handle_t handle, uint8_t rdc,
    uint64_t pg_handle);

hpi_status_t hpi_rxdma_rdc_rbr_stat_get(hpi_handle_t handle, uint8_t rdc,
    rdc_rbr_qlen_t *rbr_stat);
hpi_status_t hpi_rxdma_cfg_rdc_reset(hpi_handle_t handle, uint8_t rdc);
hpi_status_t hpi_rxdma_cfg_rdc_enable(hpi_handle_t handle, uint8_t rdc);
hpi_status_t hpi_rxdma_cfg_rdc_disable(hpi_handle_t handle, uint8_t rdc);
hpi_status_t hpi_rxdma_cfg_rdc_rcr_timeout(hpi_handle_t handle, uint8_t rdc,
    uint8_t rcr_timeout);

hpi_status_t hpi_rxdma_cfg_rdc_rcr_threshold(hpi_handle_t handle, uint8_t rdc,
    uint16_t rcr_threshold);
hpi_status_t hpi_rxdma_rdc_rcr_qlen_get(hpi_handle_t handle,
    uint8_t rdc,  uint16_t *qlen);

hpi_status_t hpi_rxdma_ring_perr_stat_get(hpi_handle_t handle,
    rdc_pref_par_log_t *pre_log, rdc_pref_par_log_t *sha_log);

hpi_status_t hpi_rxdma_control_status(hpi_handle_t handle, io_op_t op_mode,
    uint8_t channel, rdc_stat_t *cs_p);
hpi_status_t hpi_rxdma_event_mask(hpi_handle_t handle, io_op_t op_mode,
    uint8_t channel, rdc_int_mask_t *mask_p);
hpi_status_t hpi_rxdma_channel_rbr_empty_clear(hpi_handle_t handle,
    uint8_t channel);

#ifdef	__cplusplus
}
#endif

#endif	/* _HPI_RXDMA_H */
