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

#ifndef _NPI_RXDMA_H
#define	_NPI_RXDMA_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <npi.h>

#include "nxge_defs.h"
#include "nxge_hw.h"
#include <nxge_rxdma_hw.h>

/*
 * Register offset (0x200 bytes for each channel) for receive ring registers.
 */
#define	NXGE_RXDMA_OFFSET(x, v, channel) (x + \
		(!v ? DMC_OFFSET(channel) : \
		    RDMC_PIOVADDR_OFFSET(channel)))


#define	 REG_FZC_RDC_OFFSET(reg, rdc) (reg + RX_LOG_DMA_OFFSET(rdc))

#define	 REG_RDC_TABLE_OFFSET(table) \
	    (RDC_TBL_REG + table * (NXGE_MAX_RDCS * 8))

/*
 * RX NPI error codes
 */
#define	RXDMA_ER_ST			(RXDMA_BLK_ID << NPI_BLOCK_ID_SHIFT)
#define	RXDMA_ID_SHIFT(n)		(n << NPI_PORT_CHAN_SHIFT)


#define	NPI_RXDMA_ERROR			RXDMA_ER_ST

#define	NPI_RXDMA_SW_PARAM_ERROR	(NPI_RXDMA_ERROR | 0x40)
#define	NPI_RXDMA_HW_ERROR	(NPI_RXDMA_ERROR | 0x80)

#define	NPI_RXDMA_RDC_INVALID		(NPI_RXDMA_ERROR | CHANNEL_INVALID)
#define	NPI_RXDMA_PAGE_INVALID		(NPI_RXDMA_ERROR | LOGICAL_PAGE_INVALID)
#define	NPI_RXDMA_RESET_ERR		(NPI_RXDMA_HW_ERROR | RESET_FAILED)
#define	NPI_RXDMA_DISABLE_ERR		(NPI_RXDMA_HW_ERROR | 0x0000a)
#define	NPI_RXDMA_ENABLE_ERR		(NPI_RXDMA_HW_ERROR | 0x0000b)
#define	NPI_RXDMA_FUNC_INVALID		(NPI_RXDMA_SW_PARAM_ERROR | 0x0000a)
#define	NPI_RXDMA_BUFSIZE_INVALID	(NPI_RXDMA_SW_PARAM_ERROR | 0x0000b)
#define	NPI_RXDMA_RBRSIZE_INVALID	(NPI_RXDMA_SW_PARAM_ERROR | 0x0000c)
#define	NPI_RXDMA_RCRSIZE_INVALID	(NPI_RXDMA_SW_PARAM_ERROR | 0x0000d)
#define	NPI_RXDMA_PORT_INVALID		(NPI_RXDMA_ERROR | PORT_INVALID)
#define	NPI_RXDMA_TABLE_INVALID		(NPI_RXDMA_ERROR | RDC_TAB_INVALID)

#define	NPI_RXDMA_CHANNEL_INVALID(n)	(RXDMA_ID_SHIFT(n) |	\
					NPI_RXDMA_ERROR | CHANNEL_INVALID)
#define	NPI_RXDMA_OPCODE_INVALID(n)	(RXDMA_ID_SHIFT(n) |	\
					NPI_RXDMA_ERROR | OPCODE_INVALID)


#define	NPI_RXDMA_ERROR_ENCODE(err, rdc)	\
	(RXDMA_ID_SHIFT(rdc) | RXDMA_ER_ST | err)


#define	RXDMA_CHANNEL_VALID(rdc) \
	((rdc < NXGE_MAX_RDCS))

#define	RXDMA_PORT_VALID(port) \
	((port < MAX_PORTS_PER_NXGE))

#define	RXDMA_TABLE_VALID(table) \
	((table < NXGE_MAX_RDC_GROUPS))


#define	RXDMA_PAGE_VALID(page) \
	((page == 0) || (page == 1))

#define	RXDMA_BUFF_OFFSET_VALID(offset) \
	((offset == SW_OFFSET_NO_OFFSET) || \
	    (offset == SW_OFFSET_64) || \
	    (offset == SW_OFFSET_128))

#define	RXDMA_RF_BUFF_OFFSET_VALID(offset) \
	((offset == SW_OFFSET_NO_OFFSET) || \
	    (offset == SW_OFFSET_64) || \
	    (offset == SW_OFFSET_128) || \
	    (offset == SW_OFFSET_192) || \
	    (offset == SW_OFFSET_256) || \
	    (offset == SW_OFFSET_320) || \
	    (offset == SW_OFFSET_384) || \
	    (offset == SW_OFFSET_448))


#define	RXDMA_RCR_TO_VALID(tov) ((tov) && (tov < 64))
#define	RXDMA_RCR_THRESH_VALID(thresh) ((thresh) && (thresh < 512))

/*
 * RXDMA NPI defined control types.
 */
typedef	enum _rxdma_cs_cntl_e {
	RXDMA_CS_CLEAR_ALL		= 0x1,
	RXDMA_MEX_SET			= 0x2,
	RXDMA_RCRTO_CLEAR		= 0x8,
	RXDMA_PT_DROP_PKT_CLEAR		= 0x10,
	RXDMA_WRED_DROP_CLEAR		= 0x20,
	RXDMA_RCR_SFULL_CLEAR		= 0x40,
	RXDMA_RCR_FULL_CLEAR		= 0x80,
	RXDMA_RBR_PRE_EMPTY_CLEAR	= 0x100,
	RXDMA_RBR_EMPTY_CLEAR		= 0x200
} rxdma_cs_cntl_t;

/*
 * RXDMA NPI defined event masks (mapped to the hardware defined masks).
 */
typedef	enum _rxdma_ent_msk_cfg_e {
	CFG_RXDMA_ENT_MSK_CFIGLOGPGE_MASK = RX_DMA_ENT_MSK_CFIGLOGPGE_MASK,
	CFG_RXDMA_ENT_MSK_RBRLOGPGE_MASK  = RX_DMA_ENT_MSK_RBRLOGPGE_MASK,
	CFG_RXDMA_ENT_MSK_RBRFULL_MASK	  = RX_DMA_ENT_MSK_RBRFULL_MASK,
	CFG_RXDMA_ENT_MSK_RBREMPTY_MASK	  = RX_DMA_ENT_MSK_RBREMPTY_MASK,
	CFG_RXDMA_ENT_MSK_RCRFULL_MASK	  = RX_DMA_ENT_MSK_RCRFULL_MASK,
	CFG_RXDMA_ENT_MSK_RCRINCON_MASK	  = RX_DMA_ENT_MSK_RCRINCON_MASK,
	CFG_RXDMA_ENT_MSK_CONFIG_ERR	  = RX_DMA_ENT_MSK_CONFIG_ERR_MASK,
	CFG_RXDMA_ENT_MSK_RCR_SH_FULL_MASK = RX_DMA_ENT_MSK_RCRSH_FULL_MASK,
	CFG_RXDMA_ENT_MSK_RBR_PRE_EMTY_MASK = RX_DMA_ENT_MSK_RBR_PRE_EMPTY_MASK,
	CFG_RXDMA_ENT_MSK_WRED_DROP_MASK   = RX_DMA_ENT_MSK_WRED_DROP_MASK,
	CFG_RXDMA_ENT_MSK_PT_DROP_PKT_MASK = RX_DMA_ENT_MSK_PTDROP_PKT_MASK,
	CFG_RXDMA_ENT_MSK_RBR_PRE_PAR_MASK = RX_DMA_ENT_MSK_RBR_PRE_PAR_MASK,
	CFG_RXDMA_ENT_MSK_RCR_SHA_PAR_MASK = RX_DMA_ENT_MSK_RCR_SHA_PAR_MASK,
	CFG_RXDMA_ENT_MSK_RCRTO_MASK	  = RX_DMA_ENT_MSK_RCRTO_MASK,
	CFG_RXDMA_ENT_MSK_THRES_MASK	  = RX_DMA_ENT_MSK_THRES_MASK,
	CFG_RXDMA_ENT_MSK_DC_FIFO_ERR_MASK  = RX_DMA_ENT_MSK_DC_FIFO_ERR_MASK,
	CFG_RXDMA_ENT_MSK_RCR_ACK_ERR_MASK  = RX_DMA_ENT_MSK_RCR_ACK_ERR_MASK,
	CFG_RXDMA_ENT_MSK_RSP_DAT_ERR_MASK  = RX_DMA_ENT_MSK_RSP_DAT_ERR_MASK,
	CFG_RXDMA_ENT_MSK_BYTE_EN_BUS_MASK  = RX_DMA_ENT_MSK_BYTE_EN_BUS_MASK,
	CFG_RXDMA_ENT_MSK_RSP_CNT_ERR_MASK  = RX_DMA_ENT_MSK_RSP_CNT_ERR_MASK,
	CFG_RXDMA_ENT_MSK_RBR_TMOUT_MASK  = RX_DMA_ENT_MSK_RBR_TMOUT_MASK,

	CFG_RXDMA_MASK_ALL	  = (RX_DMA_ENT_MSK_CFIGLOGPGE_MASK |
					RX_DMA_ENT_MSK_RBRLOGPGE_MASK |
					RX_DMA_ENT_MSK_RBRFULL_MASK |
					RX_DMA_ENT_MSK_RBREMPTY_MASK |
					RX_DMA_ENT_MSK_RCRFULL_MASK |
					RX_DMA_ENT_MSK_RCRINCON_MASK |
					RX_DMA_ENT_MSK_CONFIG_ERR_MASK |
					RX_DMA_ENT_MSK_RCRSH_FULL_MASK |
					RX_DMA_ENT_MSK_RBR_PRE_EMPTY_MASK |
					RX_DMA_ENT_MSK_WRED_DROP_MASK |
					RX_DMA_ENT_MSK_PTDROP_PKT_MASK |
					RX_DMA_ENT_MSK_RBR_PRE_PAR_MASK |
					RX_DMA_ENT_MSK_RCR_SHA_PAR_MASK |
					RX_DMA_ENT_MSK_RCRTO_MASK |
					RX_DMA_ENT_MSK_THRES_MASK |
					RX_DMA_ENT_MSK_DC_FIFO_ERR_MASK |
					RX_DMA_ENT_MSK_RCR_ACK_ERR_MASK |
					RX_DMA_ENT_MSK_RSP_DAT_ERR_MASK |
					RX_DMA_ENT_MSK_BYTE_EN_BUS_MASK |
					RX_DMA_ENT_MSK_RSP_CNT_ERR_MASK |
					RX_DMA_ENT_MSK_RBR_TMOUT_MASK)
} rxdma_ent_msk_cfg_t;



typedef union _addr44 {
	uint64_t	addr;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t rsrvd:20;
		uint32_t hdw:12;
		uint32_t ldw;
#else
		uint32_t ldw;
		uint32_t hdw:12;
		uint32_t rsrvd:20;
#endif
	} bits;
} addr44_t;


/*
 * npi_rxdma_cfg_default_port_rdc()
 * Set the default rdc for the port
 *
 * Inputs:
 *	handle:		register handle interpreted by the underlying OS
 *	portnm:		Physical Port Number
 *	rdc:	RX DMA Channel number
 *
 * Return:
 * NPI_SUCCESS
 * NPI_RXDMA_RDC_INVALID
 * NPI_RXDMA_PORT_INVALID
 *
 */

npi_status_t npi_rxdma_cfg_default_port_rdc(npi_handle_t,
				    uint8_t, uint8_t);

/*
 * npi_rxdma_rdc_table_config
 * Configure/populate the RDC table
 *
 * Inputs:
 *	handle:	register handle interpreted by the underlying OS
 *	table:	RDC Group Number
 *	map:	Bitmap of RDCs to be written to <table>.
 *	count:	A count of the number of bits in <map>.
 *
 * Return:
 * NPI_SUCCESS
 * NPI_RXDMA_TABLE_INVALID
 *
 */

npi_status_t npi_rxdma_rdc_table_config(npi_handle_t, uint8_t, dc_map_t,
    int);

npi_status_t npi_rxdma_cfg_rdc_table_default_rdc(npi_handle_t,
					    uint8_t, uint8_t);
npi_status_t npi_rxdma_cfg_rdc_rcr_timeout_disable(npi_handle_t,
					    uint8_t);


/*
 * npi_rxdma_32bitmode_enable()
 * Enable 32 bit mode
 *
 * Inputs:
 *	handle:		register handle interpreted by the underlying OS
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 *
 */

npi_status_t npi_rxdma_cfg_32bitmode_enable(npi_handle_t);


/*
 * npi_rxdma_32bitmode_disable()
 * disable 32 bit mode
 *
 * Inputs:
 *	handle:		register handle interpreted by the underlying OS
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 *
 */


npi_status_t npi_rxdma_cfg_32bitmode_disable(npi_handle_t);

/*
 * npi_rxdma_cfg_ram_access_enable()
 * Enable PIO access to shadow and prefetch memory.
 * In the case of DMA errors, software may need to
 * initialize the shadow and prefetch memories to
 * sane value (may be clear it) before re-enabling
 * the DMA channel.
 *
 * Inputs:
 *	handle:		register handle interpreted by the underlying OS
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 *
 */

npi_status_t npi_rxdma_cfg_ram_access_enable(npi_handle_t);


/*
 * npi_rxdma_cfg_ram_access_disable()
 * Disable PIO access to shadow and prefetch memory.
 * This is the normal operation mode.
 *
 * Inputs:
 *	handle:		register handle interpreted by the underlying OS
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 *
 */

npi_status_t npi_rxdma_cfg_ram_access_disable(npi_handle_t);


/*
 * npi_rxdma_cfg_clock_div_set()
 * init the clock division, used for RX timers
 * This determines the granularity of RX DMA countdown timers
 * It depends on the system clock. For example if the system
 * clock is 300 MHz, a value of 30000 will yield a granularity
 * of 100usec.
 *
 * Inputs:
 *	handle:		register handle interpreted by the underlying OS
 *	count:		System clock divider
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_SW_ERR
 * NPI_HW_ERR
 *
 */

npi_status_t npi_rxdma_cfg_clock_div_set(npi_handle_t, uint16_t);

/*
 * npi_rxdma_cfg_red_rand_init()
 * init the WRED Discard
 * By default, it is enabled
 *
 * Inputs:
 *	handle:		register handle interpreted by the underlying OS
 *	init_value:	WRED init value
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_SW_ERR
 * NPI_HW_ERR
 *
 */

npi_status_t npi_rxdma_cfg_red_rand_init(npi_handle_t, uint16_t);

/*
 * npi_rxdma_cfg_wred_disable()
 * init the WRED Discard
 * By default, it is enabled
 *
 * Inputs:
 *	handle:		register handle interpreted by the underlying OS
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_SW_ERR
 * NPI_HW_ERR
 *
 */


npi_status_t npi_rxdma_cfg_wred_disable(npi_handle_t);

/*
 * npi_rxdma_cfg_wred_param()
 * COnfigure per rxdma channel WRED parameters
 * By default, it is enabled
 *
 * Inputs:
 *	handle:		register handle interpreted by the underlying OS
 *	rdc:	RX DMA Channel number
 *	wred_params:	WRED configuration parameters
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_SW_ERR
 * NPI_HW_ERR
 *
 */



npi_status_t npi_rxdma_cfg_wred_param(npi_handle_t, uint8_t,
				    rdc_red_para_t *);


/*
 * npi_rxdma_port_ddr_weight
 * Set the DDR weight for a port.
 *
 * Inputs:
 *	handle:		register handle interpreted by the underlying OS
 *	portnm:		Physical Port Number
 *	weight:		Port relative weight (in approx. bytes)
 *			Default values are:
 *			0x400 (port 0 and 1) corresponding to 10 standard
 *			      size (1500 bytes) Frames
 *			0x66 (port 2 and 3) corresponding to 10% 10Gig ports
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_rxdma_cfg_port_ddr_weight(npi_handle_t,
				    uint8_t, uint32_t);


/*
 * npi_rxdma_port_usage_get()
 * Gets the port usage, in terms of 16 byte blocks
 *
 * NOTE: The register count is cleared upon reading.
 *
 * Inputs:
 *	handle:		register handle interpreted by the underlying OS
 *	portnm:		Physical Port Number
 *	blocks:		ptr to save current count.
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_rxdma_port_usage_get(npi_handle_t,
				    uint8_t, uint32_t *);


/*
 * npi_rxdma_cfg_logical_page()
 * Configure per rxdma channel Logical page
 *
 * To disable the logical page, set valid = 0;
 *
 * Inputs:
 *	handle:		register handle interpreted by the underlying OS
 *	rdc:		RX DMA Channel number
 *	page_params:	Logical Page configuration parameters
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_SW_ERR
 * NPI_HW_ERR
 *
 */



npi_status_t npi_rxdma_cfg_logical_page(npi_handle_t, uint8_t,
				    dma_log_page_t *);


/*
 * npi_rxdma_cfg_logical_page_handle()
 * Configure per rxdma channel Logical page handle
 *
 *
 * Inputs:
 *	handle:		register handle interpreted by the underlying OS
 *	rdc:		RX DMA Channel number
 *	pg_handle:	Logical Page handle
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_SW_ERR
 * NPI_HW_ERR
 *
 */


npi_status_t npi_rxdma_cfg_logical_page_handle(npi_handle_t, uint8_t,
				    uint64_t);




npi_status_t npi_rxdma_cfg_logical_page_disable(npi_handle_t,
				    uint8_t, uint8_t);

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



/*
 * npi_rxdma_cfg_rdc_ring()
 * Configure The RDC channel Rcv Buffer Ring
 *
 * Inputs:
 *	rdc:		RX DMA Channel number
 *	rdc_params:	RDC configuration parameters
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_SW_ERR
 * NPI_HW_ERR
 *
 */

typedef struct _rdc_desc_cfg_t {
	uint8_t mbox_enable;	/* Enable full (18b) header */
	uint8_t full_hdr;	/* Enable full (18b) header */
	uint8_t offset;	/* 64 byte offsets */
	uint8_t valid2;	/* size 2 is valid */
	bsize_t size2;	/* Size 2 length */
	uint8_t valid1;	/* size 1 is valid */
	bsize_t size1;	/* Size 1 length */
	uint8_t valid0;	/* size 0 is valid */
	bsize_t size0;	/* Size 1 length */
	bsize_t page_size;   /* Page or buffer Size */
    uint8_t	rcr_timeout_enable;
    uint8_t	rcr_timeout;
    uint16_t	rcr_threshold;
	uint16_t rcr_len;	   /* RBR Descriptor size (entries) */
	uint16_t rbr_len;	   /* RBR Descriptor size (entries) */
	uint64_t mbox_addr;	   /* Mailbox Address */
	uint64_t rcr_addr;	   /* RCR Address */
	uint64_t rbr_addr;	   /* RBB Address */
} rdc_desc_cfg_t;



npi_status_t npi_rxdma_cfg_rdc_ring(npi_handle_t, uint8_t,
				    rdc_desc_cfg_t *, boolean_t);




/*
 * npi_rxdma_rdc_rcr_flush
 * Forces RX completion ring update
 *
 * Inputs:
 *	rdc:		RX DMA Channel number
 *
 * Return:
 *
 */

#define	npi_rxdma_rdc_rcr_flush(handle, rdc) \
	RXDMA_REG_WRITE64(handle, RCR_FLSH_REG, rdc, \
		    (RCR_FLSH_SET << RCR_FLSH_SHIFT))



/*
 * npi_rxdma_rdc_rcr_read_update
 * Update the number of rcr packets and buffers processed
 *
 * Inputs:
 *	channel:	RX DMA Channel number
 *	num_pkts:	Number of pkts processed by SW.
 *			    A packet could constitute multiple
 *			    buffers, in case jumbo packets.
 *	num_bufs:	Number of buffer processed by SW.
 *
 * Return:
 *	NPI_FAILURE		-
 *		NPI_RXDMA_OPCODE_INVALID	-
 *		NPI_RXDMA_CHANNEL_INVALID	-
 *
 */

npi_status_t npi_rxdma_rdc_rcr_read_update(npi_handle_t, uint8_t,
				    uint16_t, uint16_t);
/*
 * npi_rxdma_rdc_rcr_pktread_update
 * Update the number of packets processed
 *
 * Inputs:
 *	channel:	RX DMA Channel number
 *	num_pkts:	Number ofpkts processed by SW.
 *			A packet could constitute multiple
 *			buffers, in case jumbo packets.
 *
 * Return:
 *	NPI_FAILURE		-
 *		NPI_RXDMA_OPCODE_INVALID	-
 *		NPI_RXDMA_CHANNEL_INVALID	-
 *
 */

npi_status_t npi_rxdma_rdc_rcr_pktread_update(npi_handle_t,
					uint8_t, uint16_t);



/*
 * npi_rxdma_rdc_rcr_bufread_update
 * Update the number of buffers processed
 *
 * Inputs:
 *	channel:		RX DMA Channel number
 *	num_bufs:	Number of buffer processed by SW. Multiple buffers
 *   could be part of a single packet.
 *
 * Return:
 *	NPI_FAILURE		-
 *		NPI_RXDMA_OPCODE_INVALID	-
 *		NPI_RXDMA_CHANNEL_INVALID	-
 *
 */

npi_status_t npi_rxdma_rdc_rcr_bufread_update(npi_handle_t,
					uint8_t, uint16_t);



/*
 * npi_rxdma_rdc_rbr_kick
 * Kick RDC RBR
 *
 * Inputs:
 *	rdc:		RX DMA Channel number
 *	num_buffers:	Number of Buffers posted to the RBR
 *
 * Return:
 *
 */

#define	npi_rxdma_rdc_rbr_kick(handle, rdc, num_buffers) \
	RXDMA_REG_WRITE64(handle, RBR_KICK_REG, rdc, num_buffers)


/*
 * npi_rxdma_rdc_rbr_head_get
 * Gets the current rbr head pointer.
 *
 * Inputs:
 *	rdc:		RX DMA Channel number
 *	hdptr		ptr to write the rbr head value
 *
 * Return:
 *
 */

npi_status_t npi_rxdma_rdc_rbr_head_get(npi_handle_t,
				    uint8_t, addr44_t  *);



/*
 * npi_rxdma_rdc_rbr_stat_get
 * Returns the RBR stat. The stat consists of the
 * RX buffers in the ring. It also indicates if there
 * has been an overflow.
 *
 * Inputs:
 *	rdc:		RX DMA Channel number
 *	rbr_stat_t:	Structure to update stat
 *
 * Return:
 *
 */

npi_status_t npi_rxdma_rdc_rbr_stat_get(npi_handle_t, uint8_t,
				    rbr_stat_t *);



/*
 * npi_rxdma_cfg_rdc_reset
 * Resets the RDC channel
 *
 * Inputs:
 *	rdc:		RX DMA Channel number
 *
 * Return:
 *
 */

npi_status_t npi_rxdma_cfg_rdc_reset(npi_handle_t, uint8_t);


/*
 * npi_rxdma_rdc_enable
 * Enables the RDC channel
 *
 * Inputs:
 *	rdc:		RX DMA Channel number
 *
 * Return:
 *
 */

npi_status_t npi_rxdma_cfg_rdc_enable(npi_handle_t, uint8_t);

/*
 * npi_rxdma_rdc_disable
 * Disables the RDC channel
 *
 * Inputs:
 *	rdc:		RX DMA Channel number
 *
 * Return:
 *
 */

npi_status_t npi_rxdma_cfg_rdc_disable(npi_handle_t, uint8_t);


/*
 * npi_rxdma_cfg_rdc_rcr_timeout()
 * Configure The RDC channel completion ring timeout.
 * If a frame has been received, an event would be
 * generated atleast at the expiration of the timeout.
 *
 * Enables timeout by default.
 *
 * Inputs:
 *	rdc:		RX DMA Channel number
 *	rcr_timeout:	Completion Ring timeout value
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_SW_ERR
 * NPI_HW_ERR
 *
 */

npi_status_t npi_rxdma_cfg_rdc_rcr_timeout(npi_handle_t, uint8_t,
				    uint8_t);


/*
 * npi_rxdma_cfg_rdc_rcr_threshold()
 * Configure The RDC channel completion ring threshold.
 * An event would be If the number of frame received,
 * surpasses the threshold value
 *
 * Inputs:
 *	rdc:		RX DMA Channel number
 *	rcr_threshold:	Completion Ring Threshold count
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_SW_ERR
 * NPI_HW_ERR
 *
 */

npi_status_t npi_rxdma_cfg_rdc_rcr_threshold(npi_handle_t, uint8_t,
				    uint16_t);


npi_status_t npi_rxdma_cfg_rdc_rcr_timeout_disable(npi_handle_t, uint8_t);

typedef struct _rdc_error_stat_t {
	uint8_t fault:1;
    uint8_t	multi_fault:1;
    uint8_t	rbr_fault:1;
    uint8_t	buff_fault:1;
    uint8_t	rcr_fault:1;
	addr44_t fault_addr;
} rdc_error_stat_t;

#if OLD
/*
 * npi_rxdma_rdc_error_stat_get
 * Gets the current Error stat for the RDC.
 *
 * Inputs:
 *	rdc:		RX DMA Channel number
 *	error_stat	Structure to write current RDC Error stat
 *
 * Return:
 *
 */

npi_status_t npi_rxdma_rdc_error_stat_get(npi_handle_t,
				    uint8_t, rdc_error_stat_t *);

#endif

/*
 * npi_rxdma_rdc_rcr_tail_get
 * Gets the current RCR tail address for the RDC.
 *
 * Inputs:
 *	rdc:		RX DMA Channel number
 *	tail_addr	Structure to write current RDC RCR tail address
 *
 * Return:
 *
 */

npi_status_t npi_rxdma_rdc_rcr_tail_get(npi_handle_t,
				    uint8_t, addr44_t *);


npi_status_t npi_rxdma_rdc_rcr_qlen_get(npi_handle_t,
				    uint8_t, uint16_t *);



typedef struct _rdc_discard_stat_t {
    uint8_t	nobuf_ovflow;
    uint8_t	red_ovflow;
    uint32_t	nobuf_discard;
    uint32_t	red_discard;
} rdc_discard_stat_t;


/*
 * npi_rxdma_rdc_discard_stat_get
 * Gets the current discrad stats for the RDC.
 *
 * Inputs:
 *	rdc:		RX DMA Channel number
 *	rcr_stat	Structure to write current RDC discard stat
 *
 * Return:
 *
 */

npi_status_t npi_rxdma_rdc_discard_stat_get(npi_handle_t,
				    uint8_t, rdc_discard_stat_t);


/*
 * npi_rx_port_discard_stat_get
 * Gets the current input (IPP) discrad stats for the rx port.
 *
 * Inputs:
 *	rdc:		RX DMA Channel number
 *	rx_disc_cnt_t	Structure to write current RDC discard stat
 *
 * Return:
 *
 */

npi_status_t npi_rx_port_discard_stat_get(npi_handle_t,
				    uint8_t,
				    rx_disc_cnt_t *);


/*
 * npi_rxdma_red_discard_stat_get
 * Gets the current discrad count due RED
 * The counter overflow bit is cleared, if it has been set.
 *
 * Inputs:
 *	rdc:		RX DMA Channel number
 *	rx_disc_cnt_t	Structure to write current RDC discard stat
 *
 * Return:
 * NPI_SUCCESS
 * NPI_RXDMA_RDC_INVALID
 *
 */

npi_status_t npi_rxdma_red_discard_stat_get(npi_handle_t, uint8_t,
				    rx_disc_cnt_t *);



/*
 * npi_rxdma_red_discard_oflow_clear
 * Clear RED discard counter overflow bit
 *
 * Inputs:
 *	rdc:		RX DMA Channel number
 *
 * Return:
 * NPI_SUCCESS
 * NPI_RXDMA_RDC_INVALID
 *
 */

npi_status_t npi_rxdma_red_discard_oflow_clear(npi_handle_t,
					uint8_t);




/*
 * npi_rxdma_misc_discard_stat_get
 * Gets the current discrad count for the rdc due to
 * buffer pool empty
 * The counter overflow bit is cleared, if it has been set.
 *
 * Inputs:
 *	rdc:		RX DMA Channel number
 *	rx_disc_cnt_t	Structure to write current RDC discard stat
 *
 * Return:
 * NPI_SUCCESS
 * NPI_RXDMA_RDC_INVALID
 *
 */

npi_status_t npi_rxdma_misc_discard_stat_get(npi_handle_t, uint8_t,
				    rx_disc_cnt_t *);



/*
 * npi_rxdma_red_discard_oflow_clear
 * Clear RED discard counter overflow bit
 * clear the overflow bit for  buffer pool empty discrad counter
 * for the rdc
 *
 *
 * Inputs:
 *	rdc:		RX DMA Channel number
 *
 * Return:
 * NPI_SUCCESS
 * NPI_RXDMA_RDC_INVALID
 *
 */

npi_status_t npi_rxdma_misc_discard_oflow_clear(npi_handle_t,
					uint8_t);



/*
 * npi_rxdma_ring_perr_stat_get
 * Gets the current RDC Memory parity error
 * The counter overflow bit is cleared, if it has been set.
 *
 * Inputs:
 * pre_cnt:	Structure to write current RDC Prefetch memory
 *		Parity Error stat
 * sha_cnt:	Structure to write current RDC Shadow memory
 *		Parity Error stat
 *
 * Return:
 * NPI_SUCCESS
 * NPI_RXDMA_RDC_INVALID
 *
 */

npi_status_t npi_rxdma_ring_perr_stat_get(npi_handle_t,
				    rdmc_par_err_log_t *,
				    rdmc_par_err_log_t *);


/*
 * npi_rxdma_ring_perr_stat_get
 * Clear RDC Memory Parity Error counter overflow bits
 *
 * Inputs:
 * Return:
 * NPI_SUCCESS
 *
 */

npi_status_t npi_rxdma_ring_perr_stat_clear(npi_handle_t);


/* Access the RDMC Memory: used for debugging */

npi_status_t npi_rxdma_rdmc_memory_io(npi_handle_t,
			    rdmc_mem_access_t *, uint8_t);



/*
 * npi_rxdma_rxctl_fifo_error_intr_set
 * Configure The RX ctrl fifo error interrupt generation
 *
 * Inputs:
 *	mask:	rx_ctl_dat_fifo_mask_t specifying the errors
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 *
 */

npi_status_t npi_rxdma_rxctl_fifo_error_intr_set(npi_handle_t,
				    rx_ctl_dat_fifo_mask_t *);

/*
 * npi_rxdma_rxctl_fifo_error_status_get
 * Read The RX ctrl fifo error Status
 *
 * Inputs:
 *	stat:	rx_ctl_dat_fifo_stat_t to read the errors to
 * valid fields in  rx_ctl_dat_fifo_stat_t structure are:
 * zcp_eop_err, ipp_eop_err, id_mismatch.
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 *
 */

npi_status_t npi_rxdma_rxctl_fifo_error_status_get(npi_handle_t,
				    rx_ctl_dat_fifo_stat_t *);


/*
 * npi_rxdma_channel_mex_set():
 *	This function is called to arm the DMA channel with
 *	mailbox updating capability. Software needs to rearm
 *	for each update by writing to the control and status register.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical RXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 *
 * Return:
 *	NPI_SUCCESS		- If enable channel with mailbox update
 *				  is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE	-
 *		NPI_RXDMA_CHANNEL_INVALID -
 */
npi_status_t npi_rxdma_channel_mex_set(npi_handle_t, uint8_t);

/*
 * npi_rxdma_channel_rcrto_clear():
 *	This function is called to reset RCRTO bit to 0.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical RXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 * Return:
 *	NPI_SUCCESS
 *
 *	Error:
 *	NPI_FAILURE	-
 *		NPI_RXDMA_CHANNEL_INVALID -
 */
npi_status_t npi_rxdma_channel_rcrto_clear(npi_handle_t, uint8_t);

/*
 * npi_rxdma_channel_pt_drop_pkt_clear():
 *	This function is called to clear the port drop packet bit (debug).
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical RXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 * Return:
 *	NPI_SUCCESS
 *
 *	Error:
 *	NPI_FAILURE	-
 *		NPI_RXDMA_CHANNEL_INVALID -
 */
npi_status_t npi_rxdma_channel_pt_drop_pkt_clear(npi_handle_t, uint8_t);

/*
 * npi_rxdma_channel_wred_drop_clear():
 *	This function is called to wred drop bit (debug only).
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical RXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 * Return:
 *	NPI_SUCCESS
 *
 *	Error:
 *	NPI_FAILURE	-
 *		NPI_RXDMA_CHANNEL_INVALID -
 */
npi_status_t npi_rxdma_channel_wred_drop_clear(npi_handle_t, uint8_t);

/*
 * npi_rxdma_channel_rcr_shfull_clear():
 *	This function is called to clear RCR shadow full bit.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical RXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 * Return:
 *	NPI_SUCCESS
 *
 *	Error:
 *	NPI_FAILURE	-
 *		NPI_RXDMA_CHANNEL_INVALID -
 */
npi_status_t npi_rxdma_channel_rcr_shfull_clear(npi_handle_t, uint8_t);

/*
 * npi_rxdma_channel_rcrfull_clear():
 *	This function is called to clear RCR full bit.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical RXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 * Return:
 *	NPI_SUCCESS
 *
 *	Error:
 *	NPI_FAILURE	-
 *		NPI_RXDMA_CHANNEL_INVALID -
 */
npi_status_t npi_rxdma_channel_rcrfull_clear(npi_handle_t, uint8_t);

/*
 * npi_rxdma_rbr_pre_empty_clear():
 *	This function is called to control a receive DMA channel
 *	for arming the channel with mailbox updates, resetting
 *	various event status bits (control and status register).
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	control		- NPI defined control type supported:
 *				- RXDMA_MEX_SET
 * 				- RXDMA_RCRTO_CLEAR
 *				- RXDMA_PT_DROP_PKT_CLEAR
 *				- RXDMA_WRED_DROP_CLEAR
 *				- RXDMA_RCR_SFULL_CLEAR
 *				- RXDMA_RCR_FULL_CLEAR
 *				- RXDMA_RBR_PRE_EMPTY_CLEAR
 *	channel		- logical RXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware.
 * Return:
 *	NPI_SUCCESS
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_RXDMA_CHANNEL_INVALID -
 */
npi_status_t npi_rxdma_channel_rbr_pre_empty_clear(npi_handle_t, uint8_t);

/*
 * npi_rxdma_channel_control():
 *	This function is called to control a receive DMA channel
 *	for arming the channel with mailbox updates, resetting
 *	various event status bits (control and status register).
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	control		- NPI defined control type supported:
 *				- RXDMA_MEX_SET
 * 				- RXDMA_RCRTO_CLEAR
 *				- RXDMA_PT_DROP_PKT_CLEAR
 *				- RXDMA_WRED_DROP_CLEAR
 *				- RXDMA_RCR_SFULL_CLEAR
 *				- RXDMA_RCR_FULL_CLEAR
 *				- RXDMA_RBR_PRE_EMPTY_CLEAR
 *	channel		- logical RXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware.
 * Return:
 *	NPI_SUCCESS
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_TXDMA_OPCODE_INVALID	-
 *		NPI_TXDMA_CHANNEL_INVALID	-
 */
npi_status_t npi_rxdma_channel_control(npi_handle_t,
				rxdma_cs_cntl_t, uint8_t);

/*
 * npi_rxdma_control_status():
 *	This function is called to operate on the control
 *	and status register.
 *
 * Parameters:
 *	handle		- NPI handle
 *	op_mode		- OP_GET: get hardware control and status
 *			  OP_SET: set hardware control and status
 *			  OP_UPDATE: update hardware control and status.
 *			  OP_CLEAR: clear control and status register to 0s.
 *	channel		- hardware RXDMA channel from 0 to 23.
 *	cs_p		- pointer to hardware defined control and status
 *			  structure.
 * Return:
 *	NPI_SUCCESS
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_RXDMA_OPCODE_INVALID	-
 *		NPI_RXDMA_CHANNEL_INVALID	-
 */
npi_status_t npi_rxdma_control_status(npi_handle_t, io_op_t,
			uint8_t, p_rx_dma_ctl_stat_t);

/*
 * npi_rxdma_event_mask():
 *	This function is called to operate on the event mask
 *	register which is used for generating interrupts.
 *
 * Parameters:
 *	handle		- NPI handle
 *	op_mode		- OP_GET: get hardware event mask
 *			  OP_SET: set hardware interrupt event masks
 *			  OP_CLEAR: clear control and status register to 0s.
 *	channel		- hardware RXDMA channel from 0 to 23.
 *	mask_p		- pointer to hardware defined event mask
 *			  structure.
 * Return:
 *	NPI_SUCCESS		- If set is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_RXDMA_OPCODE_INVALID	-
 *		NPI_RXDMA_CHANNEL_INVALID	-
 */
npi_status_t npi_rxdma_event_mask(npi_handle_t, io_op_t,
		uint8_t, p_rx_dma_ent_msk_t);

/*
 * npi_rxdma_event_mask_config():
 *	This function is called to operate on the event mask
 *	register which is used for generating interrupts
 *	and status register.
 *
 * Parameters:
 *	handle		- NPI handle
 *	op_mode		- OP_GET: get hardware event mask
 *			  OP_SET: set hardware interrupt event masks
 *			  OP_CLEAR: clear control and status register to 0s.
 *	channel		- hardware RXDMA channel from 0 to 23.
 *	cfgp		- pointer to NPI defined event mask
 *			  enum data type.
 * Return:
 *	NPI_SUCCESS		- If set is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_RXDMA_OPCODE_INVALID	-
 *		NPI_RXDMA_CHANNEL_INVALID	-
 */
npi_status_t npi_rxdma_event_mask_config(npi_handle_t, io_op_t,
		uint8_t, rxdma_ent_msk_cfg_t *);


/*
 * npi_rxdma_dump_rdc_regs
 * Dumps the contents of rdc csrs and fzc registers
 *
 * Input:
 *         rdc:      RX DMA number
 *
 * return:
 *     NPI_SUCCESS
 *     NPI_FAILURE
 *     NPI_RXDMA_RDC_INVALID
 *
 */

npi_status_t npi_rxdma_dump_rdc_regs(npi_handle_t, uint8_t);


/*
 * npi_rxdma_dump_fzc_regs
 * Dumps the contents of rdc csrs and fzc registers
 *
 * Input:
 *         rdc:      RX DMA number
 *
 * return:
 *     NPI_SUCCESS
 *     NPI_FAILURE
 *     NPI_RXDMA_RDC_INVALID
 *
 */

npi_status_t npi_rxdma_dump_fzc_regs(npi_handle_t);

npi_status_t npi_rxdma_channel_rbr_empty_clear(npi_handle_t,
							uint8_t);
npi_status_t npi_rxdma_rxctl_fifo_error_intr_get(npi_handle_t,
				rx_ctl_dat_fifo_stat_t *);

npi_status_t npi_rxdma_rxctl_fifo_error_intr_set(npi_handle_t,
				rx_ctl_dat_fifo_mask_t *);

npi_status_t npi_rxdma_dump_rdc_table(npi_handle_t, uint8_t);
#ifdef	__cplusplus
}
#endif

#endif	/* _NPI_RXDMA_H */
