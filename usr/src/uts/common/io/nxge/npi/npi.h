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

#ifndef _NPI_H
#define	_NPI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <nxge_common_impl.h>

typedef	uint32_t			npi_status_t;

/* Common Block ID */

#define	MAC_BLK_ID			0x1
#define	TXMAC_BLK_ID			0x2
#define	RXMAC_BLK_ID			0x3
#define	MIF_BLK_ID			0x4
#define	IPP_BLK_ID			0x5
#define	TXC_BLK_ID			0x6
#define	TXDMA_BLK_ID			0x7
#define	RXDMA_BLK_ID			0x8
#define	ZCP_BLK_ID			0x9
#define	ESPC_BLK_ID			0xa
#define	FFLP_BLK_ID			0xb
#define	PHY_BLK_ID			0xc
#define	ETHER_SERDES_BLK_ID		0xd
#define	PCIE_SERDES_BLK_ID		0xe
#define	VIR_BLK_ID			0xf
#define	XAUI_BLK_ID			0x10
#define	XFP_BLK_ID			0x11

/* Common HW error code */
/* HW unable to exit from reset state. */
#define	RESET_FAILED			0x81

/* Write operation failed on indirect write. */
#define	WRITE_FAILED			0x82
/* Read operation failed on indirect read.	 */
#define	READ_FAILED			0x83

/* Error code boundary */

#define	COMMON_SW_ERR_START		0x40
#define	COMMON_SW_ERR_END		0x4f
#define	BLK_SPEC_SW_ERR_START		0x50
#define	BLK_SPEC_SW_ERR_END		0x7f
#define	COMMON_HW_ERR_START		0x80
#define	COMMON_HW_ERR_END		0x8f
#define	BLK_SPEC_HW_ERR_START		0x90
#define	BLK_SPEC_HW_ERR_END		0xbf

#define	IS_PORT				0x00100000
#define	IS_CHAN				0x00200000

/* Common SW errors code */

#define	PORT_INVALID			0x41	/* Invalid port number */
#define	CHANNEL_INVALID			0x42	/* Invalid dma channel number */
#define	OPCODE_INVALID			0x43	/* Invalid opcode */
#define	REGISTER_INVALID		0x44	/* Invalid register number */
#define	COUNTER_INVALID			0x45	/* Invalid counter number */
#define	CONFIG_INVALID			0x46	/* Invalid config input */
#define	LOGICAL_PAGE_INVALID		0x47	/* Invalid logical page # */
#define	VLAN_INVALID			0x48	/* Invalid Vlan ID */
#define	RDC_TAB_INVALID			0x49	/* Invalid RDC Group Number */
#define	LOCATION_INVALID		0x4a	/* Invalid Entry Location */

#define	NPI_SUCCESS			0		/* Operation succeed */
#define	NPI_FAILURE			0x80000000	/* Operation failed */

#define	NPI_CNT_CLR_VAL			0

/*
 * Block identifier starts at bit 8.
 */
#define	NPI_BLOCK_ID_SHIFT		8

/*
 * Port, channel and misc. information starts at bit 12.
 */
#define	NPI_PORT_CHAN_SHIFT			12

/*
 * Software Block specific error codes start at 0x50.
 */
#define	NPI_BK_ERROR_START		0x50

/*
 * Hardware block specific error codes start at 0x90.
 */
#define	NPI_BK_HW_ER_START		0x90

/* Structures for register tracing */

typedef struct _rt_buf {
	uint32_t	ctl_addr;
	uint32_t	align;
	uint32_t	val_h32;
	uint32_t	val_l32;
	char		name[16];
} rt_buf_t;

/*
 * Control Address field format
 *
 * Bit 0 - 23: Address
 * Bit 24 - 25: Function Number
 * Bit 26 - 29: Instance Number
 * Bit 30: Read/Write Direction bit
 * Bit 31: Invalid bit
 */

#define	MAX_RTRACE_ENTRIES	1024
#define	MAX_RTRACE_IOC_ENTRIES	64
#define	TRACE_ADDR_MASK		0x00FFFFFF
#define	TRACE_FUNC_MASK		0x03000000
#define	TRACE_INST_MASK		0x3C000000
#define	TRACE_CTL_WR		0x40000000
#define	TRACE_CTL_INVALID	0x80000000
#define	TRACE_FUNC_SHIFT	24
#define	TRACE_INST_SHIFT	26
#define	MSG_BUF_SIZE		1024


typedef struct _rtrace {
	uint16_t	next_idx;
	uint16_t	last_idx;
	boolean_t	wrapped;
	uint64_t	align;
	rt_buf_t	buf[MAX_RTRACE_ENTRIES];
} rtrace_t;

typedef struct _err_inject {
	uint8_t		blk_id;
	uint8_t		chan;
	uint32_t	err_id;
	uint32_t	control;
} err_inject_t;

/* Configuration options */
typedef enum config_op {
	DISABLE = 0,
	ENABLE,
	INIT
} config_op_t;

/* I/O options */
typedef enum io_op {
	OP_SET = 0,
	OP_GET,
	OP_UPDATE,
	OP_CLEAR
} io_op_t;

/* Counter options */
typedef enum counter_op {
	SNAP_STICKY = 0,
	SNAP_ACCUMULATE,
	CLEAR
} counter_op_t;

/* NPI attribute */
typedef struct _npi_attr_t {
	uint32_t type;
	uint32_t idata[16];
	uint32_t odata[16];
} npi_attr_t;

/* NPI Handle */
typedef	struct	_npi_handle_function {
	uint16_t		instance;
	uint16_t		function;
} npi_handle_function_t;

/* NPI Handle */
typedef	struct	_npi_handle {
	npi_reg_handle_t	regh;
	npi_reg_ptr_t		regp;
	boolean_t		is_vraddr; /* virtualization region address */
	npi_handle_function_t	function;
	void * nxgep;
} npi_handle_t;

/* NPI Counter */
typedef struct _npi_counter_t {
	uint32_t id;
	char *name;
	uint32_t val;
} npi_counter_t;

/*
 * Commmon definitions for NPI RXDMA and TXDMA functions.
 */
typedef struct _dma_log_page {
	uint8_t			page_num;
	boolean_t		valid;
	uint8_t			func_num;
	uint64_t		mask;
	uint64_t		value;
	uint64_t		reloc;
} dma_log_page_t, *p_dma_log_page_t;

extern	rtrace_t npi_rtracebuf;
void npi_rtrace_buf_init(rtrace_t *);
void npi_rtrace_update(npi_handle_t, boolean_t, rtrace_t *,
    uint32_t, uint64_t);
void npi_trace_update(npi_handle_t, boolean_t, rtrace_t *,
    const char *, uint32_t, uint64_t);
void npi_rtrace_buf_init(rtrace_t *);

void npi_debug_msg(npi_handle_function_t, uint64_t,
	char *, ...);

#ifdef	NPI_DEBUG
#define	NPI_DEBUG_MSG(params) npi_debug_msg params
#else
#define	NPI_DEBUG_MSG(params)
#endif

#define	NPI_ERROR_MSG(params) npi_debug_msg params
#define	NPI_REG_DUMP_MSG(params) npi_debug_msg params

#ifdef	__cplusplus
}
#endif

#endif	/* _NPI_H */
