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

#ifndef _HPI_H
#define	_HPI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <hxge_common_impl.h>
#include <hxge_common.h>

typedef	uint32_t hpi_status_t;

/* Common Block ID */
#define	VMAC_BLK_ID			0x1
#define	TXDMA_BLK_ID			0x2
#define	RXDMA_BLK_ID			0x3
#define	PFC_BLK_ID			0x4
#define	VIR_BLK_ID			0x5
#define	PEU_BLK_ID			0x6

/* Common HW error code */
/* HW unable to exit from reset state. */
#define	RESET_FAILED			0x81

/* Write operation failed on indirect write. */
#define	WRITE_FAILED			0x82
/* Read operation failed on indirect read.	 */
#define	READ_FAILED			0x83

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

#define	HPI_SUCCESS			0		/* Operation succeed */
#define	HPI_FAILURE			0x80000000	/* Operation failed */

/*
 * Block identifier starts at bit 8.
 */
#define	HPI_BLOCK_ID_SHIFT		8

/*
 * Port, channel and misc. information starts at bit 12.
 */
#define	HPI_PORT_CHAN_SHIFT		12

/*
 * Software Block specific error codes start at 0x50.
 */
#define	HPI_BK_ERROR_START		0x50

/*
 * Hardware block specific error codes start at 0x90.
 */
#define	HPI_BK_HW_ER_START		0x90

/* Structures for register tracing */

typedef struct _rt_buf {
	uint32_t	ctl_addr;
	uint32_t	val_l32;
	uint32_t	val_h32;
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
	rt_buf_t	buf[MAX_RTRACE_ENTRIES];
} rtrace_t;

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

/* HPI Handle */
typedef	struct	_hpi_handle_function {
	uint16_t		instance;
	uint16_t		function;
} hpi_handle_function_t;

/* HPI Handle */
typedef	struct	_hpi_handle {
	hpi_reg_handle_t	regh;
	hpi_reg_ptr_t		regp;
	boolean_t		is_vraddr; /* virtualization region address */
	hpi_handle_function_t	function;
	void			*hxgep;
} hpi_handle_t;

extern	rtrace_t hpi_rtracebuf;
void hpi_rtrace_update(hpi_handle_t handle, boolean_t wr, rtrace_t *rt,
    uint32_t addr, uint64_t val);
void hpi_rtrace_buf_init(rtrace_t *rt);

void hpi_debug_msg(hpi_handle_function_t function, uint64_t level,
    char *fmt, ...);

#ifdef	HPI_DEBUG
#define	HPI_DEBUG_MSG(params) hpi_debug_msg params
#else
#define	HPI_DEBUG_MSG(params)
#endif

#define	HPI_ERROR_MSG(params) hpi_debug_msg params

#ifdef	__cplusplus
}
#endif

#endif	/* _HPI_H */
