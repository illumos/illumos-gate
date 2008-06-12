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

#ifndef	_HXGE_RDC_HW_H
#define	_HXGE_RDC_HW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	RDC_BASE_ADDR				0X00300000

#define	RDC_PAGE_HANDLE				(RDC_BASE_ADDR + 0x8)
#define	RDC_RX_CFG1				(RDC_BASE_ADDR + 0x20)
#define	RDC_RX_CFG2				(RDC_BASE_ADDR + 0x28)
#define	RDC_RBR_CFG_A				(RDC_BASE_ADDR + 0x40)
#define	RDC_RBR_CFG_B				(RDC_BASE_ADDR + 0x48)
#define	RDC_RBR_KICK				(RDC_BASE_ADDR + 0x50)
#define	RDC_RBR_QLEN				(RDC_BASE_ADDR + 0x58)
#define	RDC_RBR_HEAD				(RDC_BASE_ADDR + 0x68)
#define	RDC_RCR_CFG_A				(RDC_BASE_ADDR + 0x80)
#define	RDC_RCR_CFG_B				(RDC_BASE_ADDR + 0x88)
#define	RDC_RCR_QLEN				(RDC_BASE_ADDR + 0x90)
#define	RDC_RCR_TAIL				(RDC_BASE_ADDR + 0xA0)
#define	RDC_RCR_FLUSH				(RDC_BASE_ADDR + 0xA8)
#define	RDC_CLOCK_DIV				(RDC_BASE_ADDR + 0xB0)
#define	RDC_INT_MASK				(RDC_BASE_ADDR + 0xB8)
#define	RDC_STAT				(RDC_BASE_ADDR + 0xC0)
#define	RDC_PKT_COUNT				(RDC_BASE_ADDR + 0xD0)
#define	RDC_DROP_COUNT				(RDC_BASE_ADDR + 0xD8)
#define	RDC_BYTE_COUNT				(RDC_BASE_ADDR + 0xE0)
#define	RDC_PREF_CMD				(RDC_BASE_ADDR + 0x100)
#define	RDC_PREF_DATA				(RDC_BASE_ADDR + 0x108)
#define	RDC_SHADOW_CMD				(RDC_BASE_ADDR + 0x110)
#define	RDC_SHADOW_DATA				(RDC_BASE_ADDR + 0x118)
#define	RDC_SHADOW_PAR_DATA			(RDC_BASE_ADDR + 0x120)
#define	RDC_CTRL_FIFO_CMD			(RDC_BASE_ADDR + 0x128)
#define	RDC_CTRL_FIFO_DATA_LO			(RDC_BASE_ADDR + 0x130)
#define	RDC_CTRL_FIFO_DATA_HI			(RDC_BASE_ADDR + 0x138)
#define	RDC_CTRL_FIFO_DATA_ECC			(RDC_BASE_ADDR + 0x140)
#define	RDC_DATA_FIFO_CMD			(RDC_BASE_ADDR + 0x148)
#define	RDC_DATA_FIFO_DATA_LO			(RDC_BASE_ADDR + 0x150)
#define	RDC_DATA_FIFO_DATA_HI			(RDC_BASE_ADDR + 0x158)
#define	RDC_DATA_FIFO_DATA_ECC			(RDC_BASE_ADDR + 0x160)
#define	RDC_STAT_INT_DBG			(RDC_BASE_ADDR + 0x200)
#define	RDC_PREF_PAR_LOG			(RDC_BASE_ADDR + 0x210)
#define	RDC_SHADOW_PAR_LOG			(RDC_BASE_ADDR + 0x218)
#define	RDC_CTRL_FIFO_ECC_LOG			(RDC_BASE_ADDR + 0x220)
#define	RDC_DATA_FIFO_ECC_LOG			(RDC_BASE_ADDR + 0x228)
#define	RDC_FIFO_ERR_INT_MASK			(RDC_BASE_ADDR + 0x230)
#define	RDC_FIFO_ERR_STAT			(RDC_BASE_ADDR + 0x238)
#define	RDC_FIFO_ERR_INT_DBG			(RDC_BASE_ADDR + 0x240)
#define	RDC_PEU_TXN_LOG				(RDC_BASE_ADDR + 0x250)
#define	RDC_DBG_TRAINING_VEC			(RDC_BASE_ADDR + 0x300)
#define	RDC_DBG_GRP_SEL				(RDC_BASE_ADDR + 0x308)


/*
 * Register: RdcPageHandle
 * Logical Page Handle
 * Description: Logical page handle specifying upper bits of 64-bit
 * PCIE addresses. Fields in this register are part of the dma
 * configuration and cannot be changed once the dma is enabled.
 * Fields:
 *     Bits [63:44] of a 64-bit address, used to concatenate to a
 *     44-bit address when generating 64-bit addresses on the PCIE
 *     bus.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:12;
		uint32_t	handle:20;
#else
		uint32_t	handle:20;
		uint32_t	rsrvd_l:12;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_page_handle_t;


/*
 * Register: RdcRxCfg1
 * DMA Configuration 1
 * Description: Configuration parameters for receive DMA block.
 * Fields in this register are part of the dma configuration and
 * cannot be changed once the dma is enabled.
 * The usage of enable, reset, and qst is as follows. Software
 * should use the following sequence to reset a DMA channel. First,
 * set DMA.enable to 0, wait for DMA.qst=1 and then, set DMA.reset to
 * 1. After DMA.reset is cleared by hardware and the DMA.qst is set
 * to 1, software may then start configuring the DMA channel. The
 * DMA.enable can be set or cleared while the DMA is in operation.
 * The state machines of the DMA may not have returned to its initial
 * states yet after the DMA.enable bit is cleared. This condition is
 * indicated by the value of the DMA.qst. An example of DMA.enable
 * being cleared during operation is when a fatal error occurs.
 * Fields:
 *     Set to 1 to enable the Receive DMA. If set to 0, packets
 *     selecting this DMA will be discarded. On fatal errors, this
 *     bit will be cleared by hardware. This bit cannot be set if sw
 *     has not resolved any pending fatal error condition: i.e. any
 *     RdcStat ldf1 error bits remain set.
 *     Set to 1 to reset the DMA. Hardware will clear this bit after
 *     reset is completed. A reset will bring the sepecific DMA back
 *     to the power on state (including the DMA.en in this register).
 *     When set to 1, it indicates all state associated with the DMA
 *     are in its initial state following either dma reset or
 *     disable. Thus, once this is set to 1, sw could start to
 *     configure the DMA if needed.
 *     Bits [43:32] of the Mailbox address.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	enable:1;
		uint32_t	reset:1;
		uint32_t	qst:1;
		uint32_t	rsrvd1:17;
		uint32_t	mbaddr_h:12;
#else
		uint32_t	mbaddr_h:12;
		uint32_t	rsrvd1:17;
		uint32_t	qst:1;
		uint32_t	reset:1;
		uint32_t	enable:1;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_rx_cfg1_t;


/*
 * Register: RdcRxCfg2
 * DMA Configuration 2
 * Description: Configuration parameters for receive DMA block.
 * Fields in this register are part of the dma configuration and
 * cannot be changed once the dma is enabled.
 * Fields:
 *     Bits [31:6] of the Mailbox address. Bits [5:0] are assumed to
 *     be zero, or 64B aligned.
 *     Multiple of 64Bs, 0 means no offset, b01 means 64B, b10 means
 *     128B. b11 is invalid, hardware behavior not specified.
 *     Set to 1 to select the entire header of 6B.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	mbaddr_l:26;
		uint32_t	rsrvd1:3;
		uint32_t	offset:2;
		uint32_t	full_hdr:1;
#else
		uint32_t	full_hdr:1;
		uint32_t	offset:2;
		uint32_t	rsrvd1:3;
		uint32_t	mbaddr_l:26;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_rx_cfg2_t;


/*
 * Register: RdcRbrCfgA
 * RBR Configuration A
 * Description: The following registers are used to configure and
 * manage the RBR. Note that the entire RBR must stay within the
 * 'page' defined by staddrBase. The behavior of the hardware is
 * undefined if the last entry is outside of the page (if bits 43:18
 * of the address of the last entry are different from bits 43:18 of
 * the base address). Hardware will support wrapping around at the
 * end of the ring buffer defined by LEN. LEN must be a multiple of
 * 64. Fields in this register are part of the dma configuration and
 * cannot be changed once the dma is enabled.
 * HW does not check for all configuration errors across different
 * fields.
 *
 * Fields:
 *     Bits 15:6 of the maximum number of RBBs in the buffer ring.
 *     Bits 5:0 are hardcoded to zero. The maximum is (2^16 - 64) and
 *     is limited by the staddr value. (len + staddr) should not
 *     exceed (2^16 - 64).
 *     Bits [43:18] of the address for the RBR. This value remains
 *     fixed, and is used as the base address of the ring. All
 *     entries in the ring have this as their upper address bits.
 *     Bits [17:6] of the address of the RBR. staddrBase concatinated
 *     with staddr is the starting address of the RBR. (len + staddr)
 *     should not exceed (2^16 - 64).
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	len:10;
		uint32_t	len_lo:6;
		uint32_t	rsrvd:4;
		uint32_t	staddr_base:12;
		uint32_t	staddr_base_l:14;
		uint32_t	staddr:12;
		uint32_t	rsrvd1:6;
#else
		uint32_t	rsrvd1:6;
		uint32_t	staddr:12;
		uint32_t	staddr_base_l:14;
		uint32_t	staddr_base:12;
		uint32_t	rsrvd:4;
		uint32_t	len_lo:6;
		uint32_t	len:10;
#endif
	} bits;
} rdc_rbr_cfg_a_t;


/*
 * Register: RdcRbrCfgB
 * RBR Configuration B
 * Description: This register configures the block size, and the
 * individual packet buffer sizes. The VLD bits of the three block
 * sizes have to be set to 1 in normal operations. These bits may be
 * turned off for debug purpose only. Fields in this register are
 * part of the dma configuration and cannot be changed once the dma
 * is enabled.
 * Fields:
 *     Buffer Block Size. b0 - 4K; b1 - 8K.
 *     Set to 1 to indicate SIZE2 is valid, and enable hardware to
 *     allocate buffers of size 2. Always set to 1 in normal
 *     operation.
 *     Size 2 of packet buffer. b0 - 2K; b1 - 4K.
 *     Set to 1 to indicate SIZE1 is valid, and enable hardware to
 *     allocate buffers of size 1. Always set to 1 in normal
 *     operation.
 *     Size 1 of packet buffer. b0 - 1K; b1 - 2K.
 *     Set to 1 to indicate SIZE0 is valid, and enable hardware to
 *     allocate buffers of size 0. Always set to 1 in normal
 *     operation.
 *     Size 0 of packet buffer. b00 - 256; b01 - 512; b10 - 1K; b11 -
 *     reserved.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:7;
		uint32_t	bksize:1;
		uint32_t	vld2:1;
		uint32_t	rsrvd1:6;
		uint32_t	bufsz2:1;
		uint32_t	vld1:1;
		uint32_t	rsrvd2:6;
		uint32_t	bufsz1:1;
		uint32_t	vld0:1;
		uint32_t	rsrvd3:5;
		uint32_t	bufsz0:2;
#else
		uint32_t	bufsz0:2;
		uint32_t	rsrvd3:5;
		uint32_t	vld0:1;
		uint32_t	bufsz1:1;
		uint32_t	rsrvd2:6;
		uint32_t	vld1:1;
		uint32_t	bufsz2:1;
		uint32_t	rsrvd1:6;
		uint32_t	vld2:1;
		uint32_t	bksize:1;
		uint32_t	rsrvd_l:7;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_rbr_cfg_b_t;


/*
 * Register: RdcRbrKick
 * RBR Kick
 * Description: Block buffer addresses are added to the ring buffer
 * by software. When software writes to the Kick register, indicating
 * the number of descriptors added, hardware will update the internal
 * state of the corresponding buffer pool.
 * HW does not check for all configuration errors across different
 * fields.
 *
 * Fields:
 *     Number of Block Buffers added by software. Hardware effect
 *     will be triggered when the register is written to.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:16;
		uint32_t	bkadd:16;
#else
		uint32_t	bkadd:16;
		uint32_t	rsrvd_l:16;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_rbr_kick_t;


/*
 * Register: RdcRbrQlen
 * RBR Queue Length
 * Description: The current number of entries in the RBR.
 * Fields:
 *     Number of block addresses in the ring buffer.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:16;
		uint32_t	qlen:16;
#else
		uint32_t	qlen:16;
		uint32_t	rsrvd_l:16;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_rbr_qlen_t;


/*
 * Register: RdcRbrHead
 * RBR Head
 * Description: Lower bits of the RBR head pointer. Software programs
 * the upper bits, specified in rdcRbrConfigA.staddrBase.
 * Fields:
 *     Bits [17:2] of the software posted address, 4B aligned. This
 *     pointer is updated by hardware after each block buffer is
 *     consumed.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:14;
		uint32_t	head:16;
		uint32_t	rsrvd1:2;
#else
		uint32_t	rsrvd1:2;
		uint32_t	head:16;
		uint32_t	rsrvd_l:14;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_rbr_head_t;


/*
 * Register: RdcRcrCfgA
 * RCR Configuration A
 * Description: The RCR should be within the 'page' defined by the
 * staddrBase, i.e. staddrBase concatenate with STADDR plus 8 x LEN
 * should be within the last address of the 'page' defined by
 * staddrBase. The length must be a multiple of 32. Fields in this
 * register are part of the dma configuration and cannot be changed
 * once the dma is enabled.
 * HW does not check for all configuration errors across different
 * fields.
 *
 * Fields:
 *     Bits 15:5 of the maximum number of 8B entries in RCR. Bits 4:0
 *     are hard-coded to zero. The maximum size is (2^16 - 32) and is
 *     limited by staddr value. (len + staddr) should not exceed
 *     (2^16 - 32).
 *     Bits [43:19] of the Start address for the RCR.
 *     Bits [18:6] of start address for the RCR. (len + staddr)
 *     should not exceed (2^16 - 32).
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	len:11;
		uint32_t	len_lo:5;
		uint32_t	rsrvd:4;
		uint32_t	staddr_base:12;
		uint32_t	staddr_base_l:13;
		uint32_t	staddr:13;
		uint32_t	rsrvd1:6;
#else
		uint32_t	rsrvd1:6;
		uint32_t	staddr:13;
		uint32_t	staddr_base_l:13;
		uint32_t	staddr_base:12;
		uint32_t	rsrvd:4;
		uint32_t	len_lo:5;
		uint32_t	len:11;
#endif
	} bits;
} rdc_rcr_cfg_a_t;


/*
 * Register: RdcRcrCfgB
 * RCR Configuration B
 * Description: RCR configuration settings.
 * Fields:
 *     Packet Threshold; when the number of packets enqueued in RCR
 *     is strictly larger than PTHRES, the DMA MAY issue an interrupt
 *     if enabled.
 *     Enable timeout. If set to one, enable the timeout. A timeout
 *     will initiate an update of the software visible states. If
 *     interrupt is armed, in addition to the update, an interrupt to
 *     CPU will be generated, and the interrupt disarmed.
 *     Time out value. The system clock is divided down by the value
 *     programmed in the Receive DMA Clock Divider register.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	pthres:16;
		uint32_t	entout:1;
		uint32_t	rsrvd1:9;
		uint32_t	timeout:6;
#else
		uint32_t	timeout:6;
		uint32_t	rsrvd1:9;
		uint32_t	entout:1;
		uint32_t	pthres:16;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_rcr_cfg_b_t;


/*
 * Register: RdcRcrQlen
 * RCR Queue Length
 * Description: The number of entries in the RCR.
 * Fields:
 *     Number of packets queued. Initialize to zero after the RCR
 *     Configuration A register is written to.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:16;
		uint32_t	qlen:16;
#else
		uint32_t	qlen:16;
		uint32_t	rsrvd_l:16;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_rcr_qlen_t;


/*
 * Register: RdcRcrTail
 * RCR Tail
 * Description: Lower bits of the RCR tail pointer. Software programs
 * the upper bits, specified in rdcRcrConfigA.staddrBase.
 * Fields:
 *     Address of the RCR Tail Pointer [18:3] (points to the next
 *     available location.) Initialized after the RCR Configuration A
 *     register is written to.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:13;
		uint32_t	tail:16;
		uint32_t	rsrvd1:3;
#else
		uint32_t	rsrvd1:3;
		uint32_t	tail:16;
		uint32_t	rsrvd_l:13;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_rcr_tail_t;


/*
 * Register: RdcRcrFlush
 * RCR Flush
 * Description: This register will force an update to the RCR in
 * system memory.
 * Fields:
 *     Set to 1 to force the hardware to store the shadow tail block
 *     to DRAM if the hardware state (queue length and pointers) is
 *     different from the software visible state. Reset to 0 by
 *     hardware when done.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:31;
		uint32_t	flush:1;
#else
		uint32_t	flush:1;
		uint32_t	rsrvd_l:31;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_rcr_flush_t;


/*
 * Register: RdcClockDiv
 * Receive DMA Clock Divider
 * Description: The granularity of the DMA timers is determined by
 * the following counter. This is used to drive the DMA timeout
 * counters. For a 250MHz system clock, a value of 25000 (decimal)
 * will yield a granularity of 100 usec.
 * Fields:
 *     System clock divider, determines the granularity of the DMA
 *     timeout count-down. The hardware count down is count+1.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:16;
		uint32_t	count:16;
#else
		uint32_t	count:16;
		uint32_t	rsrvd_l:16;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_clock_div_t;


/*
 * Register: RdcIntMask
 * RDC Interrupt Mask
 * Description: RDC interrupt status register. RCRTHRES and RCRTO
 * bits are used to keep track of normal DMA operations, while the
 * remaining bits are primarily used to detect error conditions.
 * Fields:
 *     Set to 0 to enable flagging when rdc receives a response
 *     completion timeout from peu. Part of LDF 1.
 *     Set to 1 to enable flagging when rdc receives a poisoned
 *     completion or non-zero (unsuccessful) completion status
 *     received from PEU. Part of LDF 1.
 *     Set to 0 to enable flagging when RCR threshold crossed. Part
 *     of LDF 0.
 *     Set to 0 to enable flagging when RCR timeout. Part of LDF 0.
 *     Set to 0 to enable flagging when read from rcr shadow ram
 *     generates a parity error Part of LDF 1.
 *     Set to 0 to enable flagging when read from rbr prefetch ram
 *     generates a parity error Part of LDF 1.
 *     Set to 0 to enable flagging when Receive Block Ring prefetch
 *     is empty (not enough buffer blocks available depending on
 *     incoming pkt size) when hardware tries to queue a packet.
 *     Incoming packets will be discarded. Non-fatal error. Part of
 *     LDF 1.
 *     Set to 0 to enable flagging when packet discard because of RCR
 *     shadow full.
 *     Set to 0 to enable flagging when Receive Completion Ring full
 *     when hardware tries to enqueue the completion status of a
 *     packet. Part of LDF 1.
 *     Set to 0 to enable flagging when RBR empty when hardware
 *     attempts to prefetch. Part of LDF 1.
 *     Set to 0 to enable flagging when Receive Block Ring full when
 *     software tries to post more blocks. Part of LDF 1.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:10;
		uint32_t	rbr_cpl_to:1;
		uint32_t	peu_resp_err:1;
		uint32_t	rsrvd1:5;
		uint32_t	rcr_thres:1;
		uint32_t	rcr_to:1;
		uint32_t	rcr_shadow_par_err:1;
		uint32_t	rbr_prefetch_par_err:1;
		uint32_t	rsrvd2:2;
		uint32_t	rbr_pre_empty:1;
		uint32_t	rcr_shadow_full:1;
		uint32_t	rsrvd3:2;
		uint32_t	rcr_full:1;
		uint32_t	rbr_empty:1;
		uint32_t	rbr_full:1;
		uint32_t	rsrvd4:2;
		uint32_t	rsrvd5:32;
#else
		uint32_t	rsrvd5:32;
		uint32_t	rsrvd4:2;
		uint32_t	rbr_full:1;
		uint32_t	rbr_empty:1;
		uint32_t	rcr_full:1;
		uint32_t	rsrvd3:2;
		uint32_t	rcr_shadow_full:1;
		uint32_t	rbr_pre_empty:1;
		uint32_t	rsrvd2:2;
		uint32_t	rbr_prefetch_par_err:1;
		uint32_t	rcr_shadow_par_err:1;
		uint32_t	rcr_to:1;
		uint32_t	rcr_thres:1;
		uint32_t	rsrvd1:5;
		uint32_t	peu_resp_err:1;
		uint32_t	rbr_cpl_to:1;
		uint32_t	rsrvd:10;
#endif
	} bits;
} rdc_int_mask_t;


/*
 * Register: RdcStat
 * RDC Control And Status
 * Description: The DMA channels are controlled using this register.
 * Fields:
 *     Set to 1 to indicate rdc received a response completion
 *     timeout from peu. Fatal error. Part of LDF 1.
 *     Set to 1 to indicate poisoned completion or non-zero
 *     (unsuccessful) completion status received from PEU. Part of
 *     LDF 1.
 *     Set to 1 to enable mailbox update. Hardware will reset to 0
 *     after one update. Software needs to set to 1 for each update.
 *     Write 0 has no effect. Note that once set by software, only
 *     hardware can reset the value. This bit is also used to keep
 *     track of the exclusivity between threshold triggered or
 *     timeout triggered interrupt. If this bit is not set, there
 *     will be no timer based interrupt, and threshold based
 *     interrupt will not issue a mailbox update. It is recommended
 *     that software should set this bit to one when arming the
 *     device for interrupt.
 *     Set to 1 to indicate RCR threshold crossed. This is a level
 *     event. Part of LDF 0.
 *     Set to 1 to indicate RCR time-outed if MEX bit is set and the
 *     queue length is non-zero when timeout occurs. When software
 *     writes 1 to this bit, RCRTO will be reset to 0. Part of LDF 0.
 *     Set to 1 to indicate read from rcr shadow ram generates a
 *     parity error Writing a 1 to this register also clears the
 *     rdcshadowParLog register Fatal error. Part of LDF 1.
 *     Set to 1 to indicate read from rbr prefetch ram generates
 *     parity error Writing a 1 to this register also clears the
 *     rdcPrefParLog register Fatal error. Part of LDF 1.
 *     Set to 1 to indicate Receive Block Ring prefetch is empty (not
 *     enough buffer blocks available depending on incoming pkt size)
 *     when hardware tries to queue a packet. Incoming packets will
 *     be discarded. Non-fatal error. Part of LDF 1.
 *     Set to 1 to indicate packet discard because of RCR shadow
 *     full. RCR Shadow full cannot be set to 1 in a normal
 *     operation. When set to 1, it indicates a fatal error. Part of
 *     LDF 1.
 *     Set to 1 to indicate Receive Completion Ring full when
 *     hardware tries to enqueue the completion status of a packet.
 *     Incoming packets will be discarded. No buffer consumed. Fatal
 *     error. Part of LDF 1.
 *     Set to 1 to indicate RBR empty when hardware attempts to
 *     prefetch. Part of LDF 1.
 *     Set to 1 to indicate Receive Buffer Ring full when software
 *     writes the kick register with a value greater than the length
 *     of the RBR length. Incoming packets will be discarded. Fatal
 *     error. Part of LDF 1.
 *     Number of buffer pointers read. Used to advance the RCR head
 *     pointer.
 *     Number of packets read; when written to, decrement the QLEN
 *     counter by PKTREAD. QLEN is lower bounded to zero.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:10;
		uint32_t	rbr_cpl_to:1;
		uint32_t	peu_resp_err:1;
		uint32_t	rsrvd1:4;
		uint32_t	mex:1;
		uint32_t	rcr_thres:1;
		uint32_t	rcr_to:1;
		uint32_t	rcr_shadow_par_err:1;
		uint32_t	rbr_prefetch_par_err:1;
		uint32_t	rsrvd2:2;
		uint32_t	rbr_pre_empty:1;
		uint32_t	rcr_shadow_full:1;
		uint32_t	rsrvd3:2;
		uint32_t	rcr_full:1;
		uint32_t	rbr_empty:1;
		uint32_t	rbr_full:1;
		uint32_t	rsrvd4:2;
		uint32_t	ptrread:16;
		uint32_t	pktread:16;
#else
		uint32_t	pktread:16;
		uint32_t	ptrread:16;
		uint32_t	rsrvd4:2;
		uint32_t	rbr_full:1;
		uint32_t	rbr_empty:1;
		uint32_t	rcr_full:1;
		uint32_t	rsrvd3:2;
		uint32_t	rcr_shadow_full:1;
		uint32_t	rbr_pre_empty:1;
		uint32_t	rsrvd2:2;
		uint32_t	rbr_prefetch_par_err:1;
		uint32_t	rcr_shadow_par_err:1;
		uint32_t	rcr_to:1;
		uint32_t	rcr_thres:1;
		uint32_t	mex:1;
		uint32_t	rsrvd1:4;
		uint32_t	peu_resp_err:1;
		uint32_t	rbr_cpl_to:1;
		uint32_t	rsrvd:10;
#endif
	} bits;
} rdc_stat_t;


/*
 * Register: RdcPktCount
 * Rx DMA Packet Counter
 * Description: Counts the number of packets received from the Rx
 * Virtual MAC for this DMA channel.
 * Fields:
 *     Count of SYN packets received from RVM. This counter
 *     saturates.
 *     Count of packets received from RVM. This counter saturates.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	syn_pkt_count:32;
		uint32_t	pkt_count:32;
#else
		uint32_t	pkt_count:32;
		uint32_t	syn_pkt_count:32;
#endif
	} bits;
} rdc_pkt_count_t;


/*
 * Register: RdcDropCount
 * Rx DMA Dropped Packet Counters
 * Description: Counts the number of packets dropped due to different
 * types of errors.
 * Fields:
 *     Count of packets dropped because they were longer than the
 *     maximum length. This counter saturates.
 *     Count of packets dropped because there was no block available
 *     in the RBR Prefetch Buffer. This counter saturates.
 *     Count of packets dropped because the RVM marked the packet as
 *     errored. This counter saturates.
 *     Count of packets dropped because there was a framing error
 *     from the RVM. This counter saturates.
 *     Count of packets dropped because the packet did not fit in the
 *     rx ram. This counter saturates.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:16;
		uint32_t	too_long:8;
		uint32_t	no_rbr_avail:8;
		uint32_t	rvm_error:8;
		uint32_t	frame_error:8;
		uint32_t	rxram_error:8;
		uint32_t	rsrvd1:8;
#else
		uint32_t	rsrvd1:8;
		uint32_t	rxram_error:8;
		uint32_t	frame_error:8;
		uint32_t	rvm_error:8;
		uint32_t	no_rbr_avail:8;
		uint32_t	too_long:8;
		uint32_t	rsrvd:16;
#endif
	} bits;
} rdc_drop_count_t;


/*
 * Register: RdcByteCount
 * Rx DMA Byte Counter
 * Description: Counts the number of bytes transferred by dma for all
 * channels.
 * Fields:
 *     Count of bytes transferred by dma. This counter saturates.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	count:32;
#else
		uint32_t	count:32;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_byte_count_t;


/*
 * Register: RdcPrefCmd
 * Rx DMA Prefetch Buffer Command
 * Description: Allows debug access to the entire prefetch buffer,
 * along with the rdcPrefData register. Writing the rdcPrefCmd
 * triggers the access. For writes, software writes the 32 bits of
 * data to the rdcPrefData register before writing the write command
 * to this register. For reads, software first writes the the read
 * command to this register, then reads the 32-bit value from the
 * rdcPrefData register. The status field should be polled by
 * software until it goes low, indicating the read or write has
 * completed.
 * Fields:
 *     status of indirect access 0=busy 1=done
 *     Command type. 1 indicates a read command, 0 a write command.
 *     enable writing of parity bits 1=enabled, 0=disabled
 *     DMA channel of entry to read or write
 *     Entry in the prefetch buffer to read or write
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	status:1;
		uint32_t	cmd:1;
		uint32_t	par_en:1;
		uint32_t	rsrvd1:22;
		uint32_t	dmc:2;
		uint32_t	entry:5;
#else
		uint32_t	entry:5;
		uint32_t	dmc:2;
		uint32_t	rsrvd1:22;
		uint32_t	par_en:1;
		uint32_t	cmd:1;
		uint32_t	status:1;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_pref_cmd_t;


/*
 * Register: RdcPrefData
 * Rx DMA Prefetch Buffer Data
 * Description: See rdcPrefCmd register.
 * Fields:
 *     For writes, parity bits is written into prefetch buffer. For
 *     reads, parity bits read from the prefetch buffer.
 *     For writes, data which is written into prefetch buffer. For
 *     reads, data read from the prefetch buffer.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:28;
		uint32_t	par:4;
		uint32_t	data:32;
#else
		uint32_t	data:32;
		uint32_t	par:4;
		uint32_t	rsrvd:28;
#endif
	} bits;
} rdc_pref_data_t;


/*
 * Register: RdcShadowCmd
 * Rx DMA Shadow Tail Command
 * Description: Allows debug access to the entire shadow tail, along
 * with the rdcShadowData register. Writing the rdcShadowCmd triggers
 * the access. For writes, software writes the 64 bits of data to the
 * rdcShadowData register before writing the write command to this
 * register. For reads, software first writes the the read command to
 * this register, then reads the 64-bit value from the rdcShadowData
 * register. The valid field should be polled by software until it
 * goes low, indicating the read or write has completed.
 * Fields:
 *     status of indirect access 0=busy 1=done
 *     Command type. 1 indicates a read command, 0 a write command.
 *     enable writing of parity bits 1=enabled, 0=disabled
 *     DMA channel of entry to read or write
 *     Entry in the shadow tail to read or write
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	status:1;
		uint32_t	cmd:1;
		uint32_t	par_en:1;
		uint32_t	rsrvd1:23;
		uint32_t	dmc:2;
		uint32_t	entry:4;
#else
		uint32_t	entry:4;
		uint32_t	dmc:2;
		uint32_t	rsrvd1:23;
		uint32_t	par_en:1;
		uint32_t	cmd:1;
		uint32_t	status:1;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_shadow_cmd_t;


/*
 * Register: RdcShadowData
 * Rx DMA Shadow Tail Data
 * Description: See rdcShadowCmd register.
 * Fields:
 *     For writes, data which is written into shadow tail. For reads,
 *     data read from the shadow tail.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
		uint32_t	data_l:32;
#else
		uint32_t	data_l:32;
		uint32_t	data:32;
#endif
	} bits;
} rdc_shadow_data_t;


/*
 * Register: RdcShadowParData
 * Rx DMA Shadow Tail Parity Data
 * Description: See rdcShadowCmd register.
 * Fields:
 *     For writes, parity data is written into shadow tail. For
 *     reads, parity data read from the shadow tail.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd1:24;
		uint32_t	parity_data:8;
#else
		uint32_t	parity_data:8;
		uint32_t	rsrvd1:24;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_shadow_par_data_t;


/*
 * Register: RdcCtrlFifoCmd
 * Rx DMA Control Fifo Command
 * Description: Allows debug access to the entire Rx Ctl FIFO, along
 * with the rdcCtrlFifoData register. Writing the rdcCtrlFifoCmd
 * triggers the access. For writes, software writes the 128 bits of
 * data to the rdcCtrlFifoData registers before writing the write
 * command to this register. For reads, software first writes the the
 * read command to this register, then reads the 128-bit value from
 * the rdcCtrlFifoData registers. The valid field should be polled by
 * software until it goes low, indicating the read or write has
 * completed.
 * Fields:
 *     status of indirect access 0=busy 1=done
 *     Command type. 1 indicates a read command, 0 a write command.
 *     enable writing of ECC bits 1=enabled, 0=disabled
 *     Entry in the rx control ram to read or write
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	status:1;
		uint32_t	cmd:1;
		uint32_t	ecc_en:1;
		uint32_t	rsrvd1:20;
		uint32_t	entry:9;
#else
		uint32_t	entry:9;
		uint32_t	rsrvd1:20;
		uint32_t	ecc_en:1;
		uint32_t	cmd:1;
		uint32_t	status:1;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_ctrl_fifo_cmd_t;


/*
 * Register: RdcCtrlFifoDataLo
 * Rx DMA Control Fifo Data Lo
 * Description: Lower 64 bits read or written to the Rx Ctl FIFO. See
 * rdcCtrlFifoCmd register.
 * Fields:
 *     For writes, data which is written into rx control ram. For
 *     reads, data read from the rx control ram.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
		uint32_t	data_l:32;
#else
		uint32_t	data_l:32;
		uint32_t	data:32;
#endif
	} bits;
} rdc_ctrl_fifo_data_lo_t;


/*
 * Register: RdcCtrlFifoDataHi
 * Rx DMA Control Fifo Data Hi
 * Description: Upper 64 bits read or written to the Rx Ctl FIFO. See
 * rdcCtrlFifoCmd register.
 * Fields:
 *     For writes, data which is written into rx control ram. For
 *     reads, data read from the rx control ram.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
		uint32_t	data_l:32;
#else
		uint32_t	data_l:32;
		uint32_t	data:32;
#endif
	} bits;
} rdc_ctrl_fifo_data_hi_t;


/*
 * Register: RdcCtrlFifoDataEcc
 * Rx DMA Control Fifo Data ECC
 * Description: 16 bits ECC data read or written to the Rx Ctl FIFO.
 * See rdcCtrlFifoCmd register.
 * Fields:
 *     For writes, data which is written into rx control ram. For
 *     reads, data read from the rx control ram.
 *     For writes, data which is written into rx control ram. For
 *     reads, data read from the rx control ram.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd1:16;
		uint32_t	ecc_data_hi:8;
		uint32_t	ecc_data_lo:8;
#else
		uint32_t	ecc_data_lo:8;
		uint32_t	ecc_data_hi:8;
		uint32_t	rsrvd1:16;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_ctrl_fifo_data_ecc_t;


/*
 * Register: RdcDataFifoCmd
 * Rx DMA Data Fifo Command
 * Description: Allows debug access to the entire Rx Data FIFO, along
 * with the rdcDataFifoData register. Writing the rdcCtrlFifoCmd
 * triggers the access. For writes, software writes the 128 bits of
 * data to the rdcDataFifoData registers before writing the write
 * command to this register. For reads, software first writes the the
 * read command to this register, then reads the 128-bit value from
 * the rdcDataFifoData registers. The valid field should be polled by
 * software until it goes low, indicating the read or write has
 * completed.
 * Fields:
 *     status of indirect access 0=busy 1=done
 *     Command type. 1 indicates a read command, 0 a write command.
 *     enable writing of ECC bits 1=enabled, 0=disabled
 *     Entry in the rx data ram to read or write
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	status:1;
		uint32_t	cmd:1;
		uint32_t	ecc_en:1;
		uint32_t	rsrvd1:18;
		uint32_t	entry:11;
#else
		uint32_t	entry:11;
		uint32_t	rsrvd1:18;
		uint32_t	ecc_en:1;
		uint32_t	cmd:1;
		uint32_t	status:1;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_data_fifo_cmd_t;


/*
 * Register: RdcDataFifoDataLo
 * Rx DMA Data Fifo Data Lo
 * Description: Lower 64 bits read or written to the Rx Data FIFO.
 * See rdcDataFifoCmd register.
 * Fields:
 *     For writes, data which is written into rx data ram. For reads,
 *     data read from the rx data ram.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
		uint32_t	data_l:32;
#else
		uint32_t	data_l:32;
		uint32_t	data:32;
#endif
	} bits;
} rdc_data_fifo_data_lo_t;


/*
 * Register: RdcDataFifoDataHi
 * Rx DMA Data Fifo Data Hi
 * Description: Upper 64 bits read or written to the Rx Data FIFO.
 * See rdcDataFifoCmd register.
 * Fields:
 *     For writes, data which is written into rx data ram. For reads,
 *     data read from the rx data ram.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
		uint32_t	data_l:32;
#else
		uint32_t	data_l:32;
		uint32_t	data:32;
#endif
	} bits;
} rdc_data_fifo_data_hi_t;


/*
 * Register: RdcDataFifoDataEcc
 * Rx DMA Data Fifo ECC Data
 * Description: 16 bits ECC data read or written to the Rx Data FIFO.
 * See rdcDataFifoCmd register.
 * Fields:
 *     For writes, data which is written into rx data ram. For reads,
 *     data read from the rx data ram.
 *     For writes, data which is written into rx data ram. For reads,
 *     data read from the rx data ram.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd1:16;
		uint32_t	ecc_data_hi:8;
		uint32_t	ecc_data_lo:8;
#else
		uint32_t	ecc_data_lo:8;
		uint32_t	ecc_data_hi:8;
		uint32_t	rsrvd1:16;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_data_fifo_data_ecc_t;


/*
 * Register: RdcStatIntDbg
 * RDC Debug Control and Status Interrupt
 * Description: RDC debug control and status interrupt register.
 * Debug RDC control and status register bits to check if interrupt
 * is asserted used to detect error conditions.
 * Fields:
 *     Set to 1 to enable interrupt Part of LDF 1.
 *     Set to 1 to enable interrupt Part of LDF 1.
 *     Set to 1 to enable interrupt Part of LDF 0.
 *     Set to 1 to enable interrupt Part of LDF 0.
 *     Set to 1 to enable interrupt Part of LDF 1.
 *     Set to 1 to enable interrupt Part of LDF 1.
 *     Set to 1 to enable interrupt Part of LDF 1.
 *     Set to 1 to enable interrupt
 *     Set to 1 to enable interrupt Part of LDF 1.
 *     Set to 1 to enable interrupt Part of LDF 1.
 *     Set to 1 to enable interrupt Part of LDF 1.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:10;
		uint32_t	rbr_cpl_to:1;
		uint32_t	peu_resp_err:1;
		uint32_t	rsrvd1:5;
		uint32_t	rcr_thres:1;
		uint32_t	rcr_to:1;
		uint32_t	rcr_shadow_par_err:1;
		uint32_t	rbr_prefetch_par_err:1;
		uint32_t	rsrvd2:2;
		uint32_t	rbr_pre_empty:1;
		uint32_t	rcr_shadow_full:1;
		uint32_t	rsrvd3:2;
		uint32_t	rcr_full:1;
		uint32_t	rbr_empty:1;
		uint32_t	rbr_full:1;
		uint32_t	rsrvd4:2;
		uint32_t	rsrvd5:32;
#else
		uint32_t	rsrvd5:32;
		uint32_t	rsrvd4:2;
		uint32_t	rbr_full:1;
		uint32_t	rbr_empty:1;
		uint32_t	rcr_full:1;
		uint32_t	rsrvd3:2;
		uint32_t	rcr_shadow_full:1;
		uint32_t	rbr_pre_empty:1;
		uint32_t	rsrvd2:2;
		uint32_t	rbr_prefetch_par_err:1;
		uint32_t	rcr_shadow_par_err:1;
		uint32_t	rcr_to:1;
		uint32_t	rcr_thres:1;
		uint32_t	rsrvd1:5;
		uint32_t	peu_resp_err:1;
		uint32_t	rbr_cpl_to:1;
		uint32_t	rsrvd:10;
#endif
	} bits;
} rdc_stat_int_dbg_t;


/*
 * Register: RdcPrefParLog
 * Rx DMA Prefetch Buffer Parity Log
 * Description: RDC DMA Prefetch Buffer parity log register This
 * register logs the first parity error that is encountered. Writing
 * a 1 to RdcStat::rbrPrefetchParErr clears this register
 * Fields:
 *     Address of parity error
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:25;
		uint32_t	address:7;
#else
		uint32_t	address:7;
		uint32_t	rsrvd_l:25;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_pref_par_log_t;


/*
 * Register: RdcShadowParLog
 * Rx DMA Shadow Tail Parity Log
 * Description: RDC DMA Shadow Tail parity log register This register
 * logs the first parity error that is encountered. Writing a 1 to
 * RdcStat::rcrShadowParErr clears this register
 * Fields:
 *     Address of parity error
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd1:26;
		uint32_t	address:6;
#else
		uint32_t	address:6;
		uint32_t	rsrvd1:26;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_shadow_par_log_t;


/*
 * Register: RdcCtrlFifoEccLog
 * Rx DMA Control Fifo ECC Log
 * Description: RDC DMA Control FIFO ECC log register This register
 * logs the first ECC error that is encountered. A double-bit ecc
 * error over writes any single-bit ecc error previously logged
 * Fields:
 *     Address of ECC error for upper 64 bits Writing a 1 to
 *     RdcFifoErrStat::rxCtrlFifoDed[1] or
 *     RdcFifoErrStat::rxCtrlFifoSec[1] clears this register
 *     Address of ECC error for lower 64 bits Writing a 1 to
 *     RdcFifoErrStat::rxCtrlFifoDed[0] or
 *     RdcFifoErrStat::rxCtrlFifoSec[0] clears this register
 *     ECC syndrome for upper 64 bits Writing a 1 to
 *     RdcFifoErrStat::rxCtrlFifoDed[1] or
 *     RdcFifoErrStat::rxCtrlFifoSec[1] clears this register
 *     ECC syndrome for lower 64 bits Writing a 1 to
 *     RdcFifoErrStat::rxCtrlFifoDed[0] or
 *     RdcFifoErrStat::rxCtrlFifoSec[0] clears this register
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:7;
		uint32_t	address_hi:9;
		uint32_t	rsrvd1:7;
		uint32_t	address_lo:9;
		uint32_t	rsrvd2:8;
		uint32_t	syndrome_hi:8;
		uint32_t	rsrvd3:8;
		uint32_t	syndrome_lo:8;
#else
		uint32_t	syndrome_lo:8;
		uint32_t	rsrvd3:8;
		uint32_t	syndrome_hi:8;
		uint32_t	rsrvd2:8;
		uint32_t	address_lo:9;
		uint32_t	rsrvd1:7;
		uint32_t	address_hi:9;
		uint32_t	rsrvd:7;
#endif
	} bits;
} rdc_ctrl_fifo_ecc_log_t;


/*
 * Register: RdcDataFifoEccLog
 * Rx DMA Data Fifo ECC Log
 * Description: RDC DMA data FIFO ECC log register This register logs
 * the first ECC error that is encountered. A double-bit ecc error
 * over writes any single-bit ecc error previously logged
 * Fields:
 *     Address of ECC error for upper 64 bits Writing a 1 to
 *     RdcFifoErrStat::rxDataFifoDed[1] or
 *     RdcFifoErrStat::rxDataFifoSec[1] clears this register
 *     Address of ECC error for lower 64 bits Writing a 1 to
 *     RdcFifoErrStat::rxDataFifoDed[0] or
 *     RdcFifoErrStat::rxDataFifoSec[0] clears this register
 *     ECC syndrome for upper 64 bits Writing a 1 to
 *     RdcFifoErrStat::rxDataFifoDed[1] or
 *     RdcFifoErrStat::rxDataFifoSec[1] clears this register
 *     ECC syndrome for lower 64 bits Writing a 1 to
 *     RdcFifoErrStat::rxDataFifoDed[0] or
 *     RdcFifoErrStat::rxDataFifoSec[0] clears this register
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:5;
		uint32_t	address_hi:11;
		uint32_t	rsrvd1:5;
		uint32_t	address_lo:11;
		uint32_t	rsrvd2:8;
		uint32_t	syndrome_hi:8;
		uint32_t	rsrvd3:8;
		uint32_t	syndrome_lo:8;
#else
		uint32_t	syndrome_lo:8;
		uint32_t	rsrvd3:8;
		uint32_t	syndrome_hi:8;
		uint32_t	rsrvd2:8;
		uint32_t	address_lo:11;
		uint32_t	rsrvd1:5;
		uint32_t	address_hi:11;
		uint32_t	rsrvd:5;
#endif
	} bits;
} rdc_data_fifo_ecc_log_t;


/*
 * Register: RdcFifoErrIntMask
 * FIFO Error Interrupt Mask
 * Description: FIFO Error interrupt mask register. Control the
 * interrupt assertion of FIFO Errors. see FIFO Error Status register
 * for more description
 * Fields:
 *     Set to 0 to enable flagging when rx ctrl ram logs ecc single
 *     bit error Part of Device Error 0.
 *     Set to 0 to enable flagging when rx ctrl ram logs ecc double
 *     bit error Part of Device Error 1.
 *     Set to 0 to enable flagging when rx data ram logs ecc single
 *     bit error Part of Device Error 0.
 *     Set to 0 to enable flagging when rx data ram logs ecc double
 *     bit error Part of Device Error 1.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd1:24;
		uint32_t	rx_ctrl_fifo_sec:2;
		uint32_t	rx_ctrl_fifo_ded:2;
		uint32_t	rx_data_fifo_sec:2;
		uint32_t	rx_data_fifo_ded:2;
#else
		uint32_t	rx_data_fifo_ded:2;
		uint32_t	rx_data_fifo_sec:2;
		uint32_t	rx_ctrl_fifo_ded:2;
		uint32_t	rx_ctrl_fifo_sec:2;
		uint32_t	rsrvd1:24;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_fifo_err_int_mask_t;


/*
 * Register: RdcFifoErrStat
 * FIFO Error Status
 * Description: FIFO Error Status register. Log status of FIFO
 * Errors. Rx Data buffer is physically two seperate memory, each of
 * the two error bits point to one of the memory. Each entry in the
 * rx ctrl point to 2 buffer locations and they are read seperatly.
 * The two error bits point to each half of the entry.
 * Fields:
 *     Set to 1 by HW to indicate rx control ram received a ecc
 *     single bit error Writing a 1 to either bit clears the
 *     RdcCtrlFifoEccLog register Non-Fatal error. Part of Device
 *     Error 0
 *     Set to 1 by HW to indicate rx control ram received a ecc
 *     double bit error Writing a 1 to either bit clears the
 *     RdcCtrlFifoEccLog register Fatal error. Part of Device Error 1
 *     Set to 1 by HW to indicate rx data ram received a ecc single
 *     bit error Writing a 1 to either bit clears the
 *     RdcDataFifoEccLog register Non-Fatal error. Part of Device
 *     Error 0
 *     Set to 1 by HW to indicate rx data ram received a ecc double
 *     bit error Writing a 1 to either bit clears the
 *     RdcDataFifoEccLog register Fatal error. Part of Device Error 1
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:24;
		uint32_t	rx_ctrl_fifo_sec:2;
		uint32_t	rx_ctrl_fifo_ded:2;
		uint32_t	rx_data_fifo_sec:2;
		uint32_t	rx_data_fifo_ded:2;
#else
		uint32_t	rx_data_fifo_ded:2;
		uint32_t	rx_data_fifo_sec:2;
		uint32_t	rx_ctrl_fifo_ded:2;
		uint32_t	rx_ctrl_fifo_sec:2;
		uint32_t	rsrvd_l:24;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_fifo_err_stat_t;


/*
 * Register: RdcFifoErrIntDbg
 * FIFO Error Interrupt Debug
 * Description: FIFO Error interrupt Debug register. Debug Control
 * the interrupt assertion of FIFO Errors.
 * Fields:
 *     Set to 1 to enable interrupt Part of Device Error 0.
 *     Set to 1 to enable interrupt Part of Device Error 1.
 *     Set to 1 to enable interrupt Part of Device Error 0.
 *     Set to 1 to enable interrupt Part of Device Error 1.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd1:24;
		uint32_t	rx_ctrl_fifo_sec:2;
		uint32_t	rx_ctrl_fifo_ded:2;
		uint32_t	rx_data_fifo_sec:2;
		uint32_t	rx_data_fifo_ded:2;
#else
		uint32_t	rx_data_fifo_ded:2;
		uint32_t	rx_data_fifo_sec:2;
		uint32_t	rx_ctrl_fifo_ded:2;
		uint32_t	rx_ctrl_fifo_sec:2;
		uint32_t	rsrvd1:24;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_fifo_err_int_dbg_t;


/*
 * Register: RdcPeuTxnLog
 * PEU Transaction Log
 * Description: PEU Transaction Log register. Counts the memory read
 * and write requests sent to peu block. For debug only.
 * Fields:
 *     Counts the memory write transactions sent to peu block. This
 *     counter saturates. This counter increments when vnmDbg is on
 *     Counts the memory read transactions sent to peu block. This
 *     counter saturates. This counter increments when vnmDbg is on
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd1:16;
		uint32_t	peu_mem_wr_count:8;
		uint32_t	peu_mem_rd_count:8;
#else
		uint32_t	peu_mem_rd_count:8;
		uint32_t	peu_mem_wr_count:8;
		uint32_t	rsrvd1:16;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_peu_txn_log_t;


/*
 * Register: RdcDbgTrainingVec
 * Debug Training Vector
 * Description: Debug Training Vector register Debug Training Vector
 * for the coreClk domain. For the pcieClk domain, the dbgxMsb and
 * dbgyMsb values are flipped on the debug bus.
 * Fields:
 *     Blade Number, the value read depends on the blade this block
 *     resides
 *     debug training vector the sub-group select value of 0 selects
 *     this vector
 *     Blade Number, the value read depends on the blade this block
 *     resides
 *     debug training vector the sub-group select value of 0 selects
 *     this vector
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	dbgx_msb:1;
		uint32_t	dbgx_bld_num:3;
		uint32_t	dbgx_training_vec:12;
		uint32_t	dbgy_msb:1;
		uint32_t	dbgy_bld_num:3;
		uint32_t	dbgy_training_vec:12;
#else
		uint32_t	dbgy_training_vec:12;
		uint32_t	dbgy_bld_num:3;
		uint32_t	dbgy_msb:1;
		uint32_t	dbgx_training_vec:12;
		uint32_t	dbgx_bld_num:3;
		uint32_t	dbgx_msb:1;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_dbg_training_vec_t;


/*
 * Register: RdcDbgGrpSel
 * Debug Group Select
 * Description: Debug Group Select register. Debug Group Select
 * register selects the group of signals brought out on the debug
 * port
 * Fields:
 *     high 32b sub-group select
 *     low 32b sub-group select
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:16;
		uint32_t	dbg_h32_sub_sel:8;
		uint32_t	dbg_l32_sub_sel:8;
#else
		uint32_t	dbg_l32_sub_sel:8;
		uint32_t	dbg_h32_sub_sel:8;
		uint32_t	rsrvd_l:16;
		uint32_t	rsrvd:32;
#endif
	} bits;
} rdc_dbg_grp_sel_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _HXGE_RDC_HW_H */
