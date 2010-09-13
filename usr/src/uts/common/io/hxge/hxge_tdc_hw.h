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

#ifndef	_HXGE_TDC_HW_H
#define	_HXGE_TDC_HW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	TDC_BASE_ADDR				0X00400000

#define	TDC_PAGE_HANDLE				(TDC_BASE_ADDR + 0x8)
#define	TDC_TDR_CFG				(TDC_BASE_ADDR + 0x20)
#define	TDC_TDR_HEAD				(TDC_BASE_ADDR + 0x28)
#define	TDC_TDR_PRE_HEAD			(TDC_BASE_ADDR + 0x30)
#define	TDC_TDR_KICK				(TDC_BASE_ADDR + 0x38)
#define	TDC_INT_MASK				(TDC_BASE_ADDR + 0x40)
#define	TDC_STAT				(TDC_BASE_ADDR + 0x48)
#define	TDC_MBH					(TDC_BASE_ADDR + 0x50)
#define	TDC_MBL					(TDC_BASE_ADDR + 0x58)
#define	TDC_BYTE_CNT				(TDC_BASE_ADDR + 0x80)
#define	TDC_TDR_QLEN				(TDC_BASE_ADDR + 0x88)
#define	TDC_RTAB_PTR				(TDC_BASE_ADDR + 0x90)
#define	TDC_DROP_CNT				(TDC_BASE_ADDR + 0x98)
#define	TDC_LAST_PKT_RBUF_PTRS			(TDC_BASE_ADDR + 0xA8)
#define	TDC_PREF_CMD				(TDC_BASE_ADDR + 0x100)
#define	TDC_PREF_DATA				(TDC_BASE_ADDR + 0x108)
#define	TDC_PREF_PAR_DATA			(TDC_BASE_ADDR + 0x110)
#define	TDC_REORD_BUF_CMD			(TDC_BASE_ADDR + 0x120)
#define	TDC_REORD_BUF_DATA			(TDC_BASE_ADDR + 0x128)
#define	TDC_REORD_BUF_ECC_DATA			(TDC_BASE_ADDR + 0x130)
#define	TDC_REORD_TBL_CMD			(TDC_BASE_ADDR + 0x140)
#define	TDC_REORD_TBL_DATA_LO			(TDC_BASE_ADDR + 0x148)
#define	TDC_REORD_TBL_DATA_HI			(TDC_BASE_ADDR + 0x150)
#define	TDC_PREF_PAR_LOG			(TDC_BASE_ADDR + 0x200)
#define	TDC_REORD_BUF_ECC_LOG			(TDC_BASE_ADDR + 0x208)
#define	TDC_REORD_TBL_PAR_LOG			(TDC_BASE_ADDR + 0x210)
#define	TDC_FIFO_ERR_MASK			(TDC_BASE_ADDR + 0x220)
#define	TDC_FIFO_ERR_STAT			(TDC_BASE_ADDR + 0x228)
#define	TDC_FIFO_ERR_INT_DBG			(TDC_BASE_ADDR + 0x230)
#define	TDC_STAT_INT_DBG			(TDC_BASE_ADDR + 0x240)
#define	TDC_PKT_REQ_TID_TAG			(TDC_BASE_ADDR + 0x250)
#define	TDC_SOP_PREF_DESC_LOG			(TDC_BASE_ADDR + 0x260)
#define	TDC_PREF_DESC_LOG			(TDC_BASE_ADDR + 0x268)
#define	TDC_PEU_TXN_LOG				(TDC_BASE_ADDR + 0x270)
#define	TDC_DBG_TRAINING_VEC			(TDC_BASE_ADDR + 0x300)
#define	TDC_DBG_GRP_SEL				(TDC_BASE_ADDR + 0x308)


/*
 * Register: TdcPageHandle
 * Logical Page Handle
 * Description: Upper 20 bits [63:44] to use for all accesses over
 * the PCI-E bus. Fields in this register are part of the dma
 * configuration and cannot be changed once the dma is enabled.
 * Fields:
 *     Page handle, bits [63:44] of all PCI-E transactions for this
 *     channel.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:12;
		uint32_t	page_handle:20;
#else
		uint32_t	page_handle:20;
		uint32_t	rsrvd_l:12;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_page_handle_t;


/*
 * Register: TdcTdrCfg
 * Transmit Ring Configuration
 * Description: Configuration parameters for transmit DMA block.
 * Software configures the location of the transmit ring in host
 * memory, as well as its maximum size. Fields in this register are
 * part of the dma configuration and cannot be changed once the dma
 * is enabled.
 * HW does not check for all configuration errors across different
 * fields.
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
 *     Bits [15:5] of the maximum number of entries in the Transmit
 *     Queue ring buffer. Bits [4:0] are always 0. Maximum number of
 *     entries is (2^16 - 32) and is limited by the staddr value.
 *     (len + staddr) should not exceed (2^16 - 32).
 *     Set to 1 to enable the Transmit DMA. On fatal errors, this bit
 *     will be cleared by hardware. This bit cannot be set if sw has
 *     not resolved any pending fatal error condition: i.e. any
 *     TdcStat ldf1 error bits remain set.
 *     Set to 1 to reset the DMA. Hardware will clear this bit after
 *     reset is completed. A reset will bring the sepecific DMA back
 *     to the power on state (including the DMA.en in this register).
 *     When set to 1, it indicates all state associated with the DMA
 *     are in its initial state following either dma reset or
 *     disable. Thus, once this is set to 1, sw could start to
 *     configure the DMA if needed. In an extreme case such as if a
 *     parity error on an EOP descriptor prevents recognition of the
 *     EOP, it is possible that the qst bit will not be set even
 *     though the dma engine has been disabled.
 *     Address bits [43:19] of the start address for the transmit
 *     ring buffer. The value in this field is dependent on len
 *     field. (len + staddr) should not exceed (2^16 - 32).
 *     Bits [18:6] of the start address for the transmit ring buffer.
 *     Bits [5:0] are assumed to be zero, or 64B aligned.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	len:11;
		uint32_t	rsrvd:5;
		uint32_t	enable:1;
		uint32_t	reset:1;
		uint32_t	qst:1;
		uint32_t	rsrvd1:1;
		uint32_t	staddr_base:12;
		uint32_t	staddr_base_l:13;
		uint32_t	staddr:13;
		uint32_t	rsrvd2:6;
#else
		uint32_t	rsrvd2:6;
		uint32_t	staddr:13;
		uint32_t	staddr_base_l:13;
		uint32_t	staddr_base:12;
		uint32_t	rsrvd1:1;
		uint32_t	qst:1;
		uint32_t	reset:1;
		uint32_t	enable:1;
		uint32_t	rsrvd:5;
		uint32_t	len:11;
#endif
	} bits;
} tdc_tdr_cfg_t;


/*
 * Register: TdcTdrHead
 * Transmit Ring Head
 * Description: Read-only register software call poll to determine
 * the current head of the transmit ring, from the tdcTxPkt block.
 * Software uses this to know which Tdr entries have had their
 * descriptors transmitted. These entries and their descriptors may
 * then be reused by software.
 * Fields:
 *     Hardware will toggle this bit every time the head is wrapped
 *     around the configured ring buffer.
 *     Entry in transmit ring which will be the next descriptor
 *     transmitted. Software should consider the Tdr full if head ==
 *     TdcTdrKick::tail and wrap != TdcTdrKick::wrap. The ring is
 *     empty of head == TdcTdrKick::tail and wrap ==
 *     TdcTdrKick::wrap.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:15;
		uint32_t	wrap:1;
		uint32_t	head:16;
#else
		uint32_t	head:16;
		uint32_t	wrap:1;
		uint32_t	rsrvd_l:15;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_tdr_head_t;


/*
 * Register: TdcTdrPreHead
 * Transmit Ring Prefetch Head
 * Description: Read-only register software call poll to determine
 * the current prefetch head of the transmit ring, from the tdcPktReq
 * block. Transmit descriptors are prefetched into chip memory.
 * Indicates next descriptor to be read from host memory. For debug
 * use only.
 * Fields:
 *     Hardware will toggle this bit every time the prefetch head is
 *     wrapped around the configured ring buffer.
 *     Entry in transmit ring which will be fetched next from host
 *     memory.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:15;
		uint32_t	wrap:1;
		uint32_t	head:16;
#else
		uint32_t	head:16;
		uint32_t	wrap:1;
		uint32_t	rsrvd_l:15;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_tdr_pre_head_t;


/*
 * Register: TdcTdrKick
 * Transmit Ring Kick
 * Description: After posting transmit descriptors to the Transmit
 * Ring, software updates the tail pointer to inform Hydra of the new
 * descriptors. Software can only post descriptors through this
 * register when the entire packet is in the ring. Otherwise,
 * hardware dead-lock can occur. If an overflow kick occurs when the
 * channel is disabled, tdcStat.txRngOflow (Transmit Ring Overflow)
 * status is not set.
 * Fields:
 *     Software needs to toggle this bit every time the tail is
 *     wrapped around the configured ring buffer.
 *     Entry where the next valid descriptor will be added (one entry
 *     past the last valid descriptor.)
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:15;
		uint32_t	wrap:1;
		uint32_t	tail:16;
#else
		uint32_t	tail:16;
		uint32_t	wrap:1;
		uint32_t	rsrvd_l:15;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_tdr_kick_t;


/*
 * Register: TdcIntMask
 * Transmit Event Mask
 * Description: The Tx DMA can generate a number of LDF events. The
 * events can be enabled by software by setting the corresponding bit
 * to 0. The default value of 1 means the event is masked and no LDF
 * event is generated.
 * Fields:
 *     Set to 0 to select the event to raise the LDF for packets
 *     marked. An LDF 0 event.
 *     Set to 0 to select the event to raise the LDF when poisoned
 *     completion or non-zero (unsuccessful) completion status
 *     received from PEU. An LDF 1 event.
 *     Set to 0 to select the event to raise the LDF when total bytes
 *     transmitted compared against pkt internal header bytes
 *     transmitted mismatch. An LDF 1 event.
 *     Set to 0 to select the event to raise the LDF when a runt
 *     packet is dropped (when VMAC does not allow runt packets to be
 *     padded). An LDF 1 event.
 *     Set to 0 to select the event to raise the LDF when the packet
 *     size exceeds hardware limit. An LDF 1 event.
 *     Set to 0 to select the event to raise the LDF to indicate
 *     Transmit Ring Overflow An LDF 1 event.
 *     Set to 0 to select the event to raise the LDF to indicate
 *     parity error on the tdr prefetch buffer occurred. An LDF 1
 *     event.
 *     Set to 0 to select the event to raise the LDF to indicate tdc
 *     received a response completion timeout from peu for tdr
 *     descriptor prefetch An LDF 1 event.
 *     Set to 0 to select the event to raise the LDF to indicate tdc
 *     received a response completion timeout from peu for packet
 *     data request An LDF 1 event.
 *     Set to 0 to select the event to raise the LDF to indicate tdc
 *     did not receive an SOP in the 1st descriptor as was expected
 *     or the numPtr in the 1st descriptor was set to 0. An LDF 1
 *     event.
 *     Set to 0 to select the event to raise the LDF to indicate tdc
 *     received an unexpected SOP descriptor error. An LDF 1 event.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:16;
		uint32_t	marked:1;
		uint32_t	rsrvd1:5;
		uint32_t	peu_resp_err:1;
		uint32_t	pkt_size_hdr_err:1;
		uint32_t	runt_pkt_drop_err:1;
		uint32_t	pkt_size_err:1;
		uint32_t	tx_rng_oflow:1;
		uint32_t	pref_par_err:1;
		uint32_t	tdr_pref_cpl_to:1;
		uint32_t	pkt_cpl_to:1;
		uint32_t	invalid_sop:1;
		uint32_t	unexpected_sop:1;
#else
		uint32_t	unexpected_sop:1;
		uint32_t	invalid_sop:1;
		uint32_t	pkt_cpl_to:1;
		uint32_t	tdr_pref_cpl_to:1;
		uint32_t	pref_par_err:1;
		uint32_t	tx_rng_oflow:1;
		uint32_t	pkt_size_err:1;
		uint32_t	runt_pkt_drop_err:1;
		uint32_t	pkt_size_hdr_err:1;
		uint32_t	peu_resp_err:1;
		uint32_t	rsrvd1:5;
		uint32_t	marked:1;
		uint32_t	rsrvd_l:16;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_int_mask_t;


/*
 * Register: TdcStat
 * Transmit Control and Status
 * Description: Combined control and status register. When writing to
 * this register, any bit that software wishes not to change should
 * be written to 0. The TdcStat register may be read or written only
 * when no mailbox updates are pending. Accordingly, the expected
 * algorithm for software to use in tracking marked packets and
 * mailbox updates is one of the following only: 1) enable
 * interrupts, enable mb, send a single marked packet, wait for Ldf0,
 * clear marked, repeat or 2) disable interrupts, never enable mb,
 * send one or more marked packets, poll TdcStat for marked/mMarked
 * state, clear marked/mMarked bits, repeat. If interrupts are
 * enabled, upon receiving an Ldf1 interrupt for a given channel
 * software must wait until a channel's Qst bit has asserted before
 * reading TdcStat for corresponding error information and before
 * writing to TdcStat to clear error state.
 * Fields:
 *     A wrap-around counter to keep track of packets transmitted.
 *     Reset to zero when the DMA is reset
 *     The pktCnt corresponds to the last packet with the MARK bit
 *     set. Reset to zero when the DMA is reset.
 *     Set to 1 to cause HW to update the mailbox when the next
 *     packet with the marked bit set is transmitted. HW clears this
 *     bit to zero after the mailbox update has completed. Note that,
 *     correspondingly, the TdcStat data for the Tx mailbox write
 *     will reflect the state of mb prior to the mb bit's update for
 *     the marked packet being sent. Software should send only one
 *     marked packet per assertion of the mb bit. Multiple marked
 *     packets after setting the mb bit and before receiving the
 *     corresponding mailbox update is not supported. Precautionary
 *     note: Emphasize HW is responsible for clearing this bit. If
 *     software clears this bit, the behavior is undefined.
 *     Set to 1 when a packet with the mark bit set is transmitted.
 *     If mb is set at the time of the marked packet transmission,
 *     marked will not be set until the corresponding mailbox write
 *     has completed. Note that, correspondingly, the TdcStat data
 *     for the Tx mailbox write will reflect the state of marked
 *     prior to the marked bit's update for the marked packet being
 *     sent. Software may read the register to clear the bit.
 *     Alternatively, software may write a 1 to clear the MARKED bit
 *     (Write 0 has no effect). In the case of write 1, if mMarked
 *     bit is set, MARKED bit will NOT be cleared. This bit is used
 *     to generate LDF 0 consistent with settings in TdcIntMask.
 *     Overflow bit for MARKED register bit. Indicates that multiple
 *     marked packets have been transmitted since the last clear of
 *     the marked bit. If hardware is waiting to update MARKED until
 *     a mailbox write has completed, when another marked packet is
 *     transmitted, mMarked will also not be set until the mailbox
 *     write completes. Note that, correspondingly, the TdcStat data
 *     for the Tx mailbox write will reflect the state of mMarked
 *     prior to the mMarked bit's update for the marked packet being
 *     sent. Software reads to clear. A write 1 to MARKED bit will
 *     also clear the mMarked bit. A write 0 has no effect.
 *     Set to 1 to indicate poisoned completion or non-zero
 *     (unsuccessful) completion status received from PEU. Part of
 *     LDF 1.
 *     Set to 1 to indicate tdc descriptor error: total bytes
 *     transmitted compared against pkt internal header bytes
 *     transmitted mismatch. Fatal error. Part of LDF 1.
 *     Set to 1 when a runt packet is dropped (when VMAC does not
 *     allow runt packets to be padded. Fatal error. Part of LDF1.
 *     Set to 1 when the packet size exceeds hardware limit: the sum
 *     of gathers exceeds the maximum transmit length (specified in
 *     the Tx VMAC Configuration register txMaxFrameLength) or any
 *     descriptor attempts to transmit more than 4K. Writing a 1
 *     clears the value to 0. Writing a 0 has no effect. Part of LDF
 *     1. Note that packet size for the purpose of this error is
 *     determined by the actual transfer size from the Tdc to the Tdp
 *     and not from the totXferSize field of the internal header.
 *     Set to 1 to indicate Transmit Ring Overflow: Tail > Ringlength
 *     or if the relative position of the shadow tail to the ring
 *     tail is not correct with respect to the wrap bit. Transmit
 *     Ring Overflow status is not set, if the dma is disabled. Fatal
 *     error. Part of LDF1.
 *     Set to 1 by HW to indicate parity error on the tdr prefetch
 *     buffer occurred. Writing a 1 clears the parity error log
 *     register Part of LDF 1.
 *     Set to 1 to indicate tdc received a response completion
 *     timeout from peu for tdr descriptor prefetch Fatal error. Part
 *     of LDF 1.
 *     Set to 1 to indicate tdc received a response completion
 *     timeout from peu for packet data request Fatal error. Part of
 *     LDF 1.
 *     Set to 1 to indicate tdc did not receive an SOP in the 1st
 *     descriptor as was expected or the numPtr in the 1st descriptor
 *     was set to 0. Fatal error. Part of LDF 1.
 *     Set to 1 to indicate tdc received an unexpected SOP descriptor
 *     error. Fatal error. Part of LDF 1.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:4;
		uint32_t	pkt_cnt:12;
		uint32_t	rsrvd1:4;
		uint32_t	lastmark:12;
		uint32_t	rsrvd2:2;
		uint32_t	mb:1;
		uint32_t	rsrvd3:13;
		uint32_t	marked:1;
		uint32_t	m_marked:1;
		uint32_t	rsrvd4:4;
		uint32_t	peu_resp_err:1;
		uint32_t	pkt_size_hdr_err:1;
		uint32_t	runt_pkt_drop_err:1;
		uint32_t	pkt_size_err:1;
		uint32_t	tx_rng_oflow:1;
		uint32_t	pref_par_err:1;
		uint32_t	tdr_pref_cpl_to:1;
		uint32_t	pkt_cpl_to:1;
		uint32_t	invalid_sop:1;
		uint32_t	unexpected_sop:1;
#else
		uint32_t	unexpected_sop:1;
		uint32_t	invalid_sop:1;
		uint32_t	pkt_cpl_to:1;
		uint32_t	tdr_pref_cpl_to:1;
		uint32_t	pref_par_err:1;
		uint32_t	tx_rng_oflow:1;
		uint32_t	pkt_size_err:1;
		uint32_t	runt_pkt_drop_err:1;
		uint32_t	pkt_size_hdr_err:1;
		uint32_t	peu_resp_err:1;
		uint32_t	rsrvd4:4;
		uint32_t	m_marked:1;
		uint32_t	marked:1;
		uint32_t	rsrvd3:13;
		uint32_t	mb:1;
		uint32_t	rsrvd2:2;
		uint32_t	lastmark:12;
		uint32_t	rsrvd1:4;
		uint32_t	pkt_cnt:12;
		uint32_t	rsrvd:4;
#endif
	} bits;
} tdc_stat_t;


/*
 * Register: TdcMbh
 * Tx DMA Mailbox High
 * Description: Upper bits of Tx DMA mailbox address in host memory.
 * Fields in this register are part of the dma configuration and
 * cannot be changed once the dma is enabled.
 * Fields:
 *     Bits [43:32] of the Mailbox address.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:20;
		uint32_t	mbaddr:12;
#else
		uint32_t	mbaddr:12;
		uint32_t	rsrvd_l:20;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_mbh_t;


/*
 * Register: TdcMbl
 * Tx DMA Mailbox Low
 * Description: Lower bits of Tx DMA mailbox address in host memory.
 * Fields in this register are part of the dma configuration and
 * cannot be changed once the dma is enabled.
 * Fields:
 *     Bits [31:6] of the Mailbox address. Bits [5:0] are assumed to
 *     be zero, or 64B aligned.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	mbaddr:26;
		uint32_t	rsrvd1:6;
#else
		uint32_t	rsrvd1:6;
		uint32_t	mbaddr:26;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_mbl_t;


/*
 * Register: TdcByteCnt
 * Tx DMA Byte Count
 * Description: Counts the number of bytes transmitted to the tx
 * datapath block. This count may increment in advance of
 * corresponding updates to TdcStat for the bytes transmitted.
 * Fields:
 *     Number of bytes transmitted from transmit ring. This counter
 *     will saturate. This register is cleared on read.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	byte_count:32;
#else
		uint32_t	byte_count:32;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_byte_cnt_t;


/*
 * Register: TdcTdrQlen
 * Tdr Queue Length
 * Description: Number of descriptors in Tdr For debug only. Note:
 * Not analogous to either rdc.rbrQlen or tdc.tdcKick -
 * tdc.tdcTdrHead. Indicates depth of the two intermediate descriptor
 * usage points rather than end-to-end descriptor availability.
 * Fields:
 *     Current number of descriptors in Tdr, unprefetched
 *     Current number of descriptors in Tdr in prefetch buffer, i.e.
 *     those which have been prefetched but have not yet been
 *     allocated to the RTab.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	tdr_qlen:16;
		uint32_t	tdr_pref_qlen:16;
#else
		uint32_t	tdr_pref_qlen:16;
		uint32_t	tdr_qlen:16;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_tdr_qlen_t;


/*
 * Register: TdcRtabPtr
 * RTAB pointers
 * Description: Status of the reorder table pointers Writing to this
 * register is for debug purposes only and is enabled when vnmDbgOn
 * is set to 1
 * Fields:
 *     Current rtab head pointer, used in the txPkt block This
 *     register is used to dequeue entries in the reorder table when
 *     packets are sent out
 *     Current rtab head pointer, used in the pktResp block This
 *     register is used to scan entries in the reorder table when
 *     packet data response completions arrive
 *     Current rtab tail pointer, used in the pktReq block This
 *     register is used to allocate entries in the reorder table when
 *     packet data requests are made
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:24;
		uint32_t	pkt_rtab_head:8;
		uint32_t	rsrvd1:7;
		uint32_t	rtab_head:9;
		uint32_t	rsrvd2:7;
		uint32_t	rtab_tail:9;
#else
		uint32_t	rtab_tail:9;
		uint32_t	rsrvd2:7;
		uint32_t	rtab_head:9;
		uint32_t	rsrvd1:7;
		uint32_t	pkt_rtab_head:8;
		uint32_t	rsrvd:24;
#endif
	} bits;
} tdc_rtab_ptr_t;


/*
 * Register: TdcDropCnt
 * Packet Drop Counter
 * Description: Counts the number of runt, aborted and size
 * mismatched packets dropped by the tx datapath block.
 * Fields:
 *     Number of dropped due to pktSizeHdrErr. This counter will
 *     saturate. This counter is cleared on read.
 *     Number of dropped due to packet abort bit being set. Many
 *     different error events could be the source of packet abort
 *     drop. Descriptor-related error events include those errors
 *     encountered while in the middle of processing a packet
 *     request: 1. unexpectedSop; 2. non-SOP descriptor parity error
 *     (prefParErr); 3. ran out of non-SOP descriptors due to peu
 *     response errors (tdrPrefCplTo or peuRespErr) or the channel
 *     being disabled before the TDR request can be made. Packet
 *     response errors encountered while in the middle of processing
 *     a packet request also can trigger the packet abort: 4. packet
 *     response did not return due to peu response errors ( pktCplTo
 *     or peuRespErr); 5. Rtab parity error (reordTblParErr). This
 *     counter will saturate. This counter is cleared on read. Note
 *     that packet aborts are not counted until the packet is cleared
 *     from the RTab, which may be an arbitrary amount of time after
 *     the corresponding error is logged in TdcStat. In most cases,
 *     this will occur before the channel is quiesced following
 *     channel disable. In an extreme case such as if a parity error
 *     on an EOP descriptor prevents recognition of the EOP, it is
 *     possible that the quiescent bit itself will not be set
 *     although the packet drop counter will be incremented.
 *     Number of dropped due to runt packet size error. This counter
 *     will saturate. This counter is cleared on read.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:8;
		uint32_t	hdr_size_error_count:8;
		uint32_t	abort_count:8;
		uint32_t	runt_count:8;
#else
		uint32_t	runt_count:8;
		uint32_t	abort_count:8;
		uint32_t	hdr_size_error_count:8;
		uint32_t	rsrvd_l:8;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_drop_cnt_t;


/*
 * Register: TdcLastPktRbufPtrs
 * Last Packet RBUF Pointers
 * Description: Logs the RBUF head and tail pointer of the last
 * packet sent by the tx datapath block.
 * Fields:
 *     Logs the RBUF tail pointer of the last packet sent
 *     Logs the RBUF head pointer of the last packet sent
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:4;
		uint32_t	rbuf_tail_ptr:12;
		uint32_t	rsrvd1:4;
		uint32_t	rbuf_head_ptr:12;
#else
		uint32_t	rbuf_head_ptr:12;
		uint32_t	rsrvd1:4;
		uint32_t	rbuf_tail_ptr:12;
		uint32_t	rsrvd_l:4;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_last_pkt_rbuf_ptrs_t;


/*
 * Register: TdcPrefCmd
 * Tx DMA Prefetch Buffer Command
 * Description: Allows debug access to the entire prefetch buffer.
 * For writes, software writes the tdcPrefData and tdcPrefParData
 * registers, before writing the tdcPrefCmd register. For reads,
 * software writes the tdcPrefCmd register, then reads the
 * tdcPrefData and tdcPrefParData registers. The valid field should
 * be polled by software until it goes low, indicating the read or
 * write has completed. Writing the tdcPrefCmd triggers the access.
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
} tdc_pref_cmd_t;


/*
 * Register: TdcPrefData
 * Tx DMA Prefetch Buffer Data
 * Description: See tdcPrefCmd register.
 * Fields:
 *     For writes, data which is written into prefetch buffer. For
 *     reads, data read from the prefetch buffer.
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
} tdc_pref_data_t;


/*
 * Register: TdcPrefParData
 * Tx DMA Prefetch Buffer Parity Data
 * Description: See tdcPrefCmd register.
 * Fields:
 *     For writes, parity data which is written into prefetch buffer.
 *     For reads, parity data read from the prefetch buffer.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:24;
		uint32_t	par_data:8;
#else
		uint32_t	par_data:8;
		uint32_t	rsrvd_l:24;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_pref_par_data_t;


/*
 * Register: TdcReordBufCmd
 * Tx DMA Reorder Buffer Command
 * Description: Allows debug access to the entire Reorder buffer. For
 * writes, software writes the tdcReordBufData and tdcReordBufEccData
 * before writing the tdcReordBufCmd register. For reads, software
 * writes the tdcReordBufCmd register, then reads the tdcReordBufData
 * and tdcReordBufEccData registers. The valid field should be polled
 * by software until it goes low, indicating the read or write has
 * completed. Writing the tdcReordBufCmd triggers the access.
 * Fields:
 *     status of indirect access 0=busy 1=done
 *     Command type. 1 indicates a read command, 0 a write command.
 *     enable writing of ecc bits 1=enabled, 0=disabled
 *     Entry in the reorder buffer to read or write
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	status:1;
		uint32_t	cmd:1;
		uint32_t	ecc_en:1;
		uint32_t	rsrvd1:17;
		uint32_t	entry:12;
#else
		uint32_t	entry:12;
		uint32_t	rsrvd1:17;
		uint32_t	ecc_en:1;
		uint32_t	cmd:1;
		uint32_t	status:1;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_reord_buf_cmd_t;


/*
 * Register: TdcReordBufData
 * Tx DMA Reorder Buffer Data
 * Description: See tdcReordBufCmd register.
 * Fields:
 *     For writes, data which is written into reorder buffer. For
 *     reads, data read from the reorder buffer.
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
} tdc_reord_buf_data_t;


/*
 * Register: TdcReordBufEccData
 * Tx DMA Reorder Buffer ECC Data
 * Description: See tdcReordBufCmd register.
 * Fields:
 *     For writes, ecc data which is written into reorder buffer. For
 *     reads, ecc data read from the reorder buffer.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:24;
		uint32_t	ecc_data:8;
#else
		uint32_t	ecc_data:8;
		uint32_t	rsrvd_l:24;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_reord_buf_ecc_data_t;


/*
 * Register: TdcReordTblCmd
 * Tx DMA Reorder Table Command
 * Description: Allows debug access to the entire Reorder Table. For
 * writes, software writes the tdcReordTblData and tdcReordTblParData
 * before writing the tdcReordTblCmd register. For reads, software
 * writes the tdcReordTblCmd register, then reads the tdcReordTblData
 * and tdcReordTblParData registers. The valid field should be polled
 * by software until it goes low, indicating the read or write has
 * completed. Writing the tdcReordTblCmd triggers the access.
 * Fields:
 *     status of indirect access 0=busy 1=done
 *     Command type. 1 indicates a read command, 0 a write command.
 *     enable writing of par bits 1=enabled, 0=disabled
 *     Address in the reorder table to read from or write to
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	status:1;
		uint32_t	cmd:1;
		uint32_t	par_en:1;
		uint32_t	rsrvd1:21;
		uint32_t	entry:8;
#else
		uint32_t	entry:8;
		uint32_t	rsrvd1:21;
		uint32_t	par_en:1;
		uint32_t	cmd:1;
		uint32_t	status:1;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_reord_tbl_cmd_t;


/*
 * Register: TdcReordTblDataLo
 * Tx DMA Reorder Table Data Lo
 * Description: See tdcReordTblCmd register.
 * Fields:
 *     For writes, data which is written into reorder table. For
 *     reads, data read from the reorder table.
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
} tdc_reord_tbl_data_lo_t;


/*
 * Register: TdcReordTblDataHi
 * Tx DMA Reorder Table Data Hi
 * Description: See tdcReordTblCmd register.
 * Fields:
 *     For writes, parity data which is written into reorder table.
 *     For reads, parity data read from the reorder table.
 *     For writes, data which is written into reorder table. For
 *     reads, data read from the reorder table.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:15;
		uint32_t	par_data:9;
		uint32_t	hi_data:8;
#else
		uint32_t	hi_data:8;
		uint32_t	par_data:9;
		uint32_t	rsrvd_l:15;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_reord_tbl_data_hi_t;


/*
 * Register: TdcPrefParLog
 * Tx DMA Prefetch Buffer Parity Log
 * Description: TDC DMA Prefetch Buffer parity log register This
 * register logs the first parity error encountered. Writing a 1 to
 * TdcStat::prefParErr clears this register and re-arms for logging
 * the next error
 * Fields:
 *     Address of parity error read data
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
} tdc_pref_par_log_t;


/*
 * Register: TdcReordBufEccLog
 * Tx Reorder Buffer ECC Log
 * Description: TDC Reorder Buffer ECC log register This register
 * logs the first ECC error encountered. Writing a 1 to
 * tdcFifoErrStat::reordBufDedErr or tdcFifoErrStat::reordBufSecErr
 * clears this register and re-arms for logging
 * Fields:
 *     Address of ECC error
 *     Syndrome of ECC error
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd1:4;
		uint32_t	address:12;
		uint32_t	rsrvd2:8;
		uint32_t	syndrome:8;
#else
		uint32_t	syndrome:8;
		uint32_t	rsrvd2:8;
		uint32_t	address:12;
		uint32_t	rsrvd1:4;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_reord_buf_ecc_log_t;


/*
 * Register: TdcReordTblParLog
 * Tx Reorder Table Parity Log
 * Description: TDC Reorder Table parity log register This register
 * logs the first parity error encountered. Writing a 1 to
 * tdcFifoErrStat::reordTblParErr clears this register and re-arms
 * for logging
 * Fields:
 *     Address of parity error
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd1:24;
		uint32_t	address:8;
#else
		uint32_t	address:8;
		uint32_t	rsrvd1:24;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_reord_tbl_par_log_t;


/*
 * Register: TdcFifoErrMask
 * FIFO Error Mask
 * Description: FIFO Error Mask register. Mask status of Reorder
 * Buffer and Reorder Table Buffer Errors.
 * Fields:
 *     Set to 0 to select the event to raise the LDF to indicate
 *     reorder table ram received a parity error An Device Error 1
 *     event.
 *     Set to 0 to select the event to raise the LDF to indicate
 *     reorder buffer ram received a ecc double bit error An Device
 *     Error 1 event.
 *     Set to 0 to select the event to raise the LDF to indicate
 *     reorder buffer ram received a ecc single bit error An Device
 *     Error 0 event.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:29;
		uint32_t	reord_tbl_par_err:1;
		uint32_t	reord_buf_ded_err:1;
		uint32_t	reord_buf_sec_err:1;
#else
		uint32_t	reord_buf_sec_err:1;
		uint32_t	reord_buf_ded_err:1;
		uint32_t	reord_tbl_par_err:1;
		uint32_t	rsrvd_l:29;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_fifo_err_mask_t;


/*
 * Register: TdcFifoErrStat
 * FIFO Error Status
 * Description: FIFO Error Status register. Log status of Reorder
 * Buffer and Reorder Table Buffer Errors.
 * Fields:
 *     Set to 1 by HW to indicate reorder table ram received a parity
 *     error Writing a 1 clears this bit and also clears the
 *     TdcReordTblParLog register Fatal error. Part of Device Error
 *     1.
 *     Set to 1 by HW to indicate reorder buffer ram received a
 *     double bit ecc error Writing a 1 clears this bit and also
 *     clears the tdcReordBufEccLog register Fatal error. Part of
 *     Device Error 1.
 *     Set to 1 by HW to indicate reorder buffer ram received a
 *     single bit ecc error Writing a 1 clears this bit and also
 *     clears the tdcReordBufEccLog register Non-Fatal error. Part of
 *     Device Error 0.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:29;
		uint32_t	reord_tbl_par_err:1;
		uint32_t	reord_buf_ded_err:1;
		uint32_t	reord_buf_sec_err:1;
#else
		uint32_t	reord_buf_sec_err:1;
		uint32_t	reord_buf_ded_err:1;
		uint32_t	reord_tbl_par_err:1;
		uint32_t	rsrvd_l:29;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_fifo_err_stat_t;


/*
 * Register: TdcFifoErrIntDbg
 * FIFO Error Interrupt Debug
 * Description: FIFO Error Interrupt Debug register. Write this
 * regsiter to set bits in TdcFifoErrStat, allowing debug creation of
 * interrupts without needing to create the actual events. This
 * register holds no state. Reading this register gives the Tdc Fifo
 * Err Status data. Clear interrupt state by clearing TdcFifoErrStat.
 * For Debug only
 * Fields:
 *     Set to 1 to select the event to raise the LDF to indicate
 *     reorder table ram received a parity error An Device Error 1
 *     event.
 *     Set to 1 to select the event to raise the LDF to indicate
 *     reorder buffer ram received a ecc double bit error An Device
 *     Error 1 event.
 *     Set to 1 to select the event to raise the LDF to indicate
 *     reorder buffer ram received a ecc single bit error An Device
 *     Error 0 event.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:29;
		uint32_t	reord_tbl_par_err:1;
		uint32_t	reord_buf_ded_err:1;
		uint32_t	reord_buf_sec_err:1;
#else
		uint32_t	reord_buf_sec_err:1;
		uint32_t	reord_buf_ded_err:1;
		uint32_t	reord_tbl_par_err:1;
		uint32_t	rsrvd_l:29;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_fifo_err_int_dbg_t;


/*
 * Register: TdcStatIntDbg
 * Transmit Status Interrupt Debug
 * Description: Write this regsiter to set bits in TdcStat, allowing
 * debug creation of interrupts without needing to create the actual
 * events. This register holds no state. Reading this register gives
 * the Transmit Control and Status data. Clear interrupt state by
 * clearing TdcStat. For Debug only
 * Fields:
 *     Set to 1 to select the event to raise the LDF for packets
 *     marked. An LDF 0 event.
 *     Set to 1 to select the event to raise the LDF when poisoned
 *     completion or non-zero (unsuccessful) completion status
 *     received from PEU. An LDF 1 event.
 *     Set to 1 to select the event to raise the LDF when total bytes
 *     transmitted compared against pkt internal header bytes
 *     transmitted mismatch. An LDF 1 event.
 *     Set to 1 to select the event to raise the LDF when a runt
 *     packet is dropped (when VMAC does not allow runt packets to be
 *     padded). An LDF 1 event.
 *     Set to 1 to select the event to raise the LDF when the packet
 *     size exceeds hardware limit. An LDF 1 event.
 *     Set to 1 to select the event to raise the LDF to indicate
 *     Transmit Ring Overflow An LDF 1 event.
 *     Set to 1 to select the event to raise the LDF to indicate
 *     parity error on the tdr prefetch buffer occurred. An LDF 1
 *     event.
 *     Set to 1 to select the event to raise the LDF to indicate tdc
 *     received a response completion timeout from peu for tdr
 *     descriptor prefetch An LDF 1 event.
 *     Set to 1 to select the event to raise the LDF to indicate tdc
 *     received a response completion timeout from peu for packet
 *     data request An LDF 1 event.
 *     Set to 1 to select the event to raise the LDF to indicate tdc
 *     did not receive an SOP in the 1st descriptor as was expected
 *     or the numPtr in the 1st descriptor was set to 0. An LDF 1
 *     event.
 *     Set to 1 to select the event to raise the LDF to indicate tdc
 *     received an unexpected SOP descriptor error. An LDF 1 event.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:16;
		uint32_t	marked:1;
		uint32_t	rsrvd1:5;
		uint32_t	peu_resp_err:1;
		uint32_t	pkt_size_hdr_err:1;
		uint32_t	runt_pkt_drop_err:1;
		uint32_t	pkt_size_err:1;
		uint32_t	tx_rng_oflow:1;
		uint32_t	pref_par_err:1;
		uint32_t	tdr_pref_cpl_to:1;
		uint32_t	pkt_cpl_to:1;
		uint32_t	invalid_sop:1;
		uint32_t	unexpected_sop:1;
#else
		uint32_t	unexpected_sop:1;
		uint32_t	invalid_sop:1;
		uint32_t	pkt_cpl_to:1;
		uint32_t	tdr_pref_cpl_to:1;
		uint32_t	pref_par_err:1;
		uint32_t	tx_rng_oflow:1;
		uint32_t	pkt_size_err:1;
		uint32_t	runt_pkt_drop_err:1;
		uint32_t	pkt_size_hdr_err:1;
		uint32_t	peu_resp_err:1;
		uint32_t	rsrvd1:5;
		uint32_t	marked:1;
		uint32_t	rsrvd_l:16;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_stat_int_dbg_t;


/*
 * Register: TdcPktReqTidTag
 * Packet Request TID Tag
 * Description: Packet Request TID Tag register Track the packet
 * request TID currently used
 * Fields:
 *     When set to 1, it indicates the TID is currently being used
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	pkt_req_tid_tag:24;
		uint32_t	rsrvd1:8;
#else
		uint32_t	rsrvd1:8;
		uint32_t	pkt_req_tid_tag:24;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_pkt_req_tid_tag_t;


/*
 * Register: TdcSopPrefDescLog
 * SOP Prefetch Descriptor Log
 * Description: SOP Descriptor Log register Logs the last SOP
 * prefetch descriptor processed by the packet request block. This
 * log could represent the current SOP prefetch descriptor if the
 * packet request block did not complete issuing the data requests
 * from this descriptor. Descriptors are logged to this register when
 * the packet request block is expecting an SOP descriptor, and it
 * receives it.
 * Fields:
 *     Represents the last or current SOP descriptor being processed
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	sop_pref_desc_log:32;
		uint32_t	sop_pref_desc_log_l:32;
#else
		uint32_t	sop_pref_desc_log_l:32;
		uint32_t	sop_pref_desc_log:32;
#endif
	} bits;
} tdc_sop_pref_desc_log_t;


/*
 * Register: TdcPrefDescLog
 * Prefetch Descriptor Log
 * Description: SOP Descriptor Log register Logs the last prefetch
 * descriptor processed by the packet request block. This log could
 * represent the current prefetch descriptor if the packet request
 * block did not complete issuing the data requests from this
 * descriptor. The contents in this register could differ from the
 * SOP Prefetch Descriptor Log register if a particular packet
 * requires usage of more than 1 descriptor. Descriptors are logged
 * to this register when the packet request block is expecting a
 * descriptor after the SOP descriptor.
 * Fields:
 *     Represents the last or current descriptor being processed
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	pref_desc_log:32;
		uint32_t	pref_desc_log_l:32;
#else
		uint32_t	pref_desc_log_l:32;
		uint32_t	pref_desc_log:32;
#endif
	} bits;
} tdc_pref_desc_log_t;


/*
 * Register: TdcPeuTxnLog
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
} tdc_peu_txn_log_t;


/*
 * Register: TdcDbgTrainingVec
 * Debug Training Vector
 * Description: Debug Training Vector register. Debug Training Vector
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
} tdc_dbg_training_vec_t;


/*
 * Register: TdcDbgGrpSel
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
		uint32_t	rsrvd1:1;
		uint32_t	dbg_h32_sub_sel:7;
		uint32_t	rsrvd2:1;
		uint32_t	dbg_l32_sub_sel:7;
#else
		uint32_t	dbg_l32_sub_sel:7;
		uint32_t	rsrvd2:1;
		uint32_t	dbg_h32_sub_sel:7;
		uint32_t	rsrvd1:1;
		uint32_t	rsrvd_l:16;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tdc_dbg_grp_sel_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _HXGE_TDC_HW_H */
