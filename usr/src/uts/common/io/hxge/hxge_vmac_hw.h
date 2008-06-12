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

#ifndef	_HXGE_VMAC_HW_H
#define	_HXGE_VMAC_HW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	VMAC_BASE_ADDR				0X00100000

#define	VMAC_RST				(VMAC_BASE_ADDR + 0x0)
#define	VMAC_TX_CFG				(VMAC_BASE_ADDR + 0x8)
#define	VMAC_RX_CFG				(VMAC_BASE_ADDR + 0x10)
#define	VMAC_TX_STAT				(VMAC_BASE_ADDR + 0x20)
#define	VMAC_TX_MSK				(VMAC_BASE_ADDR + 0x28)
#define	VMAC_RX_STAT				(VMAC_BASE_ADDR + 0x30)
#define	VMAC_RX_MSK				(VMAC_BASE_ADDR + 0x38)
#define	VMAC_TX_STAT_MIRROR			(VMAC_BASE_ADDR + 0x40)
#define	VMAC_RX_STAT_MIRROR			(VMAC_BASE_ADDR + 0x48)
#define	VMAC_TX_FRAME_CNT			(VMAC_BASE_ADDR + 0x100)
#define	VMAC_TX_BYTE_CNT			(VMAC_BASE_ADDR + 0x108)
#define	VMAC_RX_FRAME_CNT			(VMAC_BASE_ADDR + 0x120)
#define	VMAC_RX_BYTE_CNT			(VMAC_BASE_ADDR + 0x128)
#define	VMAC_RX_DROP_FR_CNT			(VMAC_BASE_ADDR + 0x130)
#define	VMAC_RX_DROP_BYTE_CNT			(VMAC_BASE_ADDR + 0x138)
#define	VMAC_RX_CRC_CNT				(VMAC_BASE_ADDR + 0x140)
#define	VMAC_RX_PAUSE_CNT			(VMAC_BASE_ADDR + 0x148)
#define	VMAC_RX_BCAST_FR_CNT			(VMAC_BASE_ADDR + 0x150)
#define	VMAC_RX_MCAST_FR_CNT			(VMAC_BASE_ADDR + 0x158)


/*
 * Register: VmacRst
 * VMAC Software Reset Command
 * Description:
 * Fields:
 *     Write a '1' to reset Rx VMAC; auto clears. This brings rx vmac
 *     to power on reset state.
 *     Write a '1' to reset Tx VMAC; auto clears. This brings tx vmac
 *     to power on reset state.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:23;
		uint32_t	rx_reset:1;
		uint32_t	rsrvd1:7;
		uint32_t	tx_reset:1;
#else
		uint32_t	tx_reset:1;
		uint32_t	rsrvd1:7;
		uint32_t	rx_reset:1;
		uint32_t	rsrvd_l:23;
		uint32_t	rsrvd:32;
#endif
	} bits;
} vmac_rst_t;


/*
 * Register: VmacTxCfg
 * Tx VMAC Configuration
 * Description:
 * Fields:
 *     Maximum length of any total transfer gathered by Tx VMAC,
 *     including packet data, header, crc, transmit header and any
 *     pad bytes. Default value of 0x2422 represents 9220 bytes of
 *     packet data, ethernet header, and crc, 14 bytes maximum pad,
 *     and 16 bytes transmit header = 9250 (0x2422).
 *     Enable padding of short packet to meet minimum frame length of
 *     64 bytes. Software should note that if txPad functionality is
 *     used to pad runt packets to minimum length, that crcInsert
 *     functionality (below) must also be used to provide the packet
 *     with correct L2 crc.
 *     1: Enable generation and appending of FCS to the packets. 0:
 *     Disable generation and appending of FCS to the packets.
 *     Enable Tx VMAC. Write a '1' to enable Tx VMAC; write a '0' to
 *     disable it. This bit also propagates as vmacTdcEn to the TDC
 *     block. In TDC, the vmacTdcEn bit disables the RTab state
 *     machine. Hence, the transmission from that blade would be
 *     stopped and be queued, but no packets would be dropped. Thus,
 *     the VMAC can only be enabled/disabled at packet boundary. The
 *     VMAC will not send out portion of a packet. The currently
 *     processed packet will continue to be sent out when Tx VMAC is
 *     disabled.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	tx_max_frame_length:14;
		uint32_t	rsrvd1:15;
		uint32_t	tx_pad:1;
		uint32_t	crc_insert:1;
		uint32_t	tx_en:1;
#else
		uint32_t	tx_en:1;
		uint32_t	crc_insert:1;
		uint32_t	tx_pad:1;
		uint32_t	rsrvd1:15;
		uint32_t	tx_max_frame_length:14;
		uint32_t	rsrvd:32;
#endif
	} bits;
} vmac_tx_cfg_t;


/*
 * Register: VmacRxCfg
 * Rx VMAC Configuration
 * Description: MAC address and length in Type/Length field are
 * checked in PFC.
 * Fields:
 *     Maximum length of a frame accepted by Rx/Tx VMAC. Only packets
 *     with length between 64 bytes and maxFrameLength will be
 *     accepted by Rx/Tx VMAC. This length indicates just the packet
 *     length excluding the packet header, crc, and any pad bytes.
 *     Maximum value is 9K (9*1024)
 *     enable packets from the same blade to loopback
 *     Enable acceptance of all Unicast packets for L2 destination
 *     address, ie, allow all Unicast packets to pass the L2
 *     filtering.
 *     Enable acceptance of all multi-cast packets, ie, allow all
 *     multi-cast packets to pass the L2 filtering.
 *     Enable the passing through of flow control frames.
 *     Enable the stripping of FCS field in the packets.
 *     Disable of FCS checking. When enable, packets with incorrect
 *     FCS value are dropped by Rx VMAC.
 *     Enable rx VMAC. Write a '1' to enable rx VMAC; write a '0' to
 *     disable it. The VMAC will begin to accept packet at the
 *     detection of the SOP (start of packet). When disable, the
 *     currently processed packet will continue to be accepted.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rx_max_frame_length:14;
		uint32_t	reserved:11;
		uint32_t	loopback:1;
		uint32_t	promiscuous_mode:1;
		uint32_t	promiscuous_group:1;
		uint32_t	pass_flow_ctrl_fr:1;
		uint32_t	strip_crc:1;
		uint32_t	crc_check_disable:1;
		uint32_t	rx_en:1;
#else
		uint32_t	rx_en:1;
		uint32_t	crc_check_disable:1;
		uint32_t	strip_crc:1;
		uint32_t	pass_flow_ctrl_fr:1;
		uint32_t	promiscuous_group:1;
		uint32_t	promiscuous_mode:1;
		uint32_t	loopback:1;
		uint32_t	reserved:11;
		uint32_t	rx_max_frame_length:14;
		uint32_t	rsrvd:32;
#endif
	} bits;
} vmac_rx_cfg_t;


/*
 * Register: VmacTxStat
 * Tx VMAC Status Register
 * Description: A new interrupt will be generated only if Tx VMAC is
 * enabled by vmacTxCfg::txEn=1. Disabling Tx VMAC does not affect
 * currently-existing Ldf state. Writing this register affects
 * vmacTxStatMirror register bits also the same way.
 * Fields:
 *     Indicates that counter of byte transmitted has exceeded the
 *     max value.
 *     Indicates that counter of frame transmitted has exceeded the
 *     max value.
 *     A frame has been successfully transmitted.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:29;
		uint32_t	tx_byte_cnt_overflow:1;
		uint32_t	tx_frame_cnt_overflow:1;
		uint32_t	frame_tx:1;
#else
		uint32_t	frame_tx:1;
		uint32_t	tx_frame_cnt_overflow:1;
		uint32_t	tx_byte_cnt_overflow:1;
		uint32_t	rsrvd_l:29;
		uint32_t	rsrvd:32;
#endif
	} bits;
} vmac_tx_stat_t;


/*
 * Register: VmacTxMsk
 * Tx VMAC Status Mask
 * Description: masking vmacTxStat from interrupt.
 * Fields:
 *     1: mask interrupt due to overflow of counter of byte
 *     transmitted
 *     1: mask interrupt due to overflow of counter of frame
 *     transmitted
 *     1: mask interrupt due to successful transmition of frame.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:29;
		uint32_t	tx_byte_cnt_overflow_msk:1;
		uint32_t	tx_frame_cnt_overflow_msk:1;
		uint32_t	frame_tx_msk:1;
#else
		uint32_t	frame_tx_msk:1;
		uint32_t	tx_frame_cnt_overflow_msk:1;
		uint32_t	tx_byte_cnt_overflow_msk:1;
		uint32_t	rsrvd_l:29;
		uint32_t	rsrvd:32;
#endif
	} bits;
} vmac_tx_msk_t;


/*
 * Register: VmacRxStat
 * Rx VMAC Status Register
 * Description: Overflow indicators are read-only registers; Read off
 * the counters to clear. A new interrupt will be generated only if
 * Rx VMAC is enabled by vmacRxCfg::rxEn=1. Disabling Rx VMAC does
 * not affect currently-existing Ldf state. Writing this register
 * affects vmacRxStatMirror register bits also the same way.
 * Fields:
 *     Indicates that the counter for broadcast packets has exceeded
 *     the max value.
 *     Indicates that the counter for multicast packets has exceeded
 *     the max value.
 *     Indicates that the counter for pause packets has exceeded the
 *     max value.
 *     Indicates that the counter for packets with mismatched FCS has
 *     exceeded the max value.
 *     Indicates that counter of dropped byte has exceeded the max
 *     value.
 *     Indicates that counter of dropped frame has exceeded the max
 *     value.
 *     Indicates that counter of byte received has exceeded the max
 *     value.
 *     Indicates that counter of frame received has exceeded the max
 *     value.
 *     A valid frame has been successfully received.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:23;
		uint32_t	bcast_cnt_overflow:1;
		uint32_t	mcast_cnt_overflow:1;
		uint32_t	pause_cnt_overflow:1;
		uint32_t	crc_err_cnt_overflow:1;
		uint32_t	rx_drop_byte_cnt_overflow:1;
		uint32_t	rx_drop_frame_cnt_overflow:1;
		uint32_t	rx_byte_cnt_overflow:1;
		uint32_t	rx_frame_cnt_overflow:1;
		uint32_t	frame_rx:1;
#else
		uint32_t	frame_rx:1;
		uint32_t	rx_frame_cnt_overflow:1;
		uint32_t	rx_byte_cnt_overflow:1;
		uint32_t	rx_drop_frame_cnt_overflow:1;
		uint32_t	rx_drop_byte_cnt_overflow:1;
		uint32_t	crc_err_cnt_overflow:1;
		uint32_t	pause_cnt_overflow:1;
		uint32_t	mcast_cnt_overflow:1;
		uint32_t	bcast_cnt_overflow:1;
		uint32_t	rsrvd_l:23;
		uint32_t	rsrvd:32;
#endif
	} bits;
} vmac_rx_stat_t;


/*
 * Register: VmacRxMsk
 * Rx VMAC Status Mask
 * Description:
 * Fields:
 *     1: mask interrupt due to overflow of the counter for broadcast
 *     packets
 *     1: mask interrupt due to overflow of the counter for multicast
 *     packets
 *     1: mask interrupt due to overflow of the counter for pause
 *     packets
 *     1: mask interrupt due to overflow of the counter for packets
 *     with mismatched FCS the max value.
 *     1: mask interrupt due to overflow of dropped byte counter
 *     1: mask interrupt due to overflow of dropped frame counter
 *     1: mask interrupt due to overflow of received byte counter
 *     1: mask interrupt due to overflow of received frame counter
 *     1: mask interrupt due to a valid frame has been successfully
 *     received.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:23;
		uint32_t	bcast_cnt_overflow_msk:1;
		uint32_t	mcast_cnt_overflow_msk:1;
		uint32_t	pause_cnt_overflow_msk:1;
		uint32_t	crc_err_cnt_overflow_msk:1;
		uint32_t	rx_drop_byte_cnt_overflow_msk:1;
		uint32_t	rx_drop_frame_cnt_overflow_msk:1;
		uint32_t	rx_byte_cnt_overflow_msk:1;
		uint32_t	rx_frame_cnt_overflow_msk:1;
		uint32_t	frame_rx_msk:1;
#else
		uint32_t	frame_rx_msk:1;
		uint32_t	rx_frame_cnt_overflow_msk:1;
		uint32_t	rx_byte_cnt_overflow_msk:1;
		uint32_t	rx_drop_frame_cnt_overflow_msk:1;
		uint32_t	rx_drop_byte_cnt_overflow_msk:1;
		uint32_t	crc_err_cnt_overflow_msk:1;
		uint32_t	pause_cnt_overflow_msk:1;
		uint32_t	mcast_cnt_overflow_msk:1;
		uint32_t	bcast_cnt_overflow_msk:1;
		uint32_t	rsrvd_l:23;
		uint32_t	rsrvd:32;
#endif
	} bits;
} vmac_rx_msk_t;


/*
 * Register: VmacTxStatMirror
 * Tx VMAC Status Mirror Register
 * Description: Write a 1 to this register to force the corresponding
 * interrupt. Reading this register returns the current Tx interrupt
 * status which would be the same as reading the vmacTxStat register.
 * The bits are cleared by writing 1 to the corresponding register
 * bit in the vmacTxStat register. ie, bit 0 of this register is
 * cleared by writing 1 to bit 0 in the vmacTxStat register.
 *
 * Fields:
 *     1 : Force tx byte counter overflow interrupt generation
 *     1 : Force tx frame counter overflow interrupt generation
 *     1 : Force frame transmitted interrupt generation
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:29;
		uint32_t	force_tx_byte_cnt_overflow:1;
		uint32_t	force_tx_frame_cnt_overflow:1;
		uint32_t	force_frame_tx:1;
#else
		uint32_t	force_frame_tx:1;
		uint32_t	force_tx_frame_cnt_overflow:1;
		uint32_t	force_tx_byte_cnt_overflow:1;
		uint32_t	rsrvd_l:29;
		uint32_t	rsrvd:32;
#endif
	} bits;
} vmac_tx_stat_mirror_t;


/*
 * Register: VmacRxStatMirror
 * Rx VMAC Status Mirror Register
 * Description: Write a 1 to this register to force the corresponding
 * interrupt. Reading this register returns the current Rx interrupt
 * status which would be the same as reading the vmacRxStat register.
 * The bits are cleared by writing 1 to the corresponding register
 * bit in the vmacRxStat register. ie, bit 0 of this register is
 * cleared by writing 1 to bit 0 in the vmacRxStat register.
 * Fields:
 *     1 : Force broadcast frame counter overflow interrupt
 *     generation
 *     1 : Force multicast frame counter overflow interrupt
 *     generation
 *     1 : Force pause frame counter overflow interrupt generation
 *     1 : Force crc error counter overflow interrupt generation
 *     1 : Force dropped frames byte counter overflow interrupt
 *     generation
 *     1 : Force dropped frame counter overflow interrupt generation
 *     1 : Force rx byte counter overflow interrupt generation
 *     1 : Force rx frame counter overflow interrupt generation
 *     1 : Force frame received interrupt generation
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:23;
		uint32_t	force_bcast_cnt_overflow:1;
		uint32_t	force_mcast_cnt_overflow:1;
		uint32_t	force_pause_cnt_overflow:1;
		uint32_t	force_crc_err_cnt_overflow:1;
		uint32_t	force_rx_drop_byte_cnt_overflow:1;
		uint32_t	force_rx_drop_frame_cnt_overflow:1;
		uint32_t	force_rx_byte_cnt_overflow:1;
		uint32_t	force_rx_frame_cnt_overflow:1;
		uint32_t	force_frame_rx:1;
#else
		uint32_t	force_frame_rx:1;
		uint32_t	force_rx_frame_cnt_overflow:1;
		uint32_t	force_rx_byte_cnt_overflow:1;
		uint32_t	force_rx_drop_frame_cnt_overflow:1;
		uint32_t	force_rx_drop_byte_cnt_overflow:1;
		uint32_t	force_crc_err_cnt_overflow:1;
		uint32_t	force_pause_cnt_overflow:1;
		uint32_t	force_mcast_cnt_overflow:1;
		uint32_t	force_bcast_cnt_overflow:1;
		uint32_t	rsrvd_l:23;
		uint32_t	rsrvd:32;
#endif
	} bits;
} vmac_rx_stat_mirror_t;


/*
 * Register: VmacTxFrameCnt
 * VMAC transmitted frame counter
 * Description:
 * Fields:
 *     Indicates the number of frames transmitted by Tx VMAC. The
 *     counter will saturate at max value. The counter is stalled
 *     when Tx VMAC is disabled by vmacTxCfg::txEn=0
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	tx_frame_cnt:32;
#else
		uint32_t	tx_frame_cnt:32;
		uint32_t	rsrvd:32;
#endif
	} bits;
} vmac_tx_frame_cnt_t;


/*
 * Register: VmacTxByteCnt
 * VMAC transmitted byte counter
 * Description:
 * Fields:
 *     Indicates the number of byte (octet) of data transmitted by Tx
 *     VMAC. This counter counts all the bytes of the incoming data
 *     including packet header, packet data, crc, and pad bytes. The
 *     counter will saturate at max value. The counter is stalled
 *     when Tx VMAC is disabled by vmacTxCfg::txEn=0
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	tx_byte_cnt:32;
#else
		uint32_t	tx_byte_cnt:32;
		uint32_t	rsrvd:32;
#endif
	} bits;
} vmac_tx_byte_cnt_t;


/*
 * Register: VmacRxFrameCnt
 * VMAC received frame counter
 * Description:
 * Fields:
 *     Indicates the number of frame received by Rx VMAC. The counter
 *     will saturate at max value. The counter is stalled when Rx
 *     VMAC is disabled by vmacRxCfg::rxEn=0.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rx_frame_cnt:32;
#else
		uint32_t	rx_frame_cnt:32;
		uint32_t	rsrvd:32;
#endif
	} bits;
} vmac_rx_frame_cnt_t;


/*
 * Register: VmacRxByteCnt
 * VMAC received byte counter
 * Description:
 * Fields:
 *     Indicates the number of bytes (octet) of data received by Rx
 *     VMAC including any error frames. The counter will saturate at
 *     max value. The counter is stalled when Rx VMAC is disabled by
 *     vmacRxCfg::rxEn=0.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rx_byte_cnt:32;
#else
		uint32_t	rx_byte_cnt:32;
		uint32_t	rsrvd:32;
#endif
	} bits;
} vmac_rx_byte_cnt_t;


/*
 * Register: VmacRxDropFrCnt
 * VMAC dropped frame counter
 * Description:
 * Fields:
 *     Indicates the number of frame dropped by Rx VMAC. The counter
 *     will This counter increments for every frame dropped for the
 *     following: - crc mismatch & crc check is enabled - failed the
 *     L2 address match & Vmac is not in promiscuous mode - pause
 *     packet & Vmac is not programmed to pass these frames The
 *     counter will saturate at max value. The counter is stalled
 *     when Rx VMAC is disabled by vmacRxCfg::rxEn=0.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rx_drop_frame_cnt:32;
#else
		uint32_t	rx_drop_frame_cnt:32;
		uint32_t	rsrvd:32;
#endif
	} bits;
} vmac_rx_drop_fr_cnt_t;


/*
 * Register: VmacRxDropByteCnt
 * VMAC dropped byte counter
 * Description:
 * Fields:
 *     Indicates the number of byte of data dropped by Rx VMAC.
 *     Frames are dropped for one of the follg conditions : - crc
 *     mismatch & crc check is enabled - failed the L2 address match
 *     & Vmac is not in promiscuous mode - pause packet & Vmac is not
 *     programmed to pass these frames The counter will saturate at
 *     max value. The counter is stalled when Rx VMAC is disabled by
 *     vmacRxCfg::rxEn=0.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rx_drop_byte_cnt:32;
#else
		uint32_t	rx_drop_byte_cnt:32;
		uint32_t	rsrvd:32;
#endif
	} bits;
} vmac_rx_drop_byte_cnt_t;


/*
 * Register: VmacRxCrcCnt
 * VMAC received CRC error frame counter
 * Description:
 * Fields:
 *     Indicates the number of frames with invalid CRC. When NMAC
 *     truncates a packet, it asserts crcError indication to VMAC
 *     which then counts it towards CRC error. Thus the VMAC crc
 *     error counter reflects the CRC mismatches on all the packets
 *     going out of RxMAC while the NMAC crc error counter reflects
 *     the CRC mismatches on all the packets coming into RxMAC. The
 *     counter will saturate at max value The counter is stalled when
 *     Rx VMAC is disabled by vmacRxCfg::rxEn=0.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rx_crc_cnt:32;
#else
		uint32_t	rx_crc_cnt:32;
		uint32_t	rsrvd:32;
#endif
	} bits;
} vmac_rx_crc_cnt_t;


/*
 * Register: VmacRxPauseCnt
 * VMAC received pause frame counter
 * Description:
 * Fields:
 *     Count the number of pause frames received by Rx VMAC. The
 *     counter is stalled when Rx VMAC is disabled by
 *     vmacRxCfg::rxEn=0.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rx_pause_cnt:32;
#else
		uint32_t	rx_pause_cnt:32;
		uint32_t	rsrvd:32;
#endif
	} bits;
} vmac_rx_pause_cnt_t;


/*
 * Register: VmacRxBcastFrCnt
 * VMAC received broadcast frame counter
 * Description:
 * Fields:
 *     Indicates the number of broadcast frames received The counter
 *     is stalled when Rx VMAC is disabled by vmacRxCfg::rxEn=0.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rx_bcast_fr_cnt:32;
#else
		uint32_t	rx_bcast_fr_cnt:32;
		uint32_t	rsrvd:32;
#endif
	} bits;
} vmac_rx_bcast_fr_cnt_t;


/*
 * Register: VmacRxMcastFrCnt
 * VMAC received multicast frame counter
 * Description:
 * Fields:
 *     Indicates the number of multicast frames received The counter
 *     is stalled when Rx VMAC is disabled by vmacRxCfg::rxEn=0.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rx_mcast_fr_cnt:32;
#else
		uint32_t	rx_mcast_fr_cnt:32;
		uint32_t	rsrvd:32;
#endif
	} bits;
} vmac_rx_mcast_fr_cnt_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _HXGE_VMAC_HW_H */
