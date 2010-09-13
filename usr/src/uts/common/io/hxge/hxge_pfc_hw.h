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

#ifndef	_HXGE_PFC_HW_H
#define	_HXGE_PFC_HW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PFC_BASE_ADDR				0X0200000

#define	PFC_VLAN_TABLE				(PFC_BASE_ADDR + 0x0)
#define	PFC_VLAN_CTRL				(PFC_BASE_ADDR + 0x9000)
#define	PFC_MAC_ADDR				(PFC_BASE_ADDR + 0x10000)
#define	PFC_MAC_ADDR_MASK			(PFC_BASE_ADDR + 0x10080)
#define	PFC_HASH_TABLE				(PFC_BASE_ADDR + 0x10100)
#define	PFC_L2_CLASS_CONFIG			(PFC_BASE_ADDR + 0x20000)
#define	PFC_L3_CLASS_CONFIG			(PFC_BASE_ADDR + 0x20030)
#define	PFC_TCAM_KEY0				(PFC_BASE_ADDR + 0x20090)
#define	PFC_TCAM_KEY1				(PFC_BASE_ADDR + 0x20098)
#define	PFC_TCAM_MASK0				(PFC_BASE_ADDR + 0x200B0)
#define	PFC_TCAM_MASK1				(PFC_BASE_ADDR + 0x200B8)
#define	PFC_TCAM_CTRL				(PFC_BASE_ADDR + 0x200D0)
#define	PFC_CONFIG				(PFC_BASE_ADDR + 0x20100)
#define	TCP_CTRL_MASK				(PFC_BASE_ADDR + 0x20108)
#define	SRC_HASH_VAL				(PFC_BASE_ADDR + 0x20110)
#define	PFC_INT_STATUS				(PFC_BASE_ADDR + 0x30000)
#define	PFC_DBG_INT_STATUS			(PFC_BASE_ADDR + 0x30008)
#define	PFC_INT_MASK				(PFC_BASE_ADDR + 0x30100)
#define	PFC_DROP_LOG				(PFC_BASE_ADDR + 0x30200)
#define	PFC_DROP_LOG_MASK			(PFC_BASE_ADDR + 0x30208)
#define	PFC_VLAN_PAR_ERR_LOG			(PFC_BASE_ADDR + 0x30210)
#define	PFC_TCAM_PAR_ERR_LOG			(PFC_BASE_ADDR + 0x30218)
#define	PFC_BAD_CS_COUNTER			(PFC_BASE_ADDR + 0x30220)
#define	PFC_DROP_COUNTER			(PFC_BASE_ADDR + 0x30228)
#define	PFC_AUTO_INIT				(PFC_BASE_ADDR + 0x30300)


/*
 * Register: PfcVlanTable
 * VLAN Table Registers
 * Description: VLAN membership table. CPU programs in the VLANs that
 * it wants to belong to. A blade may be a member of multiple VLANs.
 * Bits [31:0] of the first entry corresponds to vlan members [31:0],
 * bits [31:0] of the second entry corresponds to vlan members
 * [63:32] and so on.
 * Fields:
 *     Odd parities of member[31:24], member[23:16], member[17:8],
 *     member[7:0]. These parity bits are ignored when parEn in the
 *     VLAN Control register is set to '0'.
 *     Set to 1 to indicate that blade is a member of the VLAN IDs
 *     (32 to 0) * entry number
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:28;
		uint32_t	parity:4;
		uint32_t	member:32;
#else
		uint32_t	member:32;
		uint32_t	parity:4;
		uint32_t	rsrvd:28;
#endif
	} bits;
} pfc_vlan_table_t;


/*
 * Register: PfcVlanCtrl
 * VLAN Control Register
 * Description: VLAN control register. Controls VLAN table properties
 * and implicit VLAN properties for non-VLAN tagged packets.
 * Fields:
 *     VLAN table parity debug write enable. When set to 1, software
 *     writes the parity bits together with the data during a VLAN
 *     table write. Otherwise, hardware automatically generates the
 *     parity bits from the data.
 *     Set to 1 to indicate the implicit VLAN ID is valid for use in
 *     non-VLAN tagged packets filtering
 *     Implicit VLAN ID for non-VLAN tagged packets
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:18;
		uint32_t	par_en:1;
		uint32_t	valid:1;
		uint32_t	id:12;
#else
		uint32_t	id:12;
		uint32_t	valid:1;
		uint32_t	par_en:1;
		uint32_t	rsrvd_l:18;
		uint32_t	rsrvd:32;
#endif
	} bits;
} pfc_vlan_ctrl_t;


/*
 * Register: PfcMacAddr
 * MAC Address
 * Description: MAC Address - Contains a station's 48 bit MAC
 * address. The first register corresponds to MAC address 0, the
 * second register corresponds to MAC address 1 and so on. For a MAC
 * address of format aa-bb-cc-dd-ee-ff, addr[47:0] corresponds to
 * "aabbccddeeff". When used in conjunction with the MAC address
 * filter mask registers, these registers can be used to construct
 * either a unicast or multicast address. An address is considered
 * matched if (DA & ~mask) == (MAC address & ~mask)
 * Fields:
 *     48 bits of stations's MAC address
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:16;
		uint32_t	addr:16;
		uint32_t	addr_l:32;
#else
		uint32_t	addr_l:32;
		uint32_t	addr:16;
		uint32_t	rsrvd:16;
#endif
	} bits;
} pfc_mac_addr_t;


/*
 * Register: PfcMacAddrMask
 * MAC Address Filter
 * Description: MAC Address Filter Mask - Contains the station's 48
 * bit MAC address filter mask. The first register corresponds to MAC
 * address 0 filter mask, the second register corresponds to MAC
 * address 1 filter mask and so on. These filter masks cover MAC
 * address bits 47:0 in the same order as the address registers
 * Fields:
 *     48 bits of stations's MAC address filter mask
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:16;
		uint32_t	mask:16;
		uint32_t	mask_l:32;
#else
		uint32_t	mask_l:32;
		uint32_t	mask:16;
		uint32_t	rsrvd:16;
#endif
	} bits;
} pfc_mac_addr_mask_t;


/*
 * Register: PfcHashTable
 * MAC Multicast Hash Filter
 * Description: MAC multicast hash table filter. The multicast
 * destination address is used to perform Ethernet CRC-32 hashing
 * with seed value 0xffffFfff. Bits 47:40 of the hash result are used
 * to index one bit of this multicast hash table. If the bit is '1',
 * the multicast hash matches.
 * Fields:
 *     16 bits of 256 bit hash table. First entry contains bits
 *     [15:0], last entry contains bits [255:240]
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:16;
		uint32_t	hash_val:16;
#else
		uint32_t	hash_val:16;
		uint32_t	rsrvd_l:16;
		uint32_t	rsrvd:32;
#endif
	} bits;
} pfc_hash_table_t;


/*
 * Register: PfcL2ClassConfig
 * L2 Class Configuration
 * Description: Programmable EtherType for class codes 2 and 3. The
 * first register is class 2, and the second class 3
 * Fields:
 *     Set to 1 to indicate that the entry is valid for use in
 *     classification
 *     EtherType value
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:15;
		uint32_t	valid:1;
		uint32_t	etype:16;
#else
		uint32_t	etype:16;
		uint32_t	valid:1;
		uint32_t	rsrvd_l:15;
		uint32_t	rsrvd:32;
#endif
	} bits;
} pfc_l2_class_config_t;


/*
 * Register: PfcL3ClassConfig
 * L3 Class Configuration
 * Description: Configuration for class codes 0x8-0xF. PFC can be set
 * to discard certain classes of traffic, or to not initiate a TCAM
 * match for that class
 * Fields:
 *     Set to 1 to discard all packets of this class code
 *     Set to 1 to indicate that packets of this class should be sent
 *     to the TCAM for perfect match
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:28;
		uint32_t	discard:1;
		uint32_t	tsel:1;
		uint32_t	rsrvd1:2;
#else
		uint32_t	rsrvd1:2;
		uint32_t	tsel:1;
		uint32_t	discard:1;
		uint32_t	rsrvd_l:28;
		uint32_t	rsrvd:32;
#endif
	} bits;
} pfc_l3_class_config_t;


/*
 * Register: PfcTcamKey0
 * TCAM Key 0
 * Description: TCAM key value. Holds bit 63:0 of the TCAM key
 * Fields:
 *     bits 63:0 of tcam key
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	key:32;
		uint32_t	key_l:32;
#else
		uint32_t	key_l:32;
		uint32_t	key:32;
#endif
	} bits;
} pfc_tcam_key0_t;


/*
 * Register: PfcTcamKey1
 * TCAM Key 1
 * Description: TCAM key value. Holds bit 99:64 of the TCAM key
 * Fields:
 *     bits 99:64 of tcam key
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:28;
		uint32_t	key:4;
		uint32_t	key_l:32;
#else
		uint32_t	key_l:32;
		uint32_t	key:4;
		uint32_t	rsrvd:28;
#endif
	} bits;
} pfc_tcam_key1_t;


/*
 * Register: PfcTcamMask0
 * TCAM Mask 0
 * Description: TCAM mask value. Holds bit 63:0 of the TCAM mask
 * Fields:
 *     bits 63:0 of tcam mask
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	mask:32;
		uint32_t	mask_l:32;
#else
		uint32_t	mask_l:32;
		uint32_t	mask:32;
#endif
	} bits;
} pfc_tcam_mask0_t;


/*
 * Register: PfcTcamMask1
 * TCAM Mask 1
 * Description: TCAM mask value. Holds bit 99:64 of the TCAM mask
 * Fields:
 *     bits 99:64 of tcam mask
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:28;
		uint32_t	mask:4;
		uint32_t	mask_l:32;
#else
		uint32_t	mask_l:32;
		uint32_t	mask:4;
		uint32_t	rsrvd:28;
#endif
	} bits;
} pfc_tcam_mask1_t;


/*
 * Register: PfcTcamCtrl
 * TCAM Control
 * Description: TCAM and TCAM lookup memory access control register.
 * Controls how TCAM and result lookup table are accessed by blade
 * CPU. For a TCAM write, the data in the TCAM key and mask registers
 * will be written to the TCAM. A compare will initiate a TCAM match
 * with the data stored in the TCAM key register. The match bit is
 * toggled, and the matching address is reported in the addr field.
 * For an access to the TCAM result lookup memory, the TCAM 0 key
 * register is used for the read/write data.
 * Fields:
 *     TCAM lookup table debug parity bit write enable. When a '1' is
 *     written, software writes the parity bit together with the data
 *     during a TCAM result lookup write. Otherwise, hardware
 *     automatically generates the parity bit from the data.
 *     3'b000 = TCAM write 3'b001 = reserved 3'b010 = TCAM compare
 *     3'b011 = reserved 3'b100 = TCAM result lookup write 3'b101 =
 *     TCAM result lookup read 3'b110 = reserved 3'b111 = reserved
 *     Status of read/write/compare operation. When a zero is
 *     written, hardware initiates access. Hardware writes a '1' to
 *     the bit when it completes
 *     Set to 1 if there is a TCAM match for compare command. Zero
 *     otherwise
 *     Address location for access of TCAM or RAM (valid values
 *     0-42). For a compare, the location of the match is written
 *     here by hardware.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:13;
		uint32_t	par_en:1;
		uint32_t	cmd:3;
		uint32_t	status:1;
		uint32_t	match:1;
		uint32_t	rsrvd1:5;
		uint32_t	addr:8;
#else
		uint32_t	addr:8;
		uint32_t	rsrvd1:5;
		uint32_t	match:1;
		uint32_t	status:1;
		uint32_t	cmd:3;
		uint32_t	par_en:1;
		uint32_t	rsrvd_l:13;
		uint32_t	rsrvd:32;
#endif
	} bits;
} pfc_tcam_ctrl_t;


/*
 * Register: PfcConfig
 * PFC General Configuration
 * Description: PFC configuration options that are under the control
 * of a blade CPU
 * Fields:
 *     MAC address enable mask. Each bit corresponds to one MAC
 *     adress (lsb = addr0). With 16 MAC addresses, only the lower 16
 *     bits are valid.
 *     default DMA channel number
 *     force TCP/UDP checksum result to always match
 *     Enable for TCP/UDP checksum. If not enabled, the result will
 *     never match.
 *     Enable TCAM matching. If TCAM matching is not enabled, traffic
 *     will be sent to the default DMA channel.
 *     Enable L2 Multicast hash
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:24;
		uint32_t	mac_addr_en:8;
		uint32_t	mac_addr_en_l:24;
		uint32_t	default_dma:4;
		uint32_t	force_cs_en:1;
		uint32_t	tcp_cs_en:1;
		uint32_t	tcam_en:1;
		uint32_t	l2_hash_en:1;
#else
		uint32_t	l2_hash_en:1;
		uint32_t	tcam_en:1;
		uint32_t	tcp_cs_en:1;
		uint32_t	force_cs_en:1;
		uint32_t	default_dma:4;
		uint32_t	mac_addr_en_l:24;
		uint32_t	mac_addr_en:8;
		uint32_t	rsrvd:24;
#endif
	} bits;
} pfc_config_t;


/*
 * Register: TcpCtrlMask
 * TCP control bits mask
 * Description: Mask of TCP control bits to forward onto downstream
 * blocks The TCP packet's control bits are masked, and then bitwise
 * OR'd to produce a signal to the Rx DMA. Normally, all bits are
 * masked off except the TCP SYN bit. The Rx DMA uses this bitwise OR
 * for statistics. When discard = 1, the packet will be dropped if
 * the bitwise OR = 1.
 * Fields:
 *     Drop the packet if bitwise OR of the TCP control bits masked
 *     on = 1
 *     TCP end of data flag
 *     TCP SYN flag
 *     TCP reset flag
 *     TCP push flag
 *     TCP ack flag
 *     TCP urgent flag
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:25;
		uint32_t	discard:1;
		uint32_t	fin:1;
		uint32_t	syn:1;
		uint32_t	rst:1;
		uint32_t	psh:1;
		uint32_t	ack:1;
		uint32_t	urg:1;
#else
		uint32_t	urg:1;
		uint32_t	ack:1;
		uint32_t	psh:1;
		uint32_t	rst:1;
		uint32_t	syn:1;
		uint32_t	fin:1;
		uint32_t	discard:1;
		uint32_t	rsrvd_l:25;
		uint32_t	rsrvd:32;
#endif
	} bits;
} tcp_ctrl_mask_t;


/*
 * Register: SrcHashVal
 * Source hash Seed Value
 *     Hash CRC seed value
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	seed:32;
#else
		uint32_t	seed:32;
		uint32_t	rsrvd:32;
#endif
	} bits;
} src_hash_val_t;


/*
 * Register: PfcIntStatus
 * PFC Interrupt Status
 * Description: PFC interrupt status register
 * Fields:
 *     triggered when packet drop log captured a drop. Part of LDF 0.
 *     Write 1 to clear.
 *     TCAM result lookup table parity error. Part of LDF 0. Write 1
 *     to clear.
 *     VLAN table parity error. Part of LDF 0. Write 1 to clear.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:29;
		uint32_t	pkt_drop:1;
		uint32_t	tcam_parity_err:1;
		uint32_t	vlan_parity_err:1;
#else
		uint32_t	vlan_parity_err:1;
		uint32_t	tcam_parity_err:1;
		uint32_t	pkt_drop:1;
		uint32_t	rsrvd_l:29;
		uint32_t	rsrvd:32;
#endif
	} bits;
} pfc_int_status_t;


/*
 * Register: PfcDbgIntStatus
 * PFC Debug Interrupt Status
 * Description: PFC debug interrupt status mirror register. This
 * debug register triggers the same interrupts as those in the PFC
 * Interrupt Status register. Interrupts in this mirror register are
 * subject to the filtering of the PFC Interrupt Mask register.
 * Fields:
 *     Packet drop. Part of LDF 0.
 *     TCAM result lookup table parity error. Part of LDF 0.
 *     VLAN table parity error. Part of LDF 0.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:29;
		uint32_t	pkt_drop:1;
		uint32_t	tcam_parity_err:1;
		uint32_t	vlan_parity_err:1;
#else
		uint32_t	vlan_parity_err:1;
		uint32_t	tcam_parity_err:1;
		uint32_t	pkt_drop:1;
		uint32_t	rsrvd_l:29;
		uint32_t	rsrvd:32;
#endif
	} bits;
} pfc_dbg_int_status_t;


/*
 * Register: PfcIntMask
 * PFC Interrupt Mask
 * Description: PFC interrupt status mask register
 * Fields:
 *     mask for pktDrop capture;
 *     TCAM result lookup table parity error mask;
 *     VLAN table parity error mask;
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:29;
		uint32_t	pkt_drop_mask:1;
		uint32_t	tcam_parity_err_mask:1;
		uint32_t	vlan_parity_err_mask:1;
#else
		uint32_t	vlan_parity_err_mask:1;
		uint32_t	tcam_parity_err_mask:1;
		uint32_t	pkt_drop_mask:1;
		uint32_t	rsrvd_l:29;
		uint32_t	rsrvd:32;
#endif
	} bits;
} pfc_int_mask_t;


/*
 * Register: PfcDropLog
 * Packet Drop Log
 * Description: Packet drop log. Log for capturing packet drops. Log
 * is re-armed when associated interrupt bit is cleared.
 * Fields:
 *     drop because bitwise OR of the tcp control bits masked on = 1
 *     drop because L2 address did not match
 *     drop because class code indicated drop
 *     drop because TCAM result indicated drop
 *     drop because blade was not a member of VLAN
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:27;
		uint32_t	tcp_ctrl_drop:1;
		uint32_t	l2_addr_drop:1;
		uint32_t	class_code_drop:1;
		uint32_t	tcam_drop:1;
		uint32_t	vlan_drop:1;
#else
		uint32_t	vlan_drop:1;
		uint32_t	tcam_drop:1;
		uint32_t	class_code_drop:1;
		uint32_t	l2_addr_drop:1;
		uint32_t	tcp_ctrl_drop:1;
		uint32_t	rsrvd_l:27;
		uint32_t	rsrvd:32;
#endif
	} bits;
} pfc_drop_log_t;


/*
 * Register: PfcDropLogMask
 * Packet Drop Log Mask
 * Description: Mask for logging packet drop. If the drop type is
 * masked off, it will not trigger the drop log to capture the packet
 * drop
 * Fields:
 *     mask drop because bitwise OR of the tcp control bits masked on
 *     = 1
 *     mask drop because L2 address did not match
 *     mask drop because class code indicated
 *     mask drop because TCAM result indicated drop
 *     mask drop because blade was not a member of VLAN
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:27;
		uint32_t	tcp_ctrl_drop_mask:1;
		uint32_t	l2_addr_drop_mask:1;
		uint32_t	class_code_drop_mask:1;
		uint32_t	tcam_drop_mask:1;
		uint32_t	vlan_drop_mask:1;
#else
		uint32_t	vlan_drop_mask:1;
		uint32_t	tcam_drop_mask:1;
		uint32_t	class_code_drop_mask:1;
		uint32_t	l2_addr_drop_mask:1;
		uint32_t	tcp_ctrl_drop_mask:1;
		uint32_t	rsrvd_l:27;
		uint32_t	rsrvd:32;
#endif
	} bits;
} pfc_drop_log_mask_t;


/*
 * Register: PfcVlanParErrLog
 * VLAN Parity Error Log
 * Description: Log of parity errors in VLAN table.
 * Fields:
 *     address of parity error. Log is cleared when corresponding
 *     interrupt bit is cleared by writing '1'.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:20;
		uint32_t	addr:12;
#else
		uint32_t	addr:12;
		uint32_t	rsrvd_l:20;
		uint32_t	rsrvd:32;
#endif
	} bits;
} pfc_vlan_par_err_log_t;


/*
 * Register: PfcTcamParErrLog
 * TCAM Parity Error Log
 * Description: Log of parity errors in TCAM result lookup table.
 * Fields:
 *     address of parity error. Log is cleared when corresponding
 *     interrupt bit is cleared by writing '1'.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:24;
		uint32_t	addr:8;
#else
		uint32_t	addr:8;
		uint32_t	rsrvd_l:24;
		uint32_t	rsrvd:32;
#endif
	} bits;
} pfc_tcam_par_err_log_t;


/*
 * Register: PfcBadCsCounter
 * PFC Bad Checksum Counter
 * Description: Count number of bad TCP/UDP checksum. Only counted if
 * L2 adddress matched
 * Fields:
 *     count of number of bad TCP/UDP checksums received. Clear on
 *     read
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	bad_cs_count:32;
#else
		uint32_t	bad_cs_count:32;
		uint32_t	rsrvd:32;
#endif
	} bits;
} pfc_bad_cs_counter_t;


/*
 * Register: PfcDropCounter
 * PFC Drop Counter
 * Description: Count number of packets dropped due to VLAN
 * membership, class code, TCP control bits, or TCAM results Only
 * counted if L2 address matched.
 * Fields:
 *     Count of number of packets dropped due to VLAN, TCAM results.
 *     Clear on read
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	drop_count:32;
#else
		uint32_t	drop_count:32;
		uint32_t	rsrvd:32;
#endif
	} bits;
} pfc_drop_counter_t;


/*
 * Register: PfcAutoInit
 * PFC Auto Init
 * Description: PFC Auto Initialization. Writing to this register
 * triggers the auto initialization of the blade's TCAM entries with
 * 100 bits of '0' for both key and mask. TCAM lookup is disabled
 * during auto initialization.
 * Fields:
 *     TCAM auto initialization status. 0=busy, 1=done.
 */
typedef union {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
		uint32_t	rsrvd_l:31;
		uint32_t	auto_init_status:1;
#else
		uint32_t	auto_init_status:1;
		uint32_t	rsrvd_l:31;
		uint32_t	rsrvd:32;
#endif
	} bits;
} pfc_auto_init_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _HXGE_PFC_HW_H */
