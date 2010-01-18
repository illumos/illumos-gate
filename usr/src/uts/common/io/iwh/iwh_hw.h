/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2009, Intel Corporation
 * All rights reserved.
 */

/*
 * Sun elects to use this software under the BSD license.
 */

/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2005 - 2009 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110,
 * USA
 *
 * The full GNU General Public License is included in this distribution
 * in the file called LICENSE.GPL.
 *
 * Contact Information:
 * James P. Ketrenos <ipw2100-admin@linux.intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 * BSD LICENSE
 *
 * Copyright(c) 2005 - 2009 Intel Corporation. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef	_IWH_HW_H_
#define	_IWH_HW_H_

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * maximum scatter/gather
 */
#define	IWH_MAX_SCATTER	(10)

/*
 * Flow Handler Definitions
 */
#define	FH_MEM_LOWER_BOUND	(0x1000)
#define	FH_MEM_UPPER_BOUND	(0x1EF0)

#define	IWH_FH_REGS_LOWER_BOUND	(0x1000)
#define	IWH_FH_REGS_UPPER_BOUND	(0x2000)

/*
 * TFDB  Area - TFDs buffer table
 */
#define	FH_MEM_TFDB_LOWER_BOUND	(FH_MEM_LOWER_BOUND + 0x000)
#define	FH_MEM_TFDB_UPPER_BOUND	(FH_MEM_LOWER_BOUND + 0x900)

/*
 * channels 0 - 8
 */
#define	FH_MEM_TFDB_CHNL_BUF0(x) (FH_MEM_TFDB_LOWER_BOUND + (x) * 0x100)
#define	FH_MEM_TFDB_CHNL_BUF1(x) (FH_MEM_TFDB_LOWER_BOUND + 0x80 + (x) * 0x100)

/*
 * TFDIB Area - TFD Immediate Buffer
 */
#define	FH_MEM_TFDIB_LOWER_BOUND	(FH_MEM_LOWER_BOUND + 0x900)
#define	FH_MEM_TFDIB_UPPER_BOUND	(FH_MEM_LOWER_BOUND + 0x958)

/*
 * channels 0 - 10
 */
#define	FH_MEM_TFDIB_CHNL(x)	(FH_MEM_TFDIB_LOWER_BOUND + (x) * 0x8)

/*
 * TFDIB registers used in Service Mode
 */
#define	FH_MEM_TFDIB_CHNL9_REG0	(FH_MEM_TFDIB_CHNL(9))
#define	FH_MEM_TFDIB_CHNL9_REG1	(FH_MEM_TFDIB_CHNL(9) + 4)
#define	FH_MEM_TFDIB_CHNL10_REG0	(FH_MEM_TFDIB_CHNL(10))
#define	FH_MEM_TFDIB_CHNL10_REG1	(FH_MEM_TFDIB_CHNL(10) + 4)

/*
 * Tx service channels
 */
#define	FH_MEM_TFDIB_DRAM_ADDR_MSB_MASK	(0xF00000000)
#define	FH_MEM_TFDIB_TB_LENGTH_MASK	(0x0001FFFF)	/* bits 16:0 */

#define	FH_MEM_TFDIB_DRAM_ADDR_LSB_BITSHIFT	(0)
#define	FH_MEM_TFDIB_DRAM_ADDR_MSB_BITSHIFT	(32)
#define	FH_MEM_TFDIB_TB_LENGTH_BITSHIFT		(0)

#define	FH_MEM_TFDIB_REG0_ADDR_MASK	(0xFFFFFFFF)
#define	FH_MEM_TFDIB_REG1_ADDR_MASK	(0xF0000000)
#define	FH_MEM_TFDIB_REG1_LENGTH_MASK	(0x0001FFFF)

#define	FH_MEM_TFDIB_REG0_ADDR_BITSHIFT	(0)
#define	FH_MEM_TFDIB_REG1_ADDR_BITSHIFT	(28)
#define	FH_MEM_TFDIB_REG1_LENGTH_BITSHIFT	(0)
#define	FH_MEM_TFDIB_DRAM_ADDR_LSB_MASK		(0xFFFFFFFF)

/*
 * TRB Area - Transmit Request Buffers
 */
#define	FH_MEM_TRB_LOWER_BOUND	(FH_MEM_LOWER_BOUND + 0x0958)
#define	FH_MEM_TRB_UPPER_BOUND	(FH_MEM_LOWER_BOUND + 0x0980)

/*
 * channels 0 - 8
 */
#define	FH_MEM_TRB_CHNL(x)	(FH_MEM_TRB_LOWER_BOUND + (x) * 0x4)

/*
 * Keep-Warm (KW) buffer base address.
 *
 * Driver must allocate a 4KByte buffer that is used by Shirely Peak(SP) for
 * keeping the
 * host DRAM powered on (via dummy accesses to DRAM) to maintain low-latency
 * DRAM access when SP is Txing or Rxing.  The dummy accesses prevent host
 * from going into a power-savings mode that would cause higher DRAM latency,
 * and possible data over/under-runs, before all Tx/Rx is complete.
 *
 * Driver loads IWH_FH_KW_MEM_ADDR_REG with the physical address (bits 35:4)
 * of the buffer, which must be 4K aligned.  Once this is set up, the SP
 * automatically invokes keep-warm accesses when normal accesses might not
 * be sufficient to maintain fast DRAM response.
 *
 * Bit fields:
 * 31-0:  Keep-warm buffer physical base address [35:4], must be 4K aligned
 */
#define	IWH_FH_KW_MEM_ADDR_REG	(FH_MEM_LOWER_BOUND + 0x97C)

/*
 * STAGB Area - Scheduler TAG Buffer
 */
#define	FH_MEM_STAGB_LOWER_BOUND	(FH_MEM_LOWER_BOUND + 0x980)
#define	FH_MEM_STAGB_UPPER_BOUND	(FH_MEM_LOWER_BOUND + 0x9D0)

/*
 * channels 0 - 8
 */
#define	FH_MEM_STAGB_0(x)	(FH_MEM_STAGB_LOWER_BOUND + (x) * 0x8)
#define	FH_MEM_STAGB_1(x)	(FH_MEM_STAGB_LOWER_BOUND + 0x4 + (x) * 0x8)

/*
 * Tx service channels
 */
#define	FH_MEM_SRAM_ADDR_9	(FH_MEM_STAGB_LOWER_BOUND + 0x048)
#define	FH_MEM_SRAM_ADDR_10	(FH_MEM_STAGB_LOWER_BOUND + 0x04C)

#define	FH_MEM_STAGB_SRAM_ADDR_MASK	(0x00FFFFFF)

/*
 * TFD Circular Buffers Base (CBBC) addresses
 *
 * SP has 16 base pointer registers, one for each of 16 host-DRAM-resident
 * circular buffers (CBs/queues) containing Transmit Frame Descriptors (TFDs)
 * (see struct iwh_tfd_frame).  These 16 pointer registers are offset by 0x04
 * bytes from one another.  Each TFD circular buffer in DRAM must be 256-byte
 * aligned (address bits 0-7 must be 0).
 *
 * Bit fields in each pointer register:
 * 27-0: TFD CB physical base address [35:8], must be 256-byte aligned
 */
#define	FH_MEM_CBBC_LOWER_BOUND	(FH_MEM_LOWER_BOUND + 0x9D0)
#define	FH_MEM_CBBC_UPPER_BOUND	(FH_MEM_LOWER_BOUND + 0xA10)

/*
 * queues 0 - 15
 */
#define	FH_MEM_CBBC_QUEUE(x)	(FH_MEM_CBBC_LOWER_BOUND + (x) * 0x4)

/*
 * TAGR Area - TAG reconstruct table
 */
#define	FH_MEM_TAGR_LOWER_BOUND	(FH_MEM_LOWER_BOUND + 0xA10)
#define	FH_MEM_TAGR_UPPER_BOUND	(FH_MEM_LOWER_BOUND + 0xA70)

/*
 * TDBGR Area - Tx Debug Registers
 */
#define	FH_MEM_TDBGR_LOWER_BOUND	(FH_MEM_LOWER_BOUND + 0x0A70)
#define	FH_MEM_TDBGR_UPPER_BOUND	(FH_MEM_LOWER_BOUND + 0x0B20)

/*
 * channels 0 - 10
 */
#define	FH_MEM_TDBGR_CHNL(x)	(FH_MEM_TDBGR_LOWER_BOUND + (x) * 0x10)

#define	FH_MEM_TDBGR_CHNL_REG_0(x)	(FH_MEM_TDBGR_CHNL(x))
#define	FH_MEM_TDBGR_CHNL_REG_1(x)	(FH_MEM_TDBGR_CHNL_REG_0(x) + 0x4)

#define	FH_MEM_TDBGR_CHNL_BYTES_TO_FIFO_MASK	(0x000FFFFF)
#define	FH_MEM_TDBGR_CHNL_BYTES_TO_FIFO_BITSHIFT	(0)

/*
 * RDBUF Area
 */
#define	FH_MEM_RDBUF_LOWER_BOUND	(FH_MEM_LOWER_BOUND + 0xB80)
#define	FH_MEM_RDBUF_UPPER_BOUND	(FH_MEM_LOWER_BOUND + 0xBC0)
#define	FH_MEM_RDBUF_CHNL0	(FH_MEM_RDBUF_LOWER_BOUND)

/*
 * Rx SRAM Control and Status Registers (RSCSR)
 *
 * These registers provide handshake between driver and Shirley Peak for
 * the Rx queue
 * (this queue handles *all* command responses, notifications, Rx data, etc.
 * sent from SP uCode to host driver).  Unlike Tx, there is only one Rx
 * queue, and only one Rx DMA/FIFO channel.  Also unlike Tx, which can
 * concatenate up to 20 DRAM buffers to form a Tx frame, each Receive Buffer
 * Descriptor (RBD) points to only one Rx Buffer (RB); there is a 1:1
 * mapping between RBDs and RBs.
 *
 * Driver must allocate host DRAM memory for the following, and set the
 * physical address of each into SP registers:
 *
 * 1)  Receive Buffer Descriptor (RBD) circular buffer (CB), typically with 256
 *     entries (although any power of 2, up to 4096, is selectable by driver).
 *     Each entry (1 dword) points to a receive buffer (RB) of consistent size
 *     (typically 4K, although 8K or 16K are also selectable by driver).
 *     Driver sets up RB size and number of RBDs in the CB via Rx config
 *     register FH_MEM_RCSR_CHNL0_CONFIG_REG.
 *
 *     Bit fields within one RBD:
 *     27-0:  Receive Buffer physical address bits [35:8], 256-byte aligned.
 *
 *     Driver sets physical address [35:8] of base of RBD circular buffer
 *     into FH_RSCSR_CHNL0_RBDCB_BASE_REG [27:0].
 *
 * 2)  Rx status buffer, 8 bytes, in which SP indicates which Rx Buffers
 *     (RBs) have been filled, via a "write pointer", actually the index of
 *     the RB's corresponding RBD within the circular buffer.  Driver sets
 *     physical address [35:4] into FH_RSCSR_CHNL0_STTS_WPTR_REG [31:0].
 *
 *     Bit fields in lower dword of Rx status buffer (upper dword not used
 *     by driver; see struct iwh_shared, val0):
 *     31-12:  Not used by driver
 *     11- 0:  Index of last filled Rx buffer descriptor
 *             (SP writes, driver reads this value)
 *
 * As the driver prepares Receive Buffers (RBs) for SP to fill, driver must
 * enter pointers to these RBs into contiguous RBD circular buffer entries,
 * and update the SP's "write" index register, FH_RSCSR_CHNL0_RBDCB_WPTR_REG.
 *
 * This "write" index corresponds to the *next* RBD that the driver will make
 * available, i.e. one RBD past the the tail of the ready-to-fill RBDs within
 * the circular buffer.  This value should initially be 0 (before preparing any
 * RBs), should be 8 after preparing the first 8 RBs (for example), and must
 * wrap back to 0 at the end of the circular buffer (but don't wrap before
 * "read" index has advanced past 1!  See below).
 * NOTE:  SP EXPECTS THE WRITE INDEX TO BE INCREMENTED IN MULTIPLES OF 8.
 *
 * As the SP fills RBs (referenced from contiguous RBDs within the circular
 * buffer), it updates the Rx status buffer in DRAM, 2) described above,
 * to tell the driver the index of the latest filled RBD.  The driver must
 * read this "read" index from DRAM after receiving an Rx interrupt from SP.
 *
 * The driver must also internally keep track of a third index, which is the
 * next RBD to process.  When receiving an Rx interrupt, driver should process
 * all filled but unprocessed RBs up to, but not including, the RB
 * corresponding to the "read" index.  For example, if "read" index becomes "1",
 * driver may process the RB pointed to by RBD 0.  Depending on volume of
 * traffic, there may be many RBs to process.
 *
 * If read index == write index, SP thinks there is no room to put new data.
 * Due to this, the maximum number of filled RBs is 255, instead of 256.  To
 * be safe, make sure that there is a gap of at least 2 RBDs between "write"
 * and "read" indexes; that is, make sure that there are no more than 254
 * buffers waiting to be filled.
 */
#define	FH_MEM_RSCSR_LOWER_BOUND	(FH_MEM_LOWER_BOUND + 0xBC0)
#define	FH_MEM_RSCSR_UPPER_BOUND	(FH_MEM_LOWER_BOUND + 0xC00)
#define	FH_MEM_RSCSR_CHNL0	(FH_MEM_RSCSR_LOWER_BOUND)
#define	FH_MEM_RSCSR_CHNL1	(FH_MEM_RSCSR_LOWER_BOUND + 0x020)

/*
 * Physical base address of 8-byte Rx Status buffer.
 * Bit fields:
 * 31-0: Rx status buffer physical base address [35:4], must 16-byte aligned.
 */

#define	FH_RSCSR_CHNL0_STTS_WPTR_REG	(FH_MEM_RSCSR_CHNL0)

/*
 * Physical base address of Rx Buffer Descriptor Circular Buffer.
 * Bit fields:
 * 27-0:  RBD CD physical base address [35:8], must be 256-byte aligned.
 */
#define	FH_RSCSR_CHNL0_RBDCB_BASE_REG	(FH_MEM_RSCSR_CHNL0 + 0x004)

/*
 * Rx write pointer (index, really!).
 * Bit fields:
 * 11-0:  Index of driver's most recent prepared-to-be-filled RBD, + 1.
 *        NOTE:  For 256-entry circular buffer, use only bits [7:0].
 */
#define	FH_RSCSR_CHNL0_RBDCB_WPTR_REG	(FH_MEM_RSCSR_CHNL0 + 0x008)
#define	FH_RSCSR_CHNL0_RBDCB_RPTR_REG	(FH_MEM_RSCSR_CHNL0 + 0x00c)


/*
 * RSCSR registers used in Service mode
 */
#define	FH_RSCSR_CHNL1_RB_WPTR_REG	(FH_MEM_RSCSR_CHNL1)
#define	FH_RSCSR_CHNL1_RB_WPTR_OFFSET_REG	(FH_MEM_RSCSR_CHNL1 + 0x004)
#define	FH_RSCSR_CHNL1_RB_CHUNK_NUM_REG		(FH_MEM_RSCSR_CHNL1 + 0x008)
#define	FH_RSCSR_CHNL1_SRAM_ADDR_REG	(FH_MEM_RSCSR_CHNL1 + 0x00C)

/*
 * Rx Config/Status Registers (RCSR)
 * Rx Config Reg for channel 0 (only channel used)
 *
 * Driver must initialize FH_MEM_RCSR_CHNL0_CONFIG_REG as follows for
 * normal operation (see bit fields).
 *
 * Clearing FH_MEM_RCSR_CHNL0_CONFIG_REG to 0 turns off Rx DMA.
 * Driver should poll FH_MEM_RSSR_RX_STATUS_REG	for
 * FH_RSSR_CHNL0_RX_STATUS_CHNL_IDLE (bit 24) before continuing.
 *
 * Bit fields:
 * 31-30: Rx DMA channel enable: '00' off/pause, '01' pause at end of frame,
 *        '10' operate normally
 * 29-24: reserved
 * 23-20: # RBDs in circular buffer = 2^value; use "8" for 256 RBDs (normal),
 *        min "5" for 32 RBDs, max "12" for 4096 RBDs.
 * 19-18: reserved
 * 17-16: size of each receive buffer; '00' 4K (normal), '01' 8K,
 *        '10' 12K, '11' 16K.
 * 15-14: reserved
 * 13-12: IRQ destination; '00' none, '01' host driver (normal operation)
 * 11- 4: timeout for closing Rx buffer and interrupting host (units 32 usec)
 *        typical value 0x10 (about 1/2 msec)
 * 3- 0: reserved
 */
#define	FH_MEM_RCSR_LOWER_BOUND	(FH_MEM_LOWER_BOUND + 0xC00)
#define	FH_MEM_RCSR_UPPER_BOUND	(FH_MEM_LOWER_BOUND + 0xCC0)
#define	FH_MEM_RCSR_CHNL0	(FH_MEM_RCSR_LOWER_BOUND)
#define	FH_MEM_RCSR_CHNL1	(FH_MEM_RCSR_LOWER_BOUND + 0x020)

#define	FH_MEM_RCSR_CHNL0_CONFIG_REG	(FH_MEM_RCSR_CHNL0)
#define	FH_MEM_RCSR_CHNL0_CREDIT_REG	(FH_MEM_RCSR_CHNL0 + 0x004)
#define	FH_MEM_RCSR_CHNL0_RBD_STTS_REG	(FH_MEM_RCSR_CHNL0 + 0x008)
#define	FH_MEM_RCSR_CHNL0_RB_STTS_REG	(FH_MEM_RCSR_CHNL0 + 0x00C)
#define	FH_MEM_RCSR_CHNL0_RXPD_STTS_REG	(FH_MEM_RCSR_CHNL0 + 0x010)

#define	FH_MEM_RCSR_CHNL0_RBD_STTS_FRAME_RB_CNT_MASK	(0x7FFFFFF0)

/*
 * RCSR registers used in Service mode
 */
#define	FH_MEM_RCSR_CHNL1_CONFIG_REG	(FH_MEM_RCSR_CHNL1)
#define	FH_MEM_RCSR_CHNL1_RB_STTS_REG	(FH_MEM_RCSR_CHNL1 + 0x00C)
#define	FH_MEM_RCSR_CHNL1_RX_PD_STTS_REG	(FH_MEM_RCSR_CHNL1 + 0x010)

/*
 * Rx Shared Status Registers (RSSR)
 *
 * After stopping Rx DMA channel (writing 0 to FH_MEM_RCSR_CHNL0_CONFIG_REG),
 * driver must poll FH_MEM_RSSR_RX_STATUS_REG until Rx channel is idle.
 *
 * Bit fields:
 * 24:  1 = Channel 0 is idle
 *
 * FH_MEM_RSSR_SHARED_CTRL_REG and FH_MEM_RSSR_RX_ENABLE_ERR_IRQ2DRV contain
 * default values that should not be altered by the driver.
 */
#define	FH_MEM_RSSR_LOWER_BOUND	(FH_MEM_LOWER_BOUND + 0xC40)
#define	FH_MEM_RSSR_UPPER_BOUND	(FH_MEM_LOWER_BOUND + 0xD00)
#define	FH_MEM_RSSR_SHARED_CTRL_REG	(FH_MEM_RSSR_LOWER_BOUND)
#define	FH_MEM_RSSR_RX_STATUS_REG	(FH_MEM_RSSR_LOWER_BOUND + 0x004)
#define	FH_MEM_RSSR_RX_ENABLE_ERR_IRQ2DRV (FH_MEM_RSSR_LOWER_BOUND + 0x008)

/*
 * Transmit DMA Channel Control/Status Registers (TCSR)
 *
 * SP has one configuration register for each of 8 Tx DMA/FIFO channels
 * supported in hardware; config regs are separated by 0x20 bytes.
 *
 * To use a Tx DMA channel, driver must initialize its
 *
 *
 * All other bits should be 0.
 *
 * Bit fields:
 * 31-30: Tx DMA channel enable: '00' off/pause, '01' pause at end of frame,
 *        '10' operate normally
 * 29- 4: Reserved, set to "0"
 *     3: Enable internal DMA requests (1, normal operation), disable (0)
 *  2- 0: Reserved, set to "0"
 */
#define	IWH_FH_TCSR_UPPER_BOUND	(IWH_FH_REGS_LOWER_BOUND + 0xE60)

#define	IWH_FH_TCSR_CHNL_NUM	(7)

/*
 * Tx Shared Status Registers (TSSR)
 *
 * After stopping Tx DMA channel (writing 0 to
 * IWH_FH_TSSR_TX_STATUS_REG until selected Tx channel is idle
 * (channel's buffers empty | no pending requests).
 *
 * Bit fields:
 * 31-24:  1 = Channel buffers empty (channel 7:0)
 * 23-16:  1 = No pending requests (channel 7:0)
 */
#define	IWH_FH_TSSR_LOWER_BOUND	(IWH_FH_REGS_LOWER_BOUND + 0xEA0)
#define	IWH_FH_TSSR_UPPER_BOUND	(IWH_FH_REGS_LOWER_BOUND + 0xEC0)

#define	IWH_FH_TSSR_TX_MSG_CONFIG_REG (IWH_FH_TSSR_LOWER_BOUND + 0x008)
#define	IWH_FH_TSSR_TX_STATUS_REG	(IWH_FH_TSSR_LOWER_BOUND + 0x010)

#define	IWH_FH_TSSR_TX_MSG_CONFIG_REG_VAL_SNOOP_RD_TXPD_ON	(0xFF000000)
#define	IWH_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RD_TXPD_ON	(0x00FF0000)

#define	IWH_FH_TSSR_TX_MSG_CONFIG_REG_VAL_MAX_FRAG_SIZE_64B	(0x00000000)
#define	IWH_FH_TSSR_TX_MSG_CONFIG_REG_VAL_MAX_FRAG_SIZE_128B	(0x00000400)
#define	IWH_FH_TSSR_TX_MSG_CONFIG_REG_VAL_MAX_FRAG_SIZE_256B	(0x00000800)
#define	IWH_FH_TSSR_TX_MSG_CONFIG_REG_VAL_MAX_FRAG_SIZE_512B	(0x00000C00)

#define	IWH_FH_TSSR_TX_MSG_CONFIG_REG_VAL_SNOOP_RD_TFD_ON	(0x00000100)
#define	IWH_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RD_CBB_ON	(0x00000080)

#define	IWH_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RSP_WAIT_TH	(0x00000020)
#define	IWH_FH_TSSR_TX_MSG_CONFIG_REG_VAL_RSP_WAIT_TH	(0x00000005)

#define	IWH_FH_TSSR_TX_STATUS_REG_BIT_BUFS_EMPTY(_chnl)	\
	((1 << (_chnl)) << 24)
#define	IWH_FH_TSSR_TX_STATUS_REG_BIT_NO_PEND_REQ(_chnl) \
	((1 << (_chnl)) << 16)

#define	IWH_FH_TSSR_TX_STATUS_REG_MSK_CHNL_IDLE(_chnl) \
	(IWH_FH_TSSR_TX_STATUS_REG_BIT_BUFS_EMPTY(_chnl) | \
	IWH_FH_TSSR_TX_STATUS_REG_BIT_NO_PEND_REQ(_chnl))

/*
 * TFDIB
 */
#define	IWH_FH_TFDIB_UPPER_BOUND	(IWH_FH_REGS_LOWER_BOUND + 0x958)
#define	IWH_FH_TFDIB_CTRL1_REG_POS_MSB	(28)
#define	IWH_FH_TFDIB_LOWER_BOUND	(IWH_FH_REGS_LOWER_BOUND + 0x900)

#define	IWH_FH_TFDIB_CTRL0_REG(_chnl)\
	(IWH_FH_TFDIB_LOWER_BOUND + 0x8 * _chnl)

#define	IWH_FH_TFDIB_CTRL1_REG(_chnl)\
	(IWH_FH_TFDIB_LOWER_BOUND + 0x8 * _chnl + 0x4)

/*
 * Debug Monitor Area
 */
#define	FH_MEM_DM_LOWER_BOUND	(FH_MEM_LOWER_BOUND + 0xEE0)
#define	FH_MEM_DM_UPPER_BOUND	(FH_MEM_LOWER_BOUND + 0xEF0)
#define	FH_MEM_DM_CONTROL_MASK_REG	(FH_MEM_DM_LOWER_BOUND)
#define	FH_MEM_DM_CONTROL_START_REG	(FH_MEM_DM_LOWER_BOUND + 0x004)
#define	FH_MEM_DM_CONTROL_STATUS_REG	(FH_MEM_DM_LOWER_BOUND + 0x008)
#define	FH_MEM_DM_MONITOR_REG	(FH_MEM_DM_LOWER_BOUND + 0x00C)

#define	FH_TB1_ADDR_LOW_MASK	(0xFFFFFFFF)	/* bits 31:0 */
#define	FH_TB1_ADDR_HIGH_MASK	(0xF00000000)	/* bits 35:32 */
#define	FH_TB2_ADDR_LOW_MASK	(0x0000FFFF)	/* bits 15:0 */
#define	FH_TB2_ADDR_HIGH_MASK	(0xFFFFF0000)	/* bits 35:16 */

#define	FH_TB1_ADDR_LOW_BITSHIFT	(0)
#define	FH_TB1_ADDR_HIGH_BITSHIFT	(32)
#define	FH_TB2_ADDR_LOW_BITSHIFT	(0)
#define	FH_TB2_ADDR_HIGH_BITSHIFT	(16)

#define	FH_TB1_LENGTH_MASK	(0x00000FFF)	/* bits 11:0 */
#define	FH_TB2_LENGTH_MASK	(0x00000FFF)	/* bits 11:0 */

/*
 * number of FH channels including 2 service mode
 */
#define	NUM_OF_FH_CHANNELS	(10)

/*
 * ctrl field bitology
 */
#define	FH_TFD_CTRL_PADDING_MASK	(0xC0000000)	/* bits 31:30 */
#define	FH_TFD_CTRL_NUMTB_MASK		(0x1F000000)	/* bits 28:24 */

#define	FH_TFD_CTRL_PADDING_BITSHIFT	(30)
#define	FH_TFD_CTRL_NUMTB_BITSHIFT	(24)

#define	FH_TFD_GET_NUM_TBS(ctrl) \
	((ctrl & FH_TFD_CTRL_NUMTB_MASK) >> FH_TFD_CTRL_NUMTB_BITSHIFT)
#define	FH_TFD_GET_PADDING(ctrl) \
	((ctrl & FH_TFD_CTRL_PADDING_MASK) >> FH_TFD_CTRL_PADDING_BITSHIFT)

/*
 * TCSR: tx_config register values
 */
#define	IWH_FH_TCSR_TX_CONFIG_REG_VAL_MSG_MODE_TXF	(0x00000000)
#define	IWH_FH_TCSR_TX_CONFIG_REG_VAL_MSG_MODE_DRIVER	(0x00000001)
#define	IWH_FH_TCSR_TX_CONFIG_REG_VAL_MSG_MODE_ARC	(0x00000002)

#define	IWH_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE_VAL	(0x00000008)

#define	IWH_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_NOINT	(0x00000000)
#define	IWH_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_IFTFD	(0x00200000)

#define	IWH_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_RTC_NOINT		(0x00000000)
#define	IWH_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_RTC_ENDTFD	(0x00400000)
#define	IWH_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_RTC_IFTFD		(0x00800000)


#define	IWH_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_EMPTY	(0x00000000)
#define	IWH_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_WAIT	(0x00002000)

#define	IWH_FH_TCSR_CHNL_TX_BUF_STS_REG_BIT_TFDB_WPTR	(0x00000001)

#define	IWH_FH_TCSR_CHNL_TX_BUF_STS_REG_POS_TB_NUM	(20)
#define	IWH_FH_TCSR_CHNL_TX_BUF_STS_REG_POS_TB_IDX	(12)

#define	IWH_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_VALID	(0x00000003)

#define	IWH_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE	(0x80000000)

#define	IWH_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_DISABLE_VAL	(0x00000000)

#define	IWH_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_ENDTFD		(0x00100000)

#define	IWH_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_PAUSE	(0x00000000)

#define	IWH_FH_TCSR_LOWER_BOUND	(FH_MEM_LOWER_BOUND + 0xD00)

#define	IWH_FH_TCSR_CHNL_TX_CONFIG_REG(_chnl)\
	(IWH_FH_TCSR_LOWER_BOUND + 0x20 * _chnl)

#define	IWH_FH_TCSR_CHNL_TX_CREDIT_REG(_chnl)\
	(IWH_FH_TCSR_LOWER_BOUND + 0x20 * _chnl + 0x4)

#define	IWH_FH_TCSR_CHNL_TX_BUF_STS_REG(_chnl)\
	(IWH_FH_TCSR_LOWER_BOUND + 0x20 * _chnl + 0x8)
#define	IWH_FH_TCSR_CHNL_NUM		(7)

/*
 * CBB table
 */
#define	FH_CBB_ADDR_MASK	0x0FFFFFFF	/* bits 27:0 */
#define	FH_CBB_ADDR_BIT_SHIFT	(8)

/*
 * RCSR:  channel 0 rx_config register defines
 */
#define	FH_RCSR_CHNL0_RX_CONFIG_DMA_CHNL_EN_MASK (0xC0000000) /* bits 30-31 */
#define	FH_RCSR_CHNL0_RX_CONFIG_RBDBC_SIZE_MASK (0x00F00000) /* bits 20-23 */
#define	FH_RCSR_CHNL0_RX_CONFIG_RB_SIZE_MASK (0x00030000) /* bits 16-17 */
#define	FH_RCSR_CHNL0_RX_CONFIG_SINGLE_FRAME_MASK (0x00008000) /* bit 15 */
#define	FH_RCSR_CHNL0_RX_CONFIG_IRQ_DEST_MASK (0x00001000) /* bit 12 */
#define	FH_RCSR_CHNL0_RX_CONFIG_RB_TIMEOUT_MASK (0x00000FF0) /* bit 4-11 */

#define	FH_RCSR_RX_CONFIG_RBDCB_SIZE_BITSHIFT	(20)
#define	FH_RCSR_RX_CONFIG_RB_SIZE_BITSHIFT	(16)

#define	FH_RCSR_GET_RDBC_SIZE(reg) \
	((reg & FH_RCSR_RX_CONFIG_RDBC_SIZE_MASK) >> \
	FH_RCSR_RX_CONFIG_RDBC_SIZE_BITSHIFT)

/*
 * RCSR:  channel 1 rx_config register defines
 */
#define	FH_RCSR_CHNL1_RX_CONFIG_DMA_CHNL_EN_MASK  (0xC0000000) /* bits 30-31 */
#define	FH_RCSR_CHNL1_RX_CONFIG_IRQ_DEST_MASK	  (0x00003000) /* bits 12-13 */

/*
 * RCSR: rx_config register values
 */
#define	FH_RCSR_RX_CONFIG_CHNL_EN_PAUSE_VAL	(0x00000000)
#define	FH_RCSR_RX_CONFIG_CHNL_EN_PAUSE_EOF_VAL	(0x40000000)
#define	FH_RCSR_RX_CONFIG_CHNL_EN_ENABLE_VAL	(0x80000000)
#define	FH_RCSR_RX_CONFIG_SINGLE_FRAME_MODE	(0x00008000)

#define	FH_RCSR_RX_CONFIG_RDRBD_DISABLE_VAL	(0x00000000)
#define	FH_RCSR_RX_CONFIG_RDRBD_ENABLE_VAL	(0x20000000)

#define	IWH_FH_RCSR_RX_CONFIG_REG_VAL_RB_SIZE_4K	(0x00000000)
#define	IWH_TX_RTS_RETRY_LIMIT		(60)
#define	IWH_TX_DATA_RETRY_LIMIT		(15)

#define	IWH_FH_RCSR_RX_CONFIG_REG_VAL_RB_SIZE_8K	(0x00010000)
#define	IWH_FH_RCSR_RX_CONFIG_REG_VAL_RB_SIZE_12K	(0x00020000)
#define	IWH_FH_RCSR_RX_CONFIG_REG_VAL_RB_SIZE_16K	(0x00030000)

/*
 * RCSR channel 0 config register values
 */
#define	FH_RCSR_CHNL0_RX_CONFIG_IRQ_DEST_NO_INT_VAL	(0x00000000)
#define	FH_RCSR_CHNL0_RX_CONFIG_IRQ_DEST_INT_HOST_VAL	(0x00001000)

/*
 * RCSR channel 1 config register values
 */
#define	FH_RCSR_CHNL1_RX_CONFIG_IRQ_DEST_NO_INT_VAL	(0x00000000)
#define	FH_RCSR_CHNL1_RX_CONFIG_IRQ_DEST_INT_HOST_VAL	(0x00001000)
#define	FH_RCSR_CHNL1_RX_CONFIG_IRQ_DEST_INT_RTC_VAL	(0x00002000)
#define	FH_RCSR_CHNL1_RX_CONFIG_IRQ_DEST_INT_HOST_RTC_VAL (0x00003000)

/*
 * RCSR: rb status register defines
 */
#define	FH_RCSR_RB_BYTE_TO_SEND_MASK	(0x0001FFFF)	/* bits 0-16 */

/*
 * RSCSR: defs used in normal mode
 */
#define	FH_RSCSR_CHNL0_RBDCB_WPTR_MASK	(0x00000FFF)	/* bits 0-11 */

/*
 * RSCSR: defs used in service mode
 */
#define	FH_RSCSR_CHNL1_SRAM_ADDR_MASK	(0x00FFFFFF)	/* bits 0-23 */
#define	FH_RSCSR_CHNL1_RB_WPTR_MASK	(0x0FFFFFFF)	/* bits 0-27 */
#define	FH_RSCSR_CHNL1_RB_WPTR_OFFSET_MASK	(0x000000FF)	/* bits 0-7 */

/*
 * RSSR: RX Enable Error IRQ to Driver register defines
 */
#define	FH_MEM_RSSR_RX_ENABLE_ERR_IRQ2DRV_NO_RBD (0x00400000)	/* bit 22 */

#define	FH_DRAM2SRAM_DRAM_ADDR_HIGH_MASK	(0xFFFFFFF00)	/* bits 8-35 */
#define	FH_DRAM2SRAM_DRAM_ADDR_LOW_MASK		(0x000000FF)	/* bits 0-7 */

#define	FH_DRAM2SRAM_DRAM_ADDR_HIGH_BITSHIFT	(8)	/* bits 8-35 */

/*
 * RX DRAM status regs definitions
 */
#define	FH_RX_RB_NUM_MASK	(0x00000FFF)	/* bits 0-11 */
#define	FH_RX_FRAME_NUM_MASK	(0x0FFF0000) /* bits 16-27 */

#define	FH_RX_RB_NUM_BITSHIFT	(0)
#define	FH_RX_FRAME_NUM_BITSHIFT	(16)

/*
 * Tx Scheduler
 *
 * The Tx Scheduler selects the next frame to be transmitted, chosing TFDs
 * (Transmit Frame Descriptors) from up to 16 circular queues resident in
 * host DRAM.  It steers each frame's Tx command (which contains the frame
 * data) through one of up to 7 prioritized Tx DMA FIFO channels within the
 * device.  A queue maps to only one (selectable by driver) Tx DMA channel,
 * but one DMA channel may take input from several queues.
 *
 * Tx DMA channels have dedicated purposes.  For SP, and are used as follows:
 * BMC TODO:  CONFIRM channel assignments, esp for 0/1
 *
 * 0 -- EDCA BK (background) frames, lowest priority
 * 1 -- EDCA BE (best effort) frames, normal priority
 * 2 -- EDCA VI (video) frames, higher priority
 * 3 -- EDCA VO (voice) and management frames, highest priority
 * 4 -- Commands (e.g. RXON, etc.)
 * 5 -- HCCA short frames
 * 6 -- HCCA long frames
 * 7 -- not used by driver (device-internal only)
 *
 * Driver should normally map queues 0-6 to Tx DMA/FIFO channels 0-6.
 * In addition, driver can map queues 7-15 to Tx DMA/FIFO channels 0-3 to
 * support 11n aggregation via EDCA DMA channels. BMC confirm.
 *
 * The driver sets up each queue to work in one of two modes:
 *
 * 1)  Scheduler-Ack, in which the scheduler automatically supports a
 *     block-ack (BA) window of up to 64 TFDs.  In this mode, each queue
 *     contains TFDs for a unique combination of Recipient Address (RA)
 *     and Traffic Identifier (TID), that is, traffic of a given
 *     Quality-Of-Service (QOS) priority, destined for a single station.
 *
 *     In scheduler-ack mode, the scheduler keeps track of the Tx status of
 *     each frame within the BA window, including whether it's been transmitted,
 *     and whether it's been acknowledged by the receiving station.  The device
 *     automatically processes block-acks received from the receiving STA,
 *     and reschedules un-acked frames to be retransmitted (successful
 *     Tx completion may end up being out-of-order).
 *
 *     The driver must maintain the queue's Byte Count table in host DRAM
 *     (struct iwh_sched_queue_byte_cnt_tbl) for this mode.
 *     This mode does not support fragmentation.
 *
 * 2)  FIFO (a.k.a. non-Scheduler-ACK), in which each TFD is processed in order.
 *     The device may automatically retry Tx, but will retry only one frame
 *     at a time, until receiving ACK from receiving station, or reaching
 *     retry limit and giving up.
 *
 *     The command queue (#4) must use this mode!
 *     This mode does not require use of the Byte Count table in host DRAM.
 *
 * Driver controls scheduler operation via 3 means:
 * 1)  Scheduler registers
 * 2)  Shared scheduler data base in internal 4956 SRAM
 * 3)  Shared data in host DRAM
 *
 * Initialization:
 *
 * When loading, driver should allocate memory for:
 * 1)  16 TFD circular buffers, each with space for (typically) 256 TFDs.
 * 2)  16 Byte Count circular buffers in 16 KBytes contiguous memory
 *     (1024 bytes for each queue).
 *
 * After receiving "Alive" response from uCode, driver must initialize
 * the following (especially for queue #4, the command queue, otherwise
 * the driver can't issue commands!):
 *
 * 1)  SP's scheduler data base area in SRAM:
 *     a)  Read SRAM address of data base area from SCD_SRAM_BASE_ADDR
 *     b)  Clear and Init SCD_CONTEXT_DATA_OFFSET area (size 128 bytes)
 *     c)  Clear SCD_TX_STTS_BITMAP_OFFSET area (size 256 bytes)
 *     d)  Clear (BMC and init?) SCD_TRANSLATE_TBL_OFFSET (size 32 bytes)
 *
 * 2)  Init SCD_DRAM_BASE_ADDR with physical base of Tx byte count circular
 *     buffer array, allocated by driver in host DRAM.
 *
 * 3)
 */

/*
 * Max Tx window size is the max number of contiguous TFDs that the scheduler
 * can keep track of at one time when creating block-ack chains of frames.
 * Note that "64" matches the number of ack bits in a block-ack.
 * Driver should use SCD_WIN_SIZE and SCD_FRAME_LIMIT values to initialize
 * SCD_CONTEXT_QUEUE_OFFSET(x) values.
 */
#define	SCD_WIN_SIZE	64
#define	SCD_FRAME_LIMIT	64

/*
 * Driver may need to update queue-empty bits after changing queue's
 * write and read pointers (indexes) during (re-)initialization (i.e. when
 * scheduler is not tracking what's happening).
 * Bit fields:
 * 31-16:  Write mask -- 1: update empty bit, 0: don't change empty bit
 * 15-00:  Empty state, one for each queue -- 1: empty, 0: non-empty
 * NOTE BMC:  THIS REGISTER NOT USED BY LINUX DRIVER.
 */
#define	SCD_EMPTY_BITS	(SCD_START_OFFSET + 0x4)

/*
 * Physical base address of array of byte count (BC) circular buffers (CBs).
 * Each Tx queue has a BC CB in host DRAM to support Scheduler-ACK mode.
 * This register points to BC CB for queue 0, must be on 1024-byte boundary.
 * Others are spaced by 1024 bytes.
 * Each BC CB is 2 bytes * (256 + 64) = 740 bytes, followed by 384 bytes pad.
 * (Index into a queue's BC CB) = (index into queue's TFD CB) = (SSN & 0xff).
 * Bit fields:
 * 25-00:  Byte Count CB physical address [35:10], must be 1024-byte aligned.
 */
#define	SCD_AIT		(SCD_START_OFFSET + 0x18)

/*
 * Queue (x) Write Pointers (indexes, really!), one for each Tx queue.
 * Initialized and updated by driver as new TFDs are added to queue.
 * NOTE:  If using Block Ack, index must correspond to frame's
 *        Start Sequence Number; index = (SSN & 0xff)
 * NOTE BMC:  Alternative to HBUS_TARG_WRPTR, which is what Linux driver uses?
 */
#define	SCD_QUEUE_WRPTR(x)	(SCD_START_OFFSET + 0x24 + (x) * 4)

/*
 * Queue (x) Read Pointers (indexes, really!), one for each Tx queue.
 * For FIFO mode, index indicates next frame to transmit.
 * For Scheduler-ACK mode, index indicates first frame in Tx window.
 * Initialized by driver, updated by scheduler.
 */
#define	SCD_QUEUE_RDPTR(x)	(SCD_START_OFFSET + 0x64 + (x) * 4)
#define	SCD_SETQUEUENUM		(SCD_START_OFFSET + 0xa4)
#define	SCD_SET_TXSTAT_TXED	(SCD_START_OFFSET + 0xa8)
#define	SCD_SET_TXSTAT_DONE	(SCD_START_OFFSET + 0xac)
#define	SCD_SET_TXSTAT_NOT_SCHD	(SCD_START_OFFSET + 0xb0)
#define	SCD_DECREASE_CREDIT	(SCD_START_OFFSET + 0xb4)
#define	SCD_DECREASE_SCREDIT	(SCD_START_OFFSET + 0xb8)
#define	SCD_LOAD_CREDIT		(SCD_START_OFFSET + 0xbc)
#define	SCD_LOAD_SCREDIT	(SCD_START_OFFSET + 0xc0)
#define	SCD_BAR			(SCD_START_OFFSET + 0xc4)
#define	SCD_BAR_DW0		(SCD_START_OFFSET + 0xc8)
#define	SCD_BAR_DW1		(SCD_START_OFFSET + 0xcc)

/*
 * Select which queues work in chain mode (1) vs. not (0).
 * Use chain mode to build chains of aggregated frames.
 * Bit fields:
 * 31-16:  Reserved
 * 15-00:  Mode, one bit for each queue -- 1: Chain mode, 0: one-at-a-time
 * NOTE:  If driver sets up queue for chain mode, it should be also set up
 *        Scheduler-ACK mode as well, via SCD_QUEUE_STATUS_BITS(x).
 */
#define	SCD_QUERY_REQ		(SCD_START_OFFSET + 0xd8)
#define	SCD_QUERY_RES		(SCD_START_OFFSET + 0xdc)
#define	SCD_PENDING_FRAMES	(SCD_START_OFFSET + 0xe0)

/*
 * Select which queues interrupt driver when read pointer (index) increments.
 * Bit fields:
 * 31-16:  Reserved
 * 15-00:  Interrupt enable, one bit for each queue -- 1: enabled, 0: disabled
 * NOTE BMC:  THIS FUNCTIONALITY IS APPARENTLY A NO-OP.
 */
#define	SCD_INTERRUPT_THRESHOLD	(SCD_START_OFFSET + 0xe8)
#define	SCD_QUERY_MIN_FRAME_SIZE	(SCD_START_OFFSET + 0x100)


/*
 * SP internal SRAM structures for scheduler, shared with driver ...
 * Driver should clear and initialize the following areas after receiving
 * "Alive" response from SP uCode, i.e. after initial
 * uCode load, or after a uCode load done for error recovery:
 *
 * SCD_CONTEXT_DATA_OFFSET (size 128 bytes)
 * SCD_TX_STTS_BITMAP_OFFSET (size 256 bytes)
 * SCD_TRANSLATE_TBL_OFFSET (size 32 bytes)
 *
 * Driver reads base address of this scheduler area from SCD_SRAM_BASE_ADDR.
 * All OFFSET values must be added to this base address.
 * Use HBUS_TARG_MEM_* registers to access SRAM.
 */

/*
 * Queue context.  One 8-byte entry for each of 16 queues.
 *
 * Driver should clear this entire area (size 0x80) to 0 after receiving
 * "Alive" notification from uCode.  Additionally, driver should init
 * each queue's entry as follows:
 *
 * LS Dword bit fields:
 *  0-06:  Max Tx window size for Scheduler-ACK.  Driver should init to 64.
 *
 * MS Dword bit fields:
 * 16-22:  Frame limit.  Driver should init to 10 (0xa).
 *
 * Driver should init all other bits to 0.
 *
 * Init must be done after driver receives "Alive" response from SP uCode,
 * and when setting up queue for aggregation.
 */
#define	SCD_CONTEXT_DATA_OFFSET		0x380

/*
 * Tx Status Bitmap
 *
 * Driver should clear this entire area (size 0x100) to 0 after receiving
 * "Alive" notification from uCode.  Area is used only by device itself;
 * no other support (besides clearing) is required from driver.
 */
#define	SCD_TX_STTS_BITMAP_OFFSET	0x400

/*
 * RAxTID to queue translation mapping.
 *
 * When queue is in Scheduler-ACK mode, frames placed in a that queue must be
 * for only one combination of receiver address (RA) and traffic ID (TID), i.e.
 * one QOS priority level destined for one station (for this link, not final
 * destination).  The SCD_TRANSLATE_TABLE area provides 16 16-bit mappings,
 * one for each of the 16 queues.  If queue is not in Scheduler-ACK mode, the
 * device ignores the mapping value.
 *
 * Bit fields, for each 16-bit map:
 * 15-9:  Reserved, set to 0
 *  8-4:  Index into device's station table for recipient station
 *  3-0:  Traffic ID (tid), range 0-15
 *
 * Driver should clear this entire area (size 32 bytes) to 0 after receiving
 * "Alive" notification from uCode.  To update a 16-bit map value, driver
 * must read a dword-aligned value from device SRAM, replace the 16-bit map
 * value of interest, and write the dword value back into device SRAM.
 */
#define	SCD_TRANSLATE_TBL_OFFSET	0x500
#define	SCD_CONTEXT_QUEUE_OFFSET(x)	(SCD_CONTEXT_DATA_OFFSET + ((x) * 8))
#define	SCD_TRANSLATE_TBL_OFFSET_QUEUE(x) \
	((SCD_TRANSLATE_TBL_OFFSET + ((x) * 2)) & 0xfffffffc)

/*
 * Mask to enable contiguous Tx DMA/FIFO channels between "lo" and "hi".
 */
#define	SCD_TXFACT_REG_TXFIFO_MASK(lo, hi) \
	((1<<(hi))|((1<<(hi))-(1<<(lo))))

#define	SCD_MODE_REG_BIT_SEARCH_MODE		(1<<0)
#define	SCD_MODE_REG_BIT_SBYP_MODE		(1<<1)

#define	SCD_TXFIFO_POS_TID			(0)
#define	SCD_TXFIFO_POS_RA			(4)
#define	SCD_QUEUE_STTS_REG_POS_SCD_ACK		(8)
#define	SCD_QUEUE_STTS_REG_POS_SCD_ACT_EN	(10)

#define	SCD_QUEUE_RA_TID_MAP_RATID_MSK		(0x01FF)

#define	SCD_QUEUE_CTX_REG1_WIN_SIZE_POS		(0)
#define	SCD_QUEUE_CTX_REG1_WIN_SIZE_MSK		(0x0000007F)
#define	SCD_QUEUE_CTX_REG1_CREDIT_POS		(8)
#define	SCD_QUEUE_CTX_REG1_CREDIT_MSK		(0x00FFFF00)
#define	SCD_QUEUE_CTX_REG1_SUPER_CREDIT_POS	(24)
#define	SCD_QUEUE_CTX_REG1_SUPER_CREDIT_MSK	(0xFF000000)
#define	SCD_QUEUE_CTX_REG2_FRAME_LIMIT_POS	(16)
#define	SCD_QUEUE_CTX_REG2_FRAME_LIMIT_MSK	(0x007F0000)

#define	CSR_HW_IF_CONFIG_REG_BIT_KEDRON_R	(0x00000010)
#define	CSR_HW_IF_CONFIG_REG_MSK_BOARD_VER	(0x00000C00)
#define	CSR_HW_IF_CONFIG_REG_BIT_MAC_SI		(0x00000100)
#define	CSR_HW_IF_CONFIG_REG_BIT_RADIO_SI	(0x00000200)
#define	CSR_HW_IF_CONFIG_REG_EEP_SEM		(0x00200000)
#define	IWH_CSR_ANA_PLL_CFG			(0x00880300)
#define	CSR_DBG_HPET_MEM_REG_VAL		(0xFFFF0000)

/* IWH-END */


#define	STATISTICS_FLG_CLEAR				(0x1)
#define	STATISTICS_FLG_DISABLE_NOTIFICATION		(0x2)

#define	STATISTICS_REPLY_FLG_CLEAR			(0x1)
#define	STATISTICS_REPLY_FLG_BAND_24G_MSK		(0x2)
#define	STATISTICS_REPLY_FLG_TGJ_NARROW_BAND_MSK	(0x4)
#define	STATISTICS_REPLY_FLG_FAT_MODE_MSK		(0x8)
#define	RX_PHY_FLAGS_ANTENNAE_OFFSET			(4)
#define	RX_PHY_FLAGS_ANTENNAE_MASK			(0x70)

/*
 * Register and values
 */
#define	CSR_BASE	(0x0)
#define	HBUS_BASE	(0x400)

#define	HBUS_TARG_MBX_C	(HBUS_BASE+0x030)

/*
 * CSR (control and status registers)
 */
#define	CSR_SW_VER		(CSR_BASE+0x000)
#define	CSR_HW_IF_CONFIG_REG	(CSR_BASE+0x000) /* hardware interface config */
#define	CSR_INT_COALESCING	(CSR_BASE+0x004) /* accum ints, 32-usec units */
#define	CSR_INT		(CSR_BASE+0x008) /* host interrupt status/ack */
#define	CSR_INT_MASK	(CSR_BASE+0x00c) /* host interrupt enable */
#define	CSR_FH_INT_STATUS	(CSR_BASE+0x010) /* busmaster int status/ack */
#define	CSR_GPIO_IN	(CSR_BASE+0x018) /* read external chip pins */
#define	CSR_RESET	(CSR_BASE+0x020) /* busmaster enable, NMI, etc */
#define	CSR_GP_CNTRL	(CSR_BASE+0x024)
#define	CSR_HW_REV	(CSR_BASE+0x028)
#define	CSR_EEPROM_REG	(CSR_BASE+0x02c)
#define	CSR_EEPROM_GP	(CSR_BASE+0x030)
#define	CSR_UCODE_DRV_GP1	(CSR_BASE+0x054)
#define	CSR_UCODE_DRV_GP1_SET	(CSR_BASE+0x058)
#define	CSR_UCODE_DRV_GP1_CLR	(CSR_BASE+0x05c)
#define	CSR_UCODE_DRV_GP2	(CSR_BASE+0x060)
#define	CSR_GIO_CHICKEN_BITS	(CSR_BASE+0x100)
#define	CSR_ANA_PLL_CFG		(CSR_BASE+0x20c)
#define	CSR_HW_REV_WA_REG	(CSR_BASE+0x22C)
#define	CSR_DBG_HPET_MEM_REG	(CSR_BASE+0x240)

/*
 * BSM (Bootstrap State Machine)
 */
#define	BSM_BASE		(CSR_BASE + 0x3400)

#define	BSM_WR_CTRL_REG  	(BSM_BASE + 0x000) /* ctl and status */
#define	BSM_WR_MEM_SRC_REG 	(BSM_BASE + 0x004) /* source in BSM mem */
#define	BSM_WR_MEM_DST_REG 	(BSM_BASE + 0x008) /* dest in SRAM mem */
#define	BSM_WR_DWCOUNT_REG 	(BSM_BASE + 0x00C) /* bytes */
#define	BSM_WR_STATUS_REG	(BSM_BASE + 0x010) /* bit 0:  1 == done */

/*
 * BSM special memory, stays powered during power-save sleeps
 */
#define	BSM_SRAM_LOWER_BOUND	(CSR_BASE + 0x3800)
#define	BSM_SRAM_SIZE		(1024)


/*
 * card static random access memory (SRAM) for processor data and instructs
 */
#define	RTC_INST_LOWER_BOUND		(0x00000)
#define	ALM_RTC_INST_UPPER_BOUND 	(0x14000)

#define	RTC_DATA_LOWER_BOUND		(0x800000)
#define	ALM_RTC_DATA_UPPER_BOUND	(0x808000)

/*
 * HBUS (Host-side bus)
 */
#define	HBUS_TARG_MEM_RADDR 	(HBUS_BASE+0x00c)
#define	HBUS_TARG_MEM_WADDR 	(HBUS_BASE+0x010)
#define	HBUS_TARG_MEM_WDAT	(HBUS_BASE+0x018)
#define	HBUS_TARG_MEM_RDAT	(HBUS_BASE+0x01c)
#define	HBUS_TARG_PRPH_WADDR	(HBUS_BASE+0x044)
#define	HBUS_TARG_PRPH_RADDR	(HBUS_BASE+0x048)
#define	HBUS_TARG_PRPH_WDAT 	(HBUS_BASE+0x04c)
#define	HBUS_TARG_PRPH_RDAT 	(HBUS_BASE+0x050)
#define	HBUS_TARG_WRPTR		(HBUS_BASE+0x060)

/*
 * HW I/F configuration
 */
#define	CSR_HW_IF_CONFIG_REG_BIT_ALMAGOR_MB	(0x00000100)
#define	CSR_HW_IF_CONFIG_REG_BIT_ALMAGOR_MM	(0x00000200)
#define	CSR_HW_IF_CONFIG_REG_BIT_SKU_MRC	(0x00000400)
#define	CSR_HW_IF_CONFIG_REG_BIT_BOARD_TYPE	(0x00000800)
#define	CSR_HW_IF_CONFIG_REG_BITS_SILICON_TYPE_A	(0x00000000)
#define	CSR_HW_IF_CONFIG_REG_BITS_SILICON_TYPE_B	(0x00001000)
#define	CSR_HW_IF_CONFIG_REG_BITS_NIC_READY		(0x00400000)
#define	CSR_HW_IF_CONFIG_REG_BITS_HAP_WAKE_L1A		(0x00080000)
#define	CSR_HW_IF_CONFIG_REG_BITS_NIC_PREPARE_DONE	(0x02000000)
#define	CSR_HW_IF_CONFIG_REG_BITS_PREPARE		(0x08000000)

#define	CSR_UCODE_DRV_GP1_BIT_MAC_SLEEP    	(0x00000001)
#define	CSR_UCODE_SW_BIT_RFKILL			(0x00000002)
#define	CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED   	(0x00000004)
#define	CSR_UCODE_DRV_GP1_REG_BIT_CT_KILL_EXIT	(0x00000008)

#define	CSR_GPIO_IN_BIT_AUX_POWER	(0x00000200)
#define	CSR_GPIO_IN_VAL_VAUX_PWR_SRC	(0x00000000)
#define	CSR_GIO_CHICKEN_BITS_REG_BIT_L1A_NO_L0S_RX  (0x00800000)
#define	CSR_GIO_CHICKEN_BITS_REG_BIT_DIS_L0S_EXIT_TIMER  (0x20000000)
#define	CSR_GPIO_IN_VAL_VMAIN_PWR_SRC	CSR_GPIO_IN_BIT_AUX_POWER

#define	PCI_CFG_PMC_PME_FROM_D3COLD_SUPPORT	(0x80000000)

/*
 * interrupt flags in INTA, set by uCode or hardware (e.g. dma),
 * acknowledged (reset) by host writing "1" to flagged bits.
 */
#define	BIT_INT_FH_RX \
	(((uint32_t)1) << 31) /* Rx DMA, cmd responses, FH_INT[17:16] */
#define	BIT_INT_ERR	(1<<29) /* DMA hardware error FH_INT[31] */
#define	BIT_INT_FH_TX	(1<<27) /* Tx DMA FH_INT[1:0] */
#define	BIT_INT_MAC_CLK_ACTV (1<<26) /* NIC controller's clock toggled on/off */
#define	BIT_INT_SWERROR	(1<<25) /* uCode error */
#define	BIT_INT_RF_KILL	(1<<7)  /* HW RFKILL switch GP_CNTRL[27] toggled */
#define	BIT_INT_CT_KILL	(1<<6)  /* Critical temp (chip too hot) rfkill */
#define	BIT_INT_SW_RX 	(1<<3)  /* Rx, command responses, 3945 */
#define	BIT_INT_WAKEUP 	(1<<1)  /* NIC controller waking up (pwr mgmt) */
#define	BIT_INT_ALIVE 	(1<<0)  /* uCode interrupts once it initializes */

#define	CSR_INI_SET_MASK	(BIT_INT_FH_RX   |  \
				BIT_INT_ERR |      \
				BIT_INT_FH_TX   |  \
				BIT_INT_SWERROR |  \
				BIT_INT_RF_KILL |  \
				BIT_INT_SW_RX   |  \
				BIT_INT_WAKEUP  |  \
				BIT_INT_ALIVE)

/*
 * interrupt flags in FH (flow handler) (PCI busmaster DMA)
 */
#define	BIT_FH_INT_ERR		(((uint32_t)1) << 31) /* Error */
#define	BIT_FH_INT_HI_PRIOR	(1<<30) /* High priority Rx,bypass coalescing */
#define	BIT_FH_INT_RX_CHNL2	(1<<18) /* Rx channel 2 (3945 only) */
#define	BIT_FH_INT_RX_CHNL1	(1<<17) /* Rx channel 1 */
#define	BIT_FH_INT_RX_CHNL0	(1<<16) /* Rx channel 0 */
#define	BIT_FH_INT_TX_CHNL6	(1<<6)  /* Tx channel 6 (3945 only) */
#define	BIT_FH_INT_TX_CHNL1	(1<<1)  /* Tx channel 1 */
#define	BIT_FH_INT_TX_CHNL0	(1<<0)  /* Tx channel 0 */

#define	FH_INT_RX_MASK		(BIT_FH_INT_HI_PRIOR |  \
				BIT_FH_INT_RX_CHNL1 |  \
				BIT_FH_INT_RX_CHNL0)

#define	FH_INT_TX_MASK		(BIT_FH_INT_TX_CHNL6 |  \
				BIT_FH_INT_TX_CHNL1 |  \
				BIT_FH_INT_TX_CHNL0)

/*
 * RESET
 */
#define	CSR_RESET_REG_FLAG_NEVO_RESET		(0x00000001)
#define	CSR_RESET_REG_FLAG_FORCE_NMI		(0x00000002)
#define	CSR_RESET_REG_FLAG_SW_RESET		(0x00000080)
#define	CSR_RESET_REG_FLAG_MASTER_DISABLED	(0x00000100)
#define	CSR_RESET_REG_FLAG_STOP_MASTER  	(0x00000200)

/*
 * GP (general purpose) CONTROL
 */
#define	CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY	(0x00000001)
#define	CSR_GP_CNTRL_REG_FLAG_INIT_DONE   	(0x00000004)
#define	CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ 	(0x00000008)
#define	CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP 	(0x00000010)

#define	CSR_GP_CNTRL_REG_VAL_MAC_ACCESS_EN	(0x00000001)

#define	CSR_GP_CNTRL_REG_MSK_POWER_SAVE_TYPE	(0x07000000)
#define	CSR_GP_CNTRL_REG_FLAG_MAC_POWER_SAVE	(0x04000000)
#define	CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW 	(0x08000000)

/*
 * APMG (power management) constants
 */
#define	APMG_CLK_CTRL_REG  	(0x003000)
#define	ALM_APMG_CLK_EN  	(0x003004)
#define	ALM_APMG_CLK_DIS   	(0x003008)
#define	ALM_APMG_PS_CTL    	(0x00300c)
#define	ALM_APMG_PCIDEV_STT	(0x003010)
#define	ALM_APMG_RFKILL    	(0x003014)
#define	ALM_APMG_LARC_INT 	(0x00301c)
#define	ALM_APMG_LARC_INT_MSK	(0x003020)

#define	APMG_CLK_REG_VAL_DMA_CLK_RQT	(0x00000200)
#define	APMG_CLK_REG_VAL_BSM_CLK_RQT	(0x00000800)

#define	APMG_PS_CTRL_REG_VAL_ALM_R_RESET_REQ	(0x04000000)

#define	APMG_DEV_STATE_REG_VAL_L1_ACTIVE_DISABLE	(0x00000800)

#define	APMG_PS_CTRL_REG_MSK_POWER_SRC		(0x03000000)
#define	APMG_PS_CTRL_REG_VAL_POWER_SRC_VMAIN	(0x00000000)
#define	APMG_PS_CTRL_REG_VAL_POWER_SRC_VAUX	(0x01000000)

/*
 * BSM (bootstrap state machine)
 */
/*
 * start boot load now
 */
#define	BSM_WR_CTRL_REG_BIT_START	(0x80000000)
/*
 * enable boot after power up
 */
#define	BSM_WR_CTRL_REG_BIT_START_EN	(0x40000000)

/*
 * DBM
 */
#define	ALM_FH_SRVC_CHNL				(6)
#define	IWH_FH_SRVC_LOWER_BOUND		(IWH_FH_REGS_LOWER_BOUND + 0x9C8)
#define	IWH_FH_SRVC_CHNL		(9)


#define	IWH_FH_SRVC_CHNL_SRAM_ADDR_REG(_chnl)\
	(IWH_FH_SRVC_LOWER_BOUND + (_chnl - 9) * 0x4)

#define	ALM_FH_RCSR_RX_CONFIG_REG_POS_RBDC_SIZE		(20)
#define	ALM_FH_RCSR_RX_CONFIG_REG_POS_IRQ_RBTH		(4)

#define	ALM_FH_RCSR_RX_CONFIG_REG_BIT_WR_STTS_EN		(0x08000000)
#define	ALM_FH_RCSR_RX_CONFIG_REG_VAL_DMA_CHNL_EN_ENABLE	(0x80000000)
#define	ALM_FH_RCSR_RX_CONFIG_REG_VAL_RDRBD_EN_ENABLE		(0x20000000)
#define	ALM_FH_RCSR_RX_CONFIG_REG_VAL_MAX_FRAG_SIZE_128		(0x01000000)
#define	ALM_FH_RCSR_RX_CONFIG_REG_VAL_IRQ_DEST_INT_HOST		(0x00001000)
#define	ALM_FH_RCSR_RX_CONFIG_REG_VAL_MSG_MODE_FH		(0x00000000)
#define	ALM_FH_TCSR_TX_CONFIG_REG_VAL_MSG_MODE_TXF		(0x00000000)
#define	ALM_FH_TCSR_TX_CONFIG_REG_VAL_MSG_MODE_DRIVER		(0x00000001)
#define	ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_DISABLE_VAL	(0x00000000)
#define	ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE_VAL	(0x00000008)
#define	ALM_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_IFTFD		(0x00200000)
#define	ALM_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_RTC_NOINT		(0x00000000)
#define	ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_PAUSE		(0x00000000)
#define	ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE		(0x80000000)
#define	ALM_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_VALID		(0x00004000)
#define	ALM_FH_TCSR_CHNL_TX_BUF_STS_REG_BIT_TFDB_WPTR		(0x00000001)
#define	ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_SNOOP_RD_TXPD_ON	(0xFF000000)
#define	ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RD_TXPD_ON	(0x00FF0000)
#define	ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_MAX_FRAG_SIZE_128B	(0x00000400)
#define	ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_SNOOP_RD_TFD_ON	(0x00000100)
#define	ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RD_CBB_ON	(0x00000080)
#define	ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RSP_WAIT_TH	(0x00000020)
#define	ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_RSP_WAIT_TH		(0x00000005)

#define	ALM_TB_MAX_BYTES_COUNT	(0xFFF0)

#define	ALM_FH_TSSR_TX_STATUS_REG_BIT_BUFS_EMPTY(_channel) \
	((1LU << _channel) << 24)
#define	ALM_FH_TSSR_TX_STATUS_REG_BIT_NO_PEND_REQ(_channel) \
	((1LU << _channel) << 16)

#define	ALM_FH_TSSR_TX_STATUS_REG_MSK_CHNL_IDLE(_channel) \
	(ALM_FH_TSSR_TX_STATUS_REG_BIT_BUFS_EMPTY(_channel) | \
	ALM_FH_TSSR_TX_STATUS_REG_BIT_NO_PEND_REQ(_channel))
#define	PCI_CFG_REV_ID_BIT_BASIC_SKU	(0x40)	/* bit 6 */
#define	PCI_CFG_REV_ID_BIT_RTP		(0x80)	/* bit 7 */
#define	PCI_CFG_RETRY_TIMEOUT		(0x41)

#define	HBUS_TARG_MBX_C_REG_BIT_CMD_BLOCKED	(0x00000004)

#define	TFD_QUEUE_MIN		0
#define	TFD_QUEUE_MAX		6
#define	TFD_QUEUE_SIZE_MAX	(256)

/*
 * spectrum and channel data structures
 */
#define	IWH_NUM_SCAN_RATES	(2)

#define	IWH_SCAN_FLAG_24GHZ  (1<<0)
#define	IWH_SCAN_FLAG_52GHZ  (1<<1)
#define	IWH_SCAN_FLAG_ACTIVE (1<<2)
#define	IWH_SCAN_FLAG_DIRECT (1<<3)

#define	IWH_MAX_CMD_SIZE 1024

#define	IWH_DEFAULT_TX_RETRY	15
#define	IWH_MAX_TX_RETRY	16

#define	RFD_SIZE	4
#define	NUM_TFD_CHUNKS	4

#define	RX_QUEUE_SIZE		256
#define	RX_QUEUE_SIZE_LOG	8

/*
 * TX Queue Flag Definitions
 */
/*
 * use short preamble
 */
#define	DCT_FLAG_LONG_PREAMBLE	0x00
#define	DCT_FLAG_SHORT_PREAMBLE	0x04

/*
 * ACK rx is expected to follow
 */
#define	DCT_FLAG_ACK_REQD		0x80

#define	IWH_MB_DISASSOCIATE_THRESHOLD_DEFAULT	24
#define	IWH_MB_ROAMING_THRESHOLD_DEFAULT		8
#define	IWH_REAL_RATE_RX_PACKET_THRESHOLD		300

/*
 * QoS  definitions
 */

#define	AC_NUM		(4)	/* the number of access category */

/*
 * index of every AC in firmware
 */
#define	QOS_AC_BK	(0)
#define	QOS_AC_BE	(1)
#define	QOS_AC_VI	(2)
#define	QOS_AC_VO	(3)
#define	QOS_AC_INVALID	(-1)

#define	QOS_CW_RANGE_MIN	(0)	/* exponential of 2 */
#define	QOS_CW_RANGE_MAX	(15)	/* exponential of 2 */
#define	QOS_TXOP_MIN		(0)	/* unit of 32 microsecond */
#define	QOS_TXOP_MAX		(255)	/* unit of 32 microsecond */
#define	QOS_AIFSN_MIN		(2)
#define	QOS_AIFSN_MAX		(15)	/* undefined */

/*
 * masks for flags of QoS parameter command
 */
#define	QOS_PARAM_FLG_UPDATE_EDCA	(0x01)
#define	QOS_PARAM_FLG_TGN		(0x02)

/*
 * index of TX queue for every AC
 */
#define	QOS_AC_BK_TO_TXQ	(3)
#define	QOS_AC_BE_TO_TXQ	(2)
#define	QOS_AC_VI_TO_TXQ	(1)
#define	QOS_AC_VO_TO_TXQ	(0)
#define	TXQ_FOR_AC_MIN		(0)
#define	TXQ_FOR_AC_MAX		(3)
#define	TXQ_FOR_AC_INVALID	(-1)
#define	NON_QOS_TXQ		QOS_AC_BE_TO_TXQ
#define	QOS_TXQ_FOR_MGT		QOS_AC_VO_TO_TXQ

#define	WME_TID_MIN	(0)
#define	WME_TID_MAX	(7)
#define	WME_TID_INVALID	(-1)

/*
 * HT definitions
 */

/*
 * HT capabilities masks
 */
#define	HT_CAP_SUP_WIDTH	(0x0002)
#define	HT_CAP_MIMO_PS		(0x000c)
#define	HT_CAP_GRN_FLD		(0x0010)
#define	HT_CAP_SGI_20		(0x0020)
#define	HT_CAP_SGI_40		(0x0040)
#define	HT_CAP_DELAY_BA		(0x0400)
#define	HT_CAP_MAX_AMSDU	(0x0800)
#define	HT_CAP_MCS_TX_DEFINED	(0x01)
#define	HT_CAP_MCS_TX_RX_DIFF	(0x02)
#define	HT_CAP_MCS_TX_STREAMS	(0x0c)
#define	HT_CAP_MCS_TX_UEQM	(0x10)

#define	HT_CAP_MIMO_PS_STATIC	(0)
#define	HT_CAP_MIMO_PS_DYNAMIC	(1)
#define	HT_CAP_MIMO_PS_INVALID	(2)
#define	HT_CAP_MIMO_PS_NONE	(3)

#define	HT_RX_AMPDU_FACTOR_8K	(0x0)
#define	HT_RX_AMPDU_FACTOR_16K	(0x1)
#define	HT_RX_AMPDU_FACTOR_32K	(0x2)
#define	HT_RX_AMPDU_FACTOR_64K	(0x3)
#define	HT_RX_AMPDU_FACTOR	HT_RX_AMPDU_FACTOR_8K
#define	HT_RX_AMPDU_FACTOR_MSK	(0x3)

#define	HT_MPDU_DENSITY_4USEC	(0x5)
#define	HT_MPDU_DENSITY_8USEC	(0x6)
#define	HT_MPDU_DENSITY		HT_MPDU_DENSITY_4USEC
#define	HT_MPDU_DENSITY_MSK	(0x1c)
#define	HT_MPDU_DENSITY_POS	(2)

#define	HT_RATESET_NUM		(16)
#define	HT_1CHAIN_RATE_MIN_IDX	(0x0)
#define	HT_1CHAIN_RATE_MAX_IDX	(0x7)
#define	HT_2CHAIN_RATE_MIN_IDX	(0x8)
#define	HT_2CHAIN_RATE_MAX_IDX	(0xf)

struct iwh_ampdu_param {
	uint8_t	factor;
	uint8_t	density;
};

typedef	struct iwh_ht_conf {
	uint8_t			ht_support;
	uint16_t		cap;
	struct iwh_ampdu_param	ampdu_p;
	uint8_t			tx_support_mcs[HT_RATESET_NUM];
	uint8_t			rx_support_mcs[HT_RATESET_NUM];
	uint8_t			valid_chains;
	uint8_t			tx_stream_count;
	uint8_t			rx_stream_count;
	uint8_t			ht_protection;
} iwh_ht_conf_t;

#define	NO_HT_PROT		(0)
#define	HT_PROT_CHAN_NON_HT	(1)
#define	HT_PROT_FAT		(2)
#define	HT_PROT_ASSOC_NON_HT	(3)

/*
 * HT flags for RXON command.
 */
#define	RXON_FLG_CONTROL_CHANNEL_LOCATION_MSK	0x400000
#define	RXON_FLG_CONTROL_CHANNEL_LOC_LOW_MSK	0x000000
#define	RXON_FLG_CONTROL_CHANNEL_LOC_HIGH_MSK	0x400000

#define	RXON_FLG_HT_OPERATING_MODE_POS		(23)
#define	RXON_FLG_HT_PROT_MSK			0x800000
#define	RXON_FLG_FAT_PROT_MSK			0x1000000

#define	RXON_FLG_CHANNEL_MODE_POS		(25)
#define	RXON_FLG_CHANNEL_MODE_MSK		0x06000000
#define	RXON_FLG_CHANNEL_MODE_LEGACY_MSK	0x00000000
#define	RXON_FLG_CHANNEL_MODE_PURE_40_MSK	0x02000000
#define	RXON_FLG_CHANNEL_MODE_MIXED_MSK		0x04000000

#define	RXON_RX_CHAIN_DRIVER_FORCE_MSK		(0x1<<0)
#define	RXON_RX_CHAIN_VALID_MSK			(0x7<<1)
#define	RXON_RX_CHAIN_VALID_POS			(1)
#define	RXON_RX_CHAIN_FORCE_SEL_MSK		(0x7<<4)
#define	RXON_RX_CHAIN_FORCE_SEL_POS		(4)
#define	RXON_RX_CHAIN_FORCE_MIMO_SEL_MSK	(0x7<<7)
#define	RXON_RX_CHAIN_FORCE_MIMO_SEL_POS	(7)
#define	RXON_RX_CHAIN_CNT_MSK			(0x3<<10)
#define	RXON_RX_CHAIN_CNT_POS			(10)
#define	RXON_RX_CHAIN_MIMO_CNT_MSK		(0x3<<12)
#define	RXON_RX_CHAIN_MIMO_CNT_POS		(12)
#define	RXON_RX_CHAIN_MIMO_FORCE_MSK		(0x1<<14)
#define	RXON_RX_CHAIN_MIMO_FORCE_POS		(14)
#define	RXON_RX_CHAIN_A_MSK			(1)
#define	RXON_RX_CHAIN_B_MSK			(2)
#define	RXON_RX_CHAIN_C_MSK			(4)

/*
 * Generic queue structure
 *
 * Contains common data for Rx and Tx queues
 */
#define	TFD_CTL_COUNT_SET(n)	(n<<24)
#define	TFD_CTL_COUNT_GET(ctl)	((ctl>>24) & 7)
#define	TFD_CTL_PAD_SET(n)	(n<<28)
#define	TFD_CTL_PAD_GET(ctl)	(ctl>>28)

#define	TFD_TX_CMD_SLOTS 64
#define	TFD_CMD_SLOTS 32

/*
 * Tx/Rx Queues
 *
 * Most communication between driver and SP is via queues of data buffers.
 * For example, all commands that the driver issues to device's embedded
 * controller (uCode) are via the command queue (one of the Tx queues).  All
 * uCode command responses/replies/notifications, including Rx frames, are
 * conveyed from uCode to driver via the Rx queue.
 *
 * Most support for these queues, including handshake support, resides in
 * structures in host DRAM, shared between the driver and the device.  When
 * allocating this memory, the driver must make sure that data written by
 * the host CPU updates DRAM immediately (and does not get "stuck" in CPU's
 * cache memory), so DRAM and cache are consistent, and the device can
 * immediately see changes made by the driver.
 *
 * SP supports up to 16 DRAM-based Tx queues, and services these queues via
 * up to 7 DMA channels (FIFOs).  Each Tx queue is supported by a circular array
 * in DRAM containing 256 Transmit Frame Descriptors (TFDs).
 */
#define	IWH_MAX_WIN_SIZE	64
#define	IWH_QUEUE_SIZE	256
#define	IWH_NUM_FIFOS	7
#define	IWH_NUM_QUEUES	20
#define	IWH_CMD_QUEUE_NUM	4
#define	IWH_KW_SIZE 0x1000	/* 4k */
#define	IWH_CMD_FIFO_NUM	7

struct iwh_rate {
	union {
		struct {
			uint8_t rate;
			uint8_t flags;
			uint16_t ext_flags;
		} s;
		uint32_t rate_n_flags;
	} r;
};

struct iwh_dram_scratch {
	uint8_t try_cnt;
	uint8_t bt_kill_cnt;
	uint16_t reserved;
};


struct iwh_tx_power {
	uint8_t tx_gain;	/* gain for analog radio */
	uint8_t dsp_atten;	/* gain for DSP */
};


union iwh_tx_power_triple_stream {
	struct {
		uint8_t radio_tx_gain[3];
		uint8_t reserved1;
		uint8_t dsp_predis_atten[3];
		uint8_t reserved2;
	}s;
	uint32_t val1;
	uint32_t val2;
};

struct iwh_tx_power_db {
	union	iwh_tx_power_triple_stream ht_ofdm_power[24];
	union	iwh_tx_power_triple_stream cck_power[2];
};

typedef struct iwh_tx_power_table_cmd {
	uint8_t band;
	uint8_t pa_measurements;
	uint8_t channel;
	uint8_t max_mcs;
	struct iwh_tx_power_db	db;
} iwh_tx_power_table_cmd_t;

/*
 * Hardware rate scaling set by iwh_ap_lq function.
 * Given a particular initial rate and mode, the driver uses the
 * following formula to fill the rs_table[LINK_QUAL_MAX_RETRY_NUM]
 * rate table in the Link Quality command:
 *
 * 1) If using High-throughput(HT)(SISO or MIMO) initial rate:
 *    a) Use this same initial rate for first 3 entries.
 *    b) Find next lower available rate using same mode(SISO or MIMO),
 *	 use for next 3 entries. If no lower rate available, switch to
 *	 legacy mode(no FAT channel, no MIMO, no short guard interval).
 *    c) If using MIMO, set command's mimo_delimeter to number of
 *	 entries using MIMO(3 or 6).
 *    d) After trying 2 HT rates, switch to legacy mode(no FAT channel,
 *	 no MIMO, no short qguard interval), at the next lower bit rate
 *	 (e.g. if second HT bit rate was 54, try 48 legacy),and follow
 *   legacy procedure for remaining table entries.
 *
 * 2) If using legacy initial rate:
 *    a) Use the initial rate for only one entry.
 *    b) For each following entry, reduce the rate to next lower available
 *	 rate, until reaching the lowest available rate.
 *    c) When reducing rate, also switch antenna selection.
 *    b) Once lowest available rate is reached, repreat this rate until
 *   rate table is filled(16 entries),switching antenna each entry.
 */

/*
 * OFDM HT rate masks
 */
#define	R_MCS_6M_MSK 0x1
#define	R_MCS_12M_MSK 0x2
#define	R_MCS_18M_MSK 0x4
#define	R_MCS_24M_MSK 0x8
#define	R_MCS_36M_MSK 0x10
#define	R_MCS_48M_MSK 0x20
#define	R_MCS_54M_MSK 0x40
#define	R_MCS_60M_MSK 0x80
#define	R_MCS_12M_DUAL_MSK 0x100
#define	R_MCS_24M_DUAL_MSK 0x200
#define	R_MCS_36M_DUAL_MSK 0x400
#define	R_MCS_48M_DUAL_MSK 0x800

#define	RATE_MCS_CODE_MSK 0x7
#define	RATE_MCS_MIMO_POS 3
#define	RATE_MCS_MIMO_MSK 0x8
#define	RATE_MCS_HT_DUP_POS 5
#define	RATE_MCS_HT_DUP_MSK 0x20
#define	RATE_MCS_FLAGS_POS 8
#define	RATE_MCS_HT_POS 8
#define	RATE_MCS_HT_MSK 0x100
#define	RATE_MCS_CCK_POS 9
#define	RATE_MCS_CCK_MSK 0x200
#define	RATE_MCS_GF_POS 10
#define	RATE_MCS_GF_MSK 0x400

#define	RATE_MCS_FAT_POS 11
#define	RATE_MCS_FAT_MSK 0x800
#define	RATE_MCS_DUP_POS 12
#define	RATE_MCS_DUP_MSK 0x1000
#define	RATE_MCS_SGI_POS 13
#define	RATE_MCS_SGI_MSK 0x2000

#define	EEPROM_SEM_TIMEOUT 10
#define	EEPROM_SEM_RETRY_LIMIT 1000

/*
 * Antenna masks:
 * bit14:15 01 B inactive, A active
 *          10 B active, A inactive
 *          11 Both active
 */
#define	RATE_MCS_ANT_A_POS	14
#define	RATE_MCS_ANT_B_POS	15
#define	RATE_MCS_ANT_A_MSK	0x4000
#define	RATE_MCS_ANT_B_MSK	0x8000
#define	RATE_MCS_ANT_AB_MSK	0xc000

#define	is_legacy(tbl) (((tbl) == LQ_G) || ((tbl) == LQ_A))
#define	is_siso(tbl) (((tbl) == LQ_SISO))
#define	is_mimo(tbl) (((tbl) == LQ_MIMO))
#define	is_Ht(tbl) (is_siso(tbl) || is_mimo(tbl))
#define	is_a_band(tbl) (((tbl) == LQ_A))
#define	is_g_and(tbl) (((tbl) == LQ_G))

/*
 * RS_NEW_API: only TLC_RTS remains and moved to bit 0
 */
#define	LINK_QUAL_FLAGS_SET_STA_TLC_RTS_MSK	(1<<0)

#define	LINK_QUAL_AC_NUM 4
#define	LINK_QUAL_MAX_RETRY_NUM 16

#define	LINK_QUAL_ANT_A_MSK (1<<0)
#define	LINK_QUAL_ANT_B_MSK (1<<1)
#define	LINK_QUAL_ANT_MSK   (LINK_QUAL_ANT_A_MSK|LINK_QUAL_ANT_B_MSK)

struct iwh_link_qual_general_params {
	uint8_t flags;
	uint8_t mimo_delimiter;
	uint8_t single_stream_ant_msk;
	uint8_t dual_stream_ant_msk;
	uint8_t start_rate_index[LINK_QUAL_AC_NUM];
};

struct iwh_link_qual_agg_params {
	uint16_t agg_time_limit;
	uint8_t agg_dis_start_th;
	uint8_t agg_frame_cnt_limit;
	uint32_t reserved;
};

typedef struct iwh_link_quality_cmd {
	uint8_t sta_id;
	uint8_t reserved1;
	uint16_t control;
	struct iwh_link_qual_general_params general_params;
	struct iwh_link_qual_agg_params agg_params;
	uint32_t rate_n_flags[LINK_QUAL_MAX_RETRY_NUM];
	uint32_t reserved2;
} iwh_link_quality_cmd_t;

struct	iwh_rx_mpdu_body_size {
	uint16_t	byte_count;
	uint16_t	reserved;
};

typedef struct iwh_rx_phy_res {
	uint8_t non_cfg_phy_cnt;  /* non configurable DSP phy data byte count */
	uint8_t cfg_phy_cnt;	/* configurable DSP phy data byte count */
	uint8_t stat_id;	/* configurable DSP phy data set ID */
	uint8_t reserved1;
	uint32_t timestampl; /* TSF at on air rise */
	uint32_t timestamph;
	uint32_t beacon_time_stamp; /* beacon at on-air rise */
	uint16_t phy_flags;	/* general phy flags: band, modulation, ... */
	uint16_t channel;		/* channel number */
	/* for various implementations of non_cfg_phy */
	uint8_t	 non_cfg_phy[32];
	struct iwh_rate rate;	/* rate in ucode internal format */
	uint16_t byte_count;		/* frame's byte-count */
	uint16_t reserved3;
} iwh_rx_phy_res_t;

struct iwh_rx_mpdu_res_start {
	uint16_t byte_count;
	uint16_t reserved;
};

#define	IWH_AGC_DB_MASK 	(0x3f80)	/* MASK(7,13) */
#define	IWH_AGC_DB_POS	(7)

#define	IWH_RX_RES_PHY_CNT	(8)
#define	IWH_RX_RES_AGC_IDX	(1)
#define	IWH_RX_RES_RSSI_AB_IDX	(2)
#define	IWH_RX_RES_RSSI_C_IDX	(3)
#define	IWH_OFDM_AGC_MSK	(0xFE00)
#define	IWH_OFDM_AGC_BIT_POS	(9)
#define	IWH_OFDM_RSSI_A_MSK	(0x00FF)
#define	IWH_OFDM_RSSI_A_BIT_POS	(0)
#define	IWH_OFDM_RSSI_B_MSK	(0xFF0000)
#define	IWH_OFDM_RSSI_B_BIT_POS	(16)
#define	IWH_OFDM_RSSI_C_MSK	(0x00FF)
#define	IWH_OFDM_RSSI_C_BIT_POS	(0)
#define	IWH_RSSI_OFFSET		(44)

/*
 * Fixed (non-configurable) rx data from phy
 */
struct iwh_rx_non_cfg_phy {
	uint32_t non_cfg_phy[IWH_RX_RES_PHY_CNT];	/* upto 8 phy entries */
};

/*
 * Byte Count Table Entry
 *
 * Bit fields:
 * 15-12: reserved
 * 11- 0: total to-be-transmitted byte count of frame (does not include command)
 */
struct iwh_queue_byte_cnt_entry {
	uint16_t val;
};

/*
 * Byte Count table
 *
 * Each Tx queue uses a byte-count table containing 320 entries:
 * one 16-bit entry for each of 256 TFDs, plus an additional 64 entries that
 * duplicate the first 64 entries (to avoid wrap-around within a Tx window;
 * max Tx window is 64 TFDs).
 *
 * When driver sets up a new TFD, it must also enter the total byte count
 * of the frame to be transmitted into the corresponding entry in the byte
 * count table for the chosen Tx queue.  If the TFD index is 0-63, the driver
 * must duplicate the byte count entry in corresponding index 256-319.
 *
 * "dont_care" padding puts each byte count table on a 1024-byte boundary;
 * SP assumes tables are separated by 1024 bytes.
 */
struct iwh_sched_queue_byte_cnt_tbl {
	struct iwh_queue_byte_cnt_entry tfd_offset[IWH_QUEUE_SIZE +
	    IWH_MAX_WIN_SIZE];
};

/*
 * struct iwh_shared, handshake area for Tx and Rx
 *
 * For convenience in allocating memory, this structure combines 2 areas of
 * DRAM which must be shared between driver and SP.  These do not need to
 * be combined, if better allocation would result from keeping them separate:
 * TODO:  Split these; carried over from 3945, doesn't work well for SP.
 *
 * 1)  The Tx byte count tables occupy 1024 bytes each (16 KBytes total for
 *     16 queues).  Driver uses SCD_DRAM_BASE_ADDR to tell SP where to find
 *     the first of these tables.  SP assumes tables are 1024 bytes apart.
 *
 * 2)  The Rx status (val0 and val1) occupies only 8 bytes.  Driver uses
 *     FH_RSCSR_CHNL0_STTS_WPTR_REG to tell SP where to find this area.
 *     Driver reads val0 to determine the latest Receive Buffer Descriptor (RBD)
 *     that has been filled by the SP.
 *
 * Bit fields val0:
 * 31-12:  Not used
 * 11- 0:  Index of last filled Rx buffer descriptor (SP writes, driver reads)
 *
 * Bit fields val1:
 * 31- 0:  Not used
 */
typedef struct iwh_shared {
	struct iwh_sched_queue_byte_cnt_tbl
	    queues_byte_cnt_tbls[IWH_NUM_QUEUES];
	uint32_t val0;
	uint32_t val1;
	uint32_t padding1;  /* so that allocation will be aligned to 16B */
	uint32_t padding2;
} iwh_shared_t;


/*
 * struct iwh_tfd_frame_data
 *
 * Describes up to 2 buffers containing (contiguous) portions of a Tx frame.
 * Each buffer must be on dword boundary.
 * Up to 10 iwh_tfd_frame_data structures, describing up to 20 buffers,
 * may be filled within a TFD (iwh_tfd_frame).
 *
 * Bit fields in tb1_addr:
 * 31- 0: Tx buffer 1 address bits [31:0]
 *
 * Bit fields in val1:
 * 31-16: Tx buffer 2 address bits [15:0]
 * 15- 4: Tx buffer 1 length (bytes)
 *  3- 0: Tx buffer 1 address bits [32:32]
 *
 * Bit fields in val2:
 * 31-20: Tx buffer 2 length (bytes)
 * 19- 0: Tx buffer 2 address bits [35:16]
 */
struct iwh_tfd_frame_data {
		uint32_t tb1_addr;
		uint32_t val1;
		uint32_t val2;
};

typedef struct iwh_tx_desc {
	uint32_t	val0;
	struct iwh_tfd_frame_data pa[10];
	uint32_t reserved;
} iwh_tx_desc_t;

struct	agg_tx_status {
	uint16_t	status;
	uint16_t	sequence;
};

typedef struct iwh_tx_stat {
	uint8_t		frame_count;
	uint8_t		bt_kill_count;
	uint8_t		nrts;
	uint8_t		ntries;
	struct iwh_rate rate;
	uint16_t	duration;
	uint16_t	reserved;
	uint32_t	pa_power1;
	uint32_t	pa_power2;
	uint32_t	tfd_info;
	uint16_t	seq_ctl;
	uint16_t	byte_cnt;
	uint32_t	tlc_info;
	struct	agg_tx_status	status;
} iwh_tx_stat_t;

struct iwh_cmd_header {
	uint8_t		type;
	uint8_t		flags;
	uint8_t		idx;
	uint8_t		qid;
};

typedef struct iwh_rx_desc {
	uint32_t	len;
	struct iwh_cmd_header hdr;
} iwh_rx_desc_t;

typedef struct iwh_rx_stat {
	uint8_t		len;
	uint8_t		id;
	uint8_t		rssi;	/* received signal strength */
	uint8_t		agc;	/* access gain control */
	uint16_t	signal;
	uint16_t	noise;
} iwh_rx_stat_t;

typedef struct iwh_rx_head {
	uint16_t	chan;
	uint16_t	flags;
	uint8_t		reserved;
	uint8_t		rate;
	uint16_t	len;
} iwh_rx_head_t;

typedef struct iwh_rx_tail {
	uint32_t	flags;
	uint32_t	timestampl;
	uint32_t	timestamph;
	uint32_t	tbeacon;
} iwh_rx_tail_t;

enum {
	IWH_AP_ID = 0,
	IWH_MULTICAST_ID,
	IWH_STA_ID,
	IWH_BROADCAST_ID = 15,
	IWH_STATION_COUNT = 16,
	IWH_INVALID_STATION
};

/*
 * key flags
 */
enum {
	STA_KEY_FLG_ENCRYPT_MSK = 0x7,
	STA_KEY_FLG_NO_ENC = 0x0,
	STA_KEY_FLG_WEP = 0x1,
	STA_KEY_FLG_CCMP = 0x2,
	STA_KEY_FLG_TKIP = 0x3,

	STA_KEY_FLG_KEYID_POS = 8,
	STA_KEY_FLG_INVALID = 0x0800,
};

/*
 * modify flags
 */
enum {
	STA_MODIFY_KEY_MASK = 0x01,
	STA_MODIFY_TID_DISABLE_TX = 0x02,
	STA_MODIFY_TX_RATE_MSK = 0x04
};

enum {
	RX_RES_STATUS_NO_CRC32_ERROR = (1 << 0),
	RX_RES_STATUS_NO_RXE_OVERFLOW = (1 << 1),
};

enum {
	RX_RES_PHY_FLAGS_BAND_24_MSK = (1 << 0),
	RX_RES_PHY_FLAGS_MOD_CCK_MSK = (1 << 1),
	RX_RES_PHY_FLAGS_SHORT_PREAMBLE_MSK = (1 << 2),
	RX_RES_PHY_FLAGS_NARROW_BAND_MSK = (1 << 3),
	RX_RES_PHY_FLAGS_ANTENNA_MSK = 0xf0,

	RX_RES_STATUS_SEC_TYPE_MSK = (0x7 << 8),
	RX_RES_STATUS_SEC_TYPE_NONE = (STA_KEY_FLG_NO_ENC << 8),
	RX_RES_STATUS_SEC_TYPE_WEP = (STA_KEY_FLG_WEP << 8),
	RX_RES_STATUS_SEC_TYPE_TKIP = (STA_KEY_FLG_TKIP << 8),
	RX_RES_STATUS_SEC_TYPE_CCMP = (STA_KEY_FLG_CCMP << 8),

	RX_RES_STATUS_DECRYPT_TYPE_MSK = (0x3 << 11),
	RX_RES_STATUS_NOT_DECRYPT = (0x0 << 11),
	RX_RES_STATUS_DECRYPT_OK = (0x3 << 11),
	RX_RES_STATUS_BAD_ICV_MIC = (0x1 << 11),
	RX_RES_STATUS_BAD_KEY_TTAK = (0x2 << 11),
};

enum {
	REPLY_ALIVE = 0x1,
	REPLY_ERROR = 0x2,

	/* RXON state commands */
	REPLY_RXON = 0x10,
	REPLY_RXON_ASSOC = 0x11,
	REPLY_QOS_PARAM = 0x13,
	REPLY_RXON_TIMING = 0x14,

	/* Multi-Station support */
	REPLY_ADD_STA = 0x18,
	REPLY_REMOVE_STA = 0x19,
	REPLY_REMOVE_ALL_STA = 0x1a,

	/* RX, TX */

	REPLY_TX = 0x1c,

	/* timers commands */
	REPLY_BCON = 0x27,

	REPLY_SHUTDOWN = 0x40,

	/* MISC commands */
	REPLY_RATE_SCALE = 0x47,
	REPLY_LEDS_CMD = 0x48,
	REPLY_TX_LINK_QUALITY_CMD = 0x4e,

	COEX_PRIORITY_TABLE_CMD = 0x5a,
	CALIBRATION_CFG_CMD = 0x65,
	CALIBRATION_RES_NOTIFICATION = 0x66,
	CALIBRATION_COMPLETE_NOTIFICATION = 0x67,

	/* 802.11h related */
	RADAR_NOTIFICATION = 0x70,
	REPLY_QUIET_CMD = 0x71,
	REPLY_CHANNEL_SWITCH = 0x72,
	CHANNEL_SWITCH_NOTIFICATION = 0x73,
	REPLY_SPECTRUM_MEASUREMENT_CMD = 0x74,
	SPECTRUM_MEASURE_NOTIFICATION = 0x75,

	/* Power Management *** */
	POWER_TABLE_CMD = 0x77,
	PM_SLEEP_NOTIFICATION = 0x7A,
	PM_DEBUG_STATISTIC_NOTIFIC = 0x7B,

	/* Scan commands and notifications */
	REPLY_SCAN_CMD = 0x80,
	REPLY_SCAN_ABORT_CMD = 0x81,

	SCAN_START_NOTIFICATION = 0x82,
	SCAN_RESULTS_NOTIFICATION = 0x83,
	SCAN_COMPLETE_NOTIFICATION = 0x84,

	/* IBSS/AP commands */
	BEACON_NOTIFICATION = 0x90,
	REPLY_TX_BEACON = 0x91,
	WHO_IS_AWAKE_NOTIFICATION = 0x94,

	QUIET_NOTIFICATION = 0x96,
	REPLY_TX_PWR_TABLE_CMD = 0x97,
	MEASURE_ABORT_NOTIFICATION = 0x99,

	REPLY_CALIBRATION_TUNE = 0x9a,

	/* BT config command */
	REPLY_BT_CONFIG = 0x9b,
	REPLY_STATISTICS_CMD = 0x9c,
	STATISTICS_NOTIFICATION = 0x9d,

	/* RF-KILL commands and notifications *** */
	REPLY_CARD_STATE_CMD = 0xa0,
	CARD_STATE_NOTIFICATION = 0xa1,

	/* Missed beacons notification */
	MISSED_BEACONS_NOTIFICATION = 0xa2,
	MISSED_BEACONS_NOTIFICATION_TH_CMD = 0xa3,

	REPLY_CT_KILL_CONFIG_CMD = 0xa4,
	SENSITIVITY_CMD = 0xa8,
	REPLY_PHY_CALIBRATION_CMD = 0xb0,
	REPLY_RX_PHY_CMD = 0xc0,
	REPLY_RX_MPDU_CMD = 0xc1,
	REPLY_SP_RX = 0xc3,
	REPLY_COMPRESSED_BA = 0xc5,
	REPLY_MAX = 0xff
};

typedef struct iwh_cmd {
	struct iwh_cmd_header hdr;
	uint8_t	data[1024];
} iwh_cmd_t;

/*
 * Alive Command & Response
 */
#define	UCODE_VALID_OK		(0x1)
#define	INITIALIZE_SUBTYPE	(9)

struct iwh_alive_resp {
	uint8_t ucode_minor;
	uint8_t ucode_major;
	uint16_t reserved1;
	uint8_t sw_rev[8];
	uint8_t ver_type;
	uint8_t ver_subtype;
	uint16_t reserved2;
	uint32_t log_event_table_ptr;
	uint32_t error_event_table_ptr;
	uint32_t timestamp;
	uint32_t is_valid;
};

struct iwh_init_alive_resp {
	struct iwh_alive_resp s;
	/* calibration values from "initialize" uCode */
	uint32_t voltage;	/* signed */
	uint32_t therm_r1[2];	/* signed 1st for normal, 2nd for FAT channel */
	uint32_t therm_r2[2];	/* signed */
	uint32_t therm_r3[2];	/* signed */
	uint32_t therm_r4[2];	/* signed */
		/*
		 * signed MIMO gain comp, 5 freq groups, 2 Tx chains
		 */
	uint32_t tx_atten[5][2];
};

/*
 * Rx config defines & structure
 */
/*
 * rx_config device types
 */
enum {
	RXON_DEV_TYPE_AP = 1,
	RXON_DEV_TYPE_ESS = 3,
	RXON_DEV_TYPE_IBSS = 4,
	RXON_DEV_TYPE_SNIFFER = 6,
};

/*
 * rx_config flags
 */
enum {
	/* band & modulation selection */
	RXON_FLG_BAND_24G_MSK = (1 << 0),
	RXON_FLG_CCK_MSK = (1 << 1),
	/* auto detection enable */
	RXON_FLG_AUTO_DETECT_MSK = (1 << 2),
	/* TGg protection when tx */
	RXON_FLG_TGG_PROTECT_MSK = (1 << 3),
	/* cck short slot & preamble */
	RXON_FLG_SHORT_SLOT_MSK = (1 << 4),
	RXON_FLG_SHORT_PREAMBLE_MSK = (1 << 5),
	/* antenna selection */
	RXON_FLG_DIS_DIV_MSK = (1 << 7),
	RXON_FLG_ANT_SEL_MSK = 0x0f00,
	RXON_FLG_ANT_A_MSK = (1 << 8),
	RXON_FLG_ANT_B_MSK = (1 << 9),
	/* radar detection enable */
	RXON_FLG_RADAR_DETECT_MSK = (1 << 12),
	RXON_FLG_TGJ_NARROW_BAND_MSK = (1 << 13),
	/*
	 * rx response to host with 8-byte TSF
	 * (according to ON_AIR deassertion)
	 */
	RXON_FLG_TSF2HOST_MSK = (1 << 15),
	RXON_FLG_DIS_ACQUISITION = (1 << 27),
	RXON_FLG_DIS_RE_ACQUISITION = (1 << 28),
	RXON_FLG_DIS_BEAMFORM = (1 << 29)
};

/*
 * rx_config filter flags
 */
enum {
	/* accept all data frames */
	RXON_FILTER_PROMISC_MSK = (1 << 0),
	/* pass control & management to host */
	RXON_FILTER_CTL2HOST_MSK = (1 << 1),
	/* accept multi-cast */
	RXON_FILTER_ACCEPT_GRP_MSK = (1 << 2),
	/* don't decrypt uni-cast frames */
	RXON_FILTER_DIS_DECRYPT_MSK = (1 << 3),
	/* don't decrypt multi-cast frames */
	RXON_FILTER_DIS_GRP_DECRYPT_MSK = (1 << 4),
	/* STA is associated */
	RXON_FILTER_ASSOC_MSK = (1 << 5),
	/* transfer to host non bssid beacons in associated state */
	RXON_FILTER_BCON_AWARE_MSK = (1 << 6)
};


/*
 * structure for RXON Command & Response
 */
typedef struct iwh_rxon_cmd {
	uint8_t		node_addr[IEEE80211_ADDR_LEN];
	uint16_t	reserved1;
	uint8_t		bssid[IEEE80211_ADDR_LEN];
	uint16_t	reserved2;
	uint8_t		wlap_bssid[IEEE80211_ADDR_LEN];
	uint16_t	reserved3;
	uint8_t		dev_type;
	uint8_t		air_propagation;
	uint16_t	rx_chain;
	uint8_t		ofdm_basic_rates;
	uint8_t		cck_basic_rates;
	uint16_t	assoc_id;
	uint32_t	flags;
	uint32_t	filter_flags;
	uint16_t	chan;
	uint8_t		ofdm_ht_single_stream_basic_rates;
	uint8_t		ofdm_ht_dual_stream_basic_rates;
	uint8_t		ofdm_ht_triple_stream_basic_rates;
	uint8_t		reserved4;
	uint16_t	acquisition_data;
	uint16_t	reserved5;
} iwh_rxon_cmd_t;

typedef struct iwh_compressed_ba_resp {
	uint32_t sta_addr_lo32;
	uint16_t sta_addr_hi16;
	uint16_t reserved;
	uint8_t sta_id;
	uint8_t tid;
	uint16_t ba_seq_ctl;
	uint32_t ba_bitmap0;
	uint32_t ba_bitmap1;
	uint16_t scd_flow;
	uint16_t scd_ssn;
} iwh_compressed_ba_resp_t;

#define	PHY_CALIBRATE_DIFF_GAIN_CMD	(7)
#define	PHY_CALIBRATE_DC_CMD		(8)
#define	PHY_CALIBRATE_LO_CMD		(9)
#define	PHY_CALIBRATE_TX_IQ_CMD		(11)
#define	PHY_CALIBRATE_CRYSTAL_FRQ_CMD	(15)
#define	PHY_CALIBRATE_BASE_BAND_CMD	(16)
#define	PHY_CALIBRATE_TX_IQ_PERD_CMD	(17)
#define	HD_TABLE_SIZE	(11)

/*
 * Param table within SENSITIVITY_CMD
 */
#define	HD_MIN_ENERGY_CCK_DET_INDEX		(0)
#define	HD_MIN_ENERGY_OFDM_DET_INDEX		(1)
#define	HD_AUTO_CORR32_X1_TH_ADD_MIN_INDEX	(2)
#define	HD_AUTO_CORR32_X1_TH_ADD_MIN_MRC_INDEX	(3)
#define	HD_AUTO_CORR40_X4_TH_ADD_MIN_MRC_INDEX	(4)
#define	HD_AUTO_CORR32_X4_TH_ADD_MIN_INDEX	(5)
#define	HD_AUTO_CORR32_X4_TH_ADD_MIN_MRC_INDEX	(6)
#define	HD_BARKER_CORR_TH_ADD_MIN_INDEX		(7)
#define	HD_BARKER_CORR_TH_ADD_MIN_MRC_INDEX	(8)
#define	HD_AUTO_CORR40_X4_TH_ADD_MIN_INDEX	(9)
#define	HD_OFDM_ENERGY_TH_IN_INDEX		(10)

typedef struct iwh_sensitivity_cmd {
	uint16_t control;
	uint16_t table[HD_TABLE_SIZE];
} iwh_sensitivity_cmd_t;

typedef struct iwh_calibration_cmd {
	uint8_t opCode;
	uint8_t flags;
	uint16_t reserved;
	char diff_gain_a;
	char diff_gain_b;
	char diff_gain_c;
	uint8_t reserved1;
} iwh_calibation_cmd_t;


struct	iwh_calib_hdr {
	uint8_t	op_code;
	uint8_t	first_group;
	uint8_t	groups_num;
	uint8_t	data_valid;
};

#define	FH_RSCSR_FRAME_SIZE_MASK	(0x00003FFF)

struct	iwh_calib_results {
	void		*tx_iq_res;
	uint32_t	tx_iq_res_len;
	void		*tx_iq_perd_res;
	uint32_t	tx_iq_perd_res_len;
	void		*lo_res;
	uint32_t	lo_res_len;
	void		*dc_res;
	uint32_t	dc_res_len;
	void		*base_band_res;
	uint32_t	base_band_res_len;
};

#define	IWH_CALIB_INIT_CFG_ALL	(0xFFFFFFFF)

struct	iwh_calib_cfg_elmnt_s {
	uint32_t	is_enable;
	uint32_t	start;
	uint32_t	send_res;
	uint32_t	apply_res;
	uint32_t	resered;
};

struct	iwh_calib_cfg_status_s {
	struct	iwh_calib_cfg_elmnt_s	once;
	struct	iwh_calib_cfg_elmnt_s	perd;
	uint32_t	flags;
};

struct	iwh_calib_cfg_cmd {
	struct	iwh_calib_cfg_status_s	ucd_calib_cfg;
	struct	iwh_calib_cfg_status_s	drv_calib_cfg;
	uint32_t	reserved1;
};

struct	iwh_cal_crystal_freq {
	uint8_t	cap_pin1;
	uint8_t	cap_pin2;
};

typedef	struct	iwh_calibration_crystal_cmd {
	uint8_t	opCode;
	uint8_t	first_group;
	uint8_t	num_group;
	uint8_t	all_data_valid;
	struct	iwh_cal_crystal_freq	data;
} iwh_calibration_crystal_cmd_t;

#define	COEX_NUM_OF_EVENTS	(16)

struct	iwh_wimax_coex_event_entry {
	uint8_t	request_prio;
	uint8_t	win_medium_prio;
	uint8_t	reserved;
	uint8_t	flags;
};

typedef	struct	iwh_wimax_coex_cmd {
	uint8_t	flags;
	uint8_t	reserved[3];
	struct iwh_wimax_coex_event_entry	sta_prio[COEX_NUM_OF_EVENTS];
} iwh_wimax_coex_cmd_t;

typedef struct iwh_missed_beacon_notif {
	uint32_t consequtive_missed_beacons;
	uint32_t total_missed_becons;
	uint32_t num_expected_beacons;
	uint32_t num_recvd_beacons;
} iwh_missed_beacon_notif_t;

typedef struct iwh_ct_kill_config {
	uint32_t   reserved;
	uint32_t   critical_temperature_M;
	uint32_t   critical_temperature_R;
} iwh_ct_kill_config_t;

/*
 * structure for command IWH_CMD_ASSOCIATE
 */
typedef struct iwh_assoc {
	uint32_t	flags;
	uint32_t	filter;
	uint8_t		ofdm_mask;
	uint8_t		cck_mask;
	uint8_t		ofdm_ht_single_stream_basic_rates;
	uint8_t		ofdm_ht_dual_stream_basic_rates;
	uint16_t	rx_chain_select_flags;
	uint16_t	reserved;
} iwh_assoc_t;

/*
 * structure for command IWH_CMD_TSF
 */
typedef struct iwh_cmd_tsf {
	uint32_t	timestampl;
	uint32_t	timestamph;
	uint16_t	bintval;
	uint16_t	atim;
	uint32_t	binitval;
	uint16_t	lintval;
	uint16_t	reserved;
} iwh_cmd_tsf_t;

/*
 * structure for IWH_CMD_ADD_NODE
 */
#define	STA_MODE_ADD_MSK		(0)
#define	STA_MODE_MODIFY_MSK		(1)

#define	STA_FLG_RTS_MIMO_PROT		(1 << 17)
#define	STA_FLG_MAX_AMPDU_POS		(19)
#define	STA_FLG_AMPDU_DENSITY_POS	(23)
#define	STA_FLG_FAT_EN			(1 << 21)

#define	STA_MODIFY_KEY_MASK		(0x01)
#define	STA_MODIFY_TID_DISABLE_TX	(0x02)
#define	STA_MODIFY_TX_RATE_MSK		(0x04)
#define	STA_MODIFY_ADDBA_TID_MSK	(0x08)
#define	STA_MODIFY_DELBA_TID_MSK	(0x10)

struct	sta_id_modify {
	uint8_t		addr[6];
	uint16_t	reserved1;
	uint8_t		sta_id;
	uint8_t		modify_mask;
	uint16_t	reserved2;
};

struct	iwh_keyinfo {
	uint16_t	key_flags;
	uint8_t		tkip_rx_tsc_byte2;
	uint8_t		reserved1;
	uint16_t	tkip_rx_ttak[5];
	uint8_t		key_offset;
	uint8_t		reserved2;
	uint8_t		key[16];
	uint32_t	tx_secur_seq_cnt1;
	uint32_t	tx_secur_seq_cnt2;
	uint32_t	hw_tkip_mic_rx_key1;
	uint32_t	hw_tkip_mic_rx_key2;
	uint32_t	hw_tkip_mic_tx_key1;
	uint32_t	hw_tkip_mic_tx_key2;
};
typedef struct iwh_add_sta {
	uint8_t		mode;
	uint8_t		reserved[3];
	struct sta_id_modify	sta;
	struct iwh_keyinfo	key;
	uint32_t	station_flags;
	uint32_t	station_flags_msk;
	uint16_t	disable_tx;
	uint16_t	reserved1;
	uint8_t		add_immediate_ba_tid;
	uint8_t		remove_immediate_ba_tid;
	uint16_t	add_immediate_ba_ssn;
	uint32_t	reserved2;
} iwh_add_sta_t;

typedef	struct iwh_rem_sta {
	uint8_t	num_sta;	/* number of removed stations */
	uint8_t	reserved1[3];
	uint8_t	addr[6];	/* MAC address of the first station */
	uint8_t	reserved2[2];
} iwh_rem_sta_t;

/*
 * Tx flags
 */
enum {
	TX_CMD_FLG_RTS_MSK = (1 << 1),
	TX_CMD_FLG_CTS_MSK = (1 << 2),
	TX_CMD_FLG_ACK_MSK = (1 << 3),
	TX_CMD_FLG_STA_RATE_MSK = (1 << 4),
	TX_CMD_FLG_IMM_BA_RSP_MASK = (1 << 6),
	TX_CMD_FLG_FULL_TXOP_PROT_MSK = (1 << 7),
	TX_CMD_FLG_ANT_SEL_MSK = 0xf00,
	TX_CMD_FLG_ANT_A_MSK = (1 << 8),
	TX_CMD_FLG_ANT_B_MSK = (1 << 9),

	/* ucode ignores BT priority for this frame */
	TX_CMD_FLG_BT_DIS_MSK = (1 << 12),

	/* ucode overrides sequence control */
	TX_CMD_FLG_SEQ_CTL_MSK = (1 << 13),

	/* signal that this frame is non-last MPDU */
	TX_CMD_FLG_MORE_FRAG_MSK = (1 << 14),

	/* calculate TSF in outgoing frame */
	TX_CMD_FLG_TSF_MSK = (1 << 16),

	/* activate TX calibration. */
	TX_CMD_FLG_CALIB_MSK = (1 << 17),

	/*
	 * signals that 2 bytes pad was inserted
	 * after the MAC header
	 */
	TX_CMD_FLG_MH_PAD_MSK = (1 << 20),

	/* HCCA-AP - disable duration overwriting. */
	TX_CMD_FLG_DUR_MSK = (1 << 25),
};


/*
 * structure for command IWH_CMD_TX_DATA
 */
typedef struct iwh_tx_cmd {
	uint16_t len;
	uint16_t next_frame_len;
	uint32_t tx_flags;
	struct iwh_dram_scratch scratch;
	struct iwh_rate rate;
	uint8_t sta_id;
	uint8_t sec_ctl;
	uint8_t initial_rate_index;
	uint8_t reserved;
	uint8_t key[16];
	uint16_t next_frame_flags;
	uint16_t reserved2;
	union {
		uint32_t life_time;
		uint32_t attempt;
	} stop_time;
	uint32_t dram_lsb_ptr;
	uint8_t dram_msb_ptr;
	uint8_t rts_retry_limit;
	uint8_t data_retry_limit;
	uint8_t tid_tspec;
	union {
		uint16_t pm_frame_timeout;
		uint16_t attempt_duration;
	} timeout;
	uint16_t driver_txop;
} iwh_tx_cmd_t;


/*
 * structure for command "TX beacon"
 */

typedef struct iwh_tx_beacon_cmd {
	iwh_tx_cmd_t	config;
	uint16_t	tim_idx;
	uint8_t		tim_size;
	uint8_t		reserved;
	uint8_t		bcon_frame[2342];
} iwh_tx_beacon_cmd_t;


/*
 * LEDs Command & Response
 * REPLY_LEDS_CMD = 0x48 (command, has simple generic response)
 *
 * For each of 3 possible LEDs (Activity/Link/Tech, selected by "id" field),
 * this command turns it on or off, or sets up a periodic blinking cycle.
 */
typedef struct iwh_led_cmd {
	uint32_t interval;	/* "interval" in uSec */
	uint8_t id;		/* 1: Activity, 2: Link, 3: Tech */
		/*
		 * # intervals off while blinking;
		 * "0", with > 0 "on" value, turns LED on
		 */
	uint8_t off;
		/*
		 * # intervals on while blinking;
		 * "0", regardless of "off", turns LED off
		 */
	uint8_t on;
	uint8_t reserved;
} iwh_led_cmd_t;

/*
 * structure for IWH_CMD_SET_POWER_MODE
 */
typedef struct iwh_powertable_cmd {
	uint16_t	flags;
	uint8_t		keep_alive_seconds;
	uint8_t		debug_flags;
	uint32_t	rx_timeout;
	uint32_t	tx_timeout;
	uint32_t	sleep[5];
	uint32_t	keep_alive_beacons;
} iwh_powertable_cmd_t;

struct iwh_ssid_ie {
	uint8_t id;
	uint8_t len;
	uint8_t ssid[32];
};
/*
 * structure for command IWH_CMD_SCAN
 */
typedef struct iwh_scan_hdr {
	uint16_t len;
	uint8_t	 reserved1;
	uint8_t	 nchan;
		/*
		 * dwell only this long on quiet chnl
		 * (active scan)
		 */
	uint16_t quiet_time;
	uint16_t quiet_plcp_th; /* quiet chnl is < this # pkts (typ. 1) */
	uint16_t good_crc_th; /* passive -> active promotion threshold */
	uint16_t rx_chain;
		/*
		 * max usec to be out of associated (service)
		 * chnl
		 */
	uint32_t max_out_time;
		/*
		 * pause scan this long when returning to svc
		 * chnl.
		 * SP -- 31:22 # beacons, 21:0 additional usec.
		 */
	uint32_t suspend_time;
	uint32_t flags;
	uint32_t filter_flags;
	struct	 iwh_tx_cmd tx_cmd;
	struct	 iwh_ssid_ie direct_scan[20];
	/* followed by probe request body */
	/* followed by nchan x iwh_scan_chan */
} iwh_scan_hdr_t;

typedef struct iwh_scan_chan {
	uint32_t	type;
	uint16_t	chan;
	struct iwh_tx_power	tpc;
	uint16_t	active_dwell;	/* dwell time */
	uint16_t	passive_dwell;	/* dwell time */
} iwh_scan_chan_t;

/*
 * structure for IWH_CMD_BLUETOOTH
 */
typedef struct iwh_bt_cmd {
	uint8_t		flags;
	uint8_t		lead_time;
	uint8_t		max_kill;
	uint8_t		reserved;
	uint32_t	kill_ack_mask;
	uint32_t	kill_cts_mask;
} iwh_bt_cmd_t;

typedef struct iwh_wme_param {
	uint8_t		aifsn;
	uint8_t		cwmin_e;
	uint8_t		cwmax_e;
	uint16_t	txop;
} iwh_wme_param_t;
/*
 * QoS parameter command (REPLY_QOS_PARAM = 0x13)
 * FIFO0-background, FIFO1-best effort, FIFO2-video, FIFO3-voice
 */

struct iwh_edca_param {
	uint16_t	cw_min;
	uint16_t	cw_max;
	uint8_t		aifsn;
	uint8_t		reserved;
	uint16_t	txop;
};

typedef struct iwh_qos_param_cmd {
	uint32_t	flags;
	struct iwh_edca_param	ac[AC_NUM];
} iwh_qos_param_cmd_t;

/*
 * firmware image header
 */
typedef struct iwh_firmware_hdr {
	uint32_t	version;
	uint32_t	textsz;
	uint32_t	datasz;
	uint32_t	init_textsz;
	uint32_t	init_datasz;
	uint32_t	bootsz;
} iwh_firmware_hdr_t;

/*
 * structure for IWH_START_SCAN notification
 */
typedef struct iwh_start_scan {
	uint32_t	timestampl;
	uint32_t	timestamph;
	uint32_t	tbeacon;
	uint8_t		chan;
	uint8_t		band;
	uint16_t	reserved;
	uint32_t	status;
} iwh_start_scan_t;

/*
 * structure for IWK_SCAN_COMPLETE notification
 */
typedef struct iwh_stop_scan {
	uint8_t		nchan;
	uint8_t		status;
	uint8_t		reserved;
	uint8_t		chan;
	uint8_t		tsf;
} iwh_stop_scan_t;


#define	IWH_READ(sc, reg)						\
	ddi_get32((sc)->sc_handle, (uint32_t *)((sc)->sc_base + (reg)))

#define	IWH_WRITE(sc, reg, val)					\
	ddi_put32((sc)->sc_handle, (uint32_t *)((sc)->sc_base + (reg)), (val))

/*
 * Driver can access peripheral registers
 * and ram via HBUS_TARG_PRPH_* registers.
 */

#define	PRPH_BASE	(0x00000)
#define	PRPH_END	(0xFFFFF)

#define	IWH_SCD_BASE	(PRPH_BASE + 0xA02C00)

#define	IWH_SCD_SRAM_BASE_ADDR	(IWH_SCD_BASE + 0x0)
#define	IWH_SCD_DRAM_BASE_ADDR	(IWH_SCD_BASE + 0x8)
#define	IWH_SCD_QUEUECHAIN_SEL	(IWH_SCD_BASE + 0xE8)
#define	IWH_SCD_AGGR_SEL	(IWH_SCD_BASE + 0x248)
#define	IWH_SCD_QUEUE_RDPTR(x)	(IWH_SCD_BASE + 0x68 + (x) * 4)
#define	IWH_SCD_INTERRUPT_MASK	(IWH_SCD_BASE + 0x108)
#define	IWH_SCD_TXFACT		(IWH_SCD_BASE + 0x1C)
#define	IWH_SCD_QUEUE_STATUS_BITS(x)	(IWH_SCD_BASE + 0x10C + (x) * 4)

#define	IWH_SCD_CONTEXT_DATA_OFFSET	(0x600)
#define	IWH_SCD_TX_STTS_BITMAP_OFFSET	(0x7B1)
#define	IWH_SCD_TRANSLATE_TBL_OFFSET	(0x7E0)

#define	IWH_SCD_QUEUE_CTX_REG2_WIN_SIZE_POS	(0)
#define	IWH_SCD_QUEUE_CTX_REG2_WIN_SIZE_MSK	(0x0000007F)
#define	IWH_SCD_QUEUE_CTX_REG2_FRAME_LIMIT_POS	(16)
#define	IWH_SCD_QUEUE_CTX_REG2_FRAME_LIMIT_MSK	(0x007F0000)

#define	IWH_SCD_QUEUECHAIN_SEL_ALL(x)	(((1 << (x)) - 1) &\
				(~(1 << IWH_CMD_QUEUE_NUM)))

#define	IWH_SCD_CONTEXT_QUEUE_OFFSET(x)\
		(IWH_SCD_CONTEXT_DATA_OFFSET + (x) * 8)

#define	IWH_SCD_QUEUE_STTS_REG_POS_TXF		(0)
#define	IWH_SCD_QUEUE_STTS_REG_POS_ACTIVE	(3)
#define	IWH_SCD_QUEUE_STTS_REG_POS_WSL		(4)
#define	IWH_SCD_QUEUE_STTS_REG_MSK		(0x00FF0000)

/* TX command security control */
#define	TX_CMD_SEC_WEP		(0x01)
#define	TX_CMD_SEC_CCM		(0x02)
#define	TX_CMD_SEC_TKIP		(0x03)
#define	TX_CMD_SEC_MSK		(0x03)
#define	TX_CMD_SEC_SHIFT	(6)
#define	TX_CMD_SEC_KEY128	(0x08)

#define	WEP_IV_LEN	(4)
#define	WEP_ICV_LEN	(4)
#define	CCMP_MIC_LEN	(8)
#define	TKIP_ICV_LEN	(4)

#ifdef __cplusplus
}
#endif

#endif /* _IWH_HW_H_ */
