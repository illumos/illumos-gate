/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2007, Intel Corporation
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
 * Copyright(c) 2005 - 2007 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU Geeral Public License as
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
 * Copyright(c) 2005 - 2007 Intel Corporation. All rights reserved.
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

#ifndef	_IWK_HW_H_
#define	_IWK_HW_H_

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * maximum scatter/gather
 */
#define	IWK_MAX_SCATTER	(10)

/*
 * Flow Handler Definitions
 */
#define	FH_MEM_LOWER_BOUND	(0x1000)
#define	FH_MEM_UPPER_BOUND	(0x1EF0)

#define	IWK_FH_REGS_LOWER_BOUND	(0x1000)
#define	IWK_FH_REGS_UPPER_BOUND	(0x2000)

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
#define	FH_MEM_TFDIB_DRAM_ADDR_LSB_MASK	(0xFFFFFFFF)
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
 * Driver must allocate a 4KByte buffer that is used by 4965 for keeping the
 * host DRAM powered on (via dummy accesses to DRAM) to maintain low-latency
 * DRAM access when 4965 is Txing or Rxing.  The dummy accesses prevent host
 * from going into a power-savings mode that would cause higher DRAM latency,
 * and possible data over/under-runs, before all Tx/Rx is complete.
 *
 * Driver loads IWK_FH_KW_MEM_ADDR_REG with the physical address (bits 35:4)
 * of the buffer, which must be 4K aligned.  Once this is set up, the 4965
 * automatically invokes keep-warm accesses when normal accesses might not
 * be sufficient to maintain fast DRAM response.
 *
 * Bit fields:
 * 31-0:  Keep-warm buffer physical base address [35:4], must be 4K aligned
 */
#define	IWK_FH_KW_MEM_ADDR_REG	(FH_MEM_LOWER_BOUND + 0x97C)

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
 * 4965 has 16 base pointer registers, one for each of 16 host-DRAM-resident
 * circular buffers (CBs/queues) containing Transmit Frame Descriptors (TFDs)
 * (see struct iwk_tfd_frame).  These 16 pointer registers are offset by 0x04
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
 * These registers provide handshake between driver and 4965 for the Rx queue
 * (this queue handles *all* command responses, notifications, Rx data, etc.
 * sent from 4965 uCode to host driver).  Unlike Tx, there is only one Rx
 * queue, and only one Rx DMA/FIFO channel.  Also unlike Tx, which can
 * concatenate up to 20 DRAM buffers to form a Tx frame, each Receive Buffer
 * Descriptor (RBD) points to only one Rx Buffer (RB); there is a 1:1
 * mapping between RBDs and RBs.
 *
 * Driver must allocate host DRAM memory for the following, and set the
 * physical address of each into 4965 registers:
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
 * 2)  Rx status buffer, 8 bytes, in which 4965 indicates which Rx Buffers
 *     (RBs) have been filled, via a "write pointer", actually the index of
 *     the RB's corresponding RBD within the circular buffer.  Driver sets
 *     physical address [35:4] into FH_RSCSR_CHNL0_STTS_WPTR_REG [31:0].
 *
 *     Bit fields in lower dword of Rx status buffer (upper dword not used
 *     by driver; see struct iwk_shared, val0):
 *     31-12:  Not used by driver
 *     11- 0:  Index of last filled Rx buffer descriptor
 *             (4965 writes, driver reads this value)
 *
 * As the driver prepares Receive Buffers (RBs) for 4965 to fill, driver must
 * enter pointers to these RBs into contiguous RBD circular buffer entries,
 * and update the 4965's "write" index register, FH_RSCSR_CHNL0_RBDCB_WPTR_REG.
 *
 * This "write" index corresponds to the *next* RBD that the driver will make
 * available, i.e. one RBD past the the tail of the ready-to-fill RBDs within
 * the circular buffer.  This value should initially be 0 (before preparing any
 * RBs), should be 8 after preparing the first 8 RBs (for example), and must
 * wrap back to 0 at the end of the circular buffer (but don't wrap before
 * "read" index has advanced past 1!  See below).
 * NOTE:  4965 EXPECTS THE WRITE INDEX TO BE INCREMENTED IN MULTIPLES OF 8.
 *
 * As the 4965 fills RBs (referenced from contiguous RBDs within the circular
 * buffer), it updates the Rx status buffer in DRAM, 2) described above,
 * to tell the driver the index of the latest filled RBD.  The driver must
 * read this "read" index from DRAM after receiving an Rx interrupt from 4965.
 *
 * The driver must also internally keep track of a third index, which is the
 * next RBD to process.  When receiving an Rx interrupt, driver should process
 * all filled but unprocessed RBs up to, but not including, the RB
 * corresponding to the "read" index.  For example, if "read" index becomes "1",
 * driver may process the RB pointed to by RBD 0.  Depending on volume of
 * traffic, there may be many RBs to process.
 *
 * If read index == write index, 4965 thinks there is no room to put new data.
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

#define	FH_RSCSR_FRAME_SIZE_MASK	(0x00000FFF)	/* bits 0-11 */

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
 * 4965 has one configuration register for each of 8 Tx DMA/FIFO channels
 * supported in hardware; config regs are separated by 0x20 bytes.
 *
 * To use a Tx DMA channel, driver must initialize its
 * IWK_FH_TCSR_CHNL_TX_CONFIG_REG(chnl) with:
 *
 * IWK_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE |
 * IWK_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE_VAL
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
#define	IWK_FH_TCSR_LOWER_BOUND	(IWK_FH_REGS_LOWER_BOUND + 0xD00)
#define	IWK_FH_TCSR_UPPER_BOUND	(IWK_FH_REGS_LOWER_BOUND + 0xE60)

#define	IWK_FH_TCSR_CHNL_NUM	(7)
#define	IWK_FH_TCSR_CHNL_TX_CONFIG_REG(_chnl) \
	(IWK_FH_TCSR_LOWER_BOUND + 0x20 * _chnl)
#define	IWK_FH_TCSR_CHNL_TX_CREDIT_REG(_chnl) \
	(IWK_FH_TCSR_LOWER_BOUND + 0x20 * _chnl + 0x4)
#define	IWK_FH_TCSR_CHNL_TX_BUF_STS_REG(_chnl) \
	(IWK_FH_TCSR_LOWER_BOUND + 0x20 * _chnl + 0x8)

/*
 * Tx Shared Status Registers (TSSR)
 *
 * After stopping Tx DMA channel (writing 0 to
 * IWK_FH_TCSR_CHNL_TX_CONFIG_REG(chnl)), driver must poll
 * IWK_FH_TSSR_TX_STATUS_REG until selected Tx channel is idle
 * (channel's buffers empty | no pending requests).
 *
 * Bit fields:
 * 31-24:  1 = Channel buffers empty (channel 7:0)
 * 23-16:  1 = No pending requests (channel 7:0)
 */
#define	IWK_FH_TSSR_LOWER_BOUND	(IWK_FH_REGS_LOWER_BOUND + 0xEA0)
#define	IWK_FH_TSSR_UPPER_BOUND	(IWK_FH_REGS_LOWER_BOUND + 0xEC0)

#define	IWK_FH_TSSR_TX_MSG_CONFIG_REG (IWK_FH_TSSR_LOWER_BOUND + 0x008)
#define	IWK_FH_TSSR_TX_STATUS_REG	(IWK_FH_TSSR_LOWER_BOUND + 0x010)

#define	IWK_FH_TSSR_TX_MSG_CONFIG_REG_VAL_SNOOP_RD_TXPD_ON	(0xFF000000)
#define	IWK_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RD_TXPD_ON	(0x00FF0000)

#define	IWK_FH_TSSR_TX_MSG_CONFIG_REG_VAL_MAX_FRAG_SIZE_64B	(0x00000000)
#define	IWK_FH_TSSR_TX_MSG_CONFIG_REG_VAL_MAX_FRAG_SIZE_128B	(0x00000400)
#define	IWK_FH_TSSR_TX_MSG_CONFIG_REG_VAL_MAX_FRAG_SIZE_256B	(0x00000800)
#define	IWK_FH_TSSR_TX_MSG_CONFIG_REG_VAL_MAX_FRAG_SIZE_512B	(0x00000C00)

#define	IWK_FH_TSSR_TX_MSG_CONFIG_REG_VAL_SNOOP_RD_TFD_ON	(0x00000100)
#define	IWK_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RD_CBB_ON	(0x00000080)

#define	IWK_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RSP_WAIT_TH	(0x00000020)
#define	IWK_FH_TSSR_TX_MSG_CONFIG_REG_VAL_RSP_WAIT_TH	(0x00000005)

#define	IWK_FH_TSSR_TX_STATUS_REG_BIT_BUFS_EMPTY(_chnl)	\
	((1 << (_chnl)) << 24)
#define	IWK_FH_TSSR_TX_STATUS_REG_BIT_NO_PEND_REQ(_chnl) \
	((1 << (_chnl)) << 16)

#define	IWK_FH_TSSR_TX_STATUS_REG_MSK_CHNL_IDLE(_chnl) \
	(IWK_FH_TSSR_TX_STATUS_REG_BIT_BUFS_EMPTY(_chnl) | \
	IWK_FH_TSSR_TX_STATUS_REG_BIT_NO_PEND_REQ(_chnl))

/*
 * SRVC
 */
#define	IWK_FH_SRVC_LOWER_BOUND	(IWK_FH_REGS_LOWER_BOUND + 0x9C8)
#define	IWK_FH_SRVC_UPPER_BOUND	(IWK_FH_REGS_LOWER_BOUND + 0x9D0)

#define	IWK_FH_SRVC_CHNL_SRAM_ADDR_REG(_chnl) \
	(IWK_FH_SRVC_LOWER_BOUND + (_chnl - 9) * 0x4)

/*
 * TFDIB
 */
#define	IWK_FH_TFDIB_LOWER_BOUND	(IWK_FH_REGS_LOWER_BOUND + 0x900)
#define	IWK_FH_TFDIB_UPPER_BOUND	(IWK_FH_REGS_LOWER_BOUND + 0x958)

#define	IWK_FH_TFDIB_CTRL0_REG(_chnl)    \
	(IWK_FH_TFDIB_LOWER_BOUND + 0x8 * _chnl)
#define	IWK_FH_TFDIB_CTRL1_REG(_chnl)    \
	(IWK_FH_TFDIB_LOWER_BOUND + 0x8 * _chnl + 0x4)

#define	IWK_FH_SRVC_CHNL	(9)
#define	IWK_FH_TFDIB_CTRL1_REG_POS_MSB	(28)

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

/* TCSR: tx_config register values */
#define	IWK_FH_TCSR_TX_CONFIG_REG_VAL_MSG_MODE_TXF	(0x00000000)
#define	IWK_FH_TCSR_TX_CONFIG_REG_VAL_MSG_MODE_DRIVER	(0x00000001)
#define	IWK_FH_TCSR_TX_CONFIG_REG_VAL_MSG_MODE_ARC	(0x00000002)

#define	IWK_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_DISABLE_VAL	(0x00000000)
#define	IWK_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE_VAL	(0x00000008)

#define	IWK_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_NOINT	(0x00000000)
#define	IWK_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_ENDTFD	(0x00100000)
#define	IWK_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_IFTFD	(0x00200000)

#define	IWK_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_RTC_NOINT		(0x00000000)
#define	IWK_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_RTC_ENDTFD	(0x00400000)
#define	IWK_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_RTC_IFTFD		(0x00800000)

#define	IWK_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_PAUSE		(0x00000000)
#define	IWK_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_PAUSE_EOF	(0x40000000)
#define	IWK_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE	(0x80000000)

#define	IWK_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_EMPTY	(0x00000000)
#define	IWK_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_WAIT	(0x00002000)
#define	IWK_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_VALID	(0x00000003)

#define	IWK_FH_TCSR_CHNL_TX_BUF_STS_REG_BIT_TFDB_WPTR	(0x00000001)

#define	IWK_FH_TCSR_CHNL_TX_BUF_STS_REG_POS_TB_NUM	(20)
#define	IWK_FH_TCSR_CHNL_TX_BUF_STS_REG_POS_TB_IDX	(12)

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

#define	IWK_FH_RCSR_RX_CONFIG_REG_VAL_RB_SIZE_4K	(0x00000000)

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
 * Tx DMA channels have dedicated purposes.  For 4965, and are used as follows:
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
 *     (struct iwk_sched_queue_byte_cnt_tbl) for this mode.
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
 * 1)  4965's scheduler data base area in SRAM:
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
#define	SCD_FRAME_LIMIT	10

/*
 * Memory mapped registers ... access via HBUS_TARG_PRPH regs
 */
#define	SCD_START_OFFSET	0xa02c00

/*
 * 4965 tells driver SRAM address for internal scheduler structs via this reg.
 * Value is valid only after "Alive" response from uCode.
 */
#define	SCD_SRAM_BASE_ADDR	(SCD_START_OFFSET + 0x0)

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
#define	SCD_DRAM_BASE_ADDR	(SCD_START_OFFSET + 0x10)
#define	SCD_AIT		(SCD_START_OFFSET + 0x18)

/*
 * Enables any/all Tx DMA/FIFO channels.
 * Scheduler generates requests for only the active channels.
 * Set this to 0xff to enable all 8 channels (normal usage).
 * Bit fields:
 *  7- 0:  Enable (1), disable (0), one bit for each channel 0-7
 */
#define	SCD_TXFACT	(SCD_START_OFFSET + 0x1c)

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
#define	SCD_QUEUECHAIN_SEL	(SCD_START_OFFSET + 0xd0)
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
#define	SCD_INTERRUPT_MASK	(SCD_START_OFFSET + 0xe4)
#define	SCD_INTERRUPT_THRESHOLD	(SCD_START_OFFSET + 0xe8)
#define	SCD_QUERY_MIN_FRAME_SIZE	(SCD_START_OFFSET + 0x100)

/*
 * Queue search status registers.  One for each queue.
 * Sets up queue mode and assigns queue to Tx DMA channel.
 * Bit fields:
 * 19-10: Write mask/enable bits for bits 0-9
 *     9: Driver should init to "0"
 *     8: Scheduler-ACK mode (1), non-Scheduler-ACK (i.e. FIFO) mode (0).
 *        Driver should init to "1" for aggregation mode, or "0" otherwise.
 *   7-6: Driver should init to "0"
 *     5: Window Size Left; indicates whether scheduler can request
 *        another TFD, based on window size, etc.  Driver should init
 *        this bit to "1" for aggregation mode, or "0" for non-agg.
 *   4-1: Tx FIFO to use (range 0-7).
 *     0: Queue is active (1), not active (0).
 * Other bits should be written as "0"
 *
 * NOTE:  If enabling Scheduler-ACK mode, chain mode should also be enabled
 *        via SCD_QUEUECHAIN_SEL.
 */
#define	SCD_QUEUE_STATUS_BITS(x)	(SCD_START_OFFSET + 0x104 + (x) * 4)

/*
 * 4965 internal SRAM structures for scheduler, shared with driver ...
 * Driver should clear and initialize the following areas after receiving
 * "Alive" response from 4965 uCode, i.e. after initial
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
 * Init must be done after driver receives "Alive" response from 4965 uCode,
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
#define	SCD_QUEUE_STTS_REG_POS_ACTIVE		(0)
#define	SCD_QUEUE_STTS_REG_POS_TXF		(1)
#define	SCD_QUEUE_STTS_REG_POS_WSL		(5)
#define	SCD_QUEUE_STTS_REG_POS_SCD_ACK		(8)
#define	SCD_QUEUE_STTS_REG_POS_SCD_ACT_EN	(10)
#define	SCD_QUEUE_STTS_REG_MSK			(0x0007FC00)

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

/* IWK-END */

#define	RX_RES_PHY_CNT	14

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
/* 0x028 - reserved */
#define	CSR_EEPROM_REG	(CSR_BASE+0x02c)
#define	CSR_EEPROM_GP	(CSR_BASE+0x030)
#define	CSR_UCODE_DRV_GP1	(CSR_BASE+0x054)
#define	CSR_UCODE_DRV_GP1_SET	(CSR_BASE+0x058)
#define	CSR_UCODE_DRV_GP1_CLR	(CSR_BASE+0x05c)
#define	CSR_UCODE_DRV_GP2	(CSR_BASE+0x060)
#define	CSR_GIO_CHICKEN_BITS	(CSR_BASE+0x100)
#define	CSR_ANA_PLL_CFG		(CSR_BASE+0x20c)
#define	CSR_HW_REV_WA_REG	(CSR_BASE+0x22C)

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
 * pointers and size regs for bootstrap load and data SRAM save
 */
#define	BSM_DRAM_INST_PTR_REG		(BSM_BASE + 0x090)
#define	BSM_DRAM_INST_BYTECOUNT_REG	(BSM_BASE + 0x094)
#define	BSM_DRAM_DATA_PTR_REG		(BSM_BASE + 0x098)
#define	BSM_DRAM_DATA_BYTECOUNT_REG	(BSM_BASE + 0x09C)

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
				BIT_FH_INT_RX_CHNL2 |  \
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

#define	HBUS_TARG_MBX_C_REG_BIT_CMD_BLOCKED	(0x00000004)

#define	TFD_QUEUE_MIN		0
#define	TFD_QUEUE_MAX		6
#define	TFD_QUEUE_SIZE_MAX	(256)

/*
 * spectrum and channel data structures
 */
#define	IWK_NUM_SCAN_RATES	(2)

#define	IWK_SCAN_FLAG_24GHZ  (1<<0)
#define	IWK_SCAN_FLAG_52GHZ  (1<<1)
#define	IWK_SCAN_FLAG_ACTIVE (1<<2)
#define	IWK_SCAN_FLAG_DIRECT (1<<3)

#define	IWK_MAX_CMD_SIZE 1024

#define	IWK_DEFAULT_TX_RETRY	15
#define	IWK_MAX_TX_RETRY	16

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

#define	IWK_MB_DISASSOCIATE_THRESHOLD_DEFAULT	24
#define	IWK_MB_ROAMING_THRESHOLD_DEFAULT		8
#define	IWK_REAL_RATE_RX_PACKET_THRESHOLD		300

/*
 * QoS  definitions
 */
#define	CW_MIN_OFDM	15
#define	CW_MAX_OFDM	1023
#define	CW_MIN_CCK	31
#define	CW_MAX_CCK	1023

#define	QOS_TX0_CW_MIN_OFDM	CW_MIN_OFDM
#define	QOS_TX1_CW_MIN_OFDM	CW_MIN_OFDM
#define	QOS_TX2_CW_MIN_OFDM	((CW_MIN_OFDM + 1) / 2 - 1)
#define	QOS_TX3_CW_MIN_OFDM	((CW_MIN_OFDM + 1) / 4 - 1)

#define	QOS_TX0_CW_MIN_CCK	CW_MIN_CCK
#define	QOS_TX1_CW_MIN_CCK	CW_MIN_CCK
#define	QOS_TX2_CW_MIN_CCK	((CW_MIN_CCK + 1) / 2 - 1)
#define	QOS_TX3_CW_MIN_CCK	((CW_MIN_CCK + 1) / 4 - 1)

#define	QOS_TX0_CW_MAX_OFDM	CW_MAX_OFDM
#define	QOS_TX1_CW_MAX_OFDM	CW_MAX_OFDM
#define	QOS_TX2_CW_MAX_OFDM	CW_MIN_OFDM
#define	QOS_TX3_CW_MAX_OFDM	((CW_MIN_OFDM + 1) / 2 - 1)

#define	QOS_TX0_CW_MAX_CCK	CW_MAX_CCK
#define	QOS_TX1_CW_MAX_CCK	CW_MAX_CCK
#define	QOS_TX2_CW_MAX_CCK	CW_MIN_CCK
#define	QOS_TX3_CW_MAX_CCK	((CW_MIN_CCK + 1) / 2 - 1)

#define	QOS_TX0_AIFS	(3)
#define	QOS_TX1_AIFS	(7)
#define	QOS_TX2_AIFS	(2)
#define	QOS_TX3_AIFS	(2)

#define	QOS_TX0_ACM	0
#define	QOS_TX1_ACM	0
#define	QOS_TX2_ACM	0
#define	QOS_TX3_ACM	0

#define	QOS_TX0_TXOP_LIMIT_CCK	0
#define	QOS_TX1_TXOP_LIMIT_CCK	0
#define	QOS_TX2_TXOP_LIMIT_CCK	6016
#define	QOS_TX3_TXOP_LIMIT_CCK	3264

#define	QOS_TX0_TXOP_LIMIT_OFDM	0
#define	QOS_TX1_TXOP_LIMIT_OFDM	0
#define	QOS_TX2_TXOP_LIMIT_OFDM	3008
#define	QOS_TX3_TXOP_LIMIT_OFDM	1504

#define	DEF_TX0_CW_MIN_OFDM	CW_MIN_OFDM
#define	DEF_TX1_CW_MIN_OFDM	CW_MIN_OFDM
#define	DEF_TX2_CW_MIN_OFDM	CW_MIN_OFDM
#define	DEF_TX3_CW_MIN_OFDM	CW_MIN_OFDM

#define	DEF_TX0_CW_MIN_CCK	CW_MIN_CCK
#define	DEF_TX1_CW_MIN_CCK	CW_MIN_CCK
#define	DEF_TX2_CW_MIN_CCK	CW_MIN_CCK
#define	DEF_TX3_CW_MIN_CCK	CW_MIN_CCK

#define	DEF_TX0_CW_MAX_OFDM	CW_MAX_OFDM
#define	DEF_TX1_CW_MAX_OFDM	CW_MAX_OFDM
#define	DEF_TX2_CW_MAX_OFDM	CW_MAX_OFDM
#define	DEF_TX3_CW_MAX_OFDM	CW_MAX_OFDM

#define	DEF_TX0_CW_MAX_CCK	CW_MAX_CCK
#define	DEF_TX1_CW_MAX_CCK	CW_MAX_CCK
#define	DEF_TX2_CW_MAX_CCK	CW_MAX_CCK
#define	DEF_TX3_CW_MAX_CCK	CW_MAX_CCK

#define	DEF_TX0_AIFS		(2)
#define	DEF_TX1_AIFS		(2)
#define	DEF_TX2_AIFS		(2)
#define	DEF_TX3_AIFS		(2)

#define	DEF_TX0_ACM		(0)
#define	DEF_TX1_ACM		(0)
#define	DEF_TX2_ACM		(0)
#define	DEF_TX3_ACM		(0)

#define	DEF_TX0_TXOP_LIMIT_CCK	(0)
#define	DEF_TX1_TXOP_LIMIT_CCK	(0)
#define	DEF_TX2_TXOP_LIMIT_CCK	(0)
#define	DEF_TX3_TXOP_LIMIT_CCK	(0)

#define	DEF_TX0_TXOP_LIMIT_OFDM	(0)
#define	DEF_TX1_TXOP_LIMIT_OFDM	(0)
#define	DEF_TX2_TXOP_LIMIT_OFDM	(0)
#define	DEF_TX3_TXOP_LIMIT_OFDM	(0)

#define	QOS_QOS_SETS		(3)
#define	QOS_PARAM_SET_ACTIVE	(0)
#define	QOS_PARAM_SET_DEF_CCK	(1)
#define	QOS_PARAM_SET_DEF_OFDM	(2)

#define	CTRL_QOS_NO_ACK			(0x0020)
#define	DCT_FLAG_EXT_QOS_ENABLED	(0x10)

#define	IWK_TX_QUEUE_AC0		(0)
#define	IWK_TX_QUEUE_AC1		(1)
#define	IWK_TX_QUEUE_AC2		(2)
#define	IWK_TX_QUEUE_AC3		(3)
#define	IWK_TX_QUEUE_HCCA_1		(5)
#define	IWK_TX_QUEUE_HCCA_2    	(6)

#define	U32_PAD(n)	((4-(n%4))%4)

#define	AC_BE_TID_MASK 0x9	/* TID 0 and 3 */
#define	AC_BK_TID_MASK 0x6	/* TID 1 and 2 */

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
 * Most communication between driver and 4965 is via queues of data buffers.
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
 * 4965 supports up to 16 DRAM-based Tx queues, and services these queues via
 * up to 7 DMA channels (FIFOs).  Each Tx queue is supported by a circular array
 * in DRAM containing 256 Transmit Frame Descriptors (TFDs).
 */
#define	IWK_MAX_WIN_SIZE	64
#define	IWK_QUEUE_SIZE	256
#define	IWK_NUM_FIFOS	7
#define	IWK_NUM_QUEUES	6
#define	IWK_CMD_QUEUE_NUM	4
#define	IWK_KW_SIZE 0x1000	/* 4k */

struct iwk_rate {
	union {
		struct {
			uint8_t rate;
			uint8_t flags;
			uint16_t ext_flags;
		} s;
		uint32_t rate_n_flags;
	} r;
};

struct iwk_dram_scratch {
	uint8_t try_cnt;
	uint8_t bt_kill_cnt;
	uint16_t reserved;
};

/*
 * START TEMPERATURE
 */
/*
 * 4965 temperature calculation.
 *
 * The driver must calculate the device temperature before calculating
 * a txpower setting (amplifier gain is temperature dependent).  The
 * calculation uses 4 measurements, 3 of which (R1, R2, R3) are calibration
 * values used for the life of the driver, and one of which (R4) is the
 * real-time temperature indicator.
 *
 * uCode provides all 4 values to the driver via the "initialize alive"
 * notification (see struct iwk_init_alive_resp).  After the runtime uCode
 * image loads, uCode updates the R4 value via statistics notifications
 * (see STATISTICS_NOTIFICATION), which occur after each received beacon
 * when associated, or can be requested via REPLY_STATISTICS_CMD.
 *
 * NOTE:  uCode provides the R4 value as a 23-bit signed value.  Driver
 *        must sign-extend to 32 bits before applying formula below.
 *
 * Formula:
 *
 * degrees Kelvin = ((97 * 259 * (R4 - R2) / (R3 - R1)) / 100) + 8
 *
 * NOTE:  The basic formula is 259 * (R4-R2) / (R3-R1).  The 97/100 is
 * an additional correction, which should be centered around 0 degrees
 * Celsius (273 degrees Kelvin).  The 8 (3 percent of 273) compensates for
 * centering the 97/100 correction around 0 degrees K.
 *
 * Add 273 to Kelvin value to find degrees Celsius, for comparing current
 * temperature with factory-measured temperatures when calculating txpower
 * settings.
 */
#define	TEMPERATURE_CALIB_KELVIN_OFFSET 8
#define	TEMPERATURE_CALIB_A_VAL 259

/*
 * Limit range of calculated temperature to be between these Kelvin values
 */
#define	IWK_TX_POWER_TEMPERATURE_MIN  (263)
#define	IWK_TX_POWER_TEMPERATURE_MAX  (410)

#define	IWK_TX_POWER_TEMPERATURE_OUT_OF_RANGE(t) \
	(((t) < IWK_TX_POWER_TEMPERATURE_MIN) || \
	((t) > IWK_TX_POWER_TEMPERATURE_MAX))

/*
 * END TEMPERATURE
 */

/*
 * START TXPOWER
 */
/*
 * 4965 txpower calculations rely on information from three sources:
 *
 *     1) EEPROM
 *     2) "initialize" alive notification
 *     3) statistics notifications
 *
 * EEPROM data consists of:
 *
 * 1)  Regulatory information (max txpower and channel usage flags) is provided
 *     separately for each channel that can possibly supported by 4965.
 *     40 MHz wide (.11n fat) channels are listed separately from 20 MHz
 *     (legacy) channels.
 *
 *     See struct iwk_eeprom_channel for format, and struct iwk_eeprom for
 *     locations in EEPROM.
 *
 * 2)  Factory txpower calibration information is provided separately for
 *     sub-bands of contiguous channels.  2.4GHz has just one sub-band,
 *     but 5 GHz has several sub-bands.
 *
 *     In addition, per-band (2.4 and 5 Ghz) saturation txpowers are provided.
 *
 *     See struct iwk_eeprom_calib_info (and the tree of structures contained
 *     within it) for format, and struct iwk_eeprom for locations in EEPROM.
 *
 * "Initialization alive" notification (see struct iwk_init_alive_resp)
 * consists of:
 *
 * 1)  Temperature calculation parameters.
 *
 * 2)  Power supply voltage measurement.
 *
 * 3)  Tx gain compensation to balance 2 transmitters for MIMO use.
 *
 * Statistics notifications deliver:
 *
 * 1)  Current values for temperature param R4.
 */

/*
 * To calculate a txpower setting for a given desired target txpower, channel,
 * modulation bit rate, and transmitter chain (4965 has 2 transmitters to
 * support MIMO and transmit diversity), driver must do the following:
 *
 * 1)  Compare desired txpower vs. (EEPROM) regulatory limit for this channel.
 *     Do not exceed regulatory limit; reduce target txpower if necessary.
 *
 *     If setting up txpowers for MIMO rates (rate indexes 8-15, 24-31),
 *     2 transmitters will be used simultaneously; driver must reduce the
 *     regulatory limit by 3 dB (half-power) for each transmitter, so the
 *     combined total output of the 2 transmitters is within regulatory limits.
 *
 *
 * 2)  Compare target txpower vs. (EEPROM) saturation txpower *reduced by
 *     backoff for this bit rate*.  Do not exceed (saturation - backoff[rate]);
 *     reduce target txpower if necessary.
 *
 *     Backoff values below are in 1/2 dB units (equivalent to steps in
 *     txpower gain tables):
 *
 *     OFDM 6 - 36 MBit:  10 steps (5 dB)
 *     OFDM 48 MBit:      15 steps (7.5 dB)
 *     OFDM 54 MBit:      17 steps (8.5 dB)
 *     OFDM 60 MBit:      20 steps (10 dB)
 *     CCK all rates:     10 steps (5 dB)
 *
 *     Backoff values apply to saturation txpower on a per-transmitter basis;
 *     when using MIMO (2 transmitters), each transmitter uses the same
 *     saturation level provided in EEPROM, and the same backoff values;
 *     no reduction (such as with regulatory txpower limits) is required.
 *
 *     Saturation and Backoff values apply equally to 20 Mhz (legacy) channel
 *     widths and 40 Mhz (.11n fat) channel widths; there is no separate
 *     factory measurement for fat channels.
 *
 *     The result of this step is the final target txpower.  The rest of
 *     the steps figure out the proper settings for the device.
 *
 *
 * 3)  Determine (EEPROM) calibration subband for the target channel, by
 *     comparing against first and last channels in each subband
 *     (see struct iwk_eeprom_calib_subband_info).
 *
 *
 * 4)  Linearly interpolate (EEPROM) factory calibration measurement sets,
 *     referencing the 2 factory-measured (sample) channels within the subband.
 *
 *     Interpolation is based on difference between target channel's frequency
 *     and the sample channels' frequencies.  Since channel numbers are based
 *     on frequency (5 MHz between each channel number), this is equivalent
 *     to interpolating based on channel number differences.
 *
 *     Note that the sample channels may or may not be the channels at the
 *     edges of the subband.  The target channel may be "outside" of the
 *     span of the sampled channels.
 *
 *     Driver may choose the pair (for 2 Tx chains) of measurements (see
 *     struct iwk_eeprom_calib_ch_info) for which the actual measured
 *     txpower comes closest to the desired txpower.  Usually, though,
 *     the middle set of measurements is closest to the regulatory limits,
 *     and is therefore a good choice for all txpower calculations.
 *
 *     Driver should interpolate both members of the chosen measurement pair,
 *     i.e. for both Tx chains (radio transmitters), unless the driver knows
 *     that only one of the chains will be used (e.g. only one tx antenna
 *     connected, but this should be unusual).
 *
 *     Driver should interpolate factory values for temperature, gain table
 *     index, and actual power.  The power amplifier detector values are
 *     not used by the driver.
 *
 *     If the target channel happens to be one of the sample channels, the
 *     results should agree with the sample channel's measurements!
 *
 *
 * 5)  Find difference between desired txpower and (interpolated)
 *     factory-measured txpower.  Using (interpolated) factory gain table index
 *     as a starting point, adjust this index lower to increase txpower,
 *     or higher to decrease txpower, until the target txpower is reached.
 *     Each step in the gain table is 1/2 dB.
 *
 *     For example, if factory measured txpower is 16 dBm, and target txpower
 *     is 13 dBm, add 6 steps to the factory gain index to reduce txpower
 *     by 3 dB.
 *
 *
 * 6)  Find difference between current device temperature and (interpolated)
 *     factory-measured temperature for sub-band.  Factory values are in
 *     degrees Celsius.  To calculate current temperature, see comments for
 *     "4965 temperature calculation".
 *
 *     If current temperature is higher than factory temperature, driver must
 *     increase gain (lower gain table index), and vice versa.
 *
 *     Temperature affects gain differently for different channels:
 *
 *     2.4 GHz all channels:  3.5 degrees per half-dB step
 *     5 GHz channels 34-43:  4.5 degrees per half-dB step
 *     5 GHz channels >= 44:  4.0 degrees per half-dB step
 *
 *     NOTE:  Temperature can increase rapidly when transmitting, especially
 *            with heavy traffic at high txpowers.  Driver should update
 *            temperature calculations often under these conditions to
 *            maintain strong txpower in the face of rising temperature.
 *
 *
 * 7)  Find difference between current power supply voltage indicator
 *     (from "initialize alive") and factory-measured power supply voltage
 *     indicator (EEPROM).
 *
 *     If the current voltage is higher (indicator is lower) than factory
 *     voltage, gain should be reduced (gain table index increased) by:
 *
 *     (eeprom - current) / 7
 *
 *     If the current voltage is lower (indicator is higher) than factory
 *     voltage, gain should be increased (gain table index decreased) by:
 *
 *     2 * (current - eeprom) / 7
 *
 *     If number of index steps in either direction turns out to be > 2,
 *     something is wrong ... just use 0.
 *
 *     NOTE:  Voltage compensation is independent of band/channel.
 *
 *     NOTE:  "Initialize" uCode measures current voltage, which is assumed
 *            to be constant after this initial measurement.  Voltage
 *            compensation for txpower (number of steps in gain table)
 *            may be calculated once and used until the next uCode bootload.
 *
 *
 * 8)  If setting up txpowers for MIMO rates (rate indexes 8-15, 24-31),
 *     adjust txpower for each transmitter chain, so txpower is balanced
 *     between the two chains.  There are 5 pairs of tx_atten[group][chain]
 *     values in "initialize alive", one pair for each of 5 channel ranges:
 *
 *     Group 0:  5 GHz channel 34-43
 *     Group 1:  5 GHz channel 44-70
 *     Group 2:  5 GHz channel 71-124
 *     Group 3:  5 GHz channel 125-200
 *     Group 4:  2.4 GHz all channels
 *
 *     Add the tx_atten[group][chain] value to the index for the target chain.
 *     The values are signed, but are in pairs of 0 and a non-negative number,
 *     so as to reduce gain (if necessary) of the "hotter" channel.  This
 *     avoids any need to double-check for regulatory compliance after
 *     this step.
 *
 *
 * 9)  If setting up for a CCK rate, lower the gain by adding a CCK compensation
 *     value to the index:
 *
 *     Hardware rev B:  9 steps (4.5 dB)
 *     Hardware rev C:  5 steps (2.5 dB)
 *
 *     Hardware rev for 4965 can be determined by reading CSR_HW_REV_WA_REG,
 *     bits [3:2], 1 = B, 2 = C.
 *
 *     NOTE:  This compensation is in addition to any saturation backoff that
 *            might have been applied in an earlier step.
 *
 *
 * 10) Select the gain table, based on band (2.4 vs 5 GHz).
 *
 *     Limit the adjusted index to stay within the table!
 *
 *
 * 11) Read gain table entries for DSP and radio gain, place into appropriate
 *     location(s) in command.
 */

enum {
	HT_IE_EXT_CHANNEL_NONE = 0,
	HT_IE_EXT_CHANNEL_ABOVE,
	HT_IE_EXT_CHANNEL_INVALID,
	HT_IE_EXT_CHANNEL_BELOW,
	HT_IE_EXT_CHANNEL_MAX
};

enum {
	CALIB_CH_GROUP_1 = 0,
	CALIB_CH_GROUP_2 = 1,
	CALIB_CH_GROUP_3 = 2,
	CALIB_CH_GROUP_4 = 3,
	CALIB_CH_GROUP_5 = 4,
	CALIB_CH_GROUP_MAX
};

#define	POWER_TABLE_NUM_HT_OFDM_ENTRIES	(32)

/*
 * Temperature calibration offset is 3% 0C in Kelvin
 */
#define	TEMPERATURE_CALIB_KELVIN_OFFSET 8
#define	TEMPERATURE_CALIB_A_VAL 259

#define	IWK_TX_POWER_TEMPERATURE_MIN  (263)
#define	IWK_TX_POWER_TEMPERATURE_MAX  (410)

#define	IWK_TX_POWER_TEMPERATURE_OUT_OF_RANGE(t) \
	(((t) < IWK_TX_POWER_TEMPERATURE_MIN) || \
	((t) > IWK_TX_POWER_TEMPERATURE_MAX))

#define	IWK_TX_POWER_ILLEGAL_TEMPERATURE (300)

#define	IWK_TX_POWER_TEMPERATURE_DIFFERENCE (2)

/*
 * When MIMO is used (2 transmitters operating simultaneously), driver should
 * limit each transmitter to deliver a max of 3 dB below the regulatory limit
 * for the device.  That is, half power for each transmitter, so total power
 * is within regulatory limits.
 *
 * The value "6" represents number of steps in gain table to reduce power.
 * Each step is 1/2 dB.
 */
#define	IWK_TX_POWER_MIMO_REGULATORY_COMPENSATION (6)

/*
 * Limit range of txpower output target to be between these values
 */
#define	IWK_TX_POWER_TARGET_POWER_MIN	(0) /* 0 dBm = 1 milliwatt */
#define	IWK_TX_POWER_TARGET_POWER_MAX	(16) /* 16 dBm */

/*
 * timeout equivalent to 3 minutes
 */
#define	IWK_TX_POWER_TIMELIMIT_NOCALIB 1800000000

/*
 * CCK gain compensation.
 *
 * When calculating txpowers for CCK, after making sure that the target power
 * is within regulatory and saturation limits, driver must additionally
 * back off gain by adding these values to the gain table index.
 */
#define	IWK_TX_POWER_CCK_COMPENSATION (9)
#define	IWK_TX_POWER_CCK_COMPENSATION_B_STEP (9)
#define	IWK_TX_POWER_CCK_COMPENSATION_C_STEP (5)

/*
 * 4965 power supply voltage compensation
 */
#define	TX_POWER_IWK_VOLTAGE_CODES_PER_03V   (7)

/*
 * Gain tables.
 *
 * The following tables contain pair of values for setting txpower, i.e.
 * gain settings for the output of the device's digital signal processor (DSP),
 * and for the analog gain structure of the transmitter.
 *
 * Each entry in the gain tables represents a step of 1/2 dB.  Note that these
 * are *relative* steps, not indications of absolute output power.  Output
 * power varies with temperature, voltage, and channel frequency, and also
 * requires consideration of average power (to satisfy regulatory constraints),
 * and peak power (to avoid distortion of the output signal).
 *
 * Each entry contains two values:
 * 1)  DSP gain (or sometimes called DSP attenuation).  This is a fine-grained
 *     linear value that multiplies the output of the digital signal processor,
 *     before being sent to the analog radio.
 * 2)  Radio gain.  This sets the analog gain of the radio Tx path.
 *     It is a coarser setting, and behaves in a logarithmic (dB) fashion.
 *
 * EEPROM contains factory calibration data for txpower.  This maps actual
 * measured txpower levels to gain settings in the "well known" tables
 * below ("well-known" means here that both factory calibration *and* the
 * driver work with the same table).
 *
 * There are separate tables for 2.4 GHz and 5 GHz bands.  The 5 GHz table
 * has an extension (into negative indexes), in case the driver needs to
 * boost power setting for high device temperatures (higher than would be
 * present during factory calibration).  A 5 Ghz EEPROM index of "40"
 * corresponds to the 49th entry in the table used by the driver.
 */
#define	MIN_TX_GAIN_INDEX		(0)
#define	MIN_TX_GAIN_INDEX_52GHZ_EXT	(-9)
#define	MAX_TX_GAIN_INDEX_52GHZ		(98)
#define	MIN_TX_GAIN_52GHZ		(98)
#define	MAX_TX_GAIN_INDEX_24GHZ		(98)
#define	MIN_TX_GAIN_24GHZ		(98)
#define	MAX_TX_GAIN			(0)
#define	MAX_TX_GAIN_52GHZ_EXT		(-9)

/*
 * 2.4 GHz gain table
 *
 * Index    Dsp gain   Radio gain
 *   0        110         0x3f
 *   1        104         0x3f
 *   2         98         0x3f
 *   3        110         0x3e
 *   4        104         0x3e
 *   5         98         0x3e
 *   6        110         0x3d
 *   7        104         0x3d
 *   8         98         0x3d
 *   9        110         0x3c
 *  10        104         0x3c
 *  11         98         0x3c
 *  12        110         0x3b
 *  13        104         0x3b
 *  14         98         0x3b
 *  15        110         0x3a
 *  16        104         0x3a
 *  17         98         0x3a
 *  18        110         0x39
 *  19        104         0x39
 *  20         98         0x39
 *  21        110         0x38
 *  22        104         0x38
 *  23         98         0x38
 *  24        110         0x37
 *  25        104         0x37
 *  26         98         0x37
 *  27        110         0x36
 *  28        104         0x36
 *  29         98         0x36
 *  30        110         0x35
 *  31        104         0x35
 *  32         98         0x35
 *  33        110         0x34
 *  34        104         0x34
 *  35         98         0x34
 *  36        110         0x33
 *  37        104         0x33
 *  38         98         0x33
 *  39        110         0x32
 *  40        104         0x32
 *  41         98         0x32
 *  42        110         0x31
 *  43        104         0x31
 *  44         98         0x31
 *  45        110         0x30
 *  46        104         0x30
 *  47         98         0x30
 *  48        110          0x6
 *  49        104          0x6
 *  50         98          0x6
 *  51        110          0x5
 *  52        104          0x5
 *  53         98          0x5
 *  54        110          0x4
 *  55        104          0x4
 *  56         98          0x4
 *  57        110          0x3
 *  58        104          0x3
 *  59         98          0x3
 *  60        110          0x2
 *  61        104          0x2
 *  62         98          0x2
 *  63        110          0x1
 *  64        104          0x1
 *  65         98          0x1
 *  66        110          0x0
 *  67        104          0x0
 *  68         98          0x0
 *  69         97            0
 *  70         96            0
 *  71         95            0
 *  72         94            0
 *  73         93            0
 *  74         92            0
 *  75         91            0
 *  76         90            0
 *  77         89            0
 *  78         88            0
 *  79         87            0
 *  80         86            0
 *  81         85            0
 *  82         84            0
 *  83         83            0
 *  84         82            0
 *  85         81            0
 *  86         80            0
 *  87         79            0
 *  88         78            0
 *  89         77            0
 *  90         76            0
 *  91         75            0
 *  92         74            0
 *  93         73            0
 *  94         72            0
 *  95         71            0
 *  96         70            0
 *  97         69            0
 *  98         68            0
 */

/*
 * 5 GHz gain table
 *
 * Index    Dsp gain   Radio gain
 *  -9        123         0x3F
 *  -8        117         0x3F
 *  -7        110         0x3F
 *  -6        104         0x3F
 *  -5         98         0x3F
 *  -4        110         0x3E
 *  -3        104         0x3E
 *  -2         98         0x3E
 *  -1        110         0x3D
 *   0        104         0x3D
 *   1         98         0x3D
 *   2        110         0x3C
 *   3        104         0x3C
 *   4         98         0x3C
 *   5        110         0x3B
 *   6        104         0x3B
 *   7         98         0x3B
 *   8        110         0x3A
 *   9        104         0x3A
 *  10         98         0x3A
 *  11        110         0x39
 *  12        104         0x39
 *  13         98         0x39
 *  14        110         0x38
 *  15        104         0x38
 *  16         98         0x38
 *  17        110         0x37
 *  18        104         0x37
 *  19         98         0x37
 *  20        110         0x36
 *  21        104         0x36
 *  22         98         0x36
 *  23        110         0x35
 *  24        104         0x35
 *  25         98         0x35
 *  26        110         0x34
 *  27        104         0x34
 *  28         98         0x34
 *  29        110         0x33
 *  30        104         0x33
 *  31         98         0x33
 *  32        110         0x32
 *  33        104         0x32
 *  34         98         0x32
 *  35        110         0x31
 *  36        104         0x31
 *  37         98         0x31
 *  38        110         0x30
 *  39        104         0x30
 *  40         98         0x30
 *  41        110         0x25
 *  42        104         0x25
 *  43         98         0x25
 *  44        110         0x24
 *  45        104         0x24
 *  46         98         0x24
 *  47        110         0x23
 *  48        104         0x23
 *  49         98         0x23
 *  50        110         0x22
 *  51        104         0x18
 *  52         98         0x18
 *  53        110         0x17
 *  54        104         0x17
 *  55         98         0x17
 *  56        110         0x16
 *  57        104         0x16
 *  58         98         0x16
 *  59        110         0x15
 *  60        104         0x15
 *  61         98         0x15
 *  62        110         0x14
 *  63        104         0x14
 *  64         98         0x14
 *  65        110         0x13
 *  66        104         0x13
 *  67         98         0x13
 *  68        110         0x12
 *  69        104         0x08
 *  70         98         0x08
 *  71        110         0x07
 *  72        104         0x07
 *  73         98         0x07
 *  74        110         0x06
 *  75        104         0x06
 *  76         98         0x06
 *  77        110         0x05
 *  78        104         0x05
 *  79         98         0x05
 *  80        110         0x04
 *  81        104         0x04
 *  82         98         0x04
 *  83        110         0x03
 *  84        104         0x03
 *  85         98         0x03
 *  86        110         0x02
 *  87        104         0x02
 *  88         98         0x02
 *  89        110         0x01
 *  90        104         0x01
 *  91         98         0x01
 *  92        110         0x00
 *  93        104         0x00
 *  94         98         0x00
 *  95         93         0x00
 *  96         88         0x00
 *  97         83         0x00
 *  98         78         0x00
 */

/*
 * Sanity checks and default values for EEPROM regulatory levels.
 * If EEPROM values fall outside MIN/MAX range, use default values.
 *
 * Regulatory limits refer to the maximum average txpower allowed by
 * regulatory agencies in the geographies in which the device is meant
 * to be operated.  These limits are SKU-specific (i.e. geography-specific),
 * and channel-specific; each channel has an individual regulatory limit
 * listed in the EEPROM.
 *
 * Units are in half-dBm (i.e. "34" means 17 dBm).
 */
#define	IWK_TX_POWER_DEFAULT_REGULATORY_24	(34)
#define	IWK_TX_POWER_DEFAULT_REGULATORY_52	(34)
#define	IWK_TX_POWER_REGULATORY_MIN	(0)
#define	IWK_TX_POWER_REGULATORY_MAX	(34)

/*
 * Sanity checks and default values for EEPROM saturation levels.
 * If EEPROM values fall outside MIN/MAX range, use default values.
 *
 * Saturation is the highest level that the output power amplifier can produce
 * without significant clipping distortion.  This is a "peak" power level.
 * Different types of modulation (i.e. various "rates", and OFDM vs. CCK)
 * require differing amounts of backoff, relative to their average power output,
 * in order to avoid clipping distortion.
 *
 * Driver must make sure that it is violating neither the saturation limit,
 * nor the regulatory limit, when calculating Tx power settings for various
 * rates.
 *
 * Units are in half-dBm (i.e. "38" means 19 dBm).
 */
#define	IWK_TX_POWER_DEFAULT_SATURATION_24	(38)
#define	IWK_TX_POWER_DEFAULT_SATURATION_52	(38)
#define	IWK_TX_POWER_SATURATION_MIN	(20)
#define	IWK_TX_POWER_SATURATION_MAX	(50)

/*
 * dv *0.4 = dt; so that 5 degrees temperature diff equals
 * 12.5 in voltage diff
 */
#define	IWK_TX_TEMPERATURE_UPDATE_LIMIT 9

#define	IWK_INVALID_CHANNEL		(0xffffffff)
#define	IWK_TX_POWER_REGITRY_BIT	(2)

#define	MIN_IWK_TX_POWER_CALIB_DUR	(100)
#define	IWK_CCK_FROM_OFDM_POWER_DIFF	(-5)
#define	IWK_CCK_FROM_OFDM_INDEX_DIFF	(9)

/*
 * Number of entries in the gain table
 */
#define	POWER_GAIN_NUM_ENTRIES 78
#define	TX_POW_MAX_SESSION_NUM 5

/*
 * timeout equivalent to 3 minutes
 */
#define	TX_IWK_TIMELIMIT_NOCALIB 1800000000

/*
 * Kedron TX_CALIB_STATES
 */
#define	IWK_TX_CALIB_STATE_SEND_TX		0x00000001
#define	IWK_TX_CALIB_WAIT_TX_RESPONSE	0x00000002
#define	IWK_TX_CALIB_ENABLED			0x00000004
#define	IWK_TX_CALIB_XVT_ON			0x00000008
#define	IWK_TX_CALIB_TEMPERATURE_CORRECT	0x00000010
#define	IWK_TX_CALIB_WORKING_WITH_XVT	0x00000020
#define	IWK_TX_CALIB_XVT_PERIODICAL		0x00000040

#define	NUM_IWK_TX_CALIB_SETTINS 5	/* Number of tx correction groups */

#define	IWK_MIN_POWER_IN_VP_TABLE 1	/* 0.5dBm multiplied by 2 */
	/* 20dBm - multiplied by 2 - because entries are for each 0.5dBm */
#define	IWK_MAX_POWER_IN_VP_TABLE	40
#define	IWK_STEP_IN_VP_TABLE 1	/* 0.5dB - multiplied by 2 */
#define	IWK_NUM_POINTS_IN_VPTABLE \
	(1 + IWK_MAX_POWER_IN_VP_TABLE - IWK_MIN_POWER_IN_VP_TABLE)

#define	MIN_TX_GAIN_INDEX	(0)
#define	MAX_TX_GAIN_INDEX_52GHZ	(98)
#define	MIN_TX_GAIN_52GHZ	(98)
#define	MAX_TX_GAIN_INDEX_24GHZ	(98)
#define	MIN_TX_GAIN_24GHZ	(98)
#define	MAX_TX_GAIN		(0)

/*
 * Channel groups used for Tx Attenuation calibration (MIMO tx channel balance)
 * and thermal Txpower calibration.
 *
 * When calculating txpower, driver must compensate for current device
 * temperature; higher temperature requires higher gain.  Driver must calculate
 * current temperature (see "4965 temperature calculation"), then compare vs.
 * factory calibration temperature in EEPROM; if current temperature is higher
 * than factory temperature, driver must *increase* gain by proportions shown
 * in table below.  If current temperature is lower than factory, driver must
 * *decrease* gain.
 *
 * Different frequency ranges require different compensation, as shown below.
 */
/*
 * Group 0, 5.2 GHz ch 34-43:  4.5 degrees per 1/2 dB.
 */
#define	CALIB_IWK_TX_ATTEN_GR1_FCH 34
#define	CALIB_IWK_TX_ATTEN_GR1_LCH 43

/*
 * Group 1, 5.3 GHz ch 44-70:  4.0 degrees per 1/2 dB.
 */
#define	CALIB_IWK_TX_ATTEN_GR2_FCH 44
#define	CALIB_IWK_TX_ATTEN_GR2_LCH 70

/*
 * Group 2, 5.5 GHz ch 71-124:  4.0 degrees per 1/2 dB.
 */
#define	CALIB_IWK_TX_ATTEN_GR3_FCH 71
#define	CALIB_IWK_TX_ATTEN_GR3_LCH 124

/*
 * Group 3, 5.7 GHz ch 125-200:  4.0 degrees per 1/2 dB.
 */
#define	CALIB_IWK_TX_ATTEN_GR4_FCH 125
#define	CALIB_IWK_TX_ATTEN_GR4_LCH 200

/*
 * Group 4, 2.4 GHz all channels:  3.5 degrees per 1/2 dB.
 */
#define	CALIB_IWK_TX_ATTEN_GR5_FCH 1
#define	CALIB_IWK_TX_ATTEN_GR5_LCH 20

struct iwk_tx_power {
	uint8_t tx_gain;	/* gain for analog radio */
	uint8_t dsp_atten;	/* gain for DSP */
};

struct tx_power_dual_stream {
	uint16_t ramon_tx_gain;
	uint16_t dsp_predis_atten;
};

union tx_power_dual_stream_u {
	struct tx_power_dual_stream s;
	uint32_t dw;
};

struct iwk_tx_power_db {
	union tx_power_dual_stream_u
	    ht_ofdm_power[POWER_TABLE_NUM_HT_OFDM_ENTRIES];
	union tx_power_dual_stream_u legacy_cck_power;

};

typedef struct iwk_tx_power_table_cmd {
	uint8_t band;
	uint8_t channel_normal_width;
	uint16_t channel;
	struct iwk_tx_power_db tx_power;
} iwk_tx_power_table_cmd_t;

typedef struct iwk_channel_switch_cmd {
	uint8_t band;
	uint8_t expect_beacon;
	uint16_t channel;
	uint32_t rxon_flags;
	uint32_t rxon_filter_flags;
	uint32_t switch_time;
	struct iwk_tx_power_db tx_power;
} iwk_channel_switch_cmd_t;

struct iwk_channel_switch_notif {
	uint16_t band;
	uint16_t channel;
	uint32_t status;
};

/*
 * END TXPOWER
 */

/*
 * HT flags
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

#define	MCS_DUP_6M_PLCP 0x20

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

struct iwk_link_qual_general_params {
	uint8_t flags;
	uint8_t mimo_delimiter;
	uint8_t single_stream_ant_msk;
	uint8_t dual_stream_ant_msk;
	uint8_t start_rate_index[LINK_QUAL_AC_NUM];
};

struct iwk_link_qual_agg_params {
	uint16_t agg_time_limit;
	uint8_t agg_dis_start_th;
	uint8_t agg_frame_cnt_limit;
	uint32_t reserved;
};

typedef struct iwk_link_quality_cmd {
	uint8_t sta_id;
	uint8_t reserved1;
	uint16_t control;
	struct iwk_link_qual_general_params general_params;
	struct iwk_link_qual_agg_params agg_params;
	uint32_t rate_n_flags[LINK_QUAL_MAX_RETRY_NUM];
	uint32_t reserved2;
} iwk_link_quality_cmd_t;

typedef struct iwk_rx_phy_res {
	uint8_t non_cfg_phy_cnt;  /* non configurable DSP phy data byte count */
	uint8_t cfg_phy_cnt;	/* configurable DSP phy data byte count */
	uint8_t stat_id;	/* configurable DSP phy data set ID */
	uint8_t reserved1;
	uint32_t timestampl; /* TSF at on air rise */
	uint32_t timestamph;
	uint32_t beacon_time_stamp; /* beacon at on-air rise */
	uint16_t phy_flags;	/* general phy flags: band, modulation, ... */
	uint16_t channel;		/* channel number */
	uint16_t non_cfg_phy[RX_RES_PHY_CNT];	/* upto 14 phy entries */
	uint32_t reserved2;
	struct iwk_rate rate;	/* rate in ucode internal format */
	uint16_t byte_count;		/* frame's byte-count */
	uint16_t reserved3;
} iwk_rx_phy_res_t;

struct iwk_rx_mpdu_res_start {
	uint16_t byte_count;
	uint16_t reserved;
};

#define	IWK_AGC_DB_MASK 	(0x3f80)	/* MASK(7,13) */
#define	IWK_AGC_DB_POS	(7)

/*
 * Fixed (non-configurable) rx data from phy
 */
struct iwk_rx_non_cfg_phy {
	uint16_t ant_selection;	/* ant A bit 4, ant B bit 5, ant C bit 6 */
	uint16_t agc_info;	/* agc code 0:6, agc dB 7:13, reserved 14:15 */
	uint8_t rssi_info[6];	/* we use even entries, 0/2/4 for A/B/C rssi */
	uint8_t pad[2];
};

/*
 * Byte Count Table Entry
 *
 * Bit fields:
 * 15-12: reserved
 * 11- 0: total to-be-transmitted byte count of frame (does not include command)
 */
struct iwk_queue_byte_cnt_entry {
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
 * 4965 assumes tables are separated by 1024 bytes.
 */
struct iwk_sched_queue_byte_cnt_tbl {
	struct iwk_queue_byte_cnt_entry tfd_offset[IWK_QUEUE_SIZE +
	    IWK_MAX_WIN_SIZE];
	uint8_t dont_care[1024 - (IWK_QUEUE_SIZE + IWK_MAX_WIN_SIZE) *
	    sizeof (uint16_t)];
};

/*
 * struct iwk_shared, handshake area for Tx and Rx
 *
 * For convenience in allocating memory, this structure combines 2 areas of
 * DRAM which must be shared between driver and 4965.  These do not need to
 * be combined, if better allocation would result from keeping them separate:
 * TODO:  Split these; carried over from 3945, doesn't work well for 4965.
 *
 * 1)  The Tx byte count tables occupy 1024 bytes each (16 KBytes total for
 *     16 queues).  Driver uses SCD_DRAM_BASE_ADDR to tell 4965 where to find
 *     the first of these tables.  4965 assumes tables are 1024 bytes apart.
 *
 * 2)  The Rx status (val0 and val1) occupies only 8 bytes.  Driver uses
 *     FH_RSCSR_CHNL0_STTS_WPTR_REG to tell 4965 where to find this area.
 *     Driver reads val0 to determine the latest Receive Buffer Descriptor (RBD)
 *     that has been filled by the 4965.
 *
 * Bit fields val0:
 * 31-12:  Not used
 * 11- 0:  Index of last filled Rx buffer descriptor (4965 writes, driver reads)
 *
 * Bit fields val1:
 * 31- 0:  Not used
 */
typedef struct iwk_shared {
	struct iwk_sched_queue_byte_cnt_tbl
	    queues_byte_cnt_tbls[IWK_NUM_QUEUES];
	uint32_t val0;
	uint32_t val1;
	uint32_t padding1;  /* so that allocation will be aligned to 16B */
	uint32_t padding2;
} iwk_shared_t;


/*
 * struct iwk_tfd_frame_data
 *
 * Describes up to 2 buffers containing (contiguous) portions of a Tx frame.
 * Each buffer must be on dword boundary.
 * Up to 10 iwk_tfd_frame_data structures, describing up to 20 buffers,
 * may be filled within a TFD (iwk_tfd_frame).
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
struct iwk_tfd_frame_data {
		uint32_t tb1_addr;
		uint32_t val1;
		uint32_t val2;
};

typedef struct iwk_tx_desc {
	uint32_t	val0;
	struct iwk_tfd_frame_data pa[10];
	uint32_t reserved;
} iwk_tx_desc_t;

typedef struct iwk_tx_stat {
	uint8_t		frame_count;
	uint8_t		bt_kill_count;
	uint8_t		nrts;
	uint8_t		ntries;
	struct iwk_rate rate;
	uint16_t	duration;
	uint16_t	reserved;
	uint32_t	pa_power1;
	uint32_t	pa_power2;
	uint32_t	status;
} iwk_tx_stat_t;

struct iwk_cmd_header {
	uint8_t		type;
	uint8_t		flags;
	uint8_t		idx;
	uint8_t		qid;
};

typedef struct iwk_rx_desc {
	uint32_t	len;
	struct iwk_cmd_header hdr;
} iwk_rx_desc_t;

typedef struct iwk_rx_stat {
	uint8_t		len;
	uint8_t		id;
	uint8_t		rssi;	/* received signal strength */
	uint8_t		agc;	/* access gain control */
	uint16_t	signal;
	uint16_t	noise;
} iwk_rx_stat_t;

typedef struct iwk_rx_head {
	uint16_t	chan;
	uint16_t	flags;
	uint8_t		reserved;
	uint8_t		rate;
	uint16_t	len;
} iwk_rx_head_t;

typedef struct iwk_rx_tail {
	uint32_t	flags;
	uint32_t	timestampl;
	uint32_t	timestamph;
	uint32_t	tbeacon;
} iwk_rx_tail_t;

enum {
	IWK_AP_ID = 0,
	IWK_MULTICAST_ID,
	IWK_STA_ID,
	IWK_BROADCAST_ID = 31,
	IWK_STATION_COUNT = 32,
	IWK_INVALID_STATION
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
	REPLY_4965_RX = 0xc3,
	REPLY_RX_PHY_CMD = 0xc0,
	REPLY_RX_MPDU_CMD = 0xc1,
	REPLY_COMPRESSED_BA = 0xc5,
	REPLY_MAX = 0xff
};

typedef struct iwk_cmd {
	struct iwk_cmd_header hdr;
	uint8_t	data[1024];
} iwk_cmd_t;

/*
 * Alive Command & Response
 */
#define	UCODE_VALID_OK		(0x1)
#define	INITIALIZE_SUBTYPE	(9)

struct iwk_alive_resp {
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

struct iwk_init_alive_resp {
	struct iwk_alive_resp s;
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
	RXON_FLG_TSF2HOST_MSK = (1 << 15)
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
typedef struct iwk_rxon_cmd {
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
} iwk_rxon_cmd_t;

typedef struct iwk_compressed_ba_resp {
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
} iwk_compressed_ba_resp_t;

#define	PHY_CALIBRATE_DIFF_GAIN_CMD	(7)
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

typedef struct iwk_sensitivity_cmd {
	uint16_t control;
	uint16_t table[HD_TABLE_SIZE];
} iwk_sensitivity_cmd_t;

typedef struct iwk_calibration_cmd {
	uint8_t opCode;
	uint8_t flags;
	uint16_t reserved;
	char diff_gain_a;
	char diff_gain_b;
	char diff_gain_c;
	uint8_t reserved1;
} iwk_calibation_cmd_t;

typedef struct iwk_missed_beacon_notif {
	uint32_t consequtive_missed_beacons;
	uint32_t total_missed_becons;
	uint32_t num_expected_beacons;
	uint32_t num_recvd_beacons;
} iwk_missed_beacon_notif_t;

typedef struct iwk_ct_kill_config {
	uint32_t   reserved;
	uint32_t   critical_temperature_M;
	uint32_t   critical_temperature_R;
} iwk_ct_kill_config_t;

/*
 * structure for command IWK_CMD_ASSOCIATE
 */
typedef struct iwk_assoc {
	uint32_t	flags;
	uint32_t	filter;
	uint8_t		ofdm_mask;
	uint8_t		cck_mask;
	uint8_t		ofdm_ht_single_stream_basic_rates;
	uint8_t		ofdm_ht_dual_stream_basic_rates;
	uint16_t	rx_chain_select_flags;
	uint16_t	reserved;
} iwk_assoc_t;

/*
 * structure for command IWK_CMD_SET_WME
 */
typedef struct iwk_wme_setup {
	uint32_t	flags;
	struct {
		uint16_t	cwmin;
		uint16_t	cwmax;
		uint8_t		aifsn;
		uint8_t		reserved;
		uint16_t	txop;
	} ac[WME_NUM_AC];
} iwk_wme_setup_t;

/*
 * structure for command IWK_CMD_TSF
 */
typedef struct iwk_cmd_tsf {
	uint32_t	timestampl;
	uint32_t	timestamph;
	uint16_t	bintval;
	uint16_t	atim;
	uint32_t	binitval;
	uint16_t	lintval;
	uint16_t	reserved;
} iwk_cmd_tsf_t;

/*
 * structure for IWK_CMD_ADD_NODE
 */
typedef struct iwk_add_sta {
	uint8_t		control;
	uint8_t		reserved1[3];
	uint8_t		bssid[IEEE80211_ADDR_LEN];
	uint16_t	reserved2;
	uint8_t		id;
	uint8_t		sta_mask;
	uint16_t	reserved3;
	uint16_t	key_flags;
	uint8_t		tkip;
	uint8_t		reserved4;
	uint16_t	ttak[5];
	uint8_t		keyp;
	uint8_t		reserved5;
	uint8_t		key[16];
	uint32_t	flags;
	uint32_t	mask;
	uint16_t	tid;
	union		{
		struct {
			uint8_t rate;
			uint8_t flags;
		} s;
		uint16_t	rate_n_flags;
	} tx_rate;
	uint8_t		add_imm;
	uint8_t		del_imm;
	uint16_t	add_imm_start;
	uint32_t	reserved7;
} iwk_add_sta_t;

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
 * TX command security control
 */
#define	TX_CMD_SEC_CCM		0x2
#define	TX_CMD_SEC_TKIP		0x3

/*
 * structure for command IWK_CMD_TX_DATA
 */
typedef struct iwk_tx_cmd {
	uint16_t len;
	uint16_t next_frame_len;
	uint32_t tx_flags;
	struct iwk_dram_scratch scratch;
	struct iwk_rate rate;
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
} iwk_tx_cmd_t;

/*
 * structure for command "TX beacon"
 */
typedef struct iwk_tx_beacon_cmd {
	iwk_tx_cmd_t	config;
	uint16_t	tim_idx;
	uint8_t		tim_size;
	uint8_t		reserved;
	uint8_t		bcon_frame[2342];
} iwk_tx_beacon_cmd_t;

/*
 * LEDs Command & Response
 * REPLY_LEDS_CMD = 0x48 (command, has simple generic response)
 *
 * For each of 3 possible LEDs (Activity/Link/Tech, selected by "id" field),
 * this command turns it on or off, or sets up a periodic blinking cycle.
 */
typedef struct iwk_led_cmd {
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
} iwk_led_cmd_t;

/*
 * structure for IWK_CMD_SET_POWER_MODE
 */
typedef struct iwk_powertable_cmd {
	uint16_t	flags;
	uint8_t		keep_alive_seconds;
	uint8_t		debug_flags;
	uint32_t	rx_timeout;
	uint32_t	tx_timeout;
	uint32_t	sleep[5];
	uint32_t	keep_alive_beacons;
} iwk_powertable_cmd_t;

struct iwk_ssid_ie {
	uint8_t id;
	uint8_t len;
	uint8_t ssid[32];
};
/*
 * structure for command IWK_CMD_SCAN
 */
typedef struct iwk_scan_hdr {
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
		 * 3945 -- 31:24 # beacons, 19:0 additional usec,
		 * 4965 -- 31:22 # beacons, 21:0 additional usec.
		 */
	uint32_t suspend_time;
	uint32_t flags;
	uint32_t filter_flags;
	struct	 iwk_tx_cmd tx_cmd;
	struct	 iwk_ssid_ie direct_scan[4];
	/* followed by probe request body */
	/* followed by nchan x iwk_scan_chan */
} iwk_scan_hdr_t;

typedef struct iwk_scan_chan {
	uint8_t		type;
	uint8_t		chan;
	struct iwk_tx_power	tpc;
	uint16_t	active_dwell;	/* dwell time */
	uint16_t	passive_dwell;	/* dwell time */
} iwk_scan_chan_t;

/*
 * structure for IWK_CMD_BLUETOOTH
 */
typedef struct iwk_bt_cmd {
	uint8_t		flags;
	uint8_t		lead_time;
	uint8_t		max_kill;
	uint8_t		reserved;
	uint32_t	kill_ack_mask;
	uint32_t	kill_cts_mask;
} iwk_bt_cmd_t;

/*
 * firmware image header
 */
typedef struct iwk_firmware_hdr {
	uint32_t	version;
	uint32_t	textsz;
	uint32_t	datasz;
	uint32_t	init_textsz;
	uint32_t	init_datasz;
	uint32_t	bootsz;
} iwk_firmware_hdr_t;

/*
 * structure for IWK_START_SCAN notification
 */
typedef struct iwk_start_scan {
	uint32_t	timestampl;
	uint32_t	timestamph;
	uint32_t	tbeacon;
	uint8_t		chan;
	uint8_t		band;
	uint16_t	reserved;
	uint32_t	status;
} iwk_start_scan_t;

/*
 * structure for IWK_SCAN_COMPLETE notification
 */
typedef struct iwk_stop_scan {
	uint8_t		nchan;
	uint8_t		status;
	uint8_t		reserved;
	uint8_t		chan;
	uint64_t	tsf;
} iwk_stop_scan_t;

#define	IWK_READ(sc, reg)						\
	ddi_get32((sc)->sc_handle, (uint32_t *)((sc)->sc_base + (reg)))

#define	IWK_WRITE(sc, reg, val)					\
	ddi_put32((sc)->sc_handle, (uint32_t *)((sc)->sc_base + (reg)), (val))

#ifdef __cplusplus
}
#endif

#endif /* _IWK_HW_H_ */
