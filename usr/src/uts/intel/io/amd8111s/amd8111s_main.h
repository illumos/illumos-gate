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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef AMD8111S_MAIN_H
#define	AMD8111S_MAIN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 2001-2006 Advanced Micro Devices, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * + Redistributions of source code must retain the above copyright notice,
 * + this list of conditions and the following disclaimer.
 *
 * + Redistributions in binary form must reproduce the above copyright
 * + notice, this list of conditions and the following disclaimer in the
 * + documentation and/or other materials provided with the distribution.
 *
 * + Neither the name of Advanced Micro Devices, Inc. nor the names of its
 * + contributors may be used to endorse or promote products derived from
 * + this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL ADVANCED MICRO DEVICES, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Import/Export/Re-Export/Use/Release/Transfer Restrictions and
 * Compliance with Applicable Laws.  Notice is hereby given that
 * the software may be subject to restrictions on use, release,
 * transfer, importation, exportation and/or re-exportation under
 * the laws and regulations of the United States or other
 * countries ("Applicable Laws"), which include but are not
 * limited to U.S. export control laws such as the Export
 * Administration Regulations and national security controls as
 * defined thereunder, as well as State Department controls under
 * the U.S. Munitions List.  Permission to use and/or
 * redistribute the software is conditioned upon compliance with
 * all Applicable Laws, including U.S. export control laws
 * regarding specifically designated persons, countries and
 * nationals of countries subject to national security controls.
 */


#pragma ident "@(#)$RCSfile: odl.h,v $ $Revision: 1.1 $  " \
"$Date: 2004/04/22 15:22:52 $ AMD"

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/note.h>
#include <sys/modctl.h>

#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>

#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/pci.h>

#include <sys/ethernet.h>
#include <sys/dlpi.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/netlb.h>
#include "amd8111s_hw.h"

#define	MEM_REQ_MAX		100
#define	MEMSET			4

#define	IOC_LINESIZE	40

/*
 * Loopback definitions
 */
#define	AMD8111S_LB_NONE			0
#define	AMD8111S_LB_EXTERNAL_1000		1
#define	AMD8111S_LB_EXTERNAL_100		2
#define	AMD8111S_LB_EXTERNAL_10			3
#define	AMD8111S_LB_INTERNAL_PHY		4
#define	AMD8111S_LB_INTERNAL_MAC		5

/* ((2 ^ (32 - 1)) * 8) / (10 ^ 8) >= 100 */
#define	AMD8111S_DUMP_MIB_SECONDS_THRESHOLD	100
#define	AMD8111S_DUMP_MIB_BYTES_THRESHOLD	0x80000000

/* Bit flags for 'attach_progress' */
#define	AMD8111S_ATTACH_PCI		0x0001	/* pci_config_setup() */
#define	AMD8111S_ATTACH_RESOURCE	0x0002	/* odlInit() */
#define	AMD8111S_ATTACH_REGS		0x0004	/* ddi_regs_map_setup() */
#define	AMD8111S_ATTACH_INTRADDED	0x0010	/* intr_add() */
#define	AMD8111S_ATTACH_MACREGED	0x0020	/* mac_register() */
#define	AMD8111S_ATTACH_RESCHED		0x0040	/* soft_intr() */

#define	AMD8111S_TRY_SEND		0x0001
#define	AMD8111S_SEND_READY		0x0002

#define	NEXT(buf, ptr) \
	(buf.ptr + 1 >= buf.msg_buf + \
	buf.ring_size ? \
	buf.msg_buf : \
	buf.ptr + 1)
/*
 * (Internal) return values from ioctl subroutines
 */
enum ioc_reply {
	IOC_INVAL = -1,				/* bad, NAK with EINVAL	*/
	IOC_DONE,				/* OK, reply sent	*/
	IOC_ACK,				/* OK, just send ACK	*/
	IOC_REPLY,				/* OK, just send reply	*/
	IOC_RESTART_ACK,			/* OK, restart & ACK	*/
	IOC_RESTART_REPLY			/* OK, restart & reply	*/
};

typedef int (*TIMERfUNC) (struct LayerPointers *);

struct TimerStructure {
	int Type;
	int Period;	/* in milliseconds */
	timeout_id_t TimerHandle;
	int (*TimerFunptr)(struct LayerPointers *);
	struct LayerPointers *pLayerPointers;
};

struct amd8111s_statistics
{
	uint64_t intr_TINT0;	/* # of TINT0 (Tx interrupts) */
	uint64_t intr_RINT0;	/* # of RINT0 (Rx interrupts) */
	uint64_t intr_STINT;	/* # of STINT (Software Timer Intr) */
	uint64_t intr_OTHER;	/* Intr caused by other device */

	uint64_t tx_ok_packets;
	uint64_t tx_no_descriptor;
	uint64_t tx_no_buffer;
	uint64_t tx_rescheduled;
	uint64_t tx_unrescheduled;

	/* # of call amd8111s_dump_mib function */
	uint64_t mib_dump_counter;

	/*
	 * From MIB registers (TX)
	 */
	uint64_t tx_mib_packets;		/* # of packets */
	uint64_t tx_mib_multicst_packets;	/* # of multicast packets */
	uint64_t tx_mib_broadcst_packets;	/* # of broadcast packets */
	uint64_t tx_mib_flowctrl_packets;	/* # of flow ctrl packets */

	uint64_t tx_mib_bytes;			/* # of all Tx bytes */

	/* Packet drop due to Tx FIFO underrun */
	uint64_t tx_mib_underrun_packets;
	uint64_t tx_mib_collision_packets;
	/* Packets successfully transmitted after experiencing one collision */
	uint64_t tx_mib_one_coll_packets;
	uint64_t tx_mib_multi_coll_packets;
	/* # of late collisions that occur */
	uint64_t tx_mib_late_coll_packets;
	uint64_t tx_mib_ex_coll_packets;	/* excessive collision */
	uint64_t tx_mib_oversize_packets;
	uint64_t tx_mib_defer_trans_packets;	/* defer transmit */


	/*
	 * Some error counter after "ifconfig amd8111sX unplumb"
	 */
	/*
	 * Count Tx mp number from GLD even after NIC has been unplumbed.
	 * This value should always be 0.
	 */
	uint64_t tx_afterunplumb;
	/*
	 * We drain all pending tx packets during unplumb operation. This
	 * variable is to count the drain time.
	 *	30 means success; =30 means fail
	 */
	uint64_t tx_draintime;

	uint64_t rx_ok_packets;		/* # of all good packets */
	uint64_t rx_allocfail;		/* alloc memory fail during Rx */
	uint64_t rx_error_zerosize;

	uint64_t rx_0_packets;
	uint64_t rx_1_15_packets;
	uint64_t rx_16_31_packets;
	uint64_t rx_32_47_packets;
	uint64_t rx_48_63_packets;
	uint64_t rx_double_overflow;

	uint64_t rx_desc_err;
	uint64_t rx_desc_err_FRAM;	/* Framing error */
	uint64_t rx_desc_err_OFLO;	/* Overflow error */
	uint64_t rx_desc_err_CRC;	/* CRC error */
	uint64_t rx_desc_err_BUFF;	/* BCRC error */

	/*
	 * From MIB registers (RX)
	 */
	uint64_t rx_mib_unicst_packets;		/* # of unicast packets */
	uint64_t rx_mib_multicst_packets;	/* # of multicast packets */
	uint64_t rx_mib_broadcst_packets;	/* # of broadcast packets */
	uint64_t rx_mib_macctrl_packets;	/* # of mac ctrl packets */
	uint64_t rx_mib_flowctrl_packets;	/* # of flow ctrl packets */

	uint64_t rx_mib_bytes;			/* # of all Rx bytes */
	uint64_t rx_mib_good_bytes;			/* # of all Rx bytes */
	/*
	 * The total number of valid frames received that are less than 64
	 * bytes long (include the FCS).
	 */
	uint64_t rx_mib_undersize_packets;
	/*
	 * The total number of valid frames received that are greater than the
	 * maximum valid frame size (include the FCS).
	 */
	uint64_t rx_mib_oversize_packets;

	uint64_t rx_mib_align_err_packets;
	uint64_t rx_mib_fcs_err_packets;	/* has a bad FCS */
	/* Invalid data symbol (RX_ER) */
	uint64_t rx_mib_symbol_err_packets;
	/* Packets that were dropped because no descriptor was available */
	uint64_t rx_mib_drop_packets;
	/*
	 * Packets that were dropped due to lack of resources. This includes
	 * the number of times a packet was dropped due to receive FIFO
	 * overflow and lack of receive descriptor.
	 */
	uint64_t rx_mib_miss_packets;
};

struct amd8111s_msgbuf {
	uint64_t phy_addr;
	caddr_t vir_addr;
	uint32_t msg_size;
	ddi_dma_handle_t p_hdl;
	uint32_t offset;
};

struct amd8111s_dma_ringbuf {
	ddi_dma_handle_t *dma_hdl;
	ddi_acc_handle_t *acc_hdl;
	ddi_dma_cookie_t *dma_cookie;
	caddr_t		 *trunk_addr;
	uint32_t buf_sz;
	uint32_t trunk_sz;
	uint32_t trunk_num;
	struct amd8111s_msgbuf	*msg_buf;
	uint32_t ring_size;
	uint32_t dma_buf_sz;
	struct amd8111s_msgbuf *free;
	struct amd8111s_msgbuf *next;
	struct amd8111s_msgbuf *curr;

	kmutex_t ring_lock;
};

struct odl {
	dev_info_t *devinfo;

	mac_handle_t mh;		/* mac module handle */
	mac_resource_handle_t mrh;

	struct amd8111s_statistics statistics;

	/* Locks */
	kmutex_t mdlSendLock;
	kmutex_t mdlRcvLock;
	kmutex_t timer_lock;
	kmutex_t send_cv_lock;
	kcondvar_t send_cv;

	ddi_softintr_t drain_id;
	/*
	 * The chip_lock assures that the Rx/Tx process must be stopped while
	 * other functions change the hardware configuration, such as attach()
	 * detach() etc are executed.
	 */
	krwlock_t chip_lock;

	/*
	 * HW operators and parameters on attach period
	 */
	ddi_iblock_cookie_t iblock;	/* HW: interrupt block cookie */
	ddi_acc_handle_t MemBasehandle;

	/* For pci configuration */
	ddi_acc_handle_t pci_handle;	/* HW: access handle of PCI space */
	uint16_t vendor_id;
	uint16_t device_id;

	/*
	 * FreeQ: Transfer Rx Buffer parameters from top layer to low layers.
	 * Format of parameter:
	 *	(struct RxBufInfo *, physical address)
	 */
	unsigned long FreeQ[2 * RX_RING_SIZE];
	unsigned long *FreeQStart;
	unsigned long *FreeQEnd;
	long *FreeQWrite;
	long *FreeQRead;

	/* For Rx descriptors */
	ddi_dma_handle_t rx_desc_dma_handle;
	ddi_acc_handle_t rx_desc_acc_handle;
	ddi_dma_cookie_t rx_desc_dma_cookie;

	/* For Tx descriptors */
	ddi_dma_handle_t tx_desc_dma_handle;
	ddi_acc_handle_t tx_desc_acc_handle;
	ddi_dma_cookie_t tx_desc_dma_cookie;

	/* For Tx buffers */
	struct amd8111s_dma_ringbuf tx_buf;

	/* For Rx buffers */
	struct amd8111s_dma_ringbuf rx_buf;

	ether_addr_t MacAddress;	/* Mac address */

	/* Multicast addresses table */
	UCHAR MulticastAddresses
	    [MAX_MULTICAST_ADDRESSES][ETH_LENGTH_OF_ADDRESS];

	link_state_t LinkStatus;

	/* Timer */
	timeout_id_t Timer_id;
	int (*TimerFunc)(struct LayerPointers *);
	int timer_run;
	int timer_linkdown;

	unsigned int dump_mib_seconds;

	uint32_t loopback_mode;
	unsigned int rx_fcs_stripped;

	unsigned int rx_overflow_counter;
	unsigned int pause_interval;

};

#endif	/* AMD8111S_MAIN_H */
