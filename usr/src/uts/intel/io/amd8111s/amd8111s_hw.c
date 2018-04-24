/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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


#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include "amd8111s_hw.h"
#include "amd8111s_main.h"


#pragma inline(mdlTransmit)
#pragma inline(mdlReceive)

#pragma inline(mdlReadInterrupt)
#pragma inline(mdlEnableInterrupt)
#pragma inline(mdlDisableInterrupt)


static void mdlEnableMagicPacketWakeUp(struct LayerPointers *);

/* PMR (Pattern Match RAM) */
static void mdlAddWakeUpPattern(struct LayerPointers *, unsigned char *,
    unsigned char *, unsigned long, unsigned long, int *);
static void mdlRemoveWakeUpPattern(struct LayerPointers *, unsigned char *,
    unsigned long, int *);

static int mdlMulticastBitMapping(struct LayerPointers *, unsigned char *, int);

static unsigned int mdlCalculateCRC(unsigned int, unsigned char *);

static void mdlChangeFilter(struct LayerPointers *, unsigned long *);
static void mdlReceiveBroadCast(struct LayerPointers *);
static void mdlDisableReceiveBroadCast(struct LayerPointers *);

static void mdlRequestResources(ULONG *);
static void mdlSetResources(struct LayerPointers *, ULONG *);
static void mdlFreeResources(struct LayerPointers *, ULONG *);

/*
 *	Initialises the data used in Mdl.
 */
static void
mdlInitGlbds(struct LayerPointers *pLayerPointers)
{
	struct mdl *pMdl = pLayerPointers->pMdl;

	/* Disable Rx and Tx. */
	pMdl->init_blk->MODE = 0x0000;

	/* Set Interrupt Delay Parameters */
	pMdl->IntrCoalescFlag = 1;
	pMdl->rx_intrcoalesc_time = 0xC8;	/* 200 */
	pMdl->rx_intrcoalesc_events = 5;
}

void
mdlPHYAutoNegotiation(struct LayerPointers *pLayerPointers, unsigned int type)
{
	int iData = 0;
	struct mdl *pMdl = pLayerPointers->pMdl;

	/* PHY auto negotiation or force speed/duplex */
	switch (type) {
	case PHY_AUTO_NEGOTIATION: /* Auto Negotiation */
		/* EN_PMGR: Disable the Port Manager */
		WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CMD3, EN_PMGR);
		drv_usecwait(100000);

		/*
		 * Enable Autonegotiation the Phy now
		 *	XPHYANE(eXternal PHY Auto Negotiation Enable)
		 */
		WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CTRL2,
		    XPHYANE | XPHYRST);

		/* EN_PMGR: Enable the Port Manager */
		WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CMD3,
		    VAL1 | EN_PMGR);

		drv_usecwait(500000);

		pMdl->Speed = 100;
		pMdl->FullDuplex = B_TRUE;

		break;

	case PHY_FORCE_HD_100:	/* 100Mbps HD */
		WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CMD3, EN_PMGR);

		/* Force 100 Mbps, half duplex */
		iData |= XPHYSP;
		WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CTRL2, iData);

		WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CMD3,
		    VAL1 | EN_PMGR);

		drv_usecwait(500000);

		pMdl->Speed = 100;
		pMdl->FullDuplex = B_FALSE;

		break;

	case PHY_FORCE_FD_100:	/* 100Mbps FD */
		WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CMD3, EN_PMGR);

		/* Force 100 Mbps, full duplex */
		iData |= (XPHYSP | XPHYFD);
		WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CTRL2, iData);

		WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CMD3,
		    VAL1 | EN_PMGR);

		drv_usecwait(500000);

		pMdl->Speed = 100;
		pMdl->FullDuplex = B_TRUE;

		break;

	case PHY_FORCE_HD_10: /* 10 Mbps HD  */
		/* Disable the Port Manager */
		WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CMD3, EN_PMGR);
		WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CTRL2, iData);
		WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CMD3,
		    VAL1 | EN_PMGR);

		drv_usecwait(500000);

		pMdl->Speed = 10;
		pMdl->FullDuplex = B_FALSE;

		break;

	case PHY_FORCE_FD_10: /* 10Mbps FD  */
		WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CMD3, EN_PMGR);

		iData |= XPHYFD;
		WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CTRL2, iData);

		WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CMD3,
		    VAL1 | EN_PMGR);

		drv_usecwait(500000);

		pMdl->Speed = 10;
		pMdl->FullDuplex = B_TRUE;

		break;
	}
}

/*
 *	Clear HW configuration.
 */
static void
mdlClearHWConfig(struct LayerPointers *pLayerPointers)
{
	/*
	 * Before the network controller is ready for operation,
	 * several registers must be initialized.
	 */
	unsigned int data32;
	int JumboFlag = JUMBO_DISABLED;
	ULONG MemBaseAddress;

	MemBaseAddress = pLayerPointers->pMdl->Mem_Address;

	/* AUTOPOLL0 Register */
	WRITE_REG16(pLayerPointers, MemBaseAddress + AUTOPOLL0, 0x8101);

	/* Clear RCV_RING_BASE_ADDR */
	WRITE_REG32(pLayerPointers, MemBaseAddress + RCV_RING_BASE_ADDR0, 0);
	WRITE_REG32(pLayerPointers, MemBaseAddress + RCV_RING_BASE_ADDR1, 0);
	WRITE_REG32(pLayerPointers, MemBaseAddress + RCV_RING_BASE_ADDR0, 0);
	WRITE_REG32(pLayerPointers, MemBaseAddress + RCV_RING_BASE_ADDR2, 0);
	WRITE_REG32(pLayerPointers, MemBaseAddress + RCV_RING_BASE_ADDR3, 0);

	/* Clear XMT_RING_BASE_ADDR */
	WRITE_REG32(pLayerPointers, MemBaseAddress + XMT_RING_BASE_ADDR0, 0);
	WRITE_REG32(pLayerPointers, MemBaseAddress + XMT_RING_BASE_ADDR1, 0);
	WRITE_REG32(pLayerPointers, MemBaseAddress + XMT_RING_BASE_ADDR2, 0);
	WRITE_REG32(pLayerPointers, MemBaseAddress + XMT_RING_BASE_ADDR3, 0);

	/* Clear CMD0 / CMD2 */
	WRITE_REG32(pLayerPointers, MemBaseAddress + CMD0, 0x000F0F7F);
	WRITE_REG32(pLayerPointers, MemBaseAddress + CMD2, 0x3F7F3F7F);

	/* Enable Port Management */
	WRITE_REG32(pLayerPointers, MemBaseAddress + CMD3, VAL1 | EN_PMGR);

	/* Clear CMD7 */
	WRITE_REG32(pLayerPointers, MemBaseAddress + CMD7, 0x1B);

	/* Clear CTRL0/1 */
	WRITE_REG32(pLayerPointers, MemBaseAddress + CTRL1, XMTSP_MASK);

	/* Clear DLY_INT_A/B */
	WRITE_REG32(pLayerPointers, MemBaseAddress + DLY_INT_A, 0);
	WRITE_REG32(pLayerPointers, MemBaseAddress + DLY_INT_B, 0);

	/* Clear FLOW_CONTROL */
	WRITE_REG32(pLayerPointers, MemBaseAddress + FLOW_CONTROL, 0);

	/* Clear INT0 */
	data32 = READ_REG32(pLayerPointers, MemBaseAddress + INT0);
	WRITE_REG32(pLayerPointers, MemBaseAddress + INT0, data32);

	/* Clear STVAL */
	WRITE_REG32(pLayerPointers, MemBaseAddress + STVAL, 0);

	/* Clear INTEN0 */
	WRITE_REG32(pLayerPointers, MemBaseAddress + INTEN0, 0x1F7F7F1F);

	/* Clear LADRF */
	WRITE_REG32(pLayerPointers, MemBaseAddress + LADRF1, 0);
	WRITE_REG32(pLayerPointers, MemBaseAddress + LADRF1 + 4, 0);

	/* Clear LED0 */
	WRITE_REG32(pLayerPointers, MemBaseAddress + LED0, 0);
	WRITE_REG32(pLayerPointers, MemBaseAddress + LED1, 0);
	WRITE_REG32(pLayerPointers, MemBaseAddress + LED2, 0);
	WRITE_REG32(pLayerPointers, MemBaseAddress + LED3, 0);

	/* Set RCV_RING_CFG */
	WRITE_REG16(pLayerPointers, MemBaseAddress + RCV_RING_CFG, 1);

	/* SRAM_SIZE & SRAM_BOUNDARY register combined */
	if (JumboFlag == JUMBO_ENABLED) {
		WRITE_REG32(pLayerPointers, MemBaseAddress + SRAM_SIZE,
		    0xc0010);
	} else {
		WRITE_REG32(pLayerPointers, MemBaseAddress + SRAM_SIZE,
		    0x80010);
	}

	/* Clear XMT_RING0/1/2/3_LEN */
	WRITE_REG32(pLayerPointers, MemBaseAddress + XMT_RING_LEN0, 0);
	WRITE_REG32(pLayerPointers, MemBaseAddress + XMT_RING_LEN1, 0);
	WRITE_REG32(pLayerPointers, MemBaseAddress + XMT_RING_LEN2, 0);
	WRITE_REG32(pLayerPointers, MemBaseAddress + XMT_RING_LEN3, 0);

	/* Clear XMT_RING_LIMIT */
	WRITE_REG32(pLayerPointers, MemBaseAddress + XMT_RING_LIMIT, 0);

	WRITE_REG16(pLayerPointers, MemBaseAddress + MIB_ADDR, MIB_CLEAR);
}

unsigned int
mdlReadMib(struct LayerPointers *pLayerPointers, char MIB_COUNTER)
{
	unsigned int status;
	unsigned int data;
	unsigned long mmio = pLayerPointers->pMdl->Mem_Address;

	WRITE_REG16(pLayerPointers, mmio + MIB_ADDR, MIB_RD_CMD | MIB_COUNTER);
	do {
		status = READ_REG16(pLayerPointers, mmio + MIB_ADDR);
	} while ((status & MIB_CMD_ACTIVE));

	data = READ_REG32(pLayerPointers, mmio + MIB_DATA);
	return (data);
}

/* Return 1 on success, return 0 on fail */
unsigned int
mdlReadPHY(struct LayerPointers *pLayerPointers, unsigned char phyid,
    unsigned char regaddr, unsigned int *value)
{
	unsigned int status, data, count;
	unsigned long mmio = pLayerPointers->pMdl->Mem_Address;

	count = 0;
	do {
		status = READ_REG16(pLayerPointers, mmio + PHY_ACCESS);
		count ++;
		drv_usecwait(10);
	} while ((status & PHY_CMD_ACTIVE) & (count < PHY_MAX_RETRY));

	if (count == PHY_MAX_RETRY) {
		return (0);
	}

	data = ((regaddr & 0x1f) << 16) | ((phyid & 0x1f) << 21) | PHY_RD_CMD;
	WRITE_REG32(pLayerPointers, mmio + PHY_ACCESS, data);
	do {
		status = READ_REG16(pLayerPointers, mmio + PHY_ACCESS);
		drv_usecwait(10);
		count ++;
	} while ((status & PHY_CMD_ACTIVE) & (count < PHY_MAX_RETRY));

	if ((count == PHY_MAX_RETRY) || (status & PHY_RD_ERR)) {
		return (0);
	}

	*value = status & 0xffff;
	return (1);
}

void
mdlGetPHYID(struct LayerPointers *pLayerPointers)
{
	unsigned int id1, id2, i;
	for (i = 1; i < 32; i++) {
		if (mdlReadPHY(pLayerPointers, i, MII_PHYSID1, &id1) == 0)
			continue;
		if (mdlReadPHY(pLayerPointers, i, MII_PHYSID2, &id2) == 0)
			continue;
		if ((id1 != 0xffff) & (id2 != 0xffff)) {
			pLayerPointers->pMdl->phy_id = i;
			return;
		}
	}
}

/* Return 1 on success, return 0 on fail */
unsigned int
mdlWritePHY(struct LayerPointers *pLayerPointers, unsigned char phyid,
    unsigned char regaddr, unsigned int value)
{
	unsigned int status, data, count;
	unsigned long mmio = pLayerPointers->pMdl->Mem_Address;

	count = 0;
	do {
		status = READ_REG16(pLayerPointers, mmio + PHY_ACCESS);
		count ++;
		drv_usecwait(10);
	} while ((status & PHY_CMD_ACTIVE) & (count < PHY_MAX_RETRY));

	if (count == PHY_MAX_RETRY) {
		return (0);
	}

	data = ((regaddr & 0x1f) << 16) | ((phyid & 0x1f) << 21) |
	    (value & 0xffff) | PHY_WR_CMD;
	WRITE_REG32(pLayerPointers, mmio + PHY_ACCESS, data);

	do {
		status = READ_REG16(pLayerPointers, mmio + PHY_ACCESS);
		drv_usecwait(10);
		count ++;
	} while ((status & PHY_CMD_ACTIVE) & (count < PHY_MAX_RETRY));

	if ((count == PHY_MAX_RETRY) && (status & PHY_RD_ERR)) {
		return (0);
	}

	return (1);
}

/*
 *	To Send the packet.
 */
void
mdlTransmit(struct LayerPointers *pLayerPointers)
{
	WRITE_REG32(pLayerPointers, pLayerPointers->pMdl->Mem_Address + CMD0,
	    VAL1 | TDMD0);
}

/*
 *	To Receive a packet.
 */
void
mdlReceive(struct LayerPointers *pLayerPointers)
{
	/*
	 * Receive Demand for ring 0, which when set causes the Descriptor
	 * Management Unit to access the Receive Descriptor Ring if it does
	 * not already own the next descriptor.
	 */
	WRITE_REG32(pLayerPointers, pLayerPointers->pMdl->Mem_Address + CMD0,
	    VAL2 | RDMD0);
}

/*
 * Read the NIC interrupt.
 *
 * Returns:
 *	the value of interrupt causes register
 */
unsigned int
mdlReadInterrupt(struct LayerPointers *pLayerPointers)
{
	unsigned int nINT0;
	struct mdl *pMdl = 0;

	pMdl = (struct mdl *)(pLayerPointers->pMdl);

	/*
	 * INT0 identifies the source or sources of an interrupt. With the
	 * exception of INTR and INTPN, all bits in this register are "write
	 * 1 to clear" so that the CPU can clear the interrupt condition by
	 * reading the register and then writing back the same data that it
	 * read. Writing a 0 to a bit in this register has no effect.
	 */

	/* Read interrupt status */
	nINT0 = READ_REG32(pLayerPointers, pMdl->Mem_Address + INT0);

	/* Process all the INT event until INTR bit is clear. */
	WRITE_REG32(pLayerPointers, pMdl->Mem_Address + INT0, nINT0);
	return (nINT0);
}

void
mdlHWReset(struct LayerPointers *pLayerPointers)
{
	struct mdl *pMdl = pLayerPointers->pMdl;
	unsigned int ulData, i = 0;
	int  JumboFlag = JUMBO_DISABLED;
	ULONG Mem_Address = pMdl->Mem_Address;

	/*
	 * Stop the Card:
	 *	First we make sure that the device is stopped and no
	 *	more interrupts come out. Also some registers must be
	 *	programmed with CSR0 STOP bit set.
	 */
	mdlStopChip(pLayerPointers);

	/*
	 * MAC Address Setup:
	 *	MAC Physical Address register. All bits in this register are
	 *	restored to default values when the RST pin is asserted.
	 */
	for (i = 0; i < ETH_LENGTH_OF_ADDRESS; i++) {
		WRITE_REG8(pLayerPointers, pMdl->Mem_Address + PADR + i,
		    pMdl->Mac[i]);
	}

	/* Set RCV_RING_CFG */

	if (JumboFlag == JUMBO_ENABLED) {
		WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CMD2,
		    VAL0 | APAD_XMT | REX_RTRY | VAL1 | DXMTFCS | RPA | VAL2);

		WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CMD3,
		    VAL2 | JUMBO);
	} else {
		/*
		 * APAD_XMT: Auto Pad Transmit. When set, APAD_XMT enables
		 * the automatic padding feature. Transmit frames are padded
		 * to extend them to 64 bytes including FCS.
		 *
		 * DXMTFCS: Disable Transmit CRC. When DXMTFCS is set to 1, no
		 * Transmit CRC is generated. DXMTFCS is overridden when
		 * ADD_FCS and ENP bits are set in the transmit descriptor.
		 *
		 * ASTRIP_RCV: Auto Strip Receive. When ASTRP_RCV is set to 1,
		 * the receiver automatically strips pad bytes from the
		 * received message by observing the value in the length field
		 * and by stripping excess bytes if this value is below the
		 * minimum data size (46 bytes).
		 */
		WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CMD2,
		    VAL0 | APAD_XMT | REX_RTRY | REX_UFLO | VAL1 | DXMTFCS
		    | ASTRIP_RCV | RPA | VAL2);
	}

	/* Transmit Start Point setting (csr80) */
	ulData = READ_REG32(pLayerPointers, Mem_Address + CTRL1);
	ulData &= ~XMTSP_MASK;

	WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CTRL1,
	    ulData | XMTSP_128);
	/* Disable Prom  */
	WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CMD2, PROM);

	mdlPHYAutoNegotiation(pLayerPointers, pMdl->External_Phy);

	pMdl->IpgValue = MIN_IPG_DEFAULT;
	/* Set the IPG value */
	WRITE_REG16(pLayerPointers, pMdl->Mem_Address + IFS,
	    pMdl->IpgValue);

	/* Disable Following Interrupts. */
	WRITE_REG32(pLayerPointers, pMdl->Mem_Address + INTEN0,
	    APINT5EN | APINT4EN | APINT3EN |
	    APINT2EN | APINT1EN | APINT0EN | MIIPDTINTEN |
	    MCCIINTEN | MCCINTEN | MREINTEN |
	    TINTEN0 |
	    SPNDINTEN | MPINTEN | SINTEN | LCINTEN);

	/* Enable Following Interrupt */
	WRITE_REG32(pLayerPointers, pMdl->Mem_Address + INTEN0,
	    VAL0 | RINTEN0);

	/* Base Address of Transmit Descriptor Ring 0. */
	WRITE_REG32(pLayerPointers, pMdl->Mem_Address + XMT_RING_BASE_ADDR0,
	    pMdl->init_blk->TDRA);

	/* Base Address of Receive Descriptor Ring. */
	WRITE_REG32(pLayerPointers, pMdl->Mem_Address + RCV_RING_BASE_ADDR0,
	    pMdl->init_blk->RDRA);

	/* The number of descriptors in Transmit Descriptor Ring 0 */
	WRITE_REG16(pLayerPointers, pMdl->Mem_Address + XMT_RING_LEN0,
	    (unsigned short)pLayerPointers->pMdl->TxRingSize);

	/*
	 * Receive Descriptor Ring Length. All bits in this register are
	 * restored to default values when the RST pin is asserted.
	 */
	WRITE_REG16(pLayerPointers, pMdl->Mem_Address + RCV_RING_LEN0,
	    (unsigned short)pLayerPointers->pMdl->RxRingSize);

	if (pLayerPointers->pMdl->IntrCoalescFlag) {
		SetIntrCoalesc(pLayerPointers, B_TRUE);
	}

	/* Start the chip */
	mdlStartChip(pLayerPointers);
}

/*
 * Perform the open oerations on the adapter.
 */
void
mdlOpen(struct LayerPointers *pLayerPointers)
{
	int i, sum;
	struct mdl *pMdl = pLayerPointers->pMdl;

	/* Get Mac address */
	sum = 0;
	for (i = 0; i < 6; i++) {
		pMdl->Mac[i] = READ_REG8(pLayerPointers,
		    pMdl->Mem_Address + PADR + i);
		sum += pMdl->Mac[i];
	}
	if (sum == 0) {
		for (i = 0; i < 6; i++) {
			pMdl->Mac[i] = 0;
		}
	}

	/* Initialize the hardware */
	mdlClearHWConfig(pLayerPointers);
	mdlGetPHYID(pLayerPointers);

}

void
mdlGetMacAddress(struct LayerPointers *pLayerPointers,
    unsigned char *macAddress)
{
	struct mdl *pMdl = pLayerPointers->pMdl;
	int i;

	for (i = 0; i < 6; i++) {
		macAddress[i] =	pMdl->Mac[i] = READ_REG8(pLayerPointers,
		    pMdl->Mem_Address + PADR + i);
	}

}


void
mdlSetMacAddress(struct LayerPointers *pLayerPointers,
    unsigned char *macAddress)
{
	int i;
	struct mdl *pMdl = 0;

	pMdl = (struct mdl *)(pLayerPointers->pMdl);

	pMdl->Mac[0] = macAddress[0];
	pMdl->Mac[1] = macAddress[1];
	pMdl->Mac[2] = macAddress[2];
	pMdl->Mac[3] = macAddress[3];
	pMdl->Mac[4] = macAddress[4];
	pMdl->Mac[5] = macAddress[5];

	/*
	 * MAC Address Setup:
	 *	MAC Physical Address register. All bits in this register are
	 *	restored to default values when the RST pin is asserted.
	 */
	for (i = 0; i < ETH_LENGTH_OF_ADDRESS; i++) {
		WRITE_REG8(pLayerPointers, pMdl->Mem_Address + PADR + i,
		    pMdl->Mac[i]);
	}
}

/*
 * This array is filled with the size of the memory required for
 * allocating purposes.
 */
static void
mdlRequestResources(ULONG *mem_req_array)
{
	/* 1) For mdl structure */
	*mem_req_array = VIRTUAL;		/* Type */
	*(++mem_req_array) = sizeof (struct mdl); /* Size */

	/* 2) For PMR PtrList array (PMR_ptrList) */
	*(++mem_req_array) = VIRTUAL;		/* Type */
	/* Size */
	*(++mem_req_array) = sizeof (unsigned int) * (MAX_ALLOWED_PATTERNS + 2);

	/* 3) For PMR Pattern List array (PatternList) */
	*(++mem_req_array) = VIRTUAL;			/* Type */
	/* Size */
	*(++mem_req_array) = sizeof (unsigned char) * (MAX_PATTERNS + 2);

	/* 4) For pmr PatternLength array (PatternLength) */
	*(++mem_req_array) = VIRTUAL;			/* Type */
	/* Size */
	*(++mem_req_array) = sizeof (unsigned int) * (MAX_ALLOWED_PATTERNS + 2);

	/*
	 * 5) For the init_block (init_blk)
	 */
	*(++mem_req_array) = VIRTUAL;
	*(++mem_req_array) = sizeof (struct init_block);

	*(++mem_req_array) = 0;
	mem_req_array++;
}


/*
 *	Purpose  :
 *		This array contains the details of the allocated memory. The
 *		pointers are taken from the respective locations in the array &
 *		assigned appropriately to the respective structures.
 *
 *	Arguments :
 *		pLayerPointers
 *			Pointer to the adapter structure.
 *		pmem_set_array
 *			Pointer to the array that holds the data after required
 *			allocating memory.
 */
static void
mdlSetResources(struct LayerPointers *pLayerPointers, ULONG *pmem_set_array)
{
	struct mdl *pMdl = 0;

	/* 1) For mdl structure */
	pmem_set_array++;	/* Type */
	pmem_set_array++;	/* Size */
	pLayerPointers->pMdl = (struct mdl *)(*pmem_set_array);

	pMdl = (struct mdl *)(pLayerPointers->pMdl);

	pMdl->RxRingLenBits = RX_RING_LEN_BITS;
	pMdl->TxRingLenBits = TX_RING_LEN_BITS;
	pMdl->TxRingSize = TX_RING_SIZE;
	pMdl->RxRingSize = RX_RING_SIZE;

	/*
	 * Default values that would be used if it does not enable
	 * enable dynamic ipg.
	 */

	/*  2) Set the pointers to the PMR Pointer List */
	pmem_set_array++;	/* Type */
	pmem_set_array++;	/* Size */
	pmem_set_array++;	/* Virtual Addr of PtrList */
	pMdl->PMR_PtrList = (unsigned int *)(*pmem_set_array);

	/* 3) Set the pointers to the PMR Pattern List */
	pmem_set_array++;	/* Type */
	pmem_set_array++;	/* Size */
	pmem_set_array++;	/* Virtual Addr of PatternList */
	pMdl->PatternList = (unsigned char *)(*pmem_set_array);

	/* 4) Set the pointers to the PMR Pattern Length */
	pmem_set_array++;	/* Type */
	pmem_set_array++;	/* Size */
	pmem_set_array++;	/* Virtual Addr of PatternLength */
	pMdl->PatternLength = (unsigned int *)(*pmem_set_array);

	/* 5) Set the pointers to the init block */
	pmem_set_array++;	/* Type  */
	pmem_set_array++;	/* Size */
	pmem_set_array++;	/* Virtual Addr of init_block */
	pMdl->init_blk = (struct init_block *)(*pmem_set_array);

	pMdl->init_blk->TLEN = pMdl->TxRingLenBits;
	pMdl->init_blk->RLEN = pMdl->RxRingLenBits;

	pmem_set_array++;

	*pmem_set_array = 0;
}

/*
 *	Purpose:
 *		This array is filled with the size of the structure & its
 *		pointer for freeing purposes.
 *
 *	Arguments:
 *		pLayerPointers
 *			Pointer to the adapter structure.
 *		mem_free_array
 *			Pointer to the array that holds the data required for
 *			freeing.
 */
static void
mdlFreeResources(struct LayerPointers *pLayerPointers, ULONG *pmem_free_array)
{
	struct mdl *pMdl = 0;

	pMdl = (struct mdl *)(pLayerPointers->pMdl);

	/* 1) For mdl structure */
	*(pmem_free_array) = VIRTUAL;		/* Type */
	*(++pmem_free_array) = sizeof (struct mdl); /* Size */
	*(++pmem_free_array) = (ULONG)pMdl;  /* VA */

	/* 2) For ptr list */
	*(++pmem_free_array) = VIRTUAL;		/* Type */
	*(++pmem_free_array) =  sizeof (unsigned int)
	    * (MAX_ALLOWED_PATTERNS + 2);  /* Size */
	*(++pmem_free_array) = (ULONG)pMdl->PMR_PtrList;  /* VA */

	/* 3) For pattern list */
	*(++pmem_free_array) = VIRTUAL;		/* Type	 */
	/* Size */
	*(++pmem_free_array) =  sizeof (unsigned char) * (MAX_PATTERNS + 2);
	*(++pmem_free_array) = (ULONG)pMdl->PatternList;  /* VA */

	/* 4) For pattern length */
	*(++pmem_free_array) = VIRTUAL;				/* Type */
	*(++pmem_free_array) =  sizeof (unsigned int)
	    * (MAX_ALLOWED_PATTERNS + 2);			/* Size */
	*(++pmem_free_array) = (ULONG)pMdl->PatternLength;	/* VA */

	/* 5) For init_blk structure */
	*(++pmem_free_array) = VIRTUAL;				/* Type */
	/* Size */
	*(++pmem_free_array) = sizeof (struct init_block);
	*(++pmem_free_array) = (ULONG)pMdl->init_blk;		/* VA */

	*(++pmem_free_array) = 0;
}

void
mdlStartChip(struct LayerPointers *pLayerPointers)
{
	/* Enable Receiver */
	WRITE_REG32(pLayerPointers, pLayerPointers->pMdl->Mem_Address + CMD0,
	    VAL2 | RDMD0);

	/* Enable Interrupt and Start processing descriptor, Rx and Tx */
	WRITE_REG32(pLayerPointers, pLayerPointers->pMdl->Mem_Address + CMD0,
	    VAL0 | INTREN | RUN);
}

/*
 *	Stops the chip.
 */
void
mdlStopChip(struct LayerPointers *pLayerPointers)
{
	int nINT0;
	struct mdl *pMdl = 0;

	pMdl = (struct mdl *)(pLayerPointers->pMdl);

	/* Disable interrupt */
	WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CMD0, INTREN);

	/* Clear interrupt status */
	nINT0 = READ_REG32(pLayerPointers, pMdl->Mem_Address + INT0);
	WRITE_REG32(pLayerPointers, pMdl->Mem_Address + INT0, nINT0);

	/*
	 * Setting the RUN bit enables the controller to start processing
	 * descriptors and transmitting and  receiving packets. Clearing
	 * the RUN bit to 0 abruptly disables the transmitter, receiver, and
	 * descriptor processing logic, possibly while a frame is being
	 * transmitted or received.
	 * The act of changing the RUN bit from 1 to 0 causes the following
	 * bits to be reset to 0: TX_SPND, RX_SPND, TX_FAST_SPND, RX_FAST_SPND,
	 * RDMD, all TDMD bits, RINT, all TINT bits, MPINT, and SPNDINT.
	 */
	WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CMD0, RUN);
}

/*
 *	Enables the interrupt.
 */
void
mdlEnableInterrupt(struct LayerPointers *pLayerPointers)
{
	/*
	 * Interrupt Enable Bit:
	 * This bit allows INTA to be asserted if any bit in the interrupt
	 * register is set. If INTREN is cleared to 0, INTA will not be
	 * asserted, regardless of the state of the interrupt register.
	 */
	WRITE_REG32(pLayerPointers, pLayerPointers->pMdl->Mem_Address + CMD0,
	    VAL0 | INTREN);
}

#ifdef AMD8111S_DEBUG
static void
mdlClearInterrupt(struct LayerPointers *pLayerPointers)
{
	unsigned int nINT0;
	struct mdl *pMdl = 0;

	pMdl = (struct mdl *)(pLayerPointers->pMdl);

	/* Clear interrupt status */
	nINT0 = READ_REG32(pLayerPointers, pMdl->Mem_Address + INT0);
	WRITE_REG32(pLayerPointers, pMdl->Mem_Address + INT0, nINT0);

}
#endif

/*
 *	Disables the interrupt.
 */
void
mdlDisableInterrupt(struct LayerPointers *pLayerPointers)
{
	/* Disable interrupt */
	WRITE_REG32(pLayerPointers,
	    pLayerPointers->pMdl->Mem_Address + CMD0, INTREN);
}

/*
 *	Reads the link status
 */
int
mdlReadLink(struct LayerPointers *pLayerPointers)
{
	unsigned int link_status = 0;

	link_status = READ_REG32(pLayerPointers,
	    pLayerPointers->pMdl->Mem_Address + STAT0);

	if ((link_status & LINK_STAT)) {
		return (LINK_UP);
	} else {
		return (LINK_DOWN);
	}
}

/*
 *	Purpose  :
 *		Adds the wakeup pattern given by the upper layer.
 *
 *	Arguments :
 *		pLayerPointers
 *			Pointer to the Adapter structure.
 *		PatternMask
 *			The mask for the pattern to be added.
 *		Pattern
 *			The Pattern to be added.
 *		InfoBuffer_MaskSize
 *			The mask size as specified in the Information Buffer.
 *		PatternSize
 *			The PatternSize as specified in the Information Buffer.
 */
static void
mdlAddWakeUpPattern(struct LayerPointers *pLayerPointers,
    unsigned char *PatternMask, unsigned char *Pattern,
    unsigned long InfoBuffer_MaskSize, unsigned long PatternSize, int *retval)
{
	unsigned long MaskSize;
	unsigned long ReqSize;
	unsigned char byteData = 0, tmpData;
	unsigned char Skip = 0;
	unsigned int i = 0, flag = 1, count = 1;
	unsigned int j;
	int PatternOffset, SearchForStartOfPattern = 1;
	struct mdl *pMdl = 0;

	pMdl = pLayerPointers->pMdl;

	if (pMdl->TotalPatterns >= MAX_ALLOWED_PATTERNS) {
		*retval = -1;
		return;
	}

	MaskSize = PatternSize/4 + (PatternSize%4 ? 1 : 0);

	ReqSize = PatternSize + MaskSize;
	if (((PatternSize+MaskSize)%5) != 0)
		ReqSize +=  5 - ((PatternSize+MaskSize)%5);

	if (ReqSize >
	    (unsigned long)(MAX_PATTERNS - pMdl->PatternList_FreeIndex)) {
		*retval = -1;
		return;
	}

	if (InfoBuffer_MaskSize != PatternSize/8 + (PatternSize%8 ? 1 : 0)) {
		*retval = -1;
		return;
	}

	i = pMdl->PatternList_FreeIndex;

	pMdl->PMR_PtrList[pMdl->TotalPatterns] = i;

	pMdl->PatternLength[pMdl->TotalPatterns] = (unsigned int)PatternSize;

	while (i < (pMdl->PatternList_FreeIndex + PatternSize + MaskSize)) {
		if (flag) {
			byteData = *PatternMask;
			pMdl->PatternList[i++] =
			    (unsigned int)((byteData & 0x0F) | (Skip<< 4));
			flag = 0;
		} else {
			pMdl->PatternList[i++] = (unsigned int)
			    (((unsigned)(byteData & 0xF0) >> 4) | (Skip << 4));
			PatternMask++;
			flag = 1;
		}
		count = 1;
		while ((count < 5) && (i <
		    pMdl->PatternList_FreeIndex + PatternSize + MaskSize)) {
			tmpData = *Pattern;
			Pattern++;
			pMdl->PatternList[i++] = tmpData;
			count++;
		}
	}

	/* Filling up the extra byte blocks in the row to 0. */
	for (i = (pMdl->PatternList_FreeIndex + PatternSize + MaskSize);
	    i < (pMdl->PatternList_FreeIndex + ReqSize); i++)
		pMdl->PatternList[i] = 0;

	/* Set the EOP bit for the last mask!!! */
	pMdl->PatternList[pMdl->PatternList_FreeIndex + ReqSize - 5] |= 0x80;

	for (j = 0; j < 8; j++) {
		pMdl->tmpPtrArray[j] = 0;
	}

	/* Zeroing the skip value of all the pattern masks */
	j = 0;
	while (j < (pMdl->PatternList_FreeIndex + ReqSize)) {
		pMdl->PatternList[j] &= 0x8f;
		j += 5;
	}

	/*
	 * Scan the whole array & update the start offset of the pattern in the
	 * PMR and update the skip value.
	 */
	j = 0;
	i = 0;

	PatternOffset = 1;
	Skip = 0;

	while (j < (pMdl->PatternList_FreeIndex + ReqSize)) {

		if (pMdl->PatternList[j] & 0x0f) {
			PatternOffset ++;
			if (SearchForStartOfPattern == 1) {
				SearchForStartOfPattern = 0;
				pMdl->tmpPtrArray[i++] = PatternOffset;
			} else if (pMdl->PatternList[j] & 0x80) {
				SearchForStartOfPattern = 1;
			}
			pMdl->PatternList[j] |= (Skip << 4);
			Skip = 0;
		} else {
			Skip++;
		}
		j += 5;
	}

	/* valid pattern.. so update the house keeping info. */
	pMdl->PatternList_FreeIndex += (unsigned short)ReqSize;
	pMdl->TotalPatterns++;

	*retval = 0;
}

/*
 *	Purpose:
 *		Removes the specified wakeup pattern.
 *
 *	Arguments :
 *		pLayerPointers
 *			Pointer to the Adapter structure.
 *		Pattern
 *			The Pattern to be added.
 *		PatternSize
 *			The PatternSize as specified in the Information Buffer.
 */
static void
mdlRemoveWakeUpPattern(struct LayerPointers *pLayerPointers,
    unsigned char *Pattern, unsigned long PatternSize, int *retval)
{
	unsigned long ReqSize, MaskSize;
	unsigned char tmpData;
	unsigned long Data;
	unsigned short Data1, Data2, Data3, Data4, Data5, Data6, Data7, Data8;
	int PatternMismatch = 0;
	int count, StartIndex, index = 0;
	unsigned int i, j;
	unsigned char Skip = 0;
	struct mdl *pMdl = 0;
	int PatternOffset, SearchForStartOfPattern = 1;
	unsigned long tmpPtrArray[8];
	int offset;

	Data1 = Data2 = Data3 = Data4 = Data5 = Data6 = Data7 = Data8 = 0;

	pMdl = (struct mdl *)(pLayerPointers->pMdl);

	/* Find the pattern to be removed. */
	if (pMdl->TotalPatterns == 0) {
		*retval = -1;
		return;
	}

	MaskSize = PatternSize/4 + (PatternSize%4 ? 1 : 0);

	ReqSize = PatternSize + MaskSize;
	if (((PatternSize+MaskSize)%5) != 0)
		ReqSize +=  5 - ((PatternSize+MaskSize)%5);

	count = pMdl->TotalPatterns;

	while (count--) {
		PatternMismatch = 0;
		StartIndex = pMdl->PMR_PtrList[index];

		if (pMdl->PatternLength[index] != PatternSize) {
			index++;
			PatternMismatch = 1;
			continue;
		}

		for (i = StartIndex; i < (StartIndex+ReqSize); i++) {
			if (!(i%5))
				i++;

			tmpData = *Pattern;
			if (pMdl->PatternList[i] != tmpData) {
				PatternMismatch = 1;
				break;
			}
			Pattern++;
		}

		if (PatternMismatch == 0) {
			i = StartIndex + ReqSize;

			/* Pattern found remove it from the arrays */
			while (i < pMdl->PatternList_FreeIndex) {
				pMdl->PatternList[StartIndex] =
				    pMdl->PatternList[i];
				i++;
				StartIndex++;
			}

			pMdl->PatternList_FreeIndex =
			    (unsigned short)(StartIndex);

			while (StartIndex < MAX_PATTERNS)
				pMdl->PatternList[StartIndex++] = 0;

			while (index < (int)pMdl->TotalPatterns) {
				pMdl->PMR_PtrList[index] =
				    pMdl->PMR_PtrList[index+1] - ReqSize;

				pMdl->PatternLength[index] =
				    pMdl->PatternLength[index+1];

				index ++;
			}

			index--;
			while (index < MAX_ALLOWED_PATTERNS) {
				pMdl->PMR_PtrList[index+1] = 0;
				pMdl->PatternLength[index+1] = 0;
				index++;
			}

			break;
		}
		index++;
	}

	if (PatternMismatch) {
		*retval = -1;
		return;
	}


	for (j = 0; j < 8; j++) {
		tmpPtrArray[j] = 0;
	}

	/* Zeroing the skip value of all the pattern masks */
	j = 0;
	while (j < (pMdl->PatternList_FreeIndex)) {
		pMdl->PatternList[j] &= 0x8f;
		j += 5;
	}

	/*
	 * Scan the whole array & update the start offset of the pattern in the
	 * PMR and update the skip value.
	 */
	j = 0;
	i = 0;
	Skip = 0;
	PatternOffset = 1;

	while (j < (pMdl->PatternList_FreeIndex)) {
		if (pMdl->PatternList[j] & 0x0f) {

			PatternOffset++;
			if (SearchForStartOfPattern == 1) {
				SearchForStartOfPattern = 0;
				tmpPtrArray[i++] = PatternOffset;
			} else if (pMdl->PatternList[j] & 0x80) {
				SearchForStartOfPattern = 1;
			}
			pMdl->PatternList[j] |= (Skip << 4);
			Skip = 0;
		} else {
			Skip++;
		}
		j += 5;
	}


	/* Write back the arrays to the PMR & lock the pmr */
	WRITE_REG32(pLayerPointers, pMdl->Mem_Address+CMD7, PMAT_MODE);

	/* Write the data & ctrl patterns from the array to the PMR */
	i = 0;

	offset = 2;

	while (i < MAX_PATTERNS) {
		if (pMdl->PatternList[i] != 0) {
			Data = pMdl->PatternList[i+3] << 24 |
			    pMdl->PatternList[i+2] << 16 |
			    pMdl->PatternList[i+1] << 8  |
			    pMdl->PatternList[i];

			WRITE_REG32(pLayerPointers,
			    pMdl->Mem_Address+PMAT1, Data);

			Data = (unsigned long) ((1<<30) | (offset << 16) |
			    pMdl->PatternList[i+4]);

			WRITE_REG32(pLayerPointers,
			    pMdl->Mem_Address+PMAT0, Data);

			offset++;

			if (offset >= 64) {
				/* PMR is full !!!! */
				*retval = -1;
				return;

			}
		}
		i += 5;
	}

	/* Valid pattern.. so update the house keeping info. */
	pMdl->TotalPatterns--;

	/* Update the pointer in the PMR */
	pMdl->PatternEnableBit = 0;
	for (i = 0; i < pMdl->TotalPatterns; i++) {
		pMdl->PatternEnableBit |= (0x0001 << i);
	}

	Data1 = Data2 = Data3 = Data4 = Data5 = Data6 = Data7 = Data8 = 0;

	switch (pMdl->TotalPatterns) {
	case 8 :
		Data8 = (unsigned short)tmpPtrArray[7];
		/* FALLTHROUGH */
	case 7 :
		Data7 = (unsigned short)tmpPtrArray[6];
		/* FALLTHROUGH */
	case 6 :
		Data6 = (unsigned short)tmpPtrArray[5];
		/* FALLTHROUGH */
	case 5 :
		Data5 = (unsigned short)tmpPtrArray[4];
		/* FALLTHROUGH */
	case 4 :
		Data4 = (unsigned short)tmpPtrArray[3];
		/* FALLTHROUGH */
	case 3 :
		Data3 = (unsigned short)tmpPtrArray[2];
		/* FALLTHROUGH */
	case 2 :
		Data2 = (unsigned short)tmpPtrArray[1];
		/* FALLTHROUGH */
	case 1 :
		Data1 = (unsigned short)tmpPtrArray[0];
		break;
	}

	Data = pMdl->PatternEnableBit & 0x0f;

	/* Updating the pointers 1,2,3 & 4 */
	Data = (Data3 << 24 |   Data2 << 16 |   Data1 << 8  |   Data);
	WRITE_REG32(pLayerPointers, pMdl->Mem_Address + PMAT1, Data);

	Data = (unsigned long) ((1<<30) | Data4);
	WRITE_REG32(pLayerPointers, pMdl->Mem_Address + PMAT0, Data);

	/* Updating the pointers 4,5,6 & 7 */
	Data = (unsigned short)((unsigned)(pMdl->PatternEnableBit & 0xf0) >> 4);

	Data = (Data7 << 24 |   Data6 << 16 |   Data5 << 8  |   Data);
	WRITE_REG32(pLayerPointers, pMdl->Mem_Address + PMAT1, Data);

	Data = (unsigned long) ((1<<30) | (1<<16) | Data8);
	WRITE_REG32(pLayerPointers, pMdl->Mem_Address + PMAT0, Data);

	/* Unlock the PMR */
	WRITE_REG32(pLayerPointers, pMdl->Mem_Address + CMD7, VAL0 | PMAT_MODE);

	*retval = 0;
}


/*
 *	Checks the control register for the speed and the type of the
 *	network connection.
 */
void
mdlGetActiveMediaInfo(struct LayerPointers *pLayerPointers)
{

	unsigned long  ulData;
	struct mdl *pMdl = 0;

	pMdl = (struct mdl *)(pLayerPointers->pMdl);

	ulData = READ_REG32(pLayerPointers, pMdl->Mem_Address + STAT0);

	switch (ulData & SPEED_MASK) {
	case SPEED_100Mbps:
		pMdl->Speed = 100;
		break;
	case SPEED_10Mbps:
		pMdl->Speed = 10;
		break;
	default:
		pMdl->Speed = 100;
		break;
	}

	if (ulData & FULL_DPLX) {
		pMdl->FullDuplex = B_TRUE;
	} else {
		pMdl->FullDuplex = B_FALSE;
	}
}

void
mdlChangeFilter(struct LayerPointers *pLayerPointers, unsigned long  *ArrayPtr)
{
	unsigned long *Ptr;
	unsigned char *MulticastArray;
	unsigned char *Pattern, *PatternMask;
	unsigned int InfoBuffer_MaskSize, PatternSize;
	int *retval;
	int NumberOfAddress, i;
	unsigned int j, CRCValue = 0;
	unsigned char HashCode = 0, FilterByte = 0;
	int BitMapIndex = 0;

	Ptr = ArrayPtr;

	while (*Ptr) {
		switch (*Ptr) {
		case DISABLE_BROADCAST:
			mdlDisableReceiveBroadCast(pLayerPointers);
			break;

		case ENABLE_BROADCAST:
			mdlReceiveBroadCast(pLayerPointers);
			break;

		case ENABLE_ALL_MULTICAST:
			for (i = 0; i < 8; i++) {
				pLayerPointers->pMdl->init_blk->LADRF[i] = 0xff;
			}
			WRITE_REG64(pLayerPointers,
			    (unsigned long)pLayerPointers->pMdl
			    ->Mem_Address + LADRF1,
			    (char *)pLayerPointers->pMdl->init_blk->LADRF);
			break;

		case DISABLE_ALL_MULTICAST:
			if (pLayerPointers->pMdl->EnableMulticast == 1) {
				for (i = 0; i < 8; i++) {
					pLayerPointers->pMdl->init_blk
					    ->LADRF[i] =
					    pLayerPointers->pMdl->TempLADRF[i];
				}
			}

			WRITE_REG64(pLayerPointers,
			    (unsigned long)pLayerPointers->pMdl->Mem_Address
			    + LADRF1,
			    (char *)pLayerPointers->pMdl->init_blk->LADRF);
			break;


		case ADD_MULTICAST:
			NumberOfAddress = *(++Ptr);
			MulticastArray = (unsigned char *)(*(++Ptr));
			mdlAddMulticastAddresses(pLayerPointers,
			    NumberOfAddress, MulticastArray);
			break;


		case ENABLE_MULTICAST:
			for (i = 0; i < 8; i++) {
				pLayerPointers->pMdl->init_blk->LADRF[i]  =
				    pLayerPointers->pMdl->TempLADRF[i];
			}
			pLayerPointers->pMdl->EnableMulticast = 1;

			WRITE_REG64(pLayerPointers,
			    (unsigned long)pLayerPointers->pMdl->Mem_Address
			    + LADRF1,
			    (char *)pLayerPointers->pMdl->init_blk->LADRF);
			break;

		case DISABLE_MULTICAST:
			for (i = 0; i < 8; i++) {
				pLayerPointers->pMdl->init_blk->LADRF[i] = 0;
			}

			pLayerPointers->pMdl->EnableMulticast = 0;

			for (BitMapIndex = 0; BitMapIndex <
			    MULTICAST_BITMAP_ARRAY_SIZE; BitMapIndex++)
				pLayerPointers->pMdl->MulticastBitMapArray
				    [BitMapIndex] = 0;
			WRITE_REG64(pLayerPointers,
			    (unsigned long)pLayerPointers->pMdl->Mem_Address
			    + LADRF1,
			    (char *)pLayerPointers->pMdl->init_blk->LADRF);
			break;


		case ADD_WAKE_UP_PATTERN:
			PatternMask = (unsigned char *)(*(++Ptr));
			Pattern = (unsigned char *)(*(++Ptr));
			InfoBuffer_MaskSize = (*(++Ptr));
			PatternSize = (*(++Ptr));
			retval = (int *)(*(++Ptr));

			mdlAddWakeUpPattern(pLayerPointers,
			    PatternMask,
			    Pattern,
			    InfoBuffer_MaskSize,
			    PatternSize,
			    retval);
			break;

		case REMOVE_WAKE_UP_PATTERN:
			Pattern = (unsigned char *)(*(++Ptr));
			PatternSize = *(++Ptr);
			retval = (int *)(*(++Ptr));
			mdlRemoveWakeUpPattern(pLayerPointers,
			    Pattern,
			    PatternSize,
			    retval);
			break;

		case ENABLE_MAGIC_PACKET_WAKE_UP:
			mdlEnableMagicPacketWakeUp(pLayerPointers);
			break;

		case SET_SINGLE_MULTICAST:
			NumberOfAddress = *(++Ptr);
			MulticastArray = (unsigned char *)(*(++Ptr));

			for (i = 0; i < 8; i++) {
				pLayerPointers->pMdl->TempLADRF[i] =
				    pLayerPointers->pMdl->init_blk->LADRF[i];
			}
			CRCValue = mdlCalculateCRC(ETH_LENGTH_OF_ADDRESS,
			    MulticastArray);
			for (j = 0; j < 6; j++) {
				HashCode = (HashCode << 1) +
				    (((unsigned char)CRCValue >> j) & 0x01);
			}
			/*
			 * Bits 3-5 of HashCode point to byte in address
			 * filter.
			 * Bits 0-2 point to bit within that byte.
			 */
			FilterByte = HashCode >> 3;
			pLayerPointers->pMdl->TempLADRF[FilterByte] |=
			    (1 << (HashCode & 0x07));
			break;

		case UNSET_SINGLE_MULTICAST:
			NumberOfAddress = *(++Ptr);
			MulticastArray = (unsigned char *)(*(++Ptr));
			for (i = 0; i < 8; i++) {
				pLayerPointers->pMdl->TempLADRF[i] =
				    pLayerPointers->pMdl->init_blk->LADRF[i];
			}
			CRCValue = mdlCalculateCRC(ETH_LENGTH_OF_ADDRESS,
			    MulticastArray);
			for (j = 0; j < 6; j++) {
				HashCode = ((HashCode << 1) +
				    (((unsigned char)CRCValue >> j) & 0x01));
			}

			/*
			 * Bits 3-5 of HashCode point to byte in address
			 * filter.
			 * Bits 0-2 point to bit within that byte.
			 */
			FilterByte = HashCode >> 3;
			pLayerPointers->pMdl->TempLADRF[FilterByte] &=
			    ~(1 << (HashCode & 0x07));
			break;

		default:
			break;
		}
		Ptr++;
	}
}


void
mdlAddMulticastAddresses(struct LayerPointers *pLayerPointers,
    int NumberOfAddress, unsigned char *MulticastAddresses)
{
	unsigned int j, CRCValue;
	unsigned char HashCode, FilterByte;
	int i;

	for (i = 0; i < 8; i++) {
		pLayerPointers->pMdl->TempLADRF[i]  = 0x00;
	}


	for (i = 0; i < NumberOfAddress; i++) {
		HashCode = 0;

		/* Calculate CRC value */
		CRCValue = mdlCalculateCRC(ETH_LENGTH_OF_ADDRESS,
		    MulticastAddresses);

		for (j = 0; j < 6; j++) {
			HashCode = (HashCode << 1) +
			    (((unsigned char)CRCValue >> j) & 0x01);
		}

		/* Bits 3-5 of HashCode point to byte in address filter. */
		/* Bits 0-2 point to bit within that byte. */
		FilterByte = HashCode >> 3;
		pLayerPointers->pMdl->TempLADRF[FilterByte] |=
		    (1 << (HashCode & 0x07));
		MulticastAddresses += ETH_LENGTH_OF_ADDRESS;
	}
}

/* Receive all packets  */
void
mdlSetPromiscuous(struct LayerPointers *pLayerPointers)
{
	/*
	 * Writable N == Can Be Written only when device is not running
	 * (RUN == 0)
	 */
	WRITE_REG32(pLayerPointers, pLayerPointers->pMdl->Mem_Address + CMD2,
	    VAL2 | PROM);
	pLayerPointers->pMdl->FLAGS |= PROM;	/* B16_MASK */
}

/* Stop Receiving all packets  */
void
mdlDisablePromiscuous(struct LayerPointers *pLayerPointers)
{
	/*
	 * Writable N == Can Be Written only when device is not running
	 * (RUN == 0)
	 */
	WRITE_REG32(pLayerPointers, pLayerPointers->pMdl->Mem_Address + CMD2,
	    PROM);
	pLayerPointers->pMdl->FLAGS &= (~ PROM); /* B16_MASK */
}

/*
 * Disable Receive Broadcast. When set, disables the controller from receiving
 * broadcast messages. Used for protocols that do not support broadcast
 * addressing, except as a function of multicast.
 * DRCVBC is cleared by activation of H_RESET (broadcast messages will be
 * received) and is unaffected by the clearing of the RUN bit.
 */
static void
mdlReceiveBroadCast(struct LayerPointers *pLayerPointers)
{
	ULONG MappedMemBaseAddress;

	MappedMemBaseAddress = pLayerPointers->pMdl->Mem_Address;
	WRITE_REG32(pLayerPointers, MappedMemBaseAddress + CMD2, DRCVBC);
	pLayerPointers->pMdl->FLAGS |= DRCVBC;
}

static void
mdlDisableReceiveBroadCast(struct LayerPointers *pLayerPointers)
{
	ULONG MappedMemBaseAddress;

	MappedMemBaseAddress = pLayerPointers->pMdl->Mem_Address;
	WRITE_REG32(pLayerPointers, MappedMemBaseAddress + CMD2, VAL2 | DRCVBC);
	pLayerPointers->pMdl->FLAGS &= (~DRCVBC);
}

static void
mdlEnableMagicPacketWakeUp(struct LayerPointers *pLayerPointers)
{
	WRITE_REG32(pLayerPointers, pLayerPointers->pMdl->Mem_Address + CMD3,
	    VAL1 | MPPLBA);
	WRITE_REG32(pLayerPointers, pLayerPointers->pMdl->Mem_Address + CMD7,
	    VAL0 | MPEN_SW);
}

/*
 * BitMap for add/del the Multicast address Since more than one M/C address
 * can map to same bit in the filter matrix, we should maintain the count for
 * # of M/C addresses associated with each bit. Only when the bit<->count
 * becomes zero, we should go ahead with changing/reseting the bit, else just
 * reduce the count associated with each bit and return.
 */
static int
mdlMulticastBitMapping(struct LayerPointers *pLayerPointers,
    unsigned char *MulticastAddress, int FLAG)
{
	unsigned char HashCode, FilterByte;
	int j = 0, BitMapIndex = 0;
	unsigned int CRCValue = 0;

	HashCode = 0;
	/* Calculate the Bit Map location for the given Address */
	CRCValue = mdlCalculateCRC(ETH_LENGTH_OF_ADDRESS, MulticastAddress);
	for (j = 0; j < 6; j++) {
		HashCode = (HashCode << 1) +
		    (((unsigned char)CRCValue >> j) & 0x01);
	}

	/*
	 * Bits 3-5 of HashCode point to byte in address filter.
	 * Bits 0-2 point to bit within that byte.
	 */
	FilterByte = HashCode & 0x38;
	FilterByte = FilterByte >> 3;
	BitMapIndex =  (int)FilterByte * 8 + (HashCode & 0x7);

	if (FLAG == DELETE_MULTICAST) {
		if ((pLayerPointers->pMdl->MulticastBitMapArray[BitMapIndex]
		    == 0) || (--pLayerPointers->pMdl->MulticastBitMapArray
		    [BitMapIndex] == 0)) {
			return (0);
		} else {
			return (-1);
		}
	}

	if (FLAG == ADD_MULTICAST) {
		if (pLayerPointers->pMdl
		    ->MulticastBitMapArray[BitMapIndex] > 0) {
			pLayerPointers->pMdl
			    ->MulticastBitMapArray[BitMapIndex]++;
			return (-1);
		} else if (pLayerPointers->pMdl
		    ->MulticastBitMapArray[BitMapIndex] == 0) {
			pLayerPointers->pMdl
			    ->MulticastBitMapArray[BitMapIndex]++;
			return (0);
		}
	}
	return (0);
}

/*
 * Set Interrupt Coalescing registers:
 *	To reduce the host CPU interrupt service overhead the network
 *	controller can be programmed to postpone the interrupt to the host
 *	CPU until either a programmable number of receive or transmit
 *	interrupt events have occurred or a programmable amount of time has
 *	elapsed since the first interrupt event occurred.
 */
void
SetIntrCoalesc(struct LayerPointers *pLayerPointers, boolean_t on)
{
	long MemBaseAddress = pLayerPointers->pMdl->Mem_Address;
	struct mdl *pMdl = 0;
	unsigned int timeout, event_count;

	pMdl = (struct mdl *)(pLayerPointers->pMdl);

	if (on) {
		/* Set Rx Interrupt Coalescing */
		timeout = pLayerPointers->pMdl->rx_intrcoalesc_time;
		event_count = 0;
		event_count |= pLayerPointers->pMdl->rx_intrcoalesc_events;
		if (timeout > 0x7ff) {
			timeout = 0x7ff;
		}
		if (event_count > 0x1f) {
			event_count = 0x1f;
		}

		event_count =  event_count << 16;
		WRITE_REG32(pLayerPointers, MemBaseAddress + DLY_INT_A,
		    DLY_INT_A_R0 | event_count | timeout);

	} else {
		/* Disable Software Timer Interrupt */
		WRITE_REG32(pLayerPointers, MemBaseAddress + STVAL, 0);
		WRITE_REG32(pLayerPointers, pMdl->Mem_Address + INTEN0,
		    STINTEN);

		WRITE_REG32(pLayerPointers, MemBaseAddress + DLY_INT_A, 0);
		WRITE_REG32(pLayerPointers, MemBaseAddress + DLY_INT_B, 0);
	}
}

void
mdlSendPause(struct LayerPointers *pLayerPointers)
{
	WRITE_REG32(pLayerPointers, pLayerPointers->pMdl->Mem_Address
	    + FLOW_CONTROL, VAL2 | FIXP | FCCMD | 0x200);
}

/* Reset all Tx descriptors and Tx buffers */
void
milResetTxQ(struct LayerPointers *pLayerPointers)
{
	struct nonphysical *pNonphysical = pLayerPointers->pMil->pNonphysical;
	int i;

	pNonphysical->TxDescQRead = pNonphysical->TxDescQStart;
	pNonphysical->TxDescQWrite = pNonphysical->TxDescQStart;

	/* Clean all Tx descriptors */
	for (i = 0; i < TX_RING_SIZE; i++) {
		pNonphysical->TxDescQWrite->Tx_OWN = 0;
		pNonphysical->TxDescQWrite->Tx_SOP = 0;
		pNonphysical->TxDescQWrite->Tx_EOP = 0;
		pNonphysical->TxDescQWrite++;
	}
	pNonphysical->TxDescQWrite = pNonphysical->TxDescQStart;

	/* Re-init Tx Buffers */
	pLayerPointers->pOdl->tx_buf.free =
	    pLayerPointers->pOdl->tx_buf.msg_buf;
	pLayerPointers->pOdl->tx_buf.next =
	    pLayerPointers->pOdl->tx_buf.msg_buf;
	pLayerPointers->pOdl->tx_buf.curr =
	    pLayerPointers->pOdl->tx_buf.msg_buf;
}

/*
 *	Initialises the data used in Mil.
 */
void
milInitGlbds(struct LayerPointers *pLayerPointers)
{
	pLayerPointers->pMil->name = DEVICE_CHIPNAME;

	mdlInitGlbds(pLayerPointers);
}

/*
 *	Purpose  :
 *		Initialises the RxBufDescQ with the packet pointer and physical
 *		address filled in the FreeQ.
 *
 *	Arguments :
 *		pLayerPointers
 *			Pointer to the Adapter structure.
 */
void
milInitRxQ(struct LayerPointers *pLayerPointers)
{
	struct mil *pMil = pLayerPointers->pMil;
	struct nonphysical *pNonphysical = pMil->pNonphysical;
	int i;

	pNonphysical->RxBufDescQRead->descriptor = pMil->Rx_desc;
	pNonphysical->RxBufDescQStart->descriptor = pMil->Rx_desc;
	pNonphysical->RxBufDescQEnd->descriptor =
	    &(pMil->Rx_desc[pMil->RxRingSize - 1]);

	pNonphysical->RxBufDescQRead->USpaceMap = pMil->USpaceMapArray;
	pNonphysical->RxBufDescQStart->USpaceMap = pMil->USpaceMapArray;
	pNonphysical->RxBufDescQEnd->USpaceMap =
	    &(pMil->USpaceMapArray[pMil->RxRingSize - 1]);

	/* Initialize the adapter rx descriptor Q and rx buffer Q */
	for (i = 0; i < pMil->RxRingSize; i++) {
		pNonphysical->RxBufDescQRead->descriptor->Rx_BCNT
		    = (unsigned)pMil->RxBufSize;

		*(pNonphysical->RxBufDescQRead->USpaceMap) =
		    (long)(pLayerPointers->pOdl->rx_buf.next->vir_addr);

		pNonphysical->RxBufDescQRead->descriptor->Rx_Base_Addr
		    = pLayerPointers->pOdl->rx_buf.next->phy_addr;

		pNonphysical->RxBufDescQRead->descriptor->Rx_OWN = 1;
		pNonphysical->RxBufDescQRead->descriptor++;
		pNonphysical->RxBufDescQRead->USpaceMap++;
		pLayerPointers->pOdl->rx_buf.next =
		    NEXT(pLayerPointers->pOdl->rx_buf, next);
	}

	pNonphysical->RxBufDescQRead->descriptor =
	    pNonphysical->RxBufDescQStart->descriptor;
	pNonphysical->RxBufDescQRead->USpaceMap =
	    pNonphysical->RxBufDescQStart->USpaceMap;
	pLayerPointers->pOdl->rx_buf.next =
	    pLayerPointers->pOdl->rx_buf.msg_buf;
}

/*
 *	Purpose		:
 *		This array is filled with the size of the structure & its
 *		pointer for freeing purposes.
 *
 *	Arguments	:
 *		pLayerPointers
 *			Pointer to the adapter structure.
 *		mem_free_array
 *			Pointer to the array that holds the data required
 *			for freeing.
 */
void
milFreeResources(struct LayerPointers *pLayerPointers, ULONG *mem_free_array)
{
	/* 1) For mil structure (pLayerPointers->pMil) */
	/* Type */
	*(mem_free_array) = VIRTUAL;
	/* Size */
	*(++mem_free_array) = sizeof (struct mil);
	/* VA */
	*(++mem_free_array) = (ULONG)pLayerPointers->pMil;


	/* 2) For USpaceMapArray queue */
	/* Type */
	*(++mem_free_array) = VIRTUAL;
	/* Size */
	*(++mem_free_array) = pLayerPointers->pMil->RxRingSize *
	    sizeof (unsigned long);
	/* VA */
	*(++mem_free_array) = (ULONG)pLayerPointers->pMil->USpaceMapArray;


	/* 3) For non_physical structure */
	/* Type */
	*(++mem_free_array) = VIRTUAL;
	/* Size */
	*(++mem_free_array) =  sizeof (struct nonphysical);
	/* VA */
	*(++mem_free_array) = (ULONG)pLayerPointers->pMil->pNonphysical;

	/*
	 * 4~6) For four allocation are for abstracting the Rx_Descritor ring
	 */

	/* 4) Type */
	*(++mem_free_array) = VIRTUAL;
	/* Size */
	*(++mem_free_array) =  sizeof (struct Rx_Buf_Desc);
	/* VA */
	*(++mem_free_array) =
	    (ULONG)pLayerPointers->pMil->pNonphysical->RxBufDescQRead;

	/* 5) Type */
	*(++mem_free_array) = VIRTUAL;
	/* Size */
	*(++mem_free_array) =  sizeof (struct Rx_Buf_Desc);
	/* VA */
	*(++mem_free_array) =
	    (ULONG)pLayerPointers->pMil->pNonphysical->RxBufDescQStart;

	/* 6) Type */
	*(++mem_free_array) = VIRTUAL;
	/* Size */
	*(++mem_free_array) =  sizeof (struct Rx_Buf_Desc);
	/* VA */
	*(++mem_free_array) =
	    (ULONG)pLayerPointers->pMil->pNonphysical->RxBufDescQEnd;

	*(++mem_free_array) = 0;

	mdlFreeResources(pLayerPointers, mem_free_array);
}



/*
 *	Purpose  :
 *		This array is filled with the size of the memory required for
 *		allocating purposes.
 *
 *	Arguments :
 *		pLayerPointers
 *			Pointer to the adapter structure.
 *		mem_req_array
 *			Pointer to the array that holds the data required for
 *			allocating memory.
 */
void
milRequestResources(ULONG *mem_req_array)
{
	int RxRingSize;

	RxRingSize = RX_RING_SIZE;	/* 128 */

	/* 1) For mil structure (pLayerPointers->pMil) */
	/* Type */
	*mem_req_array   = VIRTUAL;
	/* Size */
	*(++mem_req_array) = sizeof (struct mil);

	/* 2) For USpaceMapArray queue (pLayerPointers->pMil->USpaceMapArray) */
	/* Type */
	*(++mem_req_array) = VIRTUAL;
	/* Size */
	*(++mem_req_array) = RxRingSize * sizeof (unsigned long);


	/* 3) For pNonphysical structure */
	/* Type */
	*(++mem_req_array) = VIRTUAL;
	/* Size */
	*(++mem_req_array) = sizeof (struct nonphysical);

	/*
	 * 4~6) For four allocation are for abstracting the Rx_Descritor ring
	 */
	/* 4) Type */
	*(++mem_req_array) = VIRTUAL;
	/* Size */
	*(++mem_req_array) = sizeof (struct Rx_Buf_Desc);

	/* 5) Type */
	*(++mem_req_array) = VIRTUAL;
	/* Size */
	*(++mem_req_array) = sizeof (struct Rx_Buf_Desc);

	/* 6) Type */
	*(++mem_req_array) = VIRTUAL;
	/* Size */
	*(++mem_req_array) = sizeof (struct Rx_Buf_Desc);

	*(++mem_req_array) = 0;

	mdlRequestResources(mem_req_array);
}



/*
 *	Purpose  :
 *		This array contains the details of the allocated memory. The
 *		pointers are taken from the respective locations in the array
 *		& assigne appropriately to the respective structures.
 *
 *	Arguments :
 *		pLayerPointers
 *			Pointer to the adapter structure.
 *		pmem_set_array
 *			Pointer to the array that holds the data after required
 *			allocating memory.
 */
void
milSetResources(struct LayerPointers *pLayerPointers, ULONG *pmem_set_array)
{
	int RxRingSize, TxRingSize;
	int RxBufSize;
	struct mil *pMil;

	RxRingSize = RX_RING_SIZE;
	TxRingSize = TX_RING_SIZE;
	RxBufSize = RX_BUF_SIZE;

	/* 1) Set the pointers to the mil pointers */
	/* Type */
	pmem_set_array++;
	/* Size */
	pmem_set_array++;
	pMil = (struct mil *)(*pmem_set_array);
	pLayerPointers->pMil = pMil;

	pMil->RxRingSize = RxRingSize;
	pMil->TxRingSize = TxRingSize;
	pMil->RxBufSize = RxBufSize;

	/* 2) Type */
	pmem_set_array++;
	/* Size */
	pmem_set_array++;
	pmem_set_array++;
	pMil->USpaceMapArray = (long *)(*pmem_set_array);

	/* 3) Set the pointers to the NonPhysical part */
	/* Type */
	pmem_set_array++;
	/* Size */
	pmem_set_array++;
	/* Virtual Addr of NonPhysical */
	pmem_set_array++;
	pMil->pNonphysical =
	    (struct nonphysical *)(*pmem_set_array);

	/*
	 * 4~6) Following four allocation are for abstracting the Rx_Descritor
	 * Ring.
	 */
	/* 4) Type */
	pmem_set_array++;
	/* Size */
	pmem_set_array++;
	/* Virtual Addr of Abstracted RxDesc */
	pmem_set_array++;
	pMil->pNonphysical->RxBufDescQRead =
	    (struct Rx_Buf_Desc *)(*pmem_set_array);

	/* 5) Type */
	pmem_set_array++;
	/* Size */
	pmem_set_array++;
	/* Virtual Addr of Abstracted RxDesc */
	pmem_set_array++;
	pMil->pNonphysical->RxBufDescQStart =
	    (struct Rx_Buf_Desc *)(*pmem_set_array);

	/* 6) Type */
	pmem_set_array++;
	/* Size */
	pmem_set_array++;
	/* Virtual Addr of Abstracted RxDesc */
	pmem_set_array++;
	pMil->pNonphysical->RxBufDescQEnd =
	    (struct Rx_Buf_Desc *)(*pmem_set_array);

	pmem_set_array++;

	mdlSetResources(pLayerPointers, pmem_set_array);
}

/*
 *	Purpose  :
 *		This routine adds the Multicast addresses to the filter
 *
 *	Arguments :
 *		pLayerPointers
 *			Pointer to Layer pointers structure.
 *		pucMulticastAddress
 *			Pointer to the array of multicast addresses
 */
void
mdlAddMulticastAddress(struct LayerPointers *pLayerPointers,
    UCHAR *pucMulticastAddress)
{
	unsigned long MODE[10];
	unsigned long tmp1;
	unsigned long tmp2;

	if (mdlMulticastBitMapping(pLayerPointers, pucMulticastAddress,
	    ADD_MULTICAST) != 0)
		return;

	tmp2 = SET_SINGLE_MULTICAST;
	MODE[0] = (unsigned long)tmp2;
	MODE[1] = 1;
	tmp1 = (unsigned long)pucMulticastAddress;
	MODE[2] = tmp1;
	MODE[3] = ENABLE_MULTICAST;
	MODE[4] = 0;
	mdlChangeFilter(pLayerPointers, (unsigned long *)MODE);
}


/*
 *	Purpose  :
 *		This routine deletes the Multicast addresses requested by OS.
 *
 *	Arguments :
 *		pLayerPointers
 *			Pointer to Layer pointers structure.
 *		pucMulticastAddress
 *			Pointer to the array of multicast addresses
 */
void
mdlDeleteMulticastAddress(struct LayerPointers *pLayerPointers,
    UCHAR *pucMulticastAddress)
{
	unsigned long MODE[10];
	unsigned long tmp;

	if (mdlMulticastBitMapping(pLayerPointers, pucMulticastAddress,
	    DELETE_MULTICAST) != 0)
		return;

	MODE[0] = UNSET_SINGLE_MULTICAST;
	MODE[1] = 1;
	tmp = (unsigned long)pucMulticastAddress;
	MODE[2] = tmp;
	MODE[3] = ENABLE_MULTICAST;
	MODE[4] = 0;
	mdlChangeFilter(pLayerPointers, (unsigned long *)MODE);
}

/*
 *	Purpose  :
 *		Calculates the CRC value over the input number of bytes.
 *
 *	Arguments :
 *		NumberOfBytes
 *			The number of bytes in the input.
 *		Input
 *			An input "string" to calculate a CRC over.
 */
static unsigned int
mdlCalculateCRC(unsigned int NumberOfBytes, unsigned char *Input)
{
	const unsigned int POLY = 0x04c11db7;
	unsigned int CRCValue = 0xffffffff;
	unsigned int CurrentBit, CurrentCRCHigh;
	unsigned char CurrentByte;

	for (; NumberOfBytes; NumberOfBytes--) {
		CurrentByte = *Input;
		Input++;

		for (CurrentBit = 8; CurrentBit; CurrentBit--) {
			CurrentCRCHigh = CRCValue >> 31;
			CRCValue <<= 1;

			if (CurrentCRCHigh ^ (CurrentByte & 0x01)) {
				CRCValue ^= POLY;
				CRCValue |= 0x00000001;
			}
			CurrentByte >>= 1;
		}
	}
	return (CRCValue);
}

void
mdlRxFastSuspend(struct LayerPointers *pLayerPointers)
{
	WRITE_REG32(pLayerPointers, pLayerPointers->pMdl->Mem_Address + CMD0,
	    VAL0 | RX_FAST_SPND);
}

void
mdlRxFastSuspendClear(struct LayerPointers *pLayerPointers)
{
	WRITE_REG32(pLayerPointers, pLayerPointers->pMdl->Mem_Address + CMD0,
	    RX_FAST_SPND);
}
