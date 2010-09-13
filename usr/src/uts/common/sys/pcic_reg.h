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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Intel 82365SL device and register definitions
 */

#ifndef _PCIC_REG_H
#define	_PCIC_REG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * global information
 */
#define	PCIC_MAX_CONTROLLERS	4 /* maximum of 4 chips in system */

/*
 * per socket information
 */

#define	PCIC_SOCKETS	2	/* number of sockets per PCIC chip */
#define	PCIC_MEMWINDOWS	5	/* number of memory windows per socket */
#define	PCIC_IOWINDOWS	2	/* number of I/O address windows per socket */
/* number of windows per chip */
#define	PCIC_NUMWINDOWS ((PCIC_MEMWINDOWS + PCIC_IOWINDOWS) * PCIC_SOCKETS)
/* number of windows per socket */
#define	PCIC_NUMWINSOCK	(PCIC_MEMWINDOWS+PCIC_IOWINDOWS)

/*
 * socket selection registers
 *
 * the PCIC allows up to 8 sockets per system
 * this is done by having two sockets per chip and up to 4 chips per
 * system.  There can be up to 4 sockets (2 PCIC chips) per I/O address.
 * There are two possible I/O address (index register) values.
 * socket#	I/O address	value to write to index register
 *   0		INDEX_REG0	BASE0 + SOCKET_0 + register offset
 *   1		INDEX_REG0	BASE0 + SOCKET_1 + register offset
 *   2		INDEX_REG0	BASE1 + SOCKET_0 + register offset
 *   3		INDEX_REG0	BASE1 + SOCKET_1 + register offset
 * next 4 are based off of INDEX_REG1
 */

#define	PCIC_INDEX_REG0	0x3e0	/* first possible index register */
#define	PCIC_INDEX_REG1	0x3e2	/* second possible index register */

#define	PCIC_BASE0	0x00	/* first set of sockets */
#define	PCIC_BASE1	0x80	/* second set of sockets */

#define	PCIC_SOCKET_0	0x00	/* first socket */
#define	PCIC_SOCKET_1	0x40	/* second socket */

#define	PCIC_DATA_REG0	(PCIC_INDEX_REG0+1)
#define	PCIC_DATA_REG1	(PCIC_INDEX_REG1+1)

/*
 * per socket register
 * these are accessed by writing the offset value into the
 * index register and adding the appropriate base offset and socket offset
 * the register is then present in the data register.
 */

/* General Registers */

#define	PCIC_CHIP_REVISION	0x00 /* identification and revision */
#define	PCIC_INTERFACE_STATUS	0x01 /* Interface status */
#define	PCIC_POWER_CONTROL	0x02 /* Power and RESETDRV control */
#define	PCIC_CARD_STATUS_CHANGE	0x04 /* card status change */
#define	PCIC_MAPPING_ENABLE	0x06 /* address window mapping enable */
#define	PCIC_CARD_DETECT	0x16 /* card detect&general control register */
#define	PCIC_MISC_CTL_1		0x16 /* CL version */
#define	PCIC_GLOBAL_CONTROL	0x1e /* global control register */
#define	PCIC_MISC_CTL_2		0x1e /* CL version */
#define	PCIC_CHIP_INFO		0x1f /* Cirrus Logic chip info register */

/* Interrupt Registers */

#define	PCIC_INTERRUPT		0x03 /* interrupt & general control register */
#define	PCIC_MANAGEMENT_INT	0x05 /* card status change interrupt register */

/* I/O Registers */

#define	PCIC_IO_CONTROL		0x07 /* I/O Control register */
#define	PCIC_IO_ADDR_0_STARTLOW	0x08 /* I/O address map 0 start low byte */
#define	PCIC_IO_ADDR_0_STARTHI	0x09 /* I/O address map 0 start high byte */
#define	PCIC_IO_ADDR_0_STOPLOW	0x0a /* I/O address map 0 stop low byte */
#define	PCIC_IO_ADDR_0_STOPHI	0x0b /* I/O address map 0 stop high byte */
#define	PCIC_IO_OFFSET_LOW	0x36 /* I/O Offset for CL */
#define	PCIC_IO_OFFSET_HI	0x37
#define	PCIC_IO_OFFSET_OFFSET	2

#define	PCIC_IO_ADDR_1_OFFSET	5 /* offset to second I/O map register set */
#define	PCIC_IO_WIN_MASK	0xf

/* Memory Registers */
				/* window 0 */
#define	PCIC_SYSMEM_0_STARTLOW	0x10 /* system memory map 0 start low byte */
#define	PCIC_SYSMEM_0_STARTHI	0x11 /* system memory map 0 start high byte */
#define	PCIC_SYSMEM_0_STOPLOW	0x12 /* system memory map 0 stop low byte */
#define	PCIC_SYSMEM_0_STOPHI	0x13 /* system memory map 0 stop high byte */
#define	PCIC_CARDMEM_0_LOW	0x14 /* card memory offset 0 low byte */
#define	PCIC_CARDMEM_0_HI	0x15 /* card memory offset 0 high byte */

				/* window 1 */
#define	PCIC_SYSMEM_1_STARTLOW	0x18 /* system memory map 0 start low byte */
#define	PCIC_SYSMEM_1_STARTHI	0x19 /* system memory map 0 start high byte */
#define	PCIC_SYSMEM_1_STOPLOW	0x1a /* system memory map 0 stop low byte */
#define	PCIC_SYSMEM_1_STOPHI	0x1b /* system memory map 0 stop high byte */
#define	PCIC_CARDMEM_1_LOW	0x1c /* card memory offset 0 low byte */
#define	PCIC_CARDMEM_1_HI	0x1d /* card memory offset 0 high byte */

#define	PCIC_MEM_1_OFFSET	8 /* offset to second memory map register set */
#define	PCIC_MEM_2_OFFSET	16
#define	PCIC_MEM_3_OFFSET	24
#define	PCIC_MEM_4_OFFSET	32

#define	PCIC_IO_OFFSET		4 /* offset to next set of I/O map registers */

/* Cirrus Logic specific registers */
#define	PCIC_TIME_SETUP_0	0x3A
#define	PCIC_TIME_SETUP_1	0x3D
#define	PCIC_TIME_COMMAND_0	0x3B
#define	PCIC_TIME_COMMAND_1	0x3E
#define	PCIC_TIME_RECOVER_0	0x3C
#define	PCIC_TIME_RECOVER_1	0x3F
#define	PCIC_ATA_CONTROL	0x26
#define	PCIC_FIFO_CONTROL	0x17
#define	PCIC_CL_EXINDEX		0x2e
#define	PCIC_CL_EXDATA		0x2f

/*
 * Cirrus Logic PCI-PCMCIA adapters extension register indicies
 */
#define	PCIC_CLEXT_SCRATCH	0x00
#define	PCIC_CLEXT_DMASK_0	0x01
#define	PCIC_CLEXT_EXT_CTL_1	0x03
#define	PCIC_CLEXT_MMAP0_UA	0x05
#define	PCIC_CLEXT_MMAP1_UA	0x06
#define	PCIC_CLEXT_MMAP2_UA	0x07
#define	PCIC_CLEXT_MMAP3_UA	0x08
#define	PCIC_CLEXT_MMAP4_UA	0x09
#define	PCIC_CLEXT_EXDATA	0x0a
#define	PCIC_CLEXT_EXT_CTL_2	0x0b	/* 6729 */
#define	PCIC_CLEXT_MISC_CTL_3	0x25	/* 6730 */
#define	PCIC_CLEXT_SMB_CTL	0x26	/* 6730 */

/* the 6832 is mapped into different offsets for extension regs */

#define	PCIC_CBCLEXT_MMAP0_UA	0x40 /* minus the 0x800 */
#define	PCIC_CBCLEXT_MMAP1_UA	0x41
#define	PCIC_CBCLEXT_MMAP2_UA	0x42
#define	PCIC_CBCLEXT_MMAP3_UA	0x43
#define	PCIC_CBCLEXT_MMAP4_UA	0x44
#define	PCIC_CBCLEXT_MMAP5_UA	0x45

#define	PCIC_CLEXT_MISC_CTL_3_REV_MASK	0xf0

/*
 * Cirrus Logic PCI-PCMCIA PCIC_CLEXT_EXT_CTL_1 reg bit definitions
 */
#define	PCIC_CLEXT_IRQ_LVL_MODE	0x08
#define	PCIC_CLEXT_SMI_LVL_MODE	0x00 /* see errata 1.0 */

/*
 * Cirrus Logic PCI-PCMCIA PCIC_MISC_CTL_2 reg bit definitions
 */
#define	PCIC_CL_LP_DYN_MODE	0x02	/* low-power dynamic mode */
#define	PCIC_CL_TIMER_CLK_DIV	0x10	/* PCI clock divide */

/*
 * Cirrus Logic PCI-PCMCIA PCIC_CLEXT_MISC_CTL_3 reg bit definitions
 */
#define	PCIC_CLEXT_INT_PC_PCI	0x00
#define	PCIC_CLEXT_INT_EXT_HW	0x01
#define	PCIC_CLEXT_INT_PCI_WAY	0x10
#define	PCIC_CLEXT_INT_PCI	0x03 /* see errata 1.0 */
#define	PCIC_CLEXT_PWR_EXT_HW	0x00
#define	PCIC_CLEXT_PWR_RESERVED	0x04
#define	PCIC_CLEXT_PWR_TI	0x80
#define	PCIC_CLEXT_PWR_SMB	0xc0

/*
 * Intel 82092-AA reg and bit definitions
 */
#define	PCIC_82092_PCICON	0x40	/* PCI configuration control */
#define	PCIC_82092_PCICLK_25MHZ	0x01	/* 25MHz PCI clock */
#define	PCIC_82092_SLOT_CONFIG	0x06	/* config mask */
#define	PCIC_82092_2_SOCKETS	0x00	/* 2 sockets */
#define	PCIC_82092_1_SOCKET	0x02	/* 1 socket + IDE */
#define	PCIC_82092_4_SOCKETS	0x04	/* 4 sockets + IDE */
#define	PCIC_82092_EN_TIMING	0x20	/* enhanced memory window timing */
#define	PCIC_82092_PWB		0x08	/* Post Write Buffering */
#define	PCIC_82092_RPFB		0x10	/* Read Prefetch Buffering */
#define	PCIC_82092_PPIRR	0x50	/* interrupt routing register */
#define	PCIC_82092_SMI_CTL(sock, state)	(state << (sock * 2))
#define	PCIC_82092_IRQ_CTL(sock, state)	(state << ((sock * 2) + 1))
#define	PCIC_82092_CTL_SMI	0x01
#define	PCIC_82092_CTL_IRQ	0x02
#define	PCIC_82092_INT_DISABLE	0x00
#define	PCIC_82092_INT_ENABLE	0x01
#define	PCIC_82092_CPAGE	0x26	/* CPAGE register */

/*
 * identification and revision register
 */
#define	PCIC_REV_ID_MASK	0xc0
#define	PCIC_REV_ID_IO		0x00
#define	PCIC_REV_ID_MEM		0x40
#define	PCIC_REV_ID_BOTH	0x80

/*
 * interface status register bit definitions
 */
#define	PCIC_ISTAT_CD_MASK	0xC /* card detect mask */
#define	PCIC_CD_PRESENT_OK	0xC /* card is present and fully seated */
#define	PCIC_CD_NOTPRESENT	0x0 /* card not present */
#define	PCIC_CD_NOTSEATED_1	0x8 /* card not fully seated */
#define	PCIC_CD1		0x8
#define	PCIC_CD_NOTSEATED_2	0x4 /* card not fully seated */
#define	PCIC_CD2		0x4
#define	PCIC_WRITE_PROTECT	0x10
#define	PCIC_READY		0x20
#define	PCIC_POWER_ON		0x40
#define	PCIC_VPP_VALID		0x80
#define	PCIC_BVD1		0x1
#define	PCIC_BVD2		0x2

/*
 * memory register definitions
 */
#define	SYSMEM_LOW(x)		(((uint32_t)(x)>>12)&0xFF)
#define	SYSMEM_HIGH(x)		(((uint32_t)(x)>>20)&0xF)
#define	SYSMEM_EXT(x)		(((uint32_t)(x)>>24)&0xFF)
#define	SYSMEM_WINDOW(x)	(1<<(x))
#define	SYSMEM_ZERO_WAIT	0x40 /* zero wait state bit */
#define	SYSMEM_DATA_16		0x80 /* 16 bit memory bit */
#define	SYSMEM_MEM16		0x20 /* 16 bit memory in window enable */
#define	SYSMEM_CLTIMER_SET_0	0x00
#define	SYSMEM_CLTIMER_SET_1	0x80

#define	SYSMEM_82092_600NS	0x0110
#define	SYSMEM_82092_250NS	0x0101
#define	SYSMEM_82092_200NS	0x0100
#define	SYSMEM_82092_150NS	0x0011
#define	SYSMEM_82092_100NS	0x0010
#define	SYSMEM_82092_80NS	0x0001

#define	DEFAULT_AM_ADDR		0xd0000

#define	CARDMEM_REG_ACTIVE	0x40
#define	CARDMEM_WRITE_PROTECT	0x80

#define	CARDMEM_LOW(x)		(((uint32_t)((x))>>12)&0xFF)
#define	CARDMEM_HIGH(x)		(((uint32_t)((x))>>20)&0x3F)

#define	POWER_CARD_ENABLE	0x10
#define	POWER_3VCARD_ENABLE	0x18
#define	POWER_OUTPUT_ENABLE	0x80
#define	POWER_VPP_VCC_ENABLE	0x01
#define	POWER_VPP_12V_ENABLE	0x02

/* interrupt register definitions */
#define	PCIC_INTR_ENABLE	0x10
#define	PCIC_IO_CARD		0x20
#define	PCIC_RESET		0x40
#define	PCIC_INTR_MASK		0x0f

/* card status change register definitions */
#define	PCIC_CD_DETECT		0x08
#define	PCIC_RD_DETECT		0x04
#define	PCIC_BW_DETECT		0x02
#define	PCIC_BD_DETECT		0x01
#define	PCIC_CHANGE_MASK	0x0f

/* card status change interrupt register definitions */
#define	PCIC_CD_ENABLE		0x08 /* card detect enable */
#define	PCIC_RD_ENABLE		0x04 /* ready change enable */
#define	PCIC_BW_ENABLE		0x02 /* battery warning enable */
#define	PCIC_BD_ENABLE		0x01 /* battery deat enable */
#define	PCIC_GPI_CHANGE		0x10 /* general purpose interrupt */
#define	PCIC_CHANGE_DEFAULT	(PCIC_CD_ENABLE|PCIC_RD_ENABLE|\
					PCIC_BW_ENABLE|PCIC_BD_ENABLE)

/* card detect change register */
#define	PCIC_GPI_ENABLE		0x04
#define	PCIC_GPI_TRANSITION	0x08
#define	PCIC_16MDI		0x01
#define	PCIC_SOFT_CD_INTR	0x20

/* misc control 1 */
#define	PCIC_MC_5VDETECT	0x01
#define	PCIC_MC_3VCC		0x02
#define	PCIC_MC_PULSE_SMI	0x04
#define	PCIC_MC_PULSE_IRQ	0x08
#define	PCIC_MC_SPEAKER_ENB	0x10
#define	PCIC_MC_INPACK_ENB 	0x80

/* global control registers definitions */
#define	PCIC_GC_POWERDOWN	0x01
#define	PCIC_GC_LEVELMODE	0x02
#define	PCIC_GC_CSC_WRITE	0x04
#define	PCIC_GC_IRQ1_PULSE	0x08

/* misc control 2 */
#define	PCIC_MC_BYPASS_FS	0x01
#define	PCIC_MC_LOWPOWER	0x02
#define	PCIC_MC_SUSPEND 	0x04
#define	PCIC_5V_CORE		0x08
#define	PCIC_LED_ENABLE		0x10
#define	PCIC_THREESTATE		0x20
#define	PCIC_CL_DMA		0x40
#define	PCIC_IRQ15_RI_OUT	0x80

/* chip info register (Cirrus) definitions */
#define	PCIC_CI_ID	0xc0
#define	PCIC_CI_SLOTS	0x20

/* Vadem unique registers */
#define	PCIC_VADEM_P1	0x0E
#define	PCIC_VADEM_P2	0x37

#define	PCIC_VG_VSENSE	0x1f
#define	PCIC_VG_VSELECT	0x2f
#define	PCIC_VG_CONTROL	0x38
#define	PCIC_VG_TIMER	0x39
#define	PCIC_VG_DMA	0x3A
#define	PCIC_VG_EXT_A	0x3C
#define	PCIC_VG_STATUS	0x3E

/* Vadem DMA Register */
#define	PCIC_V_DMAWSB	0x04
#define	PCIC_V_VADEMREV	0x40
#define	PCIC_V_UNLOCK	0x80

/* Vadem identification register */
#define	PCIC_VADEM_D3	0x8
#define	PCIC_VADEM_365	0x9
#define	PCIC_VADEM_465	0x8
#define	PCIC_VADEM_468	0xB
#define	PCIC_VADEM_469	0xC

/* Vadem Voltage Select */
#define	PCIC_VSEL_EXTENDED	0x10 /* extended mode */
#define	PCIC_VSEL_BUSSEL	0x20 /* extended buffers on ISA */

/* Vadem Control Register */
#define	PCIC_VC_DELAYENABLE	0x10

/* Vadem Extended Mode Register A */
#define	PCIC_VEXT_CABLEMODE	0x08 /* enable external cable */

#define	PCIC_YENTA_MEM_PAGE	0x40 /* yenta defined extended address byte */

/* Ricoh Specific Registers */
#define	PCIC_RF_CHIP_IDENT	0x3A
#define	PCIC_RF_296		0x32
#define	PCIC_RF_396		0xB2
#define	PCIC_RF_MEM_PAGE	PCIC_YENTA_MEM_PAGE

/* O2 Micro Specific registers */
#define	PCIC_CENTDMA	0x3C
#define	PCIC_MULTIFUNC	0x8C
#define	PCIC_O2_CTRL1	0xD0
#define	PCIC_O2_CTRL2	0xD4

/* Texas Instruments specific Registers */
#define	PCIC_INTLINE_REG	0x3C
#define	PCIC_INTPIN_REG		0x3D
#define	PCIC_BRIDGE_CTL_REG	0x3e
#define	PCIC_FUN_INT_MOD_ISA	0x80

/* for PCI1420 chip */
#define	PCIC_BRDGCTL_INTR_MASK	0x80
#define	PCIC_GPIO0_REG		0x88
#define	PCIC_GPIO1_REG		0x89
#define	PCIC_GPIO2_REG		0x8A
#define	PCIC_GPIO3_REG		0x8B

#define	PCIC_MFROUTE_REG	0x8c
#define	PCIC_MFUNC0_MASK	0xF
#define	PCIC_MFUNC0_INTA	0x2

#define	PCIC_DIAG_REG		0x93
#define	PCIC_GPIO_FMASK		0xC0
#define	PCIC_GPIO_INTENBL	0x10
#define	PCIC_GPIO_DELTA		0x08
#define	PCIC_GPIO_DOUT		0x02
#define	PCIC_GPIO_DIN		0x01
#define	PCIC_GPIO_FOUTPUT	0xC0
#define	PCIC_GPIO_FINPUT	0x80
#define	PCIC_GPIO2_IS_PCILOCK	0x00
#define	PCIC_GPIO3_IS_INTA	0x00
#define	PCIC_TI_WINDOW_PAGE	0x3C /* legacy */
#define	PCIC_TI_WINDOW_PAGE_PCI	0x40

#define	PCIC_DIAG_REG		0x93 /* Diagnostic Register */
/* for PCI1225 chip */
#define	PCIC_DIAG_CSC		0x20 /* CSC Interrupt Routing Control */
/* for PCI1221 and PCI1225 chips */
#define	PCIC_DIAG_ASYNC		0x01 /* Async. interrupt enable */

#define	PCIC_DEVCTL_REG		0x92 /* Device Control Register */
#define	PCIC_DEVCTL_INTR_MASK	0x06 /* to mask out mode */
#define	PCIC_DEVCTL_INTR_PCI	0x00 /* PCI style interrupts */
#define	PCIC_DEVCTL_INTR_ISA	0x02 /* ISA style interrupts */
#define	PCIC_DEVCTL_INTR_SER	0x04 /* serialize IRQ scheme */
#define	PCIC_DEVCTL_INTR_RSVD	0x06 /* reserved */
/* for PCI1221 and PCI1225 chips */
#define	PCIC_DEVCTL_3VCAPABLE	0x40 /* 3V socket capable force */
#define	PCIC_DEVCTL_INTR_DFLT	0x06 /* default interrupt mode */

#define	PCIC_CRDCTL_REG		0x91 /* Card Control Register */
#define	PCIC_CRDCTL_RIENABLE    0x80 /* Ring indicate enable on TI1250a */
#define	PCIC_CRDCTL_ZVENABLE    0x40 /* Z buffer enable on TI1250a */
#define	PCIC_CRDCTL_PCIINTR	0x20 /* use PCI INT A/B */
#define	PCIC_CRDCTL_PCICSC	0x10 /* PCI intr for status */
#define	PCIC_CRDCTL_PCIFUNC	0x08 /* use PCI intr for cards */
#define	PCIC_CRDCTL_SPKR_ENBL	0x02 /* Enable speaker plumbing */
#define	PCIC_CRDCTL_IFG		0x01 /* card interrupt flag */

#define	PCIC_SYSCTL_REG		0x80 /* System Control Register */
#define	PCIC_SYSCTL_INTRTIE	0x20 /* tie INTA and INTB */

/* for Toshiba chips */
#define	PCIC_TOSHIBA_SLOT_CTL_REG	0xa0 /* slot control register */
#define	PCIC_TOSHIBA_SCR_SLOTON		0x80
#define	PCIC_TOSHIBA_SCR_SLOTEN		0x40
#define	PCIC_TOSHIBA_SCR_PRT_MASK	0xc
#define	PCIC_TOSHIBA_SCR_PRT_3E0	0x0
#define	PCIC_TOSHIBA_SCR_PRT_3E2	0x4
#define	PCIC_TOSHIBA_SCR_PRT_3E4	0x8
#define	PCIC_TOSHIBA_SCR_PRT_3E6	0xc
#define	PCIC_TOSHIBA_INTR_CTL_REG	0xa1 /* interrupt control register */
#define	PCIC_TOSHIBA_ICR_PIN_MASK	0x30
#define	PCIC_TOSHIBA_ICR_PIN_DISEN	0x0
#define	PCIC_TOSHIBA_ICR_PIN_INTA	0x10
#define	PCIC_TOSHIBA_ICR_PIN_INTB	0x20
#define	PCIC_TOSHIBA_ICR_MOD_CSC	0x4 /* CSC interrupt mode */
#define	PCIC_TOSHIBA_ICR_MOD_FUN	0x2 /* Funtional interrupt mode */
#define	PCIC_TOSHIBA_ICR_SRC		0x1 /* INTA or IRQ */

/* for Ricoh chips */
#define	PCIC_RICOH_MISC_CTL	0x82
#define	PCIC_RICOH_SIRQ_EN	0x80	/* serialized IRQ */
#define	PCIC_RICOH_MISC_CTL_2	0xa0	/* ricoh */
#define	PCIC_RICOH_CSC_INT_MOD	0x80	/* csc to ISA */
#define	PCIC_RICOH_FUN_INT_MOD	0x40	/* cint to ISA */

/* for o2micro */
#define	PCIC_O2MICRO_MISC_CTL	0x28
#define	PCIC_O2MICRO_INT_MOD_MASK	0x300
#define	PCIC_O2MICRO_INT_MOD_PCI	0x300
#define	PCIC_O2MICRO_ISA_LEGACY		0x800
/*  */

/* SMC 34C90 specific registers */
#define	PCIC_SMC_MEM_PAGE	0x40

/* available interrupts and interrupt mask */
#define	PCIC_IRQ(irq)	(1 << (irq))
#define	PCIC_IRQ03	PCIC_IRQ(3)
#define	PCIC_IRQ04	PCIC_IRQ(4)
#define	PCIC_IRQ05	PCIC_IRQ(5)
#define	PCIC_IRQ07	PCIC_IRQ(7)
#define	PCIC_IRQ09	PCIC_IRQ(9)
#define	PCIC_IRQ10	PCIC_IRQ(10)
#define	PCIC_IRQ11	PCIC_IRQ(11)
#define	PCIC_IRQ12	PCIC_IRQ(12)
#define	PCIC_IRQ14	PCIC_IRQ(14)
#define	PCIC_IRQ15	PCIC_IRQ(15)

#define	PCIC_AVAIL_IRQS	(PCIC_IRQ03|PCIC_IRQ04|PCIC_IRQ05|PCIC_IRQ07|\
				PCIC_IRQ09|PCIC_IRQ10|PCIC_IRQ11|PCIC_IRQ12|\
				PCIC_IRQ14|PCIC_IRQ15)

/* page size used for window mapping and memory resource page size */
#define	PCIC_PAGE	4096

/* used in I/O window mapping */
#define	HIGH_BYTE(x)	(uchar_t)((((ushort_t)(x)) >> 8) & 0xFF)
#define	LOW_BYTE(x)	(uchar_t)(((ushort_t)(x)) & 0xFF)
#define	PCIC_IO_0_MASK	0x0f
#define	PCIC_IO_1_MASK	0xf0
#define	IOMEM_WINDOW(x)	(1<<((x)+6))

#define	IOMEM_16BIT		0x01
#define	IOMEM_IOCS16		0x02
#define	IOMEM_ZERO_WAIT		0x04
#define	IOMEM_CLTIMER_SET_0	0x00	/* CL timer set selection */
#define	IOMEM_CLTIMER_SET_1	0x08	/* CL timer set selection */
#define	IOMEM_WAIT16		0x08
#define	IOMEM_SETWIN(w, x)	((x) << ((w)*4))

#define	IOMEM_FIRST	0	/* First I/O address */
#define	IOMEM_LAST	0xFFFF	/* Last I/O address */
#define	IOMEM_MIN	1	/* minimum I/O window size */
#define	IOMEM_MAX	0x10000	/* maximum I/O window size */
#define	IOMEM_GRAN	1	/* granularity of request */
#define	IOMEM_DECODE	16	/* number of address lines decoded */

#define	MEM_FIRST	0x10000	/* first memory address */
#define	MEM_LAST	0xFFFFF	/* last memory address */
#define	MEM_MIN		PCIC_PAGE /* minimum window size */
#define	MEM_MAX		0x10000	/* maximum window size */
#define	PAGE_SHIFT	12	/* bits to shift */

#define	SYSCLK		120	/* sysclk min time (ns) */
#define	MEM_SPEED_MIN	(SYSCLK*2)
#define	MEM_SPEED_MAX	(SYSCLK*6)

/* CardBus (Yenta) specific values */
#define	CB_R2_OFFSET	0x800	/* R2 is always at offset 0x800 */
#define	CB_CLEXT_OFFSET	0x900	/* Cirrus Logic extended at offset 0x900 */
#define	CB_CB_OFFSET	0x00	/* Cardbus registers at offset 0 */

/* Cardbus registers in TI 1250A/Cirrus 6832 and probably others.  */
/* Register offsets (these are 32 bit registers).  */
#define	CB_STATUS_EVENT		0x00
#define	CB_STATUS_MASK		0x04
#define	CB_PRESENT_STATE	0x08
#define	CB_EVENT_FORCE		0x0c
#define	CB_CONTROL		0x10

/* TI1420 */
#define	CB_SOCKET_POWER		0x20

/* Cardbus registers in 02 0Z6912.  */
#define	CB_SZVCTRL		0x20
#define	CB_SIMDCTRL		0x24
#define	CB_MISCCTRL		0x28

/* Register bit definitions.  */
#define	BYTE_3(x)		((x)<<24)
#define	BYTE_2(x)		((x)<<16)
#define	BYTE_1(x)		((x)<<8)
#define	BYTE_0(x)		(x)

#define	CB_SE_POWER_CYCLE	BYTE_0(0x08)
#define	CB_SE_CCDMASK		BYTE_0(0x06)
#define	CB_SE_CCD2		BYTE_0(0x04)
#define	CB_SE_CCD1		BYTE_0(0x02)
#define	CB_SE_CSTSCHG		BYTE_0(0x01)

#define	CB_SM_POWER_CYCLE	BYTE_0(0x08)
#define	CB_SM_CCDMASK		BYTE_0(0x06)
#define	CB_SM_CCD2		BYTE_0(0x04)
#define	CB_SM_CCD1		BYTE_0(0x02)
#define	CB_SM_CSTSCHG		BYTE_0(0x01)

#define	CB_PS_CSTSCHG		BYTE_0(0x01)
#define	CB_PS_CCDMASK		BYTE_0(0x06)
#define	CB_PS_NCCD1		BYTE_0(0x02)
#define	CB_PS_NCCD2		BYTE_0(0x04)
#define	CB_PS_POWER_CYCLE	BYTE_0(0x08)
#define	CB_PS_16BITCARD		BYTE_0(0x10)
#define	CB_PS_CBCARD		BYTE_0(0x20)
#define	CB_PS_INTERRUPT		BYTE_0(0x40)
#define	CB_PS_NOTACARD		BYTE_0(0x80)

#define	CB_PS_DATALOST		BYTE_1(0x01)
#define	CB_PS_BADVCC		BYTE_1(0x02)
#define	CB_PS_50VCARD		BYTE_1(0x04)
#define	CB_PS_33VCARD		BYTE_1(0x08)
#define	CB_PS_XVCARD		BYTE_1(0x10)
#define	CB_PS_YVCARD		BYTE_1(0x20)

#define	CB_PS_50VSOCKET		BYTE_3(0x10)
#define	CB_PS_33VSOCKET		BYTE_3(0x20)
#define	CB_PS_XVSOCKET		BYTE_3(0x40)
#define	CB_PS_YVSOCKET		BYTE_3(0x80)

#define	CB_EF_CSTSCHG		BYTE_0(0x01)
#define	CB_EF_CCD1		BYTE_0(0x02)
#define	CB_EF_CCD2		BYTE_0(0x04)
#define	CB_EF_POWER_CYCLE	BYTE_0(0x08)
#define	CB_EF_16BITCARD		BYTE_0(0x10)
#define	CB_EF_CBCARD		BYTE_0(0x20)
#define	CB_EF_NOTACARD		BYTE_0(0x80)

#define	CB_EF_DATALOST		BYTE_1(0x01)
#define	CB_EF_BADVCC		BYTE_1(0x02)
#define	CB_EF_50V		BYTE_1(0x04)
#define	CB_EF_33V		BYTE_1(0x08)
#define	CB_EF_XV		BYTE_1(0x10)
#define	CB_EF_YV		BYTE_1(0x20)
#define	CB_EF_CVTEST		BYTE_1(0x40)

#define	CB_C_VPPMASK		BYTE_0(0x07)
#define	CB_C_VCCMASK		BYTE_0(0x70)

#define	CB_C_VPP0V		BYTE_0(0x00)
#define	CB_C_VPP12V		BYTE_0(0x01)
#define	CB_C_VPPVCC		BYTE_0(0x03)

#define	CB_C_VCC0V		BYTE_0(0x00)
#define	CB_C_VCC50V		BYTE_0(0x20)
#define	CB_C_VCC33V		BYTE_0(0x30)

#ifdef	__cplusplus
}
#endif

#endif	/* _PCIC_REG_H */
