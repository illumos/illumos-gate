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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2018 Joyent, Inc.
 */

#ifndef	_SYS_PCI_H
#define	_SYS_PCI_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * PCI Configuration Header offsets
 */
#define	PCI_CONF_VENID		0x0	/* vendor id, 2 bytes */
#define	PCI_CONF_DEVID		0x2	/* device id, 2 bytes */
#define	PCI_CONF_COMM		0x4	/* command register, 2 bytes */
#define	PCI_CONF_STAT		0x6	/* status register, 2 bytes */
#define	PCI_CONF_REVID		0x8	/* revision id, 1 byte */
#define	PCI_CONF_PROGCLASS	0x9	/* programming class code, 1 byte */
#define	PCI_CONF_SUBCLASS	0xA	/* sub-class code, 1 byte */
#define	PCI_CONF_BASCLASS	0xB	/* basic class code, 1 byte */
#define	PCI_CONF_CACHE_LINESZ	0xC	/* cache line size, 1 byte */
#define	PCI_CONF_LATENCY_TIMER	0xD	/* latency timer, 1 byte */
#define	PCI_CONF_HEADER		0xE	/* header type, 1 byte */
#define	PCI_CONF_BIST		0xF	/* builtin self test, 1 byte */

/*
 * Header type 0 offsets
 */
#define	PCI_CONF_BASE0		0x10	/* base register 0, 4 bytes */
#define	PCI_CONF_BASE1		0x14	/* base register 1, 4 bytes */
#define	PCI_CONF_BASE2		0x18	/* base register 2, 4 bytes */
#define	PCI_CONF_BASE3		0x1c	/* base register 3, 4 bytes */
#define	PCI_CONF_BASE4		0x20	/* base register 4, 4 bytes */
#define	PCI_CONF_BASE5		0x24	/* base register 5, 4 bytes */
#define	PCI_CONF_CIS		0x28	/* Cardbus CIS Pointer */
#define	PCI_CONF_SUBVENID	0x2c	/* Subsystem Vendor ID */
#define	PCI_CONF_SUBSYSID	0x2e	/* Subsystem ID */
#define	PCI_CONF_ROM		0x30	/* ROM base register, 4 bytes */
#define	PCI_CONF_CAP_PTR	0x34	/* capabilities pointer, 1 byte */
#define	PCI_CONF_ILINE		0x3c	/* interrupt line, 1 byte */
#define	PCI_CONF_IPIN		0x3d	/* interrupt pin, 1 byte */
#define	PCI_CONF_MIN_G		0x3e	/* minimum grant, 1 byte */
#define	PCI_CONF_MAX_L		0x3f	/* maximum grant, 1 byte */

/*
 * PCI to PCI bridge configuration space header format
 */
#define	PCI_BCNF_PRIBUS		0x18	/* primary bus number */
#define	PCI_BCNF_SECBUS		0x19	/* secondary bus number */
#define	PCI_BCNF_SUBBUS		0x1a	/* subordinate bus number */
#define	PCI_BCNF_LATENCY_TIMER	0x1b
#define	PCI_BCNF_IO_BASE_LOW	0x1c
#define	PCI_BCNF_IO_LIMIT_LOW	0x1d
#define	PCI_BCNF_SEC_STATUS	0x1e
#define	PCI_BCNF_MEM_BASE	0x20
#define	PCI_BCNF_MEM_LIMIT	0x22
#define	PCI_BCNF_PF_BASE_LOW	0x24
#define	PCI_BCNF_PF_LIMIT_LOW	0x26
#define	PCI_BCNF_PF_BASE_HIGH	0x28
#define	PCI_BCNF_PF_LIMIT_HIGH	0x2c
#define	PCI_BCNF_IO_BASE_HI	0x30
#define	PCI_BCNF_IO_LIMIT_HI	0x32
#define	PCI_BCNF_CAP_PTR	0x34
#define	PCI_BCNF_ROM		0x38
#define	PCI_BCNF_ILINE		0x3c
#define	PCI_BCNF_IPIN		0x3d
#define	PCI_BCNF_BCNTRL		0x3e

#define	PCI_BCNF_BASE_NUM	0x2

/*
 * PCI to PCI bridge control register (0x3e) format
 */
#define	PCI_BCNF_BCNTRL_PARITY_ENABLE	0x1
#define	PCI_BCNF_BCNTRL_SERR_ENABLE	0x2
#define	PCI_BCNF_BCNTRL_ISA_ENABLE	0x4
#define	PCI_BCNF_BCNTRL_VGA_ENABLE	0x8
#define	PCI_BCNF_BCNTRL_MAST_AB_MODE	0x20
#define	PCI_BCNF_BCNTRL_DTO_STAT	0x400

#define	PCI_BCNF_BCNTRL_RESET		0x0040
#define	PCI_BCNF_BCNTRL_B2B_ENAB	0x0080

#define	PCI_BCNF_IO_MASK	0xf0
#define	PCI_BCNF_IO_SHIFT	8
#define	PCI_BCNF_MEM_MASK	0xfff0
#define	PCI_BCNF_MEM_SHIFT	16
#define	PCI_BCNF_ADDR_MASK	0x000f

#define	PCI_BCNF_IO_32BIT	0x01
#define	PCI_BCNF_PF_MEM_64BIT	0x01

/*
 * Header type 2 (Cardbus) offsets
 */
#define	PCI_CBUS_SOCK_REG	0x10	/* Cardbus socket regs, 4 bytes */
#define	PCI_CBUS_CAP_PTR	0x14	/* Capability ptr, 1 byte */
#define	PCI_CBUS_RESERVED1	0x15	/* Reserved, 1 byte */
#define	PCI_CBUS_SEC_STATUS	0x16	/* Secondary status, 2 bytes */
#define	PCI_CBUS_PCI_BUS_NO	0x18	/* PCI bus number, 1 byte */
#define	PCI_CBUS_CBUS_NO	0x19	/* Cardbus bus number, 1 byte */
#define	PCI_CBUS_SUB_BUS_NO	0x1a	/* Subordinate bus number, 1 byte */
#define	PCI_CBUS_LATENCY_TIMER	0x1b	/* Cardbus latency timer, 1 byte */
#define	PCI_CBUS_MEM_BASE0	0x1c	/* Memory base reg 0, 4 bytes */
#define	PCI_CBUS_MEM_LIMIT0	0x20	/* Memory limit reg 0, 4 bytes */
#define	PCI_CBUS_MEM_BASE1	0x24	/* Memory base reg 1, 4 bytes */
#define	PCI_CBUS_MEM_LIMIT1	0x28	/* Memory limit reg 1, 4 bytes */
#define	PCI_CBUS_IO_BASE0	0x2c	/* IO base reg 0, 4 bytes */
#define	PCI_CBUS_IO_LIMIT0	0x30	/* IO limit reg 0, 4 bytes */
#define	PCI_CBUS_IO_BASE1	0x34	/* IO base reg 1, 4 bytes */
#define	PCI_CBUS_IO_LIMIT1	0x38	/* IO limit reg 1, 4 bytes */
#define	PCI_CBUS_ILINE		0x3c	/* interrupt line, 1 byte */
#define	PCI_CBUS_IPIN		0x3d	/* interrupt pin, 1 byte */
#define	PCI_CBUS_BRIDGE_CTRL	0x3e	/* Bridge control, 2 bytes */
#define	PCI_CBUS_SUBVENID	0x40	/* Subsystem Vendor ID, 2 bytes */
#define	PCI_CBUS_SUBSYSID	0x42	/* Subsystem ID, 2 bytes */
#define	PCI_CBUS_LEG_MODE_ADDR	0x44	/* PCCard 16bit IF legacy mode addr */

#define	PCI_CBUS_BASE_NUM	0x1	/* number of base registers */

/*
 * PCI command register bits
 */
#define	PCI_COMM_IO		0x1	/* I/O access enable */
#define	PCI_COMM_MAE		0x2	/* memory access enable */
#define	PCI_COMM_ME		0x4	/* master enable */
#define	PCI_COMM_SPEC_CYC	0x8
#define	PCI_COMM_MEMWR_INVAL	0x10
#define	PCI_COMM_PALETTE_SNOOP	0x20
#define	PCI_COMM_PARITY_DETECT	0x40
#define	PCI_COMM_WAIT_CYC_ENAB	0x80
#define	PCI_COMM_SERR_ENABLE	0x100
#define	PCI_COMM_BACK2BACK_ENAB	0x200
#define	PCI_COMM_INTX_DISABLE	0x400	/* INTx emulation disable */

/*
 * PCI Interrupt pin value
 */
#define	PCI_INTA	1
#define	PCI_INTB	2
#define	PCI_INTC	3
#define	PCI_INTD	4

/*
 * PCI status register bits
 */
#define	PCI_STAT_INTR		0x8	/* Interrupt state */
#define	PCI_STAT_CAP		0x10	/* Implements Capabilities */
#define	PCI_STAT_66MHZ		0x20	/* 66 MHz capable */
#define	PCI_STAT_UDF		0x40	/* UDF supported */
#define	PCI_STAT_FBBC		0x80	/* Fast Back-to-Back Capable */
#define	PCI_STAT_S_PERROR	0x100	/* Data Parity Reported */
#define	PCI_STAT_DEVSELT	0x600	/* Device select timing */
#define	PCI_STAT_S_TARG_AB	0x800	/* Signaled Target Abort */
#define	PCI_STAT_R_TARG_AB	0x1000	/* Received Target Abort */
#define	PCI_STAT_R_MAST_AB	0x2000	/* Received Master Abort */
#define	PCI_STAT_S_SYSERR	0x4000	/* Signaled System Error */
#define	PCI_STAT_PERROR		0x8000	/* Detected Parity Error */

/*
 * DEVSEL timing values
 */
#define	PCI_STAT_DEVSELT_FAST	0x0000
#define	PCI_STAT_DEVSELT_MEDIUM	0x0200
#define	PCI_STAT_DEVSELT_SLOW	0x0400

/*
 * BIST values
 */
#define	PCI_BIST_SUPPORTED	0x80
#define	PCI_BIST_GO		0x40
#define	PCI_BIST_RESULT_M	0x0f
#define	PCI_BIST_RESULT_OK	0x00

/*
 * PCI class codes
 */
#define	PCI_CLASS_NONE		0x0	/* class code for pre-2.0 devices */
#define	PCI_CLASS_MASS		0x1	/* Mass storage Controller class */
#define	PCI_CLASS_NET		0x2	/* Network Controller class */
#define	PCI_CLASS_DISPLAY	0x3	/* Display Controller class */
#define	PCI_CLASS_MM		0x4	/* Multimedia Controller class */
#define	PCI_CLASS_MEM		0x5	/* Memory Controller class */
#define	PCI_CLASS_BRIDGE	0x6	/* Bridge Controller class */
#define	PCI_CLASS_COMM		0x7	/* Communications Controller class */
#define	PCI_CLASS_PERIPH	0x8	/* Peripheral Controller class */
#define	PCI_CLASS_INPUT		0x9	/* Input Device class */
#define	PCI_CLASS_DOCK		0xa	/* Docking Station class */
#define	PCI_CLASS_PROCESSOR	0xb	/* Processor class */
#define	PCI_CLASS_SERIALBUS	0xc	/* Serial Bus class */
#define	PCI_CLASS_WIRELESS	0xd	/* Wireless Controller class */
#define	PCI_CLASS_INTIO		0xe	/* Intelligent IO Controller class */
#define	PCI_CLASS_SATELLITE	0xf	/* Satellite Communication class */
#define	PCI_CLASS_CRYPT		0x10	/* Encrytion/Decryption class */
#define	PCI_CLASS_SIGNAL	0x11	/* Signal Processing class */

/*
 * PCI Sub-class codes - base class 0x0 (no new devices should use this code).
 */
#define	PCI_NONE_NOTVGA		0x0	/* All devices except VGA compatible */
#define	PCI_NONE_VGA		0x1	/* VGA compatible */

/*
 * PCI Sub-class codes - base class 0x1 (mass storage controllers)
 */
#define	PCI_MASS_SCSI		0x0	/* SCSI bus Controller */
#define	PCI_MASS_IDE		0x1	/* IDE Controller */
#define	PCI_MASS_FD		0x2	/* Floppy disk Controller */
#define	PCI_MASS_IPI		0x3	/* IPI bus Controller */
#define	PCI_MASS_RAID		0x4	/* RAID Controller */
#define	PCI_MASS_ATA		0x5	/* ATA Controller */
#define	PCI_MASS_SATA		0x6	/* Serial ATA */
#define	PCI_MASS_SAS		0x7	/* Serial Attached SCSI (SAS) Cntrlr */
#define	PCI_MASS_NVME		0x8	/* Non-Volatile memory controller */
#define	PCI_MASS_OTHER		0x80	/* Other Mass Storage Controller */

/*
 * programming interface for IDE (subclass 1)
 */
#define	PCI_IDE_IF_NATIVE_PRI	0x1	/* primary channel is native */
#define	PCI_IDE_IF_PROG_PRI	0x2	/* primary can operate in either mode */
#define	PCI_IDE_IF_NATIVE_SEC	0x4	/* secondary channel is native */
#define	PCI_IDE_IF_PROG_SEC	0x8	/* sec. can operate in either mode */
#define	PCI_IDE_IF_MASK		0xf	/* programming interface mask */


/*
 * programming interface for ATA (subclass 5)
 */
#define	PCI_ATA_IF_SINGLE_DMA	0x20	/* ATA controller with single DMA */
#define	PCI_ATA_IF_CHAINED_DMA	0x30	/* ATA controller with chained DMA */

/*
 * programming interface for ATA (subclass 6) for SATA
 */
#define	PCI_SATA_VS_INTERFACE	0x0	/* SATA Ctlr Vendor Specific Intfc */
#define	PCI_SATA_AHCI_INTERFACE	0x1	/* SATA Ctlr AHCI 1.0 Interface */
#define	PCI_SATA_SSB_INTERFACE	0x2	/* Serial Storage Bus Interface */

/*
 * programming interface for ATA (subclass 7) for SAS
 */
#define	PCI_SAS_CONTROLLER	0x0	/* SAS Controller */
#define	PCI_SAS_BUS_INTERFACE	0x1	/* Serial Storage Bus Interface */

/*
 * PCI Sub-class codes - base class 0x2 (Network controllers)
 */
#define	PCI_NET_ENET		0x0	/* Ethernet Controller */
#define	PCI_NET_TOKEN		0x1	/* Token Ring Controller */
#define	PCI_NET_FDDI		0x2	/* FDDI Controller */
#define	PCI_NET_ATM		0x3	/* ATM Controller */
#define	PCI_NET_ISDN		0x4	/* ISDN Controller */
#define	PCI_NET_WFIP		0x5	/* WorldFip Controller */
#define	PCI_NET_PICMG		0x6	/* PICMG 2.14 Multi Computing */
#define	PCI_NET_OTHER		0x80	/* Other Network Controller */

/*
 * PCI Sub-class codes - base class 03 (display controllers)
 */
#define	PCI_DISPLAY_VGA		0x0	/* VGA device */
#define	PCI_DISPLAY_XGA		0x1	/* XGA device */
#define	PCI_DISPLAY_3D		0x2	/* 3D controller */
#define	PCI_DISPLAY_OTHER	0x80	/* Other Display Device */

/*
 * programming interface for display for display class (subclass 0) VGA ctrlrs
 */
#define	PCI_DISPLAY_IF_VGA	0x0	/* VGA compatible */
#define	PCI_DISPLAY_IF_8514	0x1	/* 8514 compatible */

/*
 * PCI Sub-class codes - base class 0x4 (multi-media devices)
 */
#define	PCI_MM_VIDEO		0x0	/* Video device */
#define	PCI_MM_AUDIO		0x1	/* Audio device */
#define	PCI_MM_TELEPHONY	0x2	/* Computer Telephony device */
#define	PCI_MM_MIXED_MODE	0x3	/* Mixed Mode device */
#define	PCI_MM_OTHER		0x80	/* Other Multimedia Device */

/*
 * PCI Sub-class codes - base class 0x5 (memory controllers)
 */
#define	PCI_MEM_RAM		0x0	/* RAM device */
#define	PCI_MEM_FLASH		0x1	/* FLASH device */
#define	PCI_MEM_OTHER		0x80	/* Other Memory Controller */

/*
 * PCI Sub-class codes - base class 0x6 (Bridge devices)
 */
#define	PCI_BRIDGE_HOST		0x0	/* Host/PCI Bridge */
#define	PCI_BRIDGE_ISA		0x1	/* PCI/ISA Bridge */
#define	PCI_BRIDGE_EISA		0x2	/* PCI/EISA Bridge */
#define	PCI_BRIDGE_MC		0x3	/* PCI/MC Bridge */
#define	PCI_BRIDGE_PCI		0x4	/* PCI/PCI Bridge */
#define	PCI_BRIDGE_PCMCIA	0x5	/* PCI/PCMCIA Bridge */
#define	PCI_BRIDGE_NUBUS	0x6	/* PCI/NUBUS Bridge */
#define	PCI_BRIDGE_CARDBUS	0x7	/* PCI/CARDBUS Bridge */
#define	PCI_BRIDGE_RACE		0x8	/* RACE-way Bridge */
#define	PCI_BRIDGE_STPCI	0x9	/* Semi-transparent PCI/PCI Bridge */
#define	PCI_BRIDGE_IB		0xA	/* InfiniBand/PCI host Bridge */
#define	PCI_BRIDGE_AS		0xB	/* AS/PCI host Bridge */
#define	PCI_BRIDGE_OTHER	0x80	/* PCI/Other Bridge Device */

/*
 * programming interface for Bridges class 0x6 (subclass 4) PCI-PCI bridge
 */
#define	PCI_BRIDGE_PCI_IF_PCI2PCI	0x0	/* PCI-PCI bridge */
#define	PCI_BRIDGE_PCI_IF_SUBDECODE	0x1	/* Subtractive Decode */
						/* PCI/PCI bridge */

/*
 * programming interface for Bridges class 0x6 (subclass 08) RACEway bridge
 */
#define	PCI_BRIDGE_RACE_IF_TRANSPARENT	0x0	/* Transport mode */
#define	PCI_BRIDGE_RACE_IF_ENDPOINT	0x1	/* Endpoint mode */

/*
 * programming interface for Bridges class 0x6 (subclass 09)
 * Semi-transparent PCI-to-PCI bridge
 */
#define	PCI_BRIDGE_STPCI_IF_PRIMARY	0x40	/* primary PCI side bus */
						/* facing system processor */
#define	PCI_BRIDGE_STPCI_IF_SECONDARY	0x80	/* secondary PCI side bus */
						/* facing system processor */

/*
 * programming interface for Bridges class 0x6 (subclass 0B) AS bridge
 */
#define	PCI_BRIDGE_AS_CUSTOM_INTFC	0x0	/* Custom interface */
#define	PCI_BRIDGE_AS_PORTAL_INTFC	0x1	/* ASI-SIG Portal Interface */

/*
 * PCI Sub-class codes - base class 0x7 (communication devices)
 */
#define	PCI_COMM_GENERIC_XT	0x0	/* XT Compatible Serial Controller */
#define	PCI_COMM_PARALLEL	0x1	/* Parallel Port Controller */
#define	PCI_COMM_MSC		0x2	/* Multiport Serial Controller */
#define	PCI_COMM_MODEM		0x3	/* Modem Controller */
#define	PCI_COMM_GPIB		0x4	/* GPIB Controller */
#define	PCI_COMM_SMARTCARD	0x5	/* Smart Card Controller */
#define	PCI_COMM_OTHER		0x80	/* Other Communications Controller */

/*
 * Programming interfaces for class 0x7 / subclass 0x0 (Serial)
 */
#define	PCI_COMM_SERIAL_IF_GENERIC	0x0	/* Generic XT-compat serial */
#define	PCI_COMM_SERIAL_IF_16450	0x1	/* 16450-compat serial ctrlr */
#define	PCI_COMM_SERIAL_IF_16550	0x2	/* 16550-compat serial ctrlr */
#define	PCI_COMM_SERIAL_IF_16650	0x3	/* 16650-compat serial ctrlr */
#define	PCI_COMM_SERIAL_IF_16750	0x4	/* 16750-compat serial ctrlr */
#define	PCI_COMM_SERIAL_IF_16850	0x5	/* 16850-compat serial ctrlr */
#define	PCI_COMM_SERIAL_IF_16950	0x6	/* 16950-compat serial ctrlr */

/*
 * Programming interfaces for class 0x7 / subclass 0x1 (Parallel)
 */
#define	PCI_COMM_PARALLEL_IF_GENERIC	0x0	/* Generic Parallel port */
#define	PCI_COMM_PARALLEL_IF_BIDIRECT	0x1	/* Bi-directional Parallel */
#define	PCI_COMM_PARALLEL_IF_ECP	0x2	/* ECP 1.X Parallel port */
#define	PCI_COMM_PARALLEL_IF_1284	0x3	/* IEEE 1284 Parallel port */
#define	PCI_COMM_PARALLEL_IF_1284_TARG	0xFE	/* IEEE 1284 target device */

/*
 * Programming interfaces for class 0x7 / subclass 0x3 (Modem)
 */
#define	PCI_COMM_MODEM_IF_GENERIC	0x0	/* Generic Modem */
#define	PCI_COMM_MODEM_IF_HAYES_16450	0x1	/* Hayes 16450-compat Modem */
#define	PCI_COMM_MODEM_IF_HAYES_16550	0x2	/* Hayes 16550-compat Modem */
#define	PCI_COMM_MODEM_IF_HAYES_16650	0x3	/* Hayes 16650-compat Modem */
#define	PCI_COMM_MODEM_IF_HAYES_16750	0x4	/* Hayes 16750-compat Modem */

/*
 * PCI Sub-class codes - base class 0x8
 */
#define	PCI_PERIPH_PIC		0x0	/* Generic PIC */
#define	PCI_PERIPH_DMA		0x1	/* Generic DMA Controller */
#define	PCI_PERIPH_TIMER	0x2	/* Generic System Timer Controller */
#define	PCI_PERIPH_RTC		0x3	/* Generic RTC Controller */
#define	PCI_PERIPH_HPC		0x4	/* Generic PCI Hot-Plug Controller */
#define	PCI_PERIPH_SD_HC	0x5	/* SD Host Controller */
#define	PCI_PERIPH_IOMMU	0x6	/* IOMMU */
#define	PCI_PERIPH_OTHER	0x80	/* Other System Peripheral */

/*
 * Programming interfaces for class 0x8 / subclass 0x0 (interrupt controller)
 */
#define	PCI_PERIPH_PIC_IF_GENERIC	0x0	/* Generic 8259 APIC */
#define	PCI_PERIPH_PIC_IF_ISA		0x1	/* ISA PIC */
#define	PCI_PERIPH_PIC_IF_EISA		0x2	/* EISA PIC */
#define	PCI_PERIPH_PIC_IF_IO_APIC	0x10	/* I/O APIC interrupt ctrlr */
#define	PCI_PERIPH_PIC_IF_IOX_APIC	0x20	/* I/O(x) APIC intr ctrlr */

/*
 * Programming interfaces for class 0x8 / subclass 0x1 (DMA controller)
 */
#define	PCI_PERIPH_DMA_IF_GENERIC	0x0	/* Generic 8237 DMA ctrlr */
#define	PCI_PERIPH_DMA_IF_ISA		0x1	/* ISA DMA ctrlr */
#define	PCI_PERIPH_DMA_IF_EISA		0x2	/* EISA DMA ctrlr */

/*
 * Programming interfaces for class 0x8 / subclass 0x2 (timer)
 */
#define	PCI_PERIPH_TIMER_IF_GENERIC	0x0	/* Generic 8254 system timer */
#define	PCI_PERIPH_TIMER_IF_ISA		0x1	/* ISA system timers */
#define	PCI_PERIPH_TIMER_IF_EISA	0x2	/* EISA system timers (two) */
#define	PCI_PERIPH_TIMER_IF_HPET	0x3	/* High Perf Event timer */

/*
 * Programming interfaces for class 0x8 / subclass 0x3 (realtime clock)
 */
#define	PCI_PERIPH_RTC_IF_GENERIC	0x0	/* Generic RTC controller */
#define	PCI_PERIPH_RTC_IF_ISA		0x1	/* ISA RTC controller */

/*
 * PCI Sub-class codes - base class 0x9
 */
#define	PCI_INPUT_KEYBOARD	0x0	/* Keyboard Controller */
#define	PCI_INPUT_DIGITIZ	0x1	/* Digitizer (Pen) */
#define	PCI_INPUT_MOUSE		0x2	/* Mouse Controller */
#define	PCI_INPUT_SCANNER	0x3	/* Scanner Controller */
#define	PCI_INPUT_GAMEPORT	0x4	/* Gameport Controller */
#define	PCI_INPUT_OTHER		0x80	/* Other Input Controller */

/*
 * Programming interfaces for class 0x9 / subclass 0x4 (Gameport controller)
 */
#define	PCI_INPUT_GAMEPORT_IF_GENERIC	0x00	/* Generic controller */
#define	PCI_INPUT_GAMEPORT_IF_LEGACY	0x10	/* Legacy controller */

/*
 * PCI Sub-class codes - base class 0xA
 */
#define	PCI_DOCK_GENERIC	0x00	/* Generic Docking Station */
#define	PCI_DOCK_OTHER		0x80	/* Other Type of Docking Station */

/*
 * PCI Sub-class codes - base class 0xB
 */
#define	PCI_PROCESSOR_386	0x0	/* 386 */
#define	PCI_PROCESSOR_486	0x1	/* 486 */
#define	PCI_PROCESSOR_PENT	0x2	/* Pentium */
#define	PCI_PROCESSOR_ALPHA	0x10	/* Alpha */
#define	PCI_PROCESSOR_POWERPC	0x20	/* PowerPC */
#define	PCI_PROCESSOR_MIPS	0x30	/* MIPS */
#define	PCI_PROCESSOR_COPROC	0x40	/* Co-processor */
#define	PCI_PROCESSOR_OTHER	0x80	/* Other processors */

/*
 * PCI Sub-class codes - base class 0xC (Serial Controllers)
 */
#define	PCI_SERIAL_FIRE		0x0	/* FireWire (IEEE 1394) */
#define	PCI_SERIAL_ACCESS	0x1	/* ACCESS.bus */
#define	PCI_SERIAL_SSA		0x2	/* SSA */
#define	PCI_SERIAL_USB		0x3	/* Universal Serial Bus */
#define	PCI_SERIAL_FIBRE	0x4	/* Fibre Channel */
#define	PCI_SERIAL_SMBUS	0x5	/* System Management Bus */
#define	PCI_SERIAL_IB		0x6	/* InfiniBand */
#define	PCI_SERIAL_IPMI		0x7	/* IPMI */
#define	PCI_SERIAL_SERCOS	0x8	/* SERCOS Interface Std (IEC 61491) */
#define	PCI_SERIAL_CANBUS	0x9	/* CANbus */
#define	PCI_SERIAL_OTHER	0x80	/* Other Serial Bus Controllers */

/*
 * Programming interfaces for class 0xC / subclass 0x0 (Firewire)
 */
#define	PCI_SERIAL_FIRE_WIRE		0x00	/* IEEE 1394 (Firewire) */
#define	PCI_SERIAL_FIRE_1394_HCI	0x10	/* 1394 OpenHCI Host Cntrlr */

/*
 * Programming interfaces for class 0xC / subclass 0x3 (USB controller)
 */
#define	PCI_SERIAL_USB_IF_UHCI		0x00	/* UHCI Compliant */
#define	PCI_SERIAL_USB_IF_OHCI		0x10	/* OHCI Compliant */
#define	PCI_SERIAL_USB_IF_EHCI		0x20	/* EHCI Compliant */
#define	PCI_SERIAL_USB_IF_GENERIC	0x80	/* no specific HCD */
#define	PCI_SERIAL_USB_IF_DEVICE	0xFE	/* not a HCD */

/*
 * Programming interfaces for class 0xC / subclass 0x7 (IPMI controller)
 */
#define	PCI_SERIAL_IPMI_IF_SMIC		0x0	/* SMIC Interface */
#define	PCI_SERIAL_IPMI_IF_KBD		0x1	/* Keyboard Ctrl Style Intfc */
#define	PCI_SERIAL_IPMI_IF_BTI		0x2	/* Block Transfer Interface */

/*
 * PCI Sub-class codes - base class 0xD (Wireless controllers)
 */
#define	PCI_WIRELESS_IRDA		0x0	/* iRDA Compatible Controller */
#define	PCI_WIRELESS_IR			0x1	/* Consumer IR Controller */
#define	PCI_WIRELESS_RF			0x10	/* RF Controller */
#define	PCI_WIRELESS_BLUETOOTH		0x11	/* Bluetooth Controller */
#define	PCI_WIRELESS_BROADBAND		0x12	/* Broadband Controller */
#define	PCI_WIRELESS_80211A		0x20	/* Ethernet 802.11a 5 GHz */
#define	PCI_WIRELESS_80211B		0x21	/* Ethernet 802.11b 2.4 GHz */
#define	PCI_WIRELESS_OTHER		0x80	/* Other Wireless Controllers */

/*
 * Programming interfaces for class 0xD / subclass 0x1 (Consumer IR controller)
 */
#define	PCI_WIRELESS_IR_CONSUMER	0x00	/* Consumer IR Controller */
#define	PCI_WIRELESS_IR_UWB_RC		0x10	/* UWB Radio Controller */

/*
 * PCI Sub-class codes - base class 0xE (Intelligent I/O controllers)
 */
#define	PCI_INTIO_MSG_FIFO		0x0	/* Message FIFO at off 40h */
#define	PCI_INTIO_I20			0x1	/* I20 Arch Spec 1.0 */

/*
 * PCI Sub-class codes - base class 0xF (Satellite Communication controllers)
 */
#define	PCI_SATELLITE_COMM_TV		0x01	/* TV */
#define	PCI_SATELLITE_COMM_AUDIO	0x02	/* Audio */
#define	PCI_SATELLITE_COMM_VOICE	0x03	/* Voice */
#define	PCI_SATELLITE_COMM_DATA		0x04	/* DATA */
#define	PCI_SATELLITE_COMM_OTHER	0x80	/* Other Satelite Comm Cntrlr */

/*
 * PCI Sub-class codes - base class 0x10 (Encryption/Decryption controllers)
 */
#define	PCI_CRYPT_NETWORK		0x00	/* Network and Computing */
#define	PCI_CRYPT_ENTERTAINMENT		0x10	/* Entertainment en/decrypt */
#define	PCI_CRYPT_OTHER			0x80	/* Other en/decryption ctrlrs */

/*
 * PCI Sub-class codes - base class 0x11 (Signal Processing controllers)
 */
#define	PCI_SIGNAL_DPIO			0x00	/* DPIO modules */
#define	PCI_SIGNAL_PERF_COUNTERS	0x01	/* Performance counters */
#define	PCI_SIGNAL_COMM_SYNC		0x10	/* Comm. synchronization plus */
						/* time and freq test ctrlr */
#define	PCI_SIGNAL_MANAGEMENT		0x20	/* Management card */
#define	PCI_SIGNAL_OTHER		0x80	/* DSP/DAP controller */

/* PCI header decode */
#define	PCI_HEADER_MULTI	0x80	/* multi-function device */
#define	PCI_HEADER_ZERO		0x00	/* type zero PCI header */
#define	PCI_HEADER_ONE		0x01	/* type one PCI header */
#define	PCI_HEADER_TWO		0x02	/* type two PCI header */
#define	PCI_HEADER_PPB		PCI_HEADER_ONE  /* type one PCI to PCI Bridge */
#define	PCI_HEADER_CARDBUS	PCI_HEADER_TWO	/* type one PCI header */

#define	PCI_HEADER_TYPE_M	0x7f  /* type mask for header */

/*
 * Base register bit definitions.
 */
#define	PCI_BASE_SPACE_M    0x1  /* memory space indicator */
#define	PCI_BASE_SPACE_IO   0x1   /* IO space */
#define	PCI_BASE_SPACE_MEM  0x0   /* memory space */

#define	PCI_BASE_TYPE_MEM   0x0   /* 32-bit memory address */
#define	PCI_BASE_TYPE_LOW   0x2   /* less than 1Mb address */
#define	PCI_BASE_TYPE_ALL   0x4   /* 64-bit memory address */
#define	PCI_BASE_TYPE_RES   0x6   /* reserved */

#define	PCI_BASE_TYPE_M		0x00000006  /* type indicator mask */
#define	PCI_BASE_PREF_M		0x00000008  /* prefetch mask */
#define	PCI_BASE_M_ADDR_M	0xfffffff0  /* memory address mask */
#define	PCI_BASE_M_ADDR64_M	0xfffffffffffffff0ULL /* 64bit mem addr mask */
#define	PCI_BASE_IO_ADDR_M	0xfffffffe  /* I/O address mask */

#define	PCI_BASE_ROM_ADDR_M	0xfffff800  /* ROM address mask */
#define	PCI_BASE_ROM_ENABLE	0x00000001  /* ROM decoder enable */

/*
 * Capabilities linked list entry offsets
 */
#define	PCI_CAP_ID		0x0	/* capability identifier, 1 byte */
#define	PCI_CAP_NEXT_PTR	0x1	/* next entry pointer, 1 byte */
#define	PCI_CAP_ID_REGS_OFF	0x2	/* cap id register offset */
#define	PCI_CAP_MAX_PTR		0x30	/* maximum number of cap pointers */
#define	PCI_CAP_PTR_OFF		0x40	/* minimum cap pointer offset */
#define	PCI_CAP_PTR_MASK	0xFC	/* mask for capability pointer */

/*
 * Capability identifier values
 */
#define	PCI_CAP_ID_PM		0x1	/* power management entry */
#define	PCI_CAP_ID_AGP		0x2	/* AGP supported */
#define	PCI_CAP_ID_VPD		0x3	/* VPD supported */
#define	PCI_CAP_ID_SLOT_ID	0x4	/* Slot Identification supported */
#define	PCI_CAP_ID_MSI		0x5	/* MSI supported */
#define	PCI_CAP_ID_cPCI_HS	0x6	/* CompactPCI Host Swap supported */
#define	PCI_CAP_ID_PCIX		0x7	/* PCI-X supported */
#define	PCI_CAP_ID_HT		0x8	/* HyperTransport supported */
#define	PCI_CAP_ID_VS		0x9	/* Vendor Specific */
#define	PCI_CAP_ID_DEBUG_PORT	0xA	/* Debug Port supported */
#define	PCI_CAP_ID_cPCI_CRC	0xB	/* CompactPCI central resource ctrl */
#define	PCI_CAP_ID_PCI_HOTPLUG	0xC	/* PCI Hot Plug (SHPC) supported */
#define	PCI_CAP_ID_P2P_SUBSYS	0xD	/* PCI bridge Sub-system ID */
#define	PCI_CAP_ID_AGP_8X	0xE	/* AGP 8X supported */
#define	PCI_CAP_ID_SECURE_DEV	0xF	/* Secure Device supported */
#define	PCI_CAP_ID_PCI_E	0x10	/* PCI Express supported */
#define	PCI_CAP_ID_MSI_X	0x11	/* MSI-X supported */
#define	PCI_CAP_ID_SATA		0x12	/* SATA Data/Index Config supported */
#define	PCI_CAP_ID_FLR		0x13	/* Function Level Reset supported */

/*
 * Capability next entry pointer values
 */
#define	PCI_CAP_NEXT_PTR_NULL	0x0	/* no more entries in the list */

/*
 * PCI power management (PM) capability entry offsets
 */
#define	PCI_PMCAP		0x2	/* PM capabilities, 2 bytes */
#define	PCI_PMCSR		0x4	/* PM control/status reg, 2 bytes */
#define	PCI_PMCSR_BSE		0x6	/* PCI-PCI bridge extensions, 1 byte */
#define	PCI_PMDATA		0x7	/* PM data, 1 byte */

/*
 * PM capabilities values - 2 bytes
 */
#define	PCI_PMCAP_VER_1_0	0x1	/* PCI PM spec 1.0 */
#define	PCI_PMCAP_VER_1_1	0x2	/* PCI PM spec 1.1 */
#define	PCI_PMCAP_VER_MASK	0x7	/* version mask */
#define	PCI_PMCAP_PME_CLOCK	0x8	/* needs PCI clock for PME */
#define	PCI_PMCAP_DSI		0x20	/* needs device specific init */
#define	PCI_PMCAP_AUX_CUR_SELF	0x0	/* 0 aux current - self powered */
#define	PCI_PMCAP_AUX_CUR_55mA	0x40	/* 55 mA aux current */
#define	PCI_PMCAP_AUX_CUR_100mA	0x80	/* 100 mA aux current */
#define	PCI_PMCAP_AUX_CUR_160mA	0xc0	/* 160 mA aux current */
#define	PCI_PMCAP_AUX_CUR_220mA	0x100	/* 220 mA aux current */
#define	PCI_PMCAP_AUX_CUR_270mA	0x140	/* 270 mA aux current */
#define	PCI_PMCAP_AUX_CUR_320mA	0x180	/* 320 mA aux current */
#define	PCI_PMCAP_AUX_CUR_375mA	0x1c0	/* 375 mA aux current */
#define	PCI_PMCAP_AUX_CUR_MASK	0x1c0	/* 3.3Vaux aux current needs */
#define	PCI_PMCAP_D1		0x200	/* D1 state supported */
#define	PCI_PMCAP_D2		0x400	/* D2 state supported */
#define	PCI_PMCAP_D0_PME	0x800	/* PME from D0 */
#define	PCI_PMCAP_D1_PME	0x1000	/* PME from D1 */
#define	PCI_PMCAP_D2_PME	0x2000	/* PME from D2 */
#define	PCI_PMCAP_D3HOT_PME	0x4000	/* PME from D3hot */
#define	PCI_PMCAP_D3COLD_PME	0x8000	/* PME from D3cold */
#define	PCI_PMCAP_PME_MASK	0xf800	/* PME support mask */

/*
 * PM control/status values - 2 bytes
 */
#define	PCI_PMCSR_D0			0x0	/* power state D0 */
#define	PCI_PMCSR_D1			0x1	/* power state D1 */
#define	PCI_PMCSR_D2			0x2	/* power state D2 */
#define	PCI_PMCSR_D3HOT			0x3	/* power state D3hot */
#define	PCI_PMCSR_STATE_MASK		0x3	/* power state mask */
#define	PCI_PMCSR_PME_EN		0x100	/* enable PME assertion */
#define	PCI_PMCSR_DSEL_D0_PWR_C		0x0	/* D0 power consumed */
#define	PCI_PMCSR_DSEL_D1_PWR_C		0x200	/* D1 power consumed */
#define	PCI_PMCSR_DSEL_D2_PWR_C		0x400	/* D2 power consumed */
#define	PCI_PMCSR_DSEL_D3_PWR_C		0x600	/* D3 power consumed */
#define	PCI_PMCSR_DSEL_D0_PWR_D		0x800	/* D0 power dissipated */
#define	PCI_PMCSR_DSEL_D1_PWR_D		0xa00	/* D1 power dissipated */
#define	PCI_PMCSR_DSEL_D2_PWR_D		0xc00	/* D2 power dissipated */
#define	PCI_PMCSR_DSEL_D3_PWR_D		0xe00	/* D3 power dissipated */
#define	PCI_PMCSR_DSEL_COM_C		0x1000	/* common power consumption */
#define	PCI_PMCSR_DSEL_MASK		0x1e00	/* data select mask */
#define	PCI_PMCSR_DSCL_UNKNOWN		0x0	/* data scale unknown */
#define	PCI_PMCSR_DSCL_1_BY_10		0x2000	/* data scale 0.1x */
#define	PCI_PMCSR_DSCL_1_BY_100		0x4000	/* data scale 0.01x */
#define	PCI_PMCSR_DSCL_1_BY_1000	0x6000	/* data scale 0.001x */
#define	PCI_PMCSR_DSCL_MASK		0x6000	/* data scale mask */
#define	PCI_PMCSR_PME_STAT		0x8000	/* PME status */

/*
 * PM PMCSR PCI to PCI bridge support extension values - 1 byte
 */
#define	PCI_PMCSR_BSE_B2_B3	0x40	/* bridge D3hot -> secondary B2 */
#define	PCI_PMCSR_BSE_BPCC_EN	0x80	/* bus power/clock control enabled */

/*
 * PCI-X capability related definitions
 */
#define	PCI_PCIX_COMMAND	0x2	/* Command register offset */
#define	PCI_PCIX_STATUS		0x4	/* Status register offset */
#define	PCI_PCIX_ECC_STATUS	0x8	/* ECC Status register offset */
#define	PCI_PCIX_ECC_FST_AD	0xC	/* ECC First address register offset */
#define	PCI_PCIX_ECC_SEC_AD	0x10	/* ECC Second address register offset */
#define	PCI_PCIX_ECC_ATTR	0x14	/* ECC Attribute register offset */

/*
 * PCI-X bridge capability related definitions
 */
#define	PCI_PCIX_SEC_STATUS		0x2	/* Secondary Status offset */
#define	PCI_PCIX_SEC_STATUS_SCD		0x4	/* Split Completion Discarded */
#define	PCI_PCIX_SEC_STATUS_USC		0x8	/* Unexpected Split Complete */
#define	PCI_PCIX_SEC_STATUS_SCO		0x10	/* Split Completion Overrun */
#define	PCI_PCIX_SEC_STATUS_SRD		0x20	/* Split Completion Delayed */
#define	PCI_PCIX_SEC_STATUS_ERR_MASK	0x3C

#define	PCI_PCIX_BDG_STATUS		0x4	/* Bridge Status offset */
#define	PCI_PCIX_BDG_STATUS_USC		0x80000
#define	PCI_PCIX_BDG_STATUS_SCO		0x100000
#define	PCI_PCIX_BDG_STATUS_SRD		0x200000
#define	PCI_PCIX_BDG_STATUS_ERR_MASK	0x380000

#define	PCI_PCIX_UP_SPL_CTL	0x8	/* Upstream split ctrl reg offset */
#define	PCI_PCIX_DOWN_SPL_CTL	0xC	/* Downstream split ctrl reg offset */
#define	PCI_PCIX_BDG_ECC_STATUS	0x10	/* ECC Status register offset */
#define	PCI_PCIX_BDG_ECC_FST_AD	0x14	/* ECC First address register offset */
#define	PCI_PCIX_BDG_ECC_SEC_AD	0x18	/* ECC Second address register offset */
#define	PCI_PCIX_BDG_ECC_ATTR	0x1C	/* ECC Attribute register offset */

/*
 * PCIX capabilities values
 */
#define	PCI_PCIX_VER_MASK	0x3000	/* Bits 12 and 13 */
#define	PCI_PCIX_VER_0		0x0000	/* PCIX cap list item version 0 */
#define	PCI_PCIX_VER_1		0x1000	/* PCIX cap list item version 1 */
#define	PCI_PCIX_VER_2		0x2000	/* PCIX cap list item version 2 */

#define	PCI_PCIX_SPL_DSCD	0x40000 /* Split Completion Discarded */
#define	PCI_PCIX_UNEX_SPL	0x80000	/* Unexpected Split Completion */
#define	PCI_PCIX_RX_SPL_MSG	0x20000000 /* Recieved Spl Comp Error Message */

#define	PCI_PCIX_ECC_SEL	0x1	/* Secondary ECC register select */
#define	PCI_PCIX_ECC_EP		0x2	/* Error Present on other side */
#define	PCI_PCIX_ECC_S_CE	0x4	/* Addl Correctable ECC Error */
#define	PCI_PCIX_ECC_S_UE	0x8	/* Addl Uncorrectable ECC Error */
#define	PCI_PCIX_ECC_PHASE	0x70	/* ECC Error Phase */
#define	PCI_PCIX_ECC_CORR	0x80	/* ECC Error Corrected */
#define	PCI_PCIX_ECC_SYN	0xff00	/* ECC Error Syndrome */
#define	PCI_PCIX_ECC_FST_CMD	0xf0000	 /* ECC Error First Command */
#define	PCI_PCIX_ECC_SEC_CMD	0xf00000 /* ECC Error Second Command */
#define	PCI_PCIX_ECC_UP_ATTR	0xf000000 /* ECC Error Upper Attributes */

/*
 * PCIX ECC Phase Values
 */
#define	PCI_PCIX_ECC_PHASE_NOERR	0x0
#define	PCI_PCIX_ECC_PHASE_FADDR	0x1
#define	PCI_PCIX_ECC_PHASE_SADDR	0x2
#define	PCI_PCIX_ECC_PHASE_ATTR		0x3
#define	PCI_PCIX_ECC_PHASE_DATA32	0x4
#define	PCI_PCIX_ECC_PHASE_DATA64	0x5

/*
 * PCI-X Command Encoding
 */
#define	PCI_PCIX_CMD_INTR		0x0
#define	PCI_PCIX_CMD_SPEC		0x1
#define	PCI_PCIX_CMD_IORD		0x2
#define	PCI_PCIX_CMD_IOWR		0x3
#define	PCI_PCIX_CMD_DEVID		0x5
#define	PCI_PCIX_CMD_MEMRD_DW		0x6
#define	PCI_PCIX_CMD_MEMWR		0x7
#define	PCI_PCIX_CMD_MEMRD_BL		0x8
#define	PCI_PCIX_CMD_MEMWR_BL		0x9
#define	PCI_PCIX_CMD_CFRD		0xA
#define	PCI_PCIX_CMD_CFWR		0xB
#define	PCI_PCIX_CMD_SPL		0xC
#define	PCI_PCIX_CMD_DADR		0xD
#define	PCI_PCIX_CMD_MEMRDBL		0xE
#define	PCI_PCIX_CMD_MEMWRBL		0xF

#if defined(_BIT_FIELDS_LTOH)
typedef struct pcix_attr {
	uint32_t	lbc	:8,
			rid	:16,
			tag	:5,
			ro	:1,
			ns	:1,
			r	:1;
} pcix_attr_t;
#elif defined(_BIT_FIELDS_HTOL)
typedef struct pcix_attr {
	uint32_t	r	:1,
			ns	:1,
			ro	:1,
			tag	:5,
			rid	:16,
			lbc	:8;
} pcix_attr_t;
#else
#error "bit field not defined"
#endif

#define	PCI_PCIX_BSS_SPL_DSCD	0x4	/* Secondary split comp discarded */
#define	PCI_PCIX_BSS_UNEX_SPL	0x8	/* Secondary unexpected split comp */
#define	PCI_PCIX_BSS_SPL_OR	0x10	/* Secondary split comp overrun */
#define	PCI_PCIX_BSS_SPL_DLY	0x20	/* Secondary split comp delayed */

/*
 * PCI Hotplug capability entry offsets
 *
 * SHPC based PCI hotplug controller registers accessed via the DWORD
 * select and DATA registers in PCI configuration space relative to the
 * PCI HP capibility pointer.
 */
#define	PCI_HP_DWORD_SELECT_OFF		0x2
#define	PCI_HP_DWORD_DATA_OFF		0x4

#define	PCI_HP_BASE_OFFSET_REG		0x00
#define	PCI_HP_SLOTS_AVAIL_I_REG	0x01
#define	PCI_HP_SLOTS_AVAIL_II_REG	0x02
#define	PCI_HP_SLOT_CONFIGURATION_REG	0x03
#define	PCI_HP_PROF_IF_SBCR_REG		0x04
#define	PCI_HP_COMMAND_STATUS_REG	0x05
#define	PCI_HP_IRQ_LOCATOR_REG		0x06
#define	PCI_HP_SERR_LOCATOR_REG		0x07
#define	PCI_HP_CTRL_SERR_INT_REG	0x08
#define	PCI_HP_LOGICAL_SLOT_REGS	0x09
#define	PCI_HP_VENDOR_SPECIFIC		0x28

/* Definitions used with the PCI_HP_SLOTS_AVAIL_I_REG register */
#define	PCI_HP_AVAIL_33MHZ_CONV_SPEED_SHIFT	0
#define	PCI_HP_AVAIL_66MHZ_PCIX_SPEED_SHIFT	8
#define	PCI_HP_AVAIL_100MHZ_PCIX_SPEED_SHIFT	16
#define	PCI_HP_AVAIL_133MHZ_PCIX_SPEED_SHIFT	24
#define	PCI_HP_AVAIL_SPEED_MASK			0x1F

/* Definitions used with the PCI_HP_SLOTS_AVAIL_II_REG register */
#define	PCI_HP_AVAIL_66MHZ_CONV_SPEED_SHIFT	0

/* Register bits used with the PCI_HP_PROF_IF_SBCR_REG register */
#define	PCI_HP_SBCR_33MHZ_CONV_SPEED		0x0
#define	PCI_HP_SBCR_66MHZ_CONV_SPEED		0x1
#define	PCI_HP_SBCR_66MHZ_PCIX_SPEED		0x2
#define	PCI_HP_SBCR_100MHZ_PCIX_SPEED		0x3
#define	PCI_HP_SBCR_133MHZ_PCIX_SPEED		0x4
#define	PCI_HP_SBCR_SPEED_MASK			0x7

/* Register bits used with the PCI_HP_COMMAND_STATUS_REG register */
#define	PCI_HP_COMM_STS_ERR_INVALID_SPEED	0x80000
#define	PCI_HP_COMM_STS_ERR_INVALID_COMMAND	0x40000
#define	PCI_HP_COMM_STS_ERR_MRL_OPEN		0x20000
#define	PCI_HP_COMM_STS_ERR_MASK		0xe0000
#define	PCI_HP_COMM_STS_CTRL_BUSY		0x10000
#define	PCI_HP_COMM_STS_SET_SPEED		0x40

/* Register bits used with the PCI_HP_CTRL_SERR_INT_REG register */
#define	PCI_HP_SERR_INT_GLOBAL_IRQ_MASK		0x1
#define	PCI_HP_SERR_INT_GLOBAL_SERR_MASK	0x2
#define	PCI_HP_SERR_INT_CMD_COMPLETE_MASK	0x4
#define	PCI_HP_SERR_INT_ARBITER_SERR_MASK	0x8
#define	PCI_HP_SERR_INT_CMD_COMPLETE_IRQ	0x10000
#define	PCI_HP_SERR_INT_ARBITER_IRQ		0x20000
#define	PCI_HP_SERR_INT_MASK_ALL		0xf

/* Register bits used with the PCI_HP_LOGICAL_SLOT_REGS register */
#define	PCI_HP_SLOT_POWER_ONLY			0x1
#define	PCI_HP_SLOT_ENABLED			0x2
#define	PCI_HP_SLOT_DISABLED			0x3
#define	PCI_HP_SLOT_STATE_MASK			0x3
#define	PCI_HP_SLOT_MRL_STATE_MASK		0x100
#define	PCI_HP_SLOT_66MHZ_CONV_CAPABLE		0x200
#define	PCI_HP_SLOT_CARD_EMPTY_MASK		0xc00
#define	PCI_HP_SLOT_66MHZ_PCIX_CAPABLE		0x1000
#define	PCI_HP_SLOT_100MHZ_PCIX_CAPABLE		0x2000
#define	PCI_HP_SLOT_133MHZ_PCIX_CAPABLE		0x3000
#define	PCI_HP_SLOT_PCIX_CAPABLE_MASK		0x3000
#define	PCI_HP_SLOT_PCIX_CAPABLE_SHIFT		12
#define	PCI_HP_SLOT_PRESENCE_DETECTED		0x10000
#define	PCI_HP_SLOT_ISO_PWR_DETECTED		0x20000
#define	PCI_HP_SLOT_ATTN_DETECTED		0x40000
#define	PCI_HP_SLOT_MRL_DETECTED		0x80000
#define	PCI_HP_SLOT_POWER_DETECTED		0x100000
#define	PCI_HP_SLOT_PRESENCE_MASK		0x1000000
#define	PCI_HP_SLOT_ISO_PWR_MASK		0x2000000
#define	PCI_HP_SLOT_ATTN_MASK			0x4000000
#define	PCI_HP_SLOT_MRL_MASK			0x8000000
#define	PCI_HP_SLOT_POWER_MASK			0x10000000
#define	PCI_HP_SLOT_MRL_SERR_MASK		0x20000000
#define	PCI_HP_SLOT_POWER_SERR_MASK		0x40000000
#define	PCI_HP_SLOT_MASK_ALL			0x5f000000

/* Register bits used with the PCI_HP_IRQ_LOCATOR_REG register */
#define	PCI_HP_IRQ_CMD_COMPLETE			0x1
#define	PCI_HP_IRQ_SLOT_N_PENDING		0x2

/* Register bits used with the PCI_HP_SERR_LOCATOR_REG register */
#define	PCI_HP_IRQ_SERR_ARBITER_PENDING		0x1
#define	PCI_HP_IRQ_SERR_SLOT_N_PENDING		0x2

/* Register bits used with the PCI_HP_SLOT_CONFIGURATION_REG register */
#define	PCI_HP_SLOT_CONFIG_MRL_SENSOR		0x40000000
#define	PCI_HP_SLOT_CONFIG_ATTN_BUTTON		0x80000000
#define	PCI_HP_SLOT_CONFIG_PHY_SLOT_NUM_SHIFT	16
#define	PCI_HP_SLOT_CONFIG_PHY_SLOT_NUM_MASK	0x3FF

/*
 * PCI Message Signalled Interrupts (MSI) capability entry offsets for 32-bit
 */
#define	PCI_MSI_CTRL		0x02	/* MSI control register, 2 bytes */
#define	PCI_MSI_ADDR_OFFSET	0x04	/* MSI 32-bit msg address, 4 bytes */
#define	PCI_MSI_32BIT_DATA	0x08	/* MSI 32-bit msg data, 2 bytes */
#define	PCI_MSI_32BIT_MASK	0x0C	/* MSI 32-bit mask bits, 4 bytes */
#define	PCI_MSI_32BIT_PENDING	0x10	/* MSI 32-bit pending bits, 4 bytes */

/*
 * PCI Message Signalled Interrupts (MSI) capability entry offsets for 64-bit
 */
#define	PCI_MSI_64BIT_DATA	0x0C	/* MSI 64-bit msg data, 2 bytes */
#define	PCI_MSI_64BIT_MASKBITS	0x10	/* MSI 64-bit mask bits, 4 bytes */
#define	PCI_MSI_64BIT_PENDING	0x14	/* MSI 64-bit pending bits, 4 bytes */

/*
 * PCI Message Signalled Interrupts (MSI) capability masks and shifts
 */
#define	PCI_MSI_ENABLE_BIT	0x0001	/* MSI enable mask in MSI ctrl reg */
#define	PCI_MSI_MMC_MASK	0x000E	/* MMC mask in MSI ctrl reg */
#define	PCI_MSI_MMC_SHIFT	0x1	/* Shift for MMC bits */
#define	PCI_MSI_MME_MASK	0x0070	/* MME mask in MSI ctrl reg */
#define	PCI_MSI_MME_SHIFT	0x4	/* Shift for MME bits */
#define	PCI_MSI_64BIT_MASK	0x0080	/* 64bit support mask in MSI ctrl reg */
#define	PCI_MSI_PVM_MASK	0x0100	/* PVM support mask in MSI ctrl reg */

/*
 * PCI Extended Message Signalled Interrupts (MSI-X) capability entry offsets
 */
#define	PCI_MSIX_CTRL		0x02	/* MSI-X control register, 2 bytes */
#define	PCI_MSIX_TBL_OFFSET	0x04	/* MSI-X table offset, 4 bytes */
#define	PCI_MSIX_TBL_BIR_MASK	0x0007	/* MSI-X table BIR mask */
#define	PCI_MSIX_PBA_OFFSET	0x08	/* MSI-X pending bit array, 4 bytes */
#define	PCI_MSIX_PBA_BIR_MASK	0x0007	/* MSI-X PBA BIR mask */

#define	PCI_MSIX_TBL_SIZE_MASK	0x07FF	/* table size mask in MSI-X ctrl reg */
#define	PCI_MSIX_FUNCTION_MASK	0x4000	/* function mask in MSI-X ctrl reg */
#define	PCI_MSIX_ENABLE_BIT	0x8000	/* MSI-X enable mask in MSI-X ctl reg */

#define	PCI_MSIX_LOWER_ADDR_OFFSET	0	/* MSI-X lower addr offset */
#define	PCI_MSIX_UPPER_ADDR_OFFSET	4	/* MSI-X upper addr offset */
#define	PCI_MSIX_DATA_OFFSET		8	/* MSI-X data offset */
#define	PCI_MSIX_VECTOR_CTRL_OFFSET	12	/* MSI-X vector ctrl offset */
#define	PCI_MSIX_VECTOR_SIZE		16	/* MSI-X size of each vector */

/*
 * PCI Message Signalled Interrupts: other interesting constants
 */
#define	PCI_MSI_MAX_INTRS	32	/* maximum MSI interrupts supported */
#define	PCI_MSIX_MAX_INTRS	2048	/* maximum MSI-X interrupts supported */

/*
 * PCI Slot Id Capabilities, 2 bytes
 */
/* Byte 1: Expansion Slot Register (ESR), Byte 2: Chassis Number Register */
#define	PCI_CAPSLOT_ESR_NSLOTS_MASK	0x1F	/* Number of slots mask */
#define	PCI_CAPSLOT_ESR_FIC		0x20	/* First In Chassis bit */
#define	PCI_CAPSLOT_ESR_FIC_MASK	0x01	/* First In Chassis mask */
#define	PCI_CAPSLOT_ESR_FIC_SHIFT	5	/* First In Chassis shift */
#define	PCI_CAPSLOT_FIC(esr_reg)	((esr_reg) & PCI_CAPSLOT_ESR_FIC)
#define	PCI_CAPSLOT_NSLOTS(esr_reg)	((esr_reg) & \
						PCI_CAPSLOT_ESR_NSLOTS_MASK)

/*
 * HyperTransport Capabilities; each HT cap uses the same PCI cap id of
 * PCI_CAP_ID_HT.  The header's upper 16-bits (command reg) contains an HT
 * cap type reg at bits [15:11].  For Slave/Pri Interface and Host/Sec
 * Interface types, only bits [15:13] are used.
 */
#define	PCI_HTCAP_TYPE_MASK		0xF800
#define	PCI_HTCAP_TYPE_SLHOST_MASK	0xE000	/* SLPRI and HOSTSEC types */
#define	PCI_HTCAP_TYPE_SHIFT		11

#define	PCI_HTCAP_SLPRI_ID		0x00
#define	PCI_HTCAP_HOSTSEC_ID		0x04
#define	PCI_HTCAP_SWITCH_ID		0x08
#define	PCI_HTCAP_INTCONF_ID		0x10
#define	PCI_HTCAP_REVID_ID		0x11
#define	PCI_HTCAP_UNITID_CLUMP_ID	0x12
#define	PCI_HTCAP_ECFG_ID		0x13
#define	PCI_HTCAP_ADDRMAP_ID		0x14
#define	PCI_HTCAP_MSIMAP_ID		0x15
#define	PCI_HTCAP_DIRROUTE_ID		0x16
#define	PCI_HTCAP_VCSET_ID		0x17
#define	PCI_HTCAP_RETRYMODE_ID		0x18
#define	PCI_HTCAP_X86ENC_ID		0x19
#define	PCI_HTCAP_GEN3_ID		0x1A
#define	PCI_HTCAP_FUNCEXT_ID		0x1B
#define	PCI_HTCAP_PM_ID			0x1C

#define	PCI_HTCAP_SLPRI_TYPE		/* 0x0000 */	\
	(PCI_HTCAP_SLPRI_ID	<< PCI_HTCAP_TYPE_SHIFT)

#define	PCI_HTCAP_HOSTSEC_TYPE		/* 0x2000 */	\
	(PCI_HTCAP_HOSTSEC_ID	<< PCI_HTCAP_TYPE_SHIFT)

#define	PCI_HTCAP_SWITCH_TYPE		/* 0x4000 */	\
	(PCI_HTCAP_SWITCH_ID	<< PCI_HTCAP_TYPE_SHIFT)

#define	PCI_HTCAP_INTCONF_TYPE		/* 0x8000 */	\
	(PCI_HTCAP_INTCONF_ID	<< PCI_HTCAP_TYPE_SHIFT)

#define	PCI_HTCAP_REVID_TYPE		/* 0x8800 */	\
	(PCI_HTCAP_REVID_ID	<< PCI_HTCAP_TYPE_SHIFT)

#define	PCI_HTCAP_UNITID_CLUMP_TYPE	/* 0x9000 */	\
	(PCI_HTCAP_UNITID_CLUMP_ID	<< PCI_HTCAP_TYPE_SHIFT)

#define	PCI_HTCAP_ECFG_TYPE		/* 0x9800 */	\
	(PCI_HTCAP_ECFG_ID	<< PCI_HTCAP_TYPE_SHIFT)

#define	PCI_HTCAP_ADDRMAP_TYPE		/* 0xA000 */	\
	(PCI_HTCAP_ADDRMAP_ID	<< PCI_HTCAP_TYPE_SHIFT)

#define	PCI_HTCAP_MSIMAP_TYPE		/* 0xA800 */	\
	(PCI_HTCAP_MSIMAP_ID	<< PCI_HTCAP_TYPE_SHIFT)

#define	PCI_HTCAP_DIRROUTE_TYPE		/* 0xB000 */	\
	(PCI_HTCAP_DIRROUTE_ID	<< PCI_HTCAP_TYPE_SHIFT)

#define	PCI_HTCAP_VCSET_TYPE		/* 0xB800 */	\
	(PCI_HTCAP_VCSET_ID	<< PCI_HTCAP_TYPE_SHIFT)

#define	PCI_HTCAP_RETRYMODE_TYPE	/* 0xC000 */	\
	(PCI_HTCAP_RETRYMODE_ID	<< PCI_HTCAP_TYPE_SHIFT)

#define	PCI_HTCAP_X86ENC_TYPE		/* 0xC800 */	\
	(PCI_HTCAP_X86ENC_ID	<< PCI_HTCAP_TYPE_SHIFT)

#define	PCI_HTCAP_GEN3_TYPE		/* 0xD000 */	\
	(PCI_HTCAP_GEN3_ID	<< PCI_HTCAP_TYPE_SHIFT)

#define	PCI_HTCAP_FUNCEXT_TYPE		/* 0xD800 */	\
	(PCI_HTCAP_FUNCEXT_ID	<< PCI_HTCAP_TYPE_SHIFT)

#define	PCI_HTCAP_PM_TYPE		/* 0xE000 */	\
	(PCI_HTCAP_PM_ID	<< PCI_HTCAP_TYPE_SHIFT)

#define	PCI_HTCAP_MSIMAP_ENABLE			0x0001
#define	PCI_HTCAP_MSIMAP_ENABLE_MASK		0x0001

#define	PCI_HTCAP_ADDRMAP_MAPTYPE_MASK		0x600
#define	PCI_HTCAP_ADDRMAP_MAPTYPE_SHIFT		9
#define	PCI_HTCAP_ADDRMAP_NUMMAP_MASK		0xF
#define	PCI_HTCAP_ADDRMAP_40BIT_ID		0x0
#define	PCI_HTCAP_ADDRMAP_64BIT_ID		0x1

#define	PCI_HTCAP_FUNCEXT_LEN_MASK		0xFF


/*
 * other interesting PCI constants
 */
#define	PCI_BASE_NUM	6	/* num of base regs in configuration header */
#define	PCI_BAR_SZ_32	4	/* size of 32 bit base addr reg in bytes */
#define	PCI_BAR_SZ_64	8	/* size of 64 bit base addr reg in bytes */
#define	PCI_BASE_SIZE	4	/* size of base reg in bytes */
#define	PCI_CONF_HDR_SIZE	256	/* configuration header size */
#define	PCI_MAX_BUS_NUM		256		/* Maximum PCI buses allowed */
#define	PCI_MAX_DEVICES		32		/* Max PCI devices allowed */
#define	PCI_MAX_FUNCTIONS	8		/* Max PCI functions allowed */
#define	PCI_MAX_CHILDREN	PCI_MAX_DEVICES * PCI_MAX_FUNCTIONS
#define	PCI_CLK_33MHZ	(33 * 1000 * 1000)	/* 33MHz clock speed */
#define	PCI_CLK_66MHZ	(66 * 1000 * 1000)	/* 66MHz clock speed */
#define	PCI_CLK_133MHZ	(133 * 1000 * 1000)	/* 133MHz clock speed */

/*
 * pci bus range definition
 */
typedef struct pci_bus_range {
	uint32_t lo;
	uint32_t hi;
} pci_bus_range_t;

/*
 * The following typedef is used to represent an entry in the "ranges"
 * property of a pci hostbridge device node.
 */
typedef struct pci_ranges {
	uint32_t child_high;
	uint32_t child_mid;
	uint32_t child_low;
	uint32_t parent_high;
	uint32_t parent_low;
	uint32_t size_high;
	uint32_t size_low;
} pci_ranges_t;

/*
 * The following typedef is used to represent an entry in the "ranges"
 * property of a pci-pci bridge device node.
 */
typedef struct {
	uint32_t child_high;
	uint32_t child_mid;
	uint32_t child_low;
	uint32_t parent_high;
	uint32_t parent_mid;
	uint32_t parent_low;
	uint32_t size_high;
	uint32_t size_low;
} ppb_ranges_t;

/*
 * This structure represents one entry of the 1275 "reg" property and
 * "assigned-addresses" property for a PCI node.  For the "reg" property, it
 * may be one of an arbitrary length array for devices with multiple address
 * windows.  For the "assigned-addresses" property, it denotes an assigned
 * physical address on the PCI bus.  It may be one entry of the six entries
 * for devices with multiple base registers.
 *
 * The physical address format is:
 *
 *             Bit#:  33222222 22221111 11111100 00000000
 *                    10987654 32109876 54321098 76543210
 *
 * pci_phys_hi cell:  npt000ss bbbbbbbb dddddfff rrrrrrrr
 * pci_phys_mid cell: hhhhhhhh hhhhhhhh hhhhhhhh hhhhhhhh
 * pci_phys_low cell: llllllll llllllll llllllll llllllll
 *
 * n          is 0 if the address is relocatable, 1 otherwise
 * p          is 1 if the addressable region is "prefetchable", 0 otherwise
 * t          is 1 if the address is aliased (for non-relocatable I/O), below
 *	      1MB (for mem), or below 64 KB (for relocatable I/O).
 * ss         is the type code, denoting which address space
 * bbbbbbbb   is the 8-bit bus number
 * ddddd      is the 5-bit device number
 * fff        is the 3-bit function number
 * rrrrrrrr   is the 8-bit register number
 *	      should be zero for non-relocatable, when ss is 01, or 10
 * hh...hhh   is the 32-bit unsigned number
 * ll...lll   is the 32-bit unsigned number
 *
 * The physical size format is:
 *
 * pci_size_hi cell:  hhhhhhhh hhhhhhhh hhhhhhhh hhhhhhhh
 * pci_size_low cell: llllllll llllllll llllllll llllllll
 *
 * hh...hhh   is the 32-bit unsigned number
 * ll...lll   is the 32-bit unsigned number
 */
struct pci_phys_spec {
	uint_t pci_phys_hi;		/* child's address, hi word */
	uint_t pci_phys_mid;		/* child's address, middle word */
	uint_t pci_phys_low;		/* child's address, low word */
	uint_t pci_size_hi;		/* high word of size field */
	uint_t pci_size_low;		/* low word of size field */
};

typedef struct pci_phys_spec pci_regspec_t;

/*
 * PCI masks for pci_phy_hi of PCI 1275 address cell.
 */
#define	PCI_REG_REG_M		0xff		/* register mask */
#define	PCI_REG_FUNC_M		0x700		/* function mask */
#define	PCI_REG_DEV_M		0xf800		/* device mask */
#define	PCI_REG_BUS_M		0xff0000	/* bus number mask */
#define	PCI_REG_ADDR_M		0x3000000	/* address space mask */
#define	PCI_REG_ALIAS_M		0x20000000	/* aliased bit mask */
#define	PCI_REG_PF_M		0x40000000	/* prefetch bit mask */
#define	PCI_REG_REL_M		0x80000000	/* relocation bit mask */
#define	PCI_REG_BDFR_M		0xffffff	/* bus, dev, func, reg mask */
#define	PCI_REG_EXTREG_M	0xF0000000	/* extended config bits mask */

#define	PCI_REG_FUNC_SHIFT	8		/* Offset of function bits */
#define	PCI_REG_DEV_SHIFT	11		/* Offset of device bits */
#define	PCI_REG_BUS_SHIFT	16		/* Offset of bus bits */
#define	PCI_REG_ADDR_SHIFT	24		/* Offset of address bits */
#define	PCI_REG_EXTREG_SHIFT	28		/* Offset of ext. config bits */

#define	PCI_REG_REG_G(x)	((x) & PCI_REG_REG_M)
#define	PCI_REG_FUNC_G(x)	(((x) & PCI_REG_FUNC_M) >> PCI_REG_FUNC_SHIFT)
#define	PCI_REG_DEV_G(x)	(((x) & PCI_REG_DEV_M) >> PCI_REG_DEV_SHIFT)
#define	PCI_REG_BUS_G(x)	(((x) & PCI_REG_BUS_M) >> PCI_REG_BUS_SHIFT)
#define	PCI_REG_ADDR_G(x)	(((x) & PCI_REG_ADDR_M) >> PCI_REG_ADDR_SHIFT)
#define	PCI_REG_BDFR_G(x)	((x) & PCI_REG_BDFR_M)

/*
 * PCI bit encodings of pci_phys_hi of PCI 1275 address cell.
 */
#define	PCI_ADDR_MASK		PCI_REG_ADDR_M
#define	PCI_ADDR_CONFIG		0x00000000	/* configuration address */
#define	PCI_ADDR_IO		0x01000000	/* I/O address */
#define	PCI_ADDR_MEM32		0x02000000	/* 32-bit memory address */
#define	PCI_ADDR_MEM64		0x03000000	/* 64-bit memory address */
#define	PCI_ALIAS_B		PCI_REG_ALIAS_M	/* aliased bit */
#define	PCI_PREFETCH_B		PCI_REG_PF_M	/* prefetch bit */
#define	PCI_RELOCAT_B		PCI_REG_REL_M	/* non-relocatable bit */
#define	PCI_CONF_ADDR_MASK	0x00ffffff	/* mask for config address */

#define	PCI_HARDDEC_8514 2	/* number of reg entries for 8514 hard-decode */
#define	PCI_HARDDEC_VGA	3	/* number of reg entries for VGA hard-decode */
#define	PCI_HARDDEC_IDE	4	/* number of reg entries for IDE hard-decode */
#define	PCI_HARDDEC_IDE_PRI 2	/* number of reg entries for IDE primary */
#define	PCI_HARDDEC_IDE_SEC 2	/* number of reg entries for IDE secondary */

/*
 * PCI Expansion ROM Header Format
 */
#define	PCI_ROM_SIGNATURE		0x0	/* ROM Signature 0xaa55 */
#define	PCI_ROM_ARCH_UNIQUE_START	0x2	/* Start of processor unique */
#define	PCI_ROM_PCI_DATA_STRUCT_PTR	0x18	/* Ptr to PCI Data Structure */

/*
 * PCI Data Structure
 *
 * The PCI Data Structure is located within the first 64KB
 * of the ROM image and must be DWORD aligned.
 */
#define	PCI_PDS_SIGNATURE	0x0	/* Signature, the string 'PCIR' */
#define	PCI_PDS_VENDOR_ID	0x4	/* Vendor Identification */
#define	PCI_PDS_DEVICE_ID	0x6	/* Device Identification */
#define	PCI_PDS_VPD_PTR		0x8	/* Pointer to Vital Product Data */
#define	PCI_PDS_PDS_LENGTH	0xa	/* PCI Data Structure Length */
#define	PCI_PDS_PDS_REVISION	0xc	/* PCI Data Structure Revision */
#define	PCI_PDS_CLASS_CODE	0xd	/* Class Code */
#define	PCI_PDS_IMAGE_LENGTH	0x10	/* Image Length in 512 byte units */
#define	PCI_PDS_CODE_REVISON	0x12	/* Revision Level of Code/Data */
#define	PCI_PDS_CODE_TYPE	0x14	/* Code Type */
#define	PCI_PDS_INDICATOR	0x15	/* Indicates if image is last in ROM */

#define	PCI_PDS_CODE_TYPE_PCAT		0x0	/* Intel x86/PC-AT Type */
#define	PCI_PDS_CODE_TYPE_OPEN_FW	0x1	/* Open Firmware */

/*
 * we recognize the non transparent bridge child nodes with the
 * following property. This is specific to an implementation only.
 * This property is specific to AP nodes only.
 */
#define	PCI_DEV_CONF_MAP_PROP	"pci-parent-indirect"

/*
 * If a bridge device provides its own config space access services,
 * and supports a hotplug/hotswap bus below at any level, then
 * the following property must be defined for the node either by
 * the driver or the OBP.
 */
#define	PCI_BUS_CONF_MAP_PROP	"pci-conf-indirect"

/*
 * PCI returns all 1s for an invalid read.
 */
#define	PCI_EINVAL8	0xff
#define	PCI_EINVAL16	0xffff
#define	PCI_EINVAL32	0xffffffff

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_H */
