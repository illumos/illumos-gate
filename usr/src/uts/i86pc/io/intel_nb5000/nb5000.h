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

#ifndef _NB5000_H
#define	_NB5000_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/cpu_module.h>

#define	NB_5000_MAX_MEM_CONTROLLERS	2
#define	NB_MEM_BRANCH_SELECT		3
#define	NB_MEM_RANK_SELECT		5
#define	NB_RANKS_IN_SELECT		4
#define	NB_PCI_DEV			8

#define	NB_PCI_NFUNC	4

#define	DOCMD_PEX_MASK	0xc0
#define	DOCMD_PEX	0x3f

#define	SPD_BUSY	0x1000
#define	SPD_BUS_ERROR	0x2000
#define	SPD_READ_DATA_VALID	0x8000
#define	SPD_EEPROM_WRITE	0xa8000000
#define	SPD_ADDR(slave, addr) ((((slave) & 7) << 24) | (((addr) & 0xff) << 16))

#define	MC_MIRROR	0x10000
#define	MC_PATROL_SCRUB	0x80
#define	MC_DEMAND_SCRUB	0x40

#define	MCA_SCHDIMM	0x4000

#define	TLOW_MAX	0x100000000ULL

#define	MTR_PRESENT(mtr)	((mtr) & 0x10)
#define	MTR_ETHROTTLE(mtr)	((mtr) & 8)
#define	MTR_WIDTH(mtr)		(((((mtr) >> 6) & 1) + 1) * 4)
#define	MTR_NUMBANK(mtr)	(((((mtr) >> 5) & 1) + 1) * 4)
#define	MTR_NUMRANK(mtr)	((((mtr) >> 4) & 1) + 1)
#define	MTR_NUMROW(mtr)		((((mtr) >> 2) & 3) + 13)
#define	MTR_NUMCOL(mtr)		(((mtr) & 3) + 10)
#define	MTR_DIMMSIZE(mtr) 	((1 << (MTR_NUMCOL(mtr) + MTR_NUMROW(mtr))) \
	* MTR_NUMRANK(mtr) * MTR_NUMBANK(mtr) * MTR_WIDTH(mtr))

/* FERR_GLOBAL and NERR_GLOBAL */
#define	GE_FERR_FSB3_FATAL	0x800000000ULL	/* FSB3 Fatal Error */
#define	GE_FERR_FSB2_FATAL	0x400000000ULL	/* FSB2 Fatal Error */
#define	GE_FERR_FSB3_NF	0x200000000ULL	/* FSB3 Non-Fatal Error */
#define	GE_FERR_FSB2_NF	0x100000000ULL	/* FSB2 Non-Fatal Error */

#define	GE_INT_FATAL	0x80000000	/* North Bridge Internal Error */
#define	GE_DMA_FATAL	0x40000000	/* DMA engine Fatal Error */
#define	GE_FSB1_FATAL	0x20000000	/* FSB1 Fatal Error */
#define	GE_FSB0_FATAL	0x10000000	/* FSB0 Fatal Error */
#define	GE_FERR_FBD3_FATAL	0x08000000	/* FBD3 channel Fatal Error */
#define	GE_FERR_FBD2_FATAL	0x04000000	/* FBD2 channel Fatal Error */
#define	GE_FERR_FBD1_FATAL	0x02000000	/* FBD1 channel Fatal Error */
#define	GE_FERR_FBD0_FATAL	0x01000000	/* FBD0 channel Fatal Error */
#define	GE_PCIEX7_FATAL	0x00800000	/* PCI Express device 7 Fatal Error */
#define	GE_PCIEX6_FATAL	0x00400000	/* PCI Express device 6 Fatal Error */
#define	GE_PCIEX5_FATAL	0x00200000	/* PCI Express device 5 Fatal Error */
#define	GE_PCIEX4_FATAL	0x00100000	/* PCI Express device 4 Fatal Error */
#define	GE_PCIEX3_FATAL	0x00080000	/* PCI Express device 3 Fatal Error */
#define	GE_PCIEX2_FATAL	0x00040000	/* PCI Express device 2 Fatal Error */
#define	GE_PCIEX1_FATAL	0x00020000	/* PCI Express device 1 Fatal Error */
#define	GE_ESI_FATAL	0x00010000	/* ESI Fatal Error */
#define	GE_INT_NF	0x00008000	/* North Bridge Internal Error */
#define	GE_DMA_NF	0x00004000	/* DMA engine Non-Fatal Error */
#define	GE_FSB1_NF	0x00002000	/* FSB1 Non-Fatal Error */
#define	GE_FSB0_NF	0x00001000	/* FSB0 Non-Fatal Error */
#define	GE_FERR_FBD3_NF	0x00000800	/* FBD channel 3 Non-Fatal Error */
#define	GE_FERR_FBD2_NF	0x00000400	/* FBD channel 2 Non-Fatal Error */
#define	GE_FERR_FBD1_NF	0x00000200	/* FBD channel 1 Non-Fatal Error */
#define	GE_FERR_FBD0_NF	0x00000100	/* FBD channel 0 Non-Fatal Error */
#define	GE_PCIEX7_NF	0x00000080	/* PCI Express dev 7 Non-Fatal Error */
#define	GE_PCIEX6_NF	0x00000040	/* PCI Express dev 6 Non-Fatal Error */
#define	GE_PCIEX5_NF	0x00000020	/* PCI Express dev 5 Non-Fatal Error */
#define	GE_PCIEX4_NF	0x00000010	/* PCI Express dev 4 Non-Fatal Error */
#define	GE_PCIEX3_NF	0x00000008	/* PCI Express dev 3 Non-Fatal Error */
#define	GE_PCIEX2_NF	0x00000004	/* PCI Express dev 2 Non-Fatal Error */
#define	GE_PCIEX1_NF	0x00000002	/* PCI Express dev 1 Non-Fatal Error */
#define	GE_ESI_NF	0x00000001	/* ESI Non-Fatal Error */

#define	GE_NERR_FSB2_FATAL	0x08000000 /* FSB2 Fatal Error */
#define	GE_NERR_FSB3_FATAL	0x04000000 /* FSB3 Fatal Error */
#define	GE_NERR_FBD_FATAL	0x01000000 /* FBD channel Fatal Error */
#define	GE_NERR_FSB2_NF		0x00000800 /* FSB2 Non-Fatal Error */
#define	GE_NERR_FSB3_NF		0x00000400 /* FSB3 Non-Fatal Error */
#define	GE_NERR_FBD_NF		0x00000100 /* FBD channel Non-Fatal Error */

#define	ERR_FAT_FSB_F9		0x20	/* F9Msk FSB Protocol */
#define	ERR_FAT_FSB_F2		0x08	/* F2Msk Unsupported Bus Transaction */
#define	ERR_FAT_FSB_F1		0x01 	/* F1Msk Request/Address Parity */

#define	ERR_NF_FSB_F7		0x04	/* F7Msk Detected MCERR */
#define	ERR_NF_FSB_F8		0x02	/* F8Msk B-INIT */
#define	ERR_NF_FSB_F6		0x01	/* F6Msk Data Parity */

#define	EMASK_FSB_F1		0x0001 	/* F1Msk Request/Address Parity */
#define	EMASK_FSB_F2		0x0002	/* F2Msk Unsupported Bus Transaction */
#define	EMASK_FSB_F6		0x0020	/* F6Msk Data Parity */
#define	EMASK_FSB_F7		0x0040	/* F7Msk Detected MCERR */
#define	EMASK_FSB_F8		0x0080	/* F8Msk B-INIT */
#define	EMASK_FSB_F9		0x0100	/* F9Msk FSB Protocol */

#define	EMASK_FSB_FATAL		(EMASK_FSB_F1 | EMASK_FSB_F2 | EMASK_FSB_F9)
#define	EMASK_FSB_NF		(EMASK_FSB_F6 | EMASK_FSB_F7 | EMASK_FSB_F8)

#define	ERR_FBD_CH_SHIFT	28 /* channel index in fat_fbd and nf_fbd */

#define	ERR_FAT_FBD_M23	0x00400000	/* M23Err Non-Redundant Fast Reset */
					/* Timeout */
#define	ERR_FAT_FBD_M3	0x00000004	/* M3Err >Tmid thermal event with */
					/* intelligent throttling disabled */
#define	ERR_FAT_FBD_M2	0x00000002	/* M2Err memory or FBD configuration */
					/* CRC read error */
#define	ERR_FAT_FBD_M1	0x00000001	/* M1Err memory write error on */
					/* non-redundant retry or FBD */
					/* configuration write error on retry */
#define	ERR_FAT_FBD_MASK 0x007fffff

#define	ERR_NF_FBD_M28	0x01000000	/* M28Err DIMM-Spare Copy Completed */
#define	ERR_NF_FBD_M27	0x00800000	/* M27Err DIMM-Spare Copy Initiated */
#define	ERR_NF_FBD_M26	0x00400000	/* M26Err Redundant Fast Reset */
					/* Timeout */
#define	ERR_NF_FBD_M25	0x00200000	/* M25Err Memory write error on */
					/* redundant retry */
#define	ERR_NF_FBD_M22	0x00040000	/* M22Err SPD protocol */
#define	ERR_NF_FBD_M21	0x00020000	/* M21Err FBD Northbound parity on */
					/* FBD sync status */
#define	ERR_NF_FBD_M20	0x00010000	/* M20Err Correctable patrol data ECC */
#define	ERR_NF_FBD_M19	0x00008000	/* M19Err Correctasble resilver or */
					/* spare-copy data ECC */
#define	ERR_NF_FBD_M18	0x00004000	/* M18Err Correctable Mirrored demand */
					/* data ECC */
#define	ERR_NF_FBD_M17	0x00002000	/* M17Err Correctable Non-mirrored */
					/* demand data ECC */
#define	ERR_NF_FBD_M15	0x00000800	/* M15Err Memory or FBD configuration */
					/* CRC read error */
#define	ERR_NF_FBD_M14	0x00000400	/* M14Err FBD configuration write */
					/* error on first attempt */
#define	ERR_NF_FBD_M13	0x00000200	/* M13Err Memory write error on first */
					/* attempt */
#define	ERR_NF_FBD_M12	0x00000100	/* M12Err Non-Aliased uncorrectable */
					/* patrol data ECC */
#define	ERR_NF_FBD_M11	0x00000080	/* M11Err Non-Aliased uncorrectable */
					/* resilver or spare copy data ECC */
#define	ERR_NF_FBD_M10	0x00000040	/* M10Err Non-Aliased uncorrectable */
					/* mirrored demand data ECC */
#define	ERR_NF_FBD_M9	0x00000020	/* M9Err Non-Aliased uncorrectable */
					/* non-mirrored demand data ECC */
#define	ERR_NF_FBD_M8	0x00000010	/* M8Err Aliased uncorrectable */
					/* patrol data ECC */
#define	ERR_NF_FBD_M7	0x00000008	/* M7Err Aliased uncorrectable */
					/* resilver or spare copy data ECC */
#define	ERR_NF_FBD_M6	0x00000004	/* M6Err Aliased uncorrectable */
					/* mirrored demand data ECC */
#define	ERR_NF_FBD_M5	0x00000002	/* M5Err Aliased uncorrectable */
					/* non-mirrored demand data ECC */
#define	ERR_NF_FBD_M4	0x00000001	/* M4Err uncorrectable data ECC on */
					/* replay */

#define	ERR_NF_FBD_MASK	0x01ffffff
#define	ERR_NF_FBD_ECC_UE	(ERR_NF_FBD_M12|ERR_NF_FBD_M11|ERR_NF_FBD_M10| \
    ERR_NF_FBD_M9|ERR_NF_FBD_M8|ERR_NF_FBD_M7|ERR_NF_FBD_M6|ERR_NF_FBD_M5| \
    ERR_NF_FBD_M4)
#define	ERR_NF_FBD_MA	(ERR_NF_FBD_M14)
#define	ERR_NF_FBD_ECC_CE	(ERR_NF_FBD_M20|ERR_NF_FBD_M19|ERR_NF_FBD_M18| \
    ERR_NF_FBD_M17|ERR_NF_FBD_M15|ERR_NF_FBD_M21)
#define	ERR_NF_FBD_SPARE (ERR_NF_FBD_M28|ERR_NF_FBD_M27)

#define	EMASK_FBD_M28	0x08000000	/* M28Err DIMM-Spare Copy Completed */
#define	EMASK_FBD_M27	0x04000000	/* M27Err DIMM-Spare Copy Initiated */
#define	EMASK_FBD_M26	0x02000000	/* M26Err Redundant Fast Reset */
					/* Timeout */
#define	EMASK_FBD_M25	0x01000000	/* M25Err Memory write error on */
					/* redundant retry */
#define	EMASK_FBD_M23	0x00400000	/* M23Err Non-Redundant Fast Reset */
					/* Timeout */
#define	EMASK_FBD_M22	0x00200000	/* M22Err SPD protocol */
#define	EMASK_FBD_M21	0x00100000	/* M21Err FBD Northbound parity on */
					/* FBD sync status */
#define	EMASK_FBD_M20	0x00080000	/* M20Err Correctable patrol data ECC */
#define	EMASK_FBD_M19	0x00040000	/* M19Err Correctasble resilver or */
					/* spare-copy data ECC */
#define	EMASK_FBD_M18	0x00020000	/* M18Err Correctable Mirrored demand */
					/* data ECC */
#define	EMASK_FBD_M17	0x00010000	/* M17Err Correctable Non-mirrored */
					/* demand data ECC */
#define	EMASK_FBD_M15	0x00004000	/* M15Err Memory or FBD configuration */
					/* CRC read error */
#define	EMASK_FBD_M14	0x00002000	/* M14Err FBD configuration write */
					/* error on first attempt */
#define	EMASK_FBD_M13	0x00001000	/* M13Err Memory write error on first */
					/* attempt */
#define	EMASK_FBD_M12	0x00000800	/* M12Err Non-Aliased uncorrectable */
					/* patrol data ECC */
#define	EMASK_FBD_M11	0x00000400	/* M11Err Non-Aliased uncorrectable */
					/* resilver or spare copy data ECC */
#define	EMASK_FBD_M10	0x00000200	/* M10Err Non-Aliased uncorrectable */
					/* mirrored demand data ECC */
#define	EMASK_FBD_M9	0x00000100	/* M9Err Non-Aliased uncorrectable */
					/* non-mirrored demand data ECC */
#define	EMASK_FBD_M8	0x00000080	/* M8Err Aliased uncorrectable */
					/* patrol data ECC */
#define	EMASK_FBD_M7	0x00000040	/* M7Err Aliased uncorrectable */
					/* resilver or spare copy data ECC */
#define	EMASK_FBD_M6	0x00000020	/* M6Err Aliased uncorrectable */
					/* mirrored demand data ECC */
#define	EMASK_FBD_M5	0x00000010	/* M5Err Aliased uncorrectable */
					/* non-mirrored demand data ECC */
#define	EMASK_FBD_M4	0x00000008	/* M4Err uncorrectable data ECC on */
					/* replay */
#define	EMASK_FBD_M3	0x00000004	/* M3Err >Tmid thermal event with */
					/* intelligent throttling disabled */
#define	EMASK_FBD_M2	0x00000002	/* M2Err memory or FBD configuration */
					/* CRC read error */
#define	EMASK_FBD_M1	0x00000001	/* M1Err memory write error on */
					/* non-redundant retry or FBD */
					/* configuration write error on retry */
/* MCH 7300 errata 34 */
#define	EMASK_FBD_RES	0x00808000	/* reserved mask bits */

#define	EMASK_FBD_FATAL	(EMASK_FBD_M23|EMASK_FBD_M3|EMASK_FBD_M2|EMASK_FBD_M1)
#define	EMASK_FBD_NF (EMASK_FBD_M28|EMASK_FBD_M27|EMASK_FBD_M26|EMASK_FBD_M25| \
	EMASK_FBD_M22|EMASK_FBD_M21|EMASK_FBD_M20|EMASK_FBD_M19|EMASK_FBD_M18| \
	EMASK_FBD_M17|EMASK_FBD_M15|EMASK_FBD_M14|EMASK_FBD_M13|EMASK_FBD_M12| \
	EMASK_FBD_M11|EMASK_FBD_M10|EMASK_FBD_M9|EMASK_FBD_M8|EMASK_FBD_M7| \
	EMASK_FBD_M6|EMASK_FBD_M5|EMASK_FBD_M4)

#define	ERR_FAT_INT_B8	0x10	/* B8Msk SF Coherency Error for BIL */
#define	ERR_FAT_INT_B4	0x08	/* B4Msk Virtual pin port error */
#define	ERR_FAT_INT_B3	0x04	/* B3Msk Coherency violation error for EWB */
#define	ERR_FAT_INT_B2	0x02	/* B2Msk Multi-tag hit SF */
#define	ERR_FAT_INT_B1	0x01	/* B1Msk DM parity error */

#define	ERR_NF_INT_B7	0x04	/* B7Msk Multiple ECC error in any of */
					/* the ways during SF lookup */
#define	ERR_NF_INT_B6	0x02	/* B6Msk Single ECC error on SF lookup */
#define	ERR_NF_INT_B5	0x01	/* B5Msk Address Map error */

#define	EMASK_INT_B8	0x80	/* B8Msk SF Coherency Error for BIL */
#define	EMASK_INT_B7	0x40	/* B7Msk Multiple ECC error in any of */
				/* the ways during SF lookup */
#define	EMASK_INT_B6	0x20	/* B6Msk Single ECC error on SF lookup */
#define	EMASK_INT_B5	0x10	/* B5Msk Address Map error */
#define	EMASK_INT_B4	0x08	/* B4Msk Virtual pin port error */
#define	EMASK_INT_B3	0x04	/* B3Msk Coherency violation error for EWB */
#define	EMASK_INT_B2	0x02	/* B2Msk Multi-tag hit SF */
#define	EMASK_INT_B1	0x01	/* B1Msk DM parity error */

/* MCH 5000 errata 2 */
#define	EMASK_INT_5000	EMASK_INT_B1
/* MCH 7300 errata 17 & 20 */
#define	EMASK_INT_7300	(EMASK_INT_B3|EMASK_INT_B1)
/* MCH 7300 errata 17,20 & 21 */
#define	EMASK_INT_7300_STEP_0	(EMASK_INT_B7|EMASK_INT_B3|EMASK_INT_B1)

#define	EMASK_INT_FATAL (EMASK_INT_B7|EMASK_INT_B4|EMASK_INT_B3|EMASK_INT_B2| \
	EMASK_INT_B1)
#define	EMASK_INT_NF	(EMASK_INT_B8|EMASK_INT_B6|EMASK_INT_B5)
#define	GE_FBD_FATAL (GE_FERR_FBD0_FATAL|GE_FERR_FBD1_FATAL| \
	GE_FERR_FBD2_FATAL|GE_FERR_FBD3_FATAL)
#define	GE_FBD_NF \
	(GE_FERR_FBD0_NF|GE_FERR_FBD1_NF|GE_FERR_FBD2_NF|GE_FERR_FBD3_NF)

#define	EMASK_UNCOR_PEX_IO18	0x00200000	/* ESI Reset timeout */
#define	EMASK_UNCOR_PEX_IO2	0x00100000	/* Received an unsupported */
						/* request */
#define	EMASK_UNCOR_PEX_IO9	0x00040000	/* Malformed TLP Status */
#define	EMASK_UNCOR_PEX_IO10	0x00020000	/* Received buffer overflow */
#define	EMASK_UNCOR_PEX_IO8	0x00010000	/* unexpected completion */
#define	EMASK_UNCOR_PEX_IO7	0x00008000	/* completion abort */
#define	EMASK_UNCOR_PEX_IO6	0x00004000	/* completion timeout */
#define	EMASK_UNCOR_PEX_IO5	0x00002000	/* flow control protocol */
#define	EMASK_UNCOR_PEX_IO4	0x00001000	/* poisoned TLP */
#define	EMASK_UNCOR_PEX_IO19	0x00000020	/* surprise link down */
#define	EMASK_UNCOR_PEX_IO0	0x00000010	/* data link protocol */
#define	EMASK_UNCOR_PEX_IO3	0x00000001	/* training error */

#define	EMASK_COR_PEX_NF_EDM	0x00002000	/* Advisory Non Fatal */
#define	EMASK_COR_PEX_IO16	0x00001000	/* replay timer timeout */
#define	EMASK_COR_PEX_IO15	0x00000100	/* replay num pollover */
#define	EMASK_COR_PEX_IO14	0x00000080	/* bad DLLP */
#define	EMASK_COR_PEX_IO13	0x00000040	/* bad TLP */
#define	EMASK_COR_PEX_IO12	0x00000001	/* receiver error mask */

#define	EMASK_RP_PEX_IO1	0x00000004	/* fatal message detect */
#define	EMASK_RP_PEX_IO11	0x00000002	/* uncorrectable message */
#define	EMASK_RP_PEX_IO17	0x00000001	/* correctable message */

#define	PEX_FAT_IO19	0x00001000	/* surprise link down */
#define	PEX_FAT_IO18	0x00000800	/* ESI reset timeout */
#define	PEX_FAT_IO9	0x00000400	/* malformed TLP */
#define	PEX_FAT_IO10	0x00000200	/* receiver buffer overflow */
#define	PEX_FAT_IO8	0x00000100	/* unexpected completion */
#define	PEX_FAT_IO7	0x00000080	/* completer abort */
#define	PEX_FAT_IO6	0x00000040	/* completion timeout */
#define	PEX_FAT_IO5	0x00000020	/* flow control protocol */
#define	PEX_FAT_IO4	0x00000010	/* poisoned TLP */
#define	PEX_FAT_IO3	0x00000008	/* training error */
#define	PEX_FAT_IO2	0x00000004	/* received unsupported req  */
#define	PEX_FAT_IO1	0x00000002	/* received fatal error message */
#define	PEX_FAT_IO0	0x00000001	/* data link layer protocol */

#define	PEX_NF_IO19	0x00020000	/* surprise link down */
#define	PEX_NF_IO17	0x00010000	/* received correctable error message */
#define	PEX_NF_IO16	0x00008000	/* replay timer timeout */
#define	PEX_NF_IO15	0x00004000	/* replay num pollover */
#define	PEX_NF_IO14	0x00002000	/* bad DLLP */
#define	PEX_NF_IO13	0x00001000	/* bad TLP */
#define	PEX_NF_IO12	0x00000800	/* receiver error mask */
#define	PEX_NF_IO11	0x00000400	/* received non fatal error message */
#define	PEX_NF_IO10	0x00000200	/* Received buffer overflow */
#define	PEX_NF_IO9	0x00000100	/* Malformed TLP */
#define	PEX_NF_IO8	0x00000080
#define	PEX_NF_IO7	0x00000040
#define	PEX_NF_IO6	0x00000020	/* completion timeout */
#define	PEX_NF_IO5	0x00000010	/* flow control protocol */
#define	PEX_NF_IO4	0x00000008	/* poisoned TLP */
#define	PEX_NF_IO3	0x00000004
#define	PEX_NF_IO2	0x00000002
#define	PEX_NF_IO0	0x00000001	/* data link layer protocol */

#define	GE_FERR_FSB(ferr) ( \
	((ferr) & (GE_FSB0_FATAL|GE_FSB0_NF)) ? 0 : \
	((ferr) & (GE_FSB1_FATAL|GE_FSB1_NF)) ? 1 : \
	(nb_chipset == INTEL_NB_7300) && \
	((ferr) & (GE_FERR_FSB2_FATAL|GE_FERR_FSB2_NF)) ? 2 : \
	(nb_chipset == INTEL_NB_7300) && \
	((ferr) & (GE_FERR_FSB3_FATAL|GE_FERR_FSB3_NF)) ? 3 : \
	-1)

#define	GE_NERR_TO_FERR_FSB(nerr) \
	(((nerr) & GE_NERR_FSB3_FATAL) ? GE_FERR_FSB3_FATAL : 0 | \
	((nerr) & GE_NERR_FSB2_FATAL) ? GE_FERR_FSB2_FATAL : 0  | \
	((nerr) & GE_NERR_FSB3_NF) ? GE_FERR_FBD3_NF : 0  | \
	((nerr) & GE_NERR_FSB2_NF) ? GE_FERR_FBD2_NF : 0)

#define	GE_ERR_PEX(ferr) ( \
	((ferr) & (GE_ESI_FATAL|GE_ESI_NF)) ? 0 : \
	((nb_chipset == INTEL_NB_7300) && \
	((ferr) & (GE_PCIEX1_FATAL|GE_PCIEX1_NF))) ? 1 : \
	((ferr) & (GE_PCIEX2_FATAL|GE_PCIEX2_NF)) ? 2 : \
	((ferr) & (GE_PCIEX3_FATAL|GE_PCIEX3_NF)) ? 3 : \
	((ferr) & (GE_PCIEX4_FATAL|GE_PCIEX4_NF)) ? 4 : \
	((ferr) & (GE_PCIEX5_FATAL|GE_PCIEX5_NF)) ? 5 : \
	((ferr) & (GE_PCIEX6_FATAL|GE_PCIEX6_NF)) ? 6 : \
	((ferr) & (GE_PCIEX7_FATAL|GE_PCIEX7_NF)) ? 7 : \
	-1)

#define	GE_FERR_FATAL	((nb_chipset == INTEL_NB_7300) ? \
	(GE_INT_FATAL|GE_DMA_FATAL|GE_FERR_FSB3_FATAL|GE_FERR_FSB2_FATAL| \
	GE_FSB1_FATAL|GE_FSB0_FATAL|GE_FBD_FATAL|GE_PCIEX7_FATAL| \
	GE_PCIEX6_FATAL| GE_PCIEX5_FATAL|GE_PCIEX4_FATAL|GE_PCIEX3_FATAL| \
	GE_PCIEX2_FATAL| GE_ESI_FATAL) :  \
	(GE_INT_FATAL|GE_DMA_FATAL|GE_FSB1_FATAL|GE_FSB0_FATAL|GE_FBD_FATAL| \
	GE_PCIEX7_FATAL|GE_PCIEX6_FATAL|GE_PCIEX5_FATAL|GE_PCIEX4_FATAL| \
	GE_PCIEX3_FATAL|GE_PCIEX2_FATAL|GE_ESI_FATAL))

#define	GE_NERR_FATAL	((nb_chipset == INTEL_NB_7300) ? \
	(GE_INT_FATAL|GE_DMA_FATAL|GE_NERR_FSB3_FATAL|GE_NERR_FSB2_FATAL| \
	GE_FSB1_FATAL|GE_FSB0_FATAL|GE_FBD_FATAL|GE_PCIEX7_FATAL| \
	GE_PCIEX6_FATAL|GE_PCIEX5_FATAL|GE_PCIEX4_FATAL|GE_PCIEX3_FATAL| \
	GE_PCIEX2_FATALGE_ESI_FATAL) :  \
	(GE_INT_FATAL|GE_DMA_FATAL|GE_FSB1_FATAL|GE_FSB0_FATAL|GE_FBD_FATAL| \
	GE_PCIEX7_FATAL|GE_PCIEX6_FATAL|GE_PCIEX5_FATAL|GE_PCIEX4_FATAL| \
	GE_PCIEX3_FATAL|GE_PCIEX2_FATAL|GE_ESI_FATAL))

#define	GE_PCIEX_FATAL	(GE_ESI_FATAL|GE_PCIEX1_FATAL|GE_PCIEX2_FATAL| \
	GE_PCIEX3_FATAL|GE_PCIEX4_FATAL|GE_PCIEX5_FATAL|GE_PCIEX6_FATAL| \
	GE_PCIEX7_FATAL)
#define	GE_PCIEX_NF	(GE_ESI_NF|GE_PCIEX1_NF|GE_PCIEX2_NF|GE_PCIEX3_NF| \
	GE_PCIEX4_NF|GE_PCIEX5_NF|GE_PCIEX6_NF|GE_PCIEX7_NF)
#define	GE_FERR_FSB_FATAL	((nb_chipset == INTEL_NB_7300) ? \
	(GE_FSB0_FATAL|GE_FSB1_FATAL|GE_FERR_FSB2_FATAL|GE_FERR_FSB3_FATAL) : \
	(GE_FSB0_FATAL|GE_FSB1_FATAL))
#define	GE_NERR_FSB_FATAL	((nb_chipset == INTEL_NB_7300) ? \
	(GE_FSB0_FATAL|GE_FSB1_FATAL|GE_NERR_FSB2_FATAL|GE_NERR_FSB3_FATAL) : \
	(GE_FSB0_FATAL|GE_FSB1_FATAL))
#define	GE_FERR_FSB_NF	((nb_chipset == INTEL_NB_7300) ? \
	(GE_FSB0_NF|GE_FSB1_NF|GE_FERR_FSB2_NF|GE_FERR_FSB3_NF) : \
	(GE_FSB0_NF|GE_FSB1_NF|GE_FERR_FSB2_NF|GE_FERR_FSB3_NF))
#define	GE_NERR_FSB_NF	((nb_chipset == INTEL_NB_7300) ? \
	(GE_FSB0_NF|GE_FSB1_NF|GE_NERR_FSB2_NF|GE_NERR_FSB3_NF) : \
	(GE_FSB0_NF|GE_FSB1_NF|GE_NERR_FSB2_NF|GE_NERR_FSB3_NF))

#define	FERR_FBD_CHANNEL(reg)	((reg)>>28 & 3)

#define	NB5000_STEPPING()	nb_pci_getw(0, 0, 0, 8, 0)

#define	FERR_GLOBAL_RD()	((nb_chipset == INTEL_NB_7300) ? \
				    ((uint64_t)nb_pci_getl(0, 16, 2, \
				    0x48, 0) << 32) | nb_pci_getl(0, 16, 2, \
				    0x40, 0) : \
				    (uint64_t)nb_pci_getl(0, 16, 2, 0x40, 0))
#define	NERR_GLOBAL_RD()	nb_pci_getl(0, 16, 2, 0x44, 0)
#define	FERR_FAT_FSB_RD(fsb, ip)	((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_getb(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xc0 : 0x40, ip) : \
	nb_pci_getb(0, 16, 0, fsb ? 0x480 : 0x180, ip))
#define	FERR_NF_FSB_RD(fsb, ip)	((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_getb(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xc1 : 0x41, ip) : \
	nb_pci_getb(0, 16, 0, fsb ? 0x481 : 0x181, ip))
#define	NERR_FAT_FSB_RD(fsb, ip) ((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_getb(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xc2 : 0x42, ip) : \
	nb_pci_getb(0, 16, 0, fsb ? 0x482 : 0x182, ip))
#define	NERR_NF_FSB_RD(fsb, ip) ((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_getb(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xc3 : 0x43, ip) : \
	nb_pci_getb(0, 16, 0, fsb ? 0x483 : 0x183, ip))

#define	NRECFSB_RD(fsb)	((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_getl(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xc4 : 0x44, 0) : \
	nb_pci_getl(0, 16, 0, fsb ? 0x484 : 0x184, 0))
#define	NRECFSB_WR(fsb)	\
	if (nb_chipset == INTEL_NB_7300) { \
		nb_pci_putl(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xc4 : 0x44, \
		    0); \
	} else { \
		nb_pci_putl(0, 16, 0, fsb ? 0x484 : 0x184, 0); \
	}
#define	RECFSB_RD(fsb)	((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_getl(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xc8 : 0x48, 0) : \
	nb_pci_getl(0, 16, 0, fsb ? 0x488 : 0x188, 0))
#define	RECFSB_WR(fsb) \
	if (nb_chipset == INTEL_NB_7300) { \
		nb_pci_putl(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xc8 : 0x48, \
		    0); \
	} else { \
		nb_pci_putl(0, 16, 0, fsb ? 0x488 : 0x188, 0); \
	}
#define	NRECADDR_RD(fsb)	((nb_chipset == INTEL_NB_7300) ? \
	((uint64_t)(nb_pci_getb(0, 17, (fsb & 2) ? 3 : 0, \
	(fsb & 1) ? 0xd0 : 0x50, 0)) << 32) | \
	nb_pci_getl(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xcc : 0x4c, 0) : \
	((uint64_t)(nb_pci_getb(0, 16, 0, fsb ? 0x490 : 0x190, 0)) << 32) | \
	nb_pci_getl(0, 16, 0, fsb ? 0x48c : 0x18c, 0))
#define	NRECADDR_WR(fsb) \
	if (nb_chipset == INTEL_NB_7300) { \
		nb_pci_putb(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xd0 : 0x50, \
		    0); \
		nb_pci_putl(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xcc : 0x4c, \
		    0); \
	} else { \
		nb_pci_putb(0, 16, 0, fsb ? 0x490 : 0x190, 0); \
		nb_pci_putl(0, 16, 0, fsb ? 0x48c : 0x18c, 0); \
	}
#define	EMASK_FSB_RD(fsb)	((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_getw(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xd2 : 0x52, 0) : \
	nb_pci_getw(0, 16, 0, fsb ? 0x492 : 0x192, 0))
#define	ERR0_FSB_RD(fsb)	((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_getw(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xd4 : 0x54, 0) : \
	nb_pci_getw(0, 16, 0, fsb ? 0x494 : 0x194, 0))
#define	ERR1_FSB_RD(fsb)	((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_getw(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xd6 : 0x56, 0) : \
	nb_pci_getw(0, 16, 0, fsb ? 0x496 : 0x196, 0))
#define	ERR2_FSB_RD(fsb)	((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_getw(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xd8 : 0x58, 0) : \
	nb_pci_getw(0, 16, 0, fsb ? 0x498 : 0x198, 0))
#define	MCERR_FSB_RD(fsb)	((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_getw(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xda : 0x5a, 0) : \
	nb_pci_getw(0, 16, 0, fsb ? 0x49a : 0x19a, 0))

#define	FERR_GLOBAL_WR(val) \
	if (nb_chipset == INTEL_NB_7300) \
	{ \
		    nb_pci_putl(0, 16, 2, 0x48, (uint32_t)(val >> 32)); \
		    nb_pci_putl(0, 16, 2, 0x40, (uint32_t)val); \
	} else { \
		    nb_pci_putl(0, 16, 2, 0x40, (uint32_t)val); \
	}
#define	NERR_GLOBAL_WR(val)	nb_pci_putl(0, 16, 2, 0x44, val)
#define	FERR_FAT_FSB_WR(fsb, val)	((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_putb(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xc0 : 0x40, val) : \
	nb_pci_putb(0, 16, 0, fsb ? 0x480 : 0x180, val))
#define	FERR_NF_FSB_WR(fsb, val)	((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_putb(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xc1 : 0x41, val) : \
	nb_pci_putb(0, 16, 0, fsb ? 0x481 : 0x181, val))
#define	NERR_FAT_FSB_WR(fsb, val)	((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_putb(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xc2 : 0x42, val) : \
	nb_pci_putb(0, 16, 0, fsb ? 0x482 : 0x182, val))
#define	NERR_NF_FSB_WR(fsb, val)	((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_putb(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xc3 : 0x43, val) : \
	nb_pci_putb(0, 16, 0, fsb ? 0x483 : 0x183, val))
#define	EMASK_FSB_WR(fsb, val)	((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_putw(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xd2 : 0x52, val) : \
	nb_pci_putw(0, 16, 0, fsb ? 0x492 : 0x192, val))
#define	ERR0_FSB_WR(fsb, val)	((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_putw(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xd4 : 0x54, val) : \
	nb_pci_putw(0, 16, 0, fsb ? 0x494 : 0x194, val))
#define	ERR1_FSB_WR(fsb, val)	((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_putw(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xd6 : 0x56, val) : \
	nb_pci_putw(0, 16, 0, fsb ? 0x496 : 0x196, val))
#define	ERR2_FSB_WR(fsb, val)	((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_putw(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xd8 : 0x58, val) : \
	nb_pci_putw(0, 16, 0, fsb ? 0x498 : 0x198, val))
#define	MCERR_FSB_WR(fsb, val)	((nb_chipset == INTEL_NB_7300) ? \
	nb_pci_putw(0, 17, (fsb & 2) ? 3 : 0, (fsb & 1) ? 0xda : 0x5a, val) : \
	nb_pci_putw(0, 16, 0, fsb ? 0x49a : 0x19a, val))

#define	NRECSF_RD()	(nb_chipset == INTEL_NB_5000X || \
	nb_chipset == INTEL_NB_7300) ? ((uint64_t)( \
	nb_pci_getl(0, 16, 2, 0xb4, 0)) << 32) | \
	nb_pci_getl(0, 16, 2, 0xb0, 0) : 0LL
#define	RECSF_RD()	(nb_chipset == INTEL_NB_5000X || \
	nb_chipset == INTEL_NB_7300) ? ((uint64_t)( \
	nb_pci_getl(0, 16, 2, 0xbc, 0)) << 32) | \
	nb_pci_getl(0, 16, 2, 0xb8, 0) : 0LL

#define	NRECSF_WR()	if (nb_chipset == INTEL_NB_5000X || \
	nb_chipset == INTEL_NB_7300) { \
		nb_pci_putl(0, 16, 2, 0xbc, 0); \
		nb_pci_putl(0, 16, 2, 0xb0, 0); \
	}
#define	RECSF_WR()	if (nb_chipset == INTEL_NB_5000X || \
	nb_chipset == INTEL_NB_7300) { \
		nb_pci_putl(0, 16, 2, 0xbc, 0); \
		nb_pci_putl(0, 16, 2, 0xb8, 0); \
	}

#define	FERR_FAT_INT_RD(ip)	nb_pci_getb(0, 16, 2, 0xc0, ip)
#define	FERR_NF_INT_RD(ip)	nb_pci_getb(0, 16, 2, 0xc1, ip)
#define	NERR_FAT_INT_RD(ip)	nb_pci_getb(0, 16, 2, 0xc2, ip)
#define	NERR_NF_INT_RD(ip)	nb_pci_getb(0, 16, 2, 0xc3, ip)
#define	EMASK_INT_RD()		nb_pci_getb(0, 16, 2, 0xcc, 0)
#define	ERR0_INT_RD()		nb_pci_getb(0, 16, 2, 0xd0, 0)
#define	ERR1_INT_RD()		nb_pci_getb(0, 16, 2, 0xd1, 0)
#define	ERR2_INT_RD()		nb_pci_getb(0, 16, 2, 0xd2, 0)
#define	MCERR_INT_RD()		nb_pci_getb(0, 16, 2, 0xd3, 0)

#define	FERR_FAT_INT_WR(val)	nb_pci_putb(0, 16, 2, 0xc0, val)
#define	FERR_NF_INT_WR(val)	nb_pci_putb(0, 16, 2, 0xc1, val)
#define	NERR_FAT_INT_WR(val)	nb_pci_putb(0, 16, 2, 0xc2, val)
#define	NERR_NF_INT_WR(val)	nb_pci_putb(0, 16, 2, 0xc3, val)
#define	EMASK_INT_WR(val)	nb_pci_putb(0, 16, 2, 0xcc, val)
#define	ERR0_INT_WR(val)	nb_pci_putb(0, 16, 2, 0xd0, val)
#define	ERR1_INT_WR(val)	nb_pci_putb(0, 16, 2, 0xd1, val)
#define	ERR2_INT_WR(val)	nb_pci_putb(0, 16, 2, 0xd2, val)
#define	MCERR_INT_WR(val)	nb_pci_putb(0, 16, 2, 0xd3, val)

#define	NRECINT_RD()		nb_pci_getl(0, 16, 2, 0xc4, 0)
#define	RECINT_RD()		nb_pci_getl(0, 16, 2, 0xc8, 0)

#define	NRECINT_WR()		nb_pci_putl(0, 16, 2, 0xc4, 0)
#define	RECINT_WR()		nb_pci_putl(0, 16, 2, 0xc8, 0)

#define	FERR_FAT_FBD_RD(ip)	nb_pci_getl(0, 16, 1, 0x98, ip)
#define	NERR_FAT_FBD_RD(ip)	nb_pci_getl(0, 16, 1, 0x9c, ip)
#define	FERR_NF_FBD_RD(ip)	nb_pci_getl(0, 16, 1, 0xa0, ip)
#define	NERR_NF_FBD_RD(ip)	nb_pci_getl(0, 16, 1, 0xa4, ip)
#define	EMASK_FBD_RD()		nb_pci_getl(0, 16, 1, 0xa8, 0)
#define	ERR0_FBD_RD()		nb_pci_getl(0, 16, 1, 0xac, 0)
#define	ERR1_FBD_RD()		nb_pci_getl(0, 16, 1, 0xb0, 0)
#define	ERR2_FBD_RD()		nb_pci_getl(0, 16, 1, 0xb4, 0)
#define	MCERR_FBD_RD()		nb_pci_getl(0, 16, 1, 0xb8, 0)

#define	FERR_FAT_FBD_WR(val)	nb_pci_putl(0, 16, 1, 0x98, val)
#define	NERR_FAT_FBD_WR(val)	nb_pci_putl(0, 16, 1, 0x9c, val)
#define	FERR_NF_FBD_WR(val)	nb_pci_putl(0, 16, 1, 0xa0, val)
#define	NERR_NF_FBD_WR(val)	nb_pci_putl(0, 16, 1, 0xa4, val)
#define	EMASK_FBD_WR(val)	nb_pci_putl(0, 16, 1, 0xa8, val)
#define	ERR0_FBD_WR(val)	nb_pci_putl(0, 16, 1, 0xac, val)
#define	ERR1_FBD_WR(val)	nb_pci_putl(0, 16, 1, 0xb0, val)
#define	ERR2_FBD_WR(val)	nb_pci_putl(0, 16, 1, 0xb4, val)
#define	MCERR_FBD_WR(val)	nb_pci_putl(0, 16, 1, 0xb8, val)

#define	NRECMEMA_RD()	nb_pci_getw(0, 16, 1, 0xbe, 0)
#define	NRECMEMB_RD()	nb_pci_getw(0, 16, 1, 0xc0, 0)
#define	NRECFGLOG_RD()	nb_pci_getl(0, 16, 1, 0xc4, 0)
#define	NRECFBDA_RD()	nb_pci_getl(0, 16, 1, 0xc8, 0)
#define	NRECFBDB_RD()	nb_pci_getl(0, 16, 1, 0xcc, 0)
#define	NRECFBDC_RD()	nb_pci_getl(0, 16, 1, 0xd0, 0)
#define	NRECFBDD_RD()	nb_pci_getl(0, 16, 1, 0xd4, 0)
#define	NRECFBDE_RD()	nb_pci_getl(0, 16, 1, 0xd8, 0)
#define	REDMEMB_RD()	nb_pci_getl(0, 16, 1, 0x7c, 0)
#define	RECMEMA_RD()	nb_pci_getw(0, 16, 1, 0xe2, 0)
#define	RECMEMB_RD()	nb_pci_getl(0, 16, 1, 0xe4, 0)
#define	RECFGLOG_RD()	nb_pci_getl(0, 16, 1, 0xe8, 0)
#define	RECFBDA_RD()	nb_pci_getl(0, 16, 1, 0xec, 0)
#define	RECFBDB_RD()	nb_pci_getl(0, 16, 1, 0xf0, 0)
#define	RECFBDC_RD()	nb_pci_getl(0, 16, 1, 0xf4, 0)
#define	RECFBDD_RD()	nb_pci_getl(0, 16, 1, 0xf8, 0)
#define	RECFBDE_RD()	nb_pci_getl(0, 16, 1, 0xfc, 0)
#define	NRECMEMA_WR()	nb_pci_putw(0, 16, 1, 0xbe, 0)
#define	NRECMEMB_WR()	nb_pci_putw(0, 16, 1, 0xc0, 0)
#define	NRECFGLOG_WR()	nb_pci_putl(0, 16, 1, 0xc4, 0)
#define	NRECFBDA_WR()	nb_pci_putl(0, 16, 1, 0xc8, 0)
#define	NRECFBDB_WR()	nb_pci_putl(0, 16, 1, 0xcc, 0)
#define	NRECFBDC_WR()	nb_pci_putl(0, 16, 1, 0xd0, 0)
#define	NRECFBDD_WR()	nb_pci_putl(0, 16, 1, 0xd4, 0)
#define	NRECFBDE_WR()	nb_pci_putl(0, 16, 1, 0xd8, 0)
#define	REDMEMB_WR()	nb_pci_putl(0, 16, 1, 0x7c, 0)
#define	RECMEMA_WR()	nb_pci_putw(0, 16, 1, 0xe2, 0)
#define	RECMEMB_WR()	nb_pci_putl(0, 16, 1, 0xe4, 0)
#define	RECFGLOG_WR()	nb_pci_putl(0, 16, 1, 0xe8, 0)
#define	RECFBDA_WR()	nb_pci_putl(0, 16, 1, 0xec, 0)
#define	RECFBDB_WR()	nb_pci_putl(0, 16, 1, 0xf0, 0)
#define	RECFBDC_WR()	nb_pci_putl(0, 16, 1, 0xf4, 0)
#define	RECFBDD_WR()	nb_pci_putl(0, 16, 1, 0xf8, 0)
#define	RECFBDE_WR()	nb_pci_putl(0, 16, 1, 0xfc, 0)

#define	MC_RD()		nb_pci_getl(0, 16, 1, 0x40, 0)
#define	MC_WR(val)	nb_pci_putl(0, 16, 1, 0x40, val)
#define	MCA_RD()	nb_pci_getl(0, 16, 1, 0x58, 0)
#define	TOLM_RD()	nb_pci_getw(0, 16, 1, 0x6c, 0)

#define	MTR_RD(branch, dimm) ((branch) == 0) ? \
	nb_pci_getw(0, 21, 0, 0x80 + dimm * 4, 0) : \
	(nb_number_memory_controllers == 2) ? \
	nb_pci_getw(0, 22, 0, 0x80 + dimm * 4, 0) : 0
#define	MIR_RD(reg)	nb_pci_getw(0, 16, 1, 0x80 + ((reg)*4), 0)

#define	DMIR_RD(branch, reg) \
	((branch) == 0) ? nb_pci_getl(0, 21, 0, 0x90 + ((reg)*4), 0) : \
	(nb_number_memory_controllers == 2) ? \
	nb_pci_getl(0, 22, 0, 0x90 + ((reg)*4), 0) : 0

#define	SPCPC_RD(branch) (nb_dimms_per_channel <= 4 ? \
	(((branch) == 0) ? \
	(uint32_t)nb_pci_getb(0, 21, 0, 0x40, 0) : \
	    (nb_number_memory_controllers == 2) ? \
	    (uint32_t)nb_pci_getb(0, 22, 0, 0x40, 0) : 0) : \
	nb_pci_getl(0, ((branch) == 0) ? 21 : 22, 0, 0x40, 0))

#define	SPCPC_SPARE_ENABLE (nb_dimms_per_channel <= 4 ? 1 : 0x20)
#define	SPCPC_SPRANK(spcpc) (nb_dimms_per_channel <= 4 ? \
	(((spcpc) >> 1) & 7) : ((spcpc) & 0xf))

#define	SPCPS_RD(branch) ((branch) == 0) ? \
	nb_pci_getb(0, 21, 0, nb_dimms_per_channel <= 4 ? 0x41 : 0x43, 0) : \
	(nb_number_memory_controllers == 2) ? \
	nb_pci_getb(0, 22, 0, nb_dimms_per_channel <= 4 ? 0x41 : 0x43, 0) : 0

#define	SPCPS_WR(branch) \
	if ((branch) == 0) { \
		nb_pci_putb(0, 21, 0, nb_dimms_per_channel <= 4 ? 0x41 : 0x43, \
		    0); \
	} else if (nb_number_memory_controllers == 2) { \
		nb_pci_putb(0, 22, 0, nb_dimms_per_channel <= 4 ? 0x41 : 0x43, \
		    0); \
	}

#define	SPCPS_SPARE_DEPLOYED (nb_dimms_per_channel <= 4 ? 0x11 : 0x60)
#define	SPCPS_FAILED_RANK(spcps) (nb_dimms_per_channel <= 4 ? \
	(((spcps) >> 1) & 7) : ((spcps) & 0xf))

#define	UERRCNT_RD(branch) ((branch) == 0) ? \
	nb_pci_getl(0, 21, 0, 0xa4, 0) : \
	(nb_number_memory_controllers == 2) ? \
	nb_pci_getl(0, 22, 0, 0xa4, 0) : 0
#define	CERRCNT_RD(branch) ((branch) == 0) ? \
	nb_pci_getl(0, 21, 0, 0xa8, 0) : \
	(nb_number_memory_controllers == 2) ? \
	nb_pci_getl(0, 22, 0, 0xa8, 0) : 0
#define	BADRAMA_RD(branch) ((branch) == 0) ? \
	nb_pci_getl(0, 21, 0, 0xac, 0) : \
	(nb_number_memory_controllers == 2) ? \
	nb_pci_getl(0, 22, 0, 0xac, 0) : 0
#define	BADRAMB_RD(branch) ((branch) == 0) ? \
	nb_pci_getw(0, 21, 0, 0xb0, 0) : \
	(nb_number_memory_controllers == 2) ? \
	nb_pci_getw(0, 22, 0, 0xb0, 0) : 0
#define	BADCNT_RD(branch) ((branch) == 0) ? \
	nb_pci_getl(0, 21, 0, 0xb4, 0) : \
	(nb_number_memory_controllers == 2) ? \
	nb_pci_getl(0, 22, 0, 0xb4, 0) : 0

#define	UERRCNT_WR(branch, val)	((branch) == 0) ? \
	nb_pci_putl(0, 21, 0, 0xa4, val) : \
	(nb_number_memory_controllers == 2) ? \
	nb_pci_putl(0, 22, 0, 0xa4, val) \
					: 0
#define	CERRCNT_WR(branch, val)	((branch) == 0) ? \
	nb_pci_putl(0, 21, 0, 0xa8, val) : \
	(nb_number_memory_controllers == 2) ? \
	nb_pci_putl(0, 22, 0, 0xa8, val) : 0
#define	BADRAMA_WR(branch, val)	((branch) == 0) ? \
	nb_pci_putl(0, 21, 0, 0xac, val) : \
	(nb_number_memory_controllers == 2) ? \
	nb_pci_putl(0, 22, 0, 0xac, val) : 0
#define	BADRAMB_WR(branch, val)	((branch) == 0) ? \
	nb_pci_putw(0, 21, 0, 0xb0, val) : \
	(nb_number_memory_controllers == 2) ? \
	nb_pci_putw(0, 22, 0, 0xb0) : 0
#define	BADCNT_WR(branch, val) ((branch) == 0) ? \
	nb_pci_putl(0, 21, 0, 0xb4, val) : \
	(nb_number_memory_controllers == 2) ? \
	nb_pci_putl(0, 22, 0, 0xb4, val) : 0

#define	SPD_RD(branch, channel)	((branch) == 0) ? \
	nb_pci_getw(0, 21, 0, 0x74 + ((channel) * 2), 0) : \
	(nb_number_memory_controllers == 2) ? \
	nb_pci_getw(0, 22, 0, 0x74 + ((channel) * 2), 0) : 0
#define	SPDCMDRD(branch, channel) ((branch) == 0) ? \
	nb_pci_getl(0, 21, 0, 0x78 + ((channel) * 4), 0) : \
	(nb_number_memory_controllers == 2) ? \
	nb_pci_getl(0, 22, 0, 0x78 + ((channel) * 4), 0) : 0

#define	SPDCMD1_1_WR(val)	nb_pci_putl(0, 21, 0, 0x7c, val)
#define	SPDCMD_WR(branch, channel, val)	\
	if ((branch) == 0) \
	nb_pci_putl(0, 21, 0, 0x78 + ((channel) * 4), val); \
	else if (nb_number_memory_controllers == 2) \
	nb_pci_putl(0, 22, 0, 0x78 + ((channel) * 4), val)

#define	UNCERRSTS_RD(pex)		nb_pci_getl(0, pex, 0, 0x104, 0)
#define	UNCERRMSK_RD(pex) nb_pci_getl(0, pex, 0, 0x108, 0)
#define	PEX_FAT_FERR_ESI_RD()	nb_pci_getl(0, 0, 0, 0x154, 0)
#define	PEX_FAT_NERR_ESI_RD()	nb_pci_getl(0, 0, 0, 0x15c, 0)
#define	PEX_NF_FERR_ESI_RD()	nb_pci_getl(0, 0, 0, 0x158, 0)
#define	PEX_NF_NERR_ESI_RD()	nb_pci_getl(0, 0, 0, 0x160, 0)
#define	PEX_ERR_DOCMD_RD(pex)	nb_pci_getl(0, pex, 0, 0x144, 0)
#define	EMASK_UNCOR_PEX_RD(pex)	nb_pci_getl(0, pex, 0, 0x148, 0)
#define	EMASK_COR_PEX_RD(pex)	nb_pci_getl(0, pex, 0, 0x14c, 0)
#define	EMASK_RP_PEX_RD(pex)	nb_pci_getl(0, pex, 0, 0x150, 0)

#define	UNCERRSTS_WR(pex, val)	nb_pci_putl(0, pex, 0, 0x104, val)
#define	UNCERRMSK_WR(pex, val)	nb_pci_putl(0, pex, 0, 0x108, val)
#define	PEX_FAT_FERR_ESI_WR(val) nb_pci_putl(0, 0, 0, 0x154, val)
#define	PEX_FAT_NERR_ESI_WR(val) nb_pci_putl(0, 0, 0, 0x15c, val)
#define	PEX_NF_FERR_ESI_WR(val)	nb_pci_putl(0, 0, 0, 0x158, val)
#define	PEX_NF_NERR_ESI_WR(val)	nb_pci_putl(0, 0, 0, 0x160, val)
#define	PEX_ERR_DOCMD_WR(pex, val)	nb_pci_putl(0, pex, 0, 0x144, val)
#define	EMASK_UNCOR_PEX_WR(pex, val)	nb_pci_putl(0, pex, 0, 0x148, val)
#define	EMASK_COR_PEX_WR(pex, val)	nb_pci_putl(0, pex, 0, 0x14c, val)
#define	EMASK_RP_PEX_WR(pex, val)	nb_pci_putl(0, pex, 0, 0x150, val)

#define	PEX_FAT_FERR_RD(pex, ip)	nb_pci_getl(0, pex, 0, 0x154, ip)
#define	PEX_FAT_NERR_RD(pex, ip)	nb_pci_getl(0, pex, 0, 0x15c, ip)
#define	PEX_NF_FERR_RD(pex, ip)	nb_pci_getl(0, pex, 0, 0x158, ip)
#define	PEX_NF_NERR_RD(pex, ip)	nb_pci_getl(0, pex, 0, 0x160, ip)
#define	UNCERRSEV_RD(pex)	nb_pci_getl(0, pex, 0, 0x10c, 0)
#define	CORERRSTS_RD(pex)	nb_pci_getl(0, pex, 0, 0x110, 0)
#define	RPERRSTS_RD(pex)	nb_pci_getl(0, pex, 0, 0x130, 0)
#define	RPERRSID_RD(pex)	nb_pci_getl(0, pex, 0, 0x134, 0)
#define	AERRCAPCTRL_RD(pex)	nb_pci_getl(0, pex, 0, 0x118, 0)
#define	PEXDEVSTS_RD(pex)	nb_pci_getw(0, pex, 0, 0x76, 0)

#define	PEX_FAT_FERR_WR(pex, val) nb_pci_putl(0, pex, 0, 0x154, val)
#define	PEX_FAT_NERR_WR(pex, val) nb_pci_putl(0, pex, 0, 0x15c, val)
#define	PEX_NF_FERR_WR(pex, val)	nb_pci_putl(0, pex, 0, 0x158, val)
#define	PEX_NF_NERR_WR(pex, val)	nb_pci_putl(0, pex, 0, 0x160, val)
#define	CORERRSTS_WR(pex, val)	nb_pci_putl(0, pex, 0, 0x110, val)
#define	UNCERRSEV_WR(pex, val)	nb_pci_putl(0, pex, 0, 0x10c, val)
#define	RPERRSTS_WR(pex, val)	nb_pci_putl(0, pex, 0, 0x130, val)
#define	PEXDEVSTS_WR(pex, val)	nb_pci_putl(0, pex, 0, 0x76, val)

#define	PCISTS_RD(ip)		nb_pci_getw(0, 8, 0, 0x6, ip)
#define	PCIDEVSTS_RD()		nb_pci_getw(0, 8, 0, 0x76, 0)
#define	PCISTS_WR(val)		nb_pci_putw(0, 8, 0, 0x6, val)
#define	PCIDEVSTS_WR(val)	nb_pci_putw(0, 8, 0, 0x76, val)

#define	RANK_MASK	(nb_dimms_per_channel <= 4 ? 7 : 0xf)
#define	CAS_MASK	(nb_dimms_per_channel <= 4 ? 0xfff : 0x1fff)
#define	RAS_MASK	(nb_dimms_per_channel <= 4 ? 0x7fff : 0xffff)
#define	BANK_MASK	7

#define	DMIR_RANKS(dimms_per_channel, dmir, rank0, rank1, rank2, rank3) \
	if ((dimms_per_channel) == 4) { \
		rank0 = (dmir) & 3; \
		rank1 = ((dmir) >> 3) & 3; \
		rank2 = ((dmir) >> 6) & 3; \
		rank3 = ((dmir) >> 9) & 3; \
	} else { \
		rank0 = (dmir) & 0xf; \
		rank1 = ((dmir) >> 4) & 0xf; \
		rank2 = ((dmir) >> 8) & 0xf; \
		rank3 = ((dmir) >> 12) & 0xf; \
	}

#ifdef __cplusplus
}
#endif

#endif /* _NB5000_H */
