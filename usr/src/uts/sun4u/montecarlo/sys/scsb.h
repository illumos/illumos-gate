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
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MONTECARLO_SYS_SCSB_H
#define	_MONTECARLO_SYS_SCSB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL
#include <sys/inttypes.h>
#include <sys/i2c/misc/i2c_svc.h>
#include <sys/ksynch.h>
#endif	/* _KERNEL */

/*
 * CPU and AlarmCard slots
 * MonteCarlo:	CPU = SLOT1, AC = SLOT8
 * Tonga:	CPU = SLOT3, AC = SLOT1
 */
#define	SC_MC_CPU_SLOT			1
#define	SC_TG_CPU_SLOT			3
#define	SC_MC_AC_SLOT			8
#define	SC_TG_AC_SLOT			1
#define	SC_MC_CTC_SLOT			2

#define	SCSB_MC_ALARM_SLOT		SC_MC_AC_SLOT
#define	SCSB_TONGA_ALARM_SLOT		SC_TG_AC_SLOT

#define	SCTRL_PROM_P06			0x00
#define	SCTRL_PROM_P10			0x01
#define	SCTRL_PROM_P15			0x02
#define	SCTRL_PROM_P20			0x03

#define	SCSB_RESET_SLOT			1
#define	SCSB_UNRESET_SLOT		2
#define	SCSB_GET_SLOT_RESET_STATUS	3

#define	SCTRL_CFG_SLOT16		SCTRL_SYSCFG_5_READ-SCTRL_SYSCFG_BASE
#define	SCTRL_CFG_SLOT710		SCTRL_SYSCFG_6_READ-SCTRL_SYSCFG_BASE
#define	SCTRL_CFG_SLOTAC		SCTRL_SYSCFG_4_READ-SCTRL_SYSCFG_BASE

/*
 * SCSB operations between scsb and the hotswap controller module
 */
#define	SCSB_HSC_AC_BUSY		1
#define	SCSB_HSC_AC_CONFIGURED		2
#define	SCSB_HSC_AC_UNCONFIGURED	3
#define	SCSB_HSC_AC_UNCONFIGURE		4
#define	SCSB_HSC_AC_CONFIGURE		5
#define	SCSB_HSC_AC_SET_BUSY		6
#define	SCSB_HSC_AC_REMOVAL_ALERT	7
/*
 * SCSB_HSC_AC_GET_SLOT_INFO for hsc_ac_op()
 * to return hsc_slot_t pointer (for debugging)
 */
#define	SCSB_HSC_AC_GET_SLOT_INFO	11

/*
 * The register set starting address, and macro for translating
 * the index to 0 base.
 */
#define	SCSB_REG_ADDR_START		0xC0
#define	SCSB_REG_INDEX(raddr)		((raddr) % SCSB_REG_ADDR_START)

/*
 * ----------------------
 * P1.0
 * ----------------------
 * The following three register offset groups are defined for P1.0 where
 * FRUs might have three different bit offset values,
 * Group 1:	LEDs, Slot Reset, and BrdHlthy,
 * Group 2:	Config/Status registers
 * Group 3:	Interrupt Pointer/Mask registers
 */
#define	REG_GROUP1		0
#define	REG_GROUP2		1
#define	REG_GROUP3		2
#define	REG_GROUPS_NUM		3
#define	IS_GROUP1(rx)			(rx < SCTRL_SYSCFG_5)
#define	IS_GROUP3(rx)			(rx > SCTRL_SYSCFG_4)
#define	IS_GROUP2(rx)			(rx > (SCTRL_SYSCFG_5 - 1) && \
					(rx < (SCTRL_SYSCFG_4 + 1)))
#define	IS_SCB_P10			(scsb->scsb_state & \
						(SCSB_P06_PROM | SCSB_P10_PROM))
/*
 * ----------------------
 * P1.5
 * ----------------------
 * The table access macros use BASE register plus register offset to get the
 * correct register index or address.
 * The SCB FRU type has two register offsets, LED reg and INT reg offsets.
 * The one in fru_offsets[] is for the NOK, OK, and BLINK LED data.
 * To get the register offset for the INTSRC and INTMASK registers, the
 * following constant must be added to the table value returned by
 * FRU_REG_INDEX(SCTRL_EVENT_SCB, SCTRL_INTMSK_BASE), NOT SCTRL_INTMASK_BASE.
 * Given enough time, this too should be handled via macro access to tables.
 */
#define	SCB_INT_OFFSET	2

/*
 * ----------------------------------
 * P0.6, P1.0, P1.5, P2.0 DEFINITIONS
 * ----------------------------------
 */

#define	SCTRL_PROM_VERSION		0xCF	/* same Addr for P06 thru P20 */
#define	IS_SCB_P15			(scsb->scsb_state & \
						(SCSB_P15_PROM | SCSB_P20_PROM))

/*
 * SCB Register Indicies to scb_reg_index[] table
 */
#define	SCTRL_SYS_CMD_BASE		0
#define	SCTRL_SYS_CMD1			SCTRL_SYS_CMD_BASE
#define	SCTRL_SYS_CMD2			1
#define	SCTRL_LED_NOK_BASE		2
#define	SCTRL_LED_SLOT_16_NOK		SCTRL_LED_NOK_BASE
#define	SCTRL_LED_SLOT_712_NOK		3
#define	SCTRL_LED_DPP_NOK		4
#define	SCTRL_LED_FAN_NOK 		5
#define	SCTRL_LED_OK_BASE		6
#define	SCTRL_LED_SLOT_16_OK		SCTRL_LED_OK_BASE
#define	SCTRL_LED_SLOT_712_OK		7
#define	SCTRL_LED_DPP_OK		8
#define	SCTRL_LED_FAN_OK		9
#define	SCTRL_RESET_BASE		10
#define	SCTRL_RESET_SLOT_16		SCTRL_RESET_BASE
#define	SCTRL_RESET_SLOT_710A		11
#define	SCTRL_RESET_ALARM		11
#define	SCTRL_BLINK_OK_BASE		12
#define	SCTRL_BLINK_OK_1		SCTRL_BLINK_OK_BASE
#define	SCTRL_BLINK_OK_2		13
#define	SCTRL_BLINK_GR_3		14			/* 0xCE */
#define	SCTRL_SCBID_BASE		15
#define	SCTRL_BHLTHY_BASE		16
#define	SCTRL_BHLTHY_SLOT_16		SCTRL_BHLTHY_BASE
#define	SCTRL_BHLTHY_SLOT_710		17
#define	SCTRL_SYSCFG_BASE		18
#define	SCTRL_SYSCFG_5			SCTRL_SYSCFG_BASE
#define	SCTRL_SYSCFG_6			19
#define	SCTRL_SYSCFG_1			20
#define	SCTRL_SYSCFG_2			21
#define	SCTRL_SYSCFG_3			22
#define	SCTRL_SYSCFG_4			23
#define	SCTRL_INTSRC_BASE		24
#define	SCTRL_INTSRC_HLTHY_BASE		SCTRL_INTSRC_BASE
#define	SCTRL_INTSRC_1			SCTRL_INTSRC_BASE
#define	SCTRL_INTSRC_2			25
#define	SCTRL_INTSRC_3			26
#define	SCTRL_INTSRC_4			27
#define	SCTRL_INTSRC_5			28
#define	SCTRL_INTSRC_6			29
#define	SCTRL_INTSRC_SCB_P15		SCTRL_INTSRC_6
#define	SCTRL_INTMASK_BASE		30
#define	SCTRL_INTMASK_HLTHY_BASE	SCTRL_INTMASK_BASE
#define	SCTRL_INTMASK_1			SCTRL_INTMASK_BASE
#define	SCTRL_INTMASK_2			31
#define	SCTRL_INTMASK_3			32
#define	SCTRL_INTMASK_4			33
#define	SCTRL_INTMASK_5			34
#define	SCTRL_INTMASK_6			35

#define	SCTRL_INTPTR_BASE		SCTRL_INTSRC_3
#define	SCTRL_INTMSK_BASE		SCTRL_INTMASK_3
/*
 * The last two definitions are for register offset compatibility.
 * These will be used with FRU_REG_INDEX macros, for P1.0 and P1.5, so 1.5
 * register offsets in upper nibble of fru_offset[] tables will be consistent.
 * This happens because the HLTHY INTs and INT masks come before the slots and
 * FRUs.  That's what changes the register offsets.
 * The only EXCEPTION is the ALARM RESET register, which for P1.5 is not
 * BASE + 3 as in all other cases, but BASE + 1.  FRU_REG_INDEX(code,base) does
 * NOT work for ALARM RESET.  Use ALARM_RESET_REG_INDEX() instead.
 * FRU_REG_INDEX() works differently for P1.0, using offset groups to calculate
 * the index to the fru_offset[] table.
 */

/*
 * REGISTER BIT OFFSETS
 * For the bit definitions, the SCB register sets are divided into two tables,
 * 1. scb_1x_fru_offset[]	bit-offsets for all FRUs and
 *				Interrupt events
 * 2. scb_1x_sys_offset[]	for system command/control registers
 *				and any remaining bits, like MPID.
 *
 * This is a bit historic from P0.6,P1.0 days.
 * The fru_offset table is indexed using the SCTRL_EVENT_ codes defined in
 * mct_topology.h.  Almost all of these describe interrupt generated events.
 * Ths sys_offset table contains anything else, mostly the System Control
 * registers and some bit definitions form the config/status registers.
 */

/*
 * scb_1x_sys_offset[] table indicies
 *
 * SCB System Command/Control Registers from 1.0 and 1.5
 */
#define	SCTRL_SYS_PS1_OFF		0
#define	SCTRL_SYS_PS2_OFF		1
#define	SCTRL_SYS_PS_OFF_BASE		SCTRL_SYS_PS1_OFF
#define	SCTRL_SYS_PS1_ON		2
#define	SCTRL_SYS_PS2_ON		3
#define	SCTRL_SYS_PS_ON_BASE		SCTRL_SYS_PS1_ON
#define	SCTRL_SYS_SCB_CTL0		4
#define	SCTRL_SYS_SCB_CTL1		5
#define	SCTRL_SYS_SCB_CTL2		6
#define	SCTRL_SYS_SCB_CTL3		7
#define	SCTRL_SYS_PSM_INT_ENABLE	8
#define	SCTRL_SYS_SCB_INIT		9
#define	SCTRL_SYS_TEST_MODE		10
#define	SCTRL_SYS_SCBLED		11
#define	SCTRL_SYS_SPA0			12
#define	SCTRL_SYS_SPA1			13
#define	SCTRL_SYS_SPA2			14
#define	SCTRL_SYS_RSVD			15
/*
 * SCB Config/Status register leftovers
 */
#define	SCTRL_CFG_MPID0			16
#define	SCTRL_CFG_MPID1			17
#define	SCTRL_CFG_MPID2			18
#define	SCTRL_CFG_MPID3			19
#define	SCTRL_CFG_SCB_STAT0		20
#define	SCTRL_CFG_SCB_STAT2		21
/*
 * SCB Identity register offsets
 */
#define	SCTRL_SCBID0			22
#define	SCTRL_SCBID_SIZE		4
#define	SCTRL_SCB_TEST			23

/* numregs table order and indicies */
#define	SCTRL_SYS_CMD_NUM		0
#define	SCTRL_LED_NOK_NUM		1
#define	SCTRL_LED_OK_NUM		2
#define	SCTRL_LED_NUM			3
#define	SCTRL_RESET_NUM			4
#define	SCTRL_BLINK_NUM			5
#define	SCTRL_SCBID_NUM			6
#define	SCTRL_BHLTHY_NUM		7
#define	SCTRL_SYSCFG_NUM		8
#define	SCTRL_INTSRC_NUM		9
#define	SCTRL_INTMSK_NUM		10
#define	SCTRL_TOTAL_NUM			11


/*
 * Macro Definitions for register and bit offset values
 */
/* macros names for scb_numregs[] access */
#define	SCTRL_SYSCMD_NUMREGS	(scb_numregs[SCTRL_SYS_CMD_NUM])
#define	SCTRL_LED_NOK_NUMREGS	(scb_numregs[SCTRL_LED_NOK_NUM])
#define	SCTRL_LED_OK_NUMREGS	(scb_numregs[SCTRL_LED_OK_NUM])
#define	SCTRL_LED_NUMREGS	(scb_numregs[SCTRL_LED_NUM])
#define	SCTRL_RESET_NUMREGS	(scb_numregs[SCTRL_RESET_NUM])
#define	SCTRL_BLINK_NUMREGS	(scb_numregs[SCTRL_BLINK_NUM])
#define	SCTRL_SCBID_NUMREGS	(scb_numregs[SCTRL_SCBID_NUM])
#define	SCTRL_BHLTHY_NUMREGS	(scb_numregs[SCTRL_BHLTHY_NUM])
#define	SCTRL_CFG_NUMREGS	(scb_numregs[SCTRL_SYSCFG_NUM])
#define	SCTRL_INTR_NUMREGS	(scb_numregs[SCTRL_INTSRC_NUM])
#define	SCTRL_MASK_NUMREGS	(scb_numregs[SCTRL_INTMSK_NUM])
#define	SCTRL_TOTAL_NUMREGS	(scb_numregs[SCTRL_TOTAL_NUM])

/*
 * Maximum number of registers in a register group
 * Needed for above register groups array sizing
 */
#define	SCTRL_MAX_GROUP_NUMREGS		16

#define	SCSB_REG_ADDR(rx)		(scb_reg_index[rx])
#define	FRU_INDEX(code)			(event_to_index(code))
#define	FRU_OFFSET_BASE(rx)		(MCT_MAX_FRUS * (IS_SCB_P15 ? 0 : \
						(IS_GROUP1(rx) ? REG_GROUP1 : \
						(IS_GROUP3(rx) ? REG_GROUP3 : \
						REG_GROUP2))))
#define	FRU_OFFSET_VAL(code, rx)	(scb_fru_offset[FRU_OFFSET_BASE(rx) + \
							FRU_INDEX(code)])

#define	FRU_OFFSET(code, rx)		(FRU_OFFSET_VAL(code, rx) & 0xf)
#define	FRU_REG_INDEX(code, rx)		(((FRU_OFFSET_VAL(code, rx) >> 4) \
						& 0xf) + rx)
#define	FRU_REG_ADDR(code, rx)		(SCSB_REG_ADDR(FRU_REG_INDEX(code, rx)))
#define	SYS_OFFSET_VAL(idx)		(scb_sys_offset[idx])
#define	SYS_OFFSET(idx)			(SYS_OFFSET_VAL(idx) & 0xf)
#define	SYS_REG_INDEX(idx, rx)		(((SYS_OFFSET_VAL(idx) >> 4) \
						& 0xf) + rx)

#define	ALARM_RESET_REG_INDEX(code, rx)	((IS_SCB_P15 ? 1 : \
					((FRU_OFFSET_VAL(code, rx) >> 4) \
					& 0xf)) + rx)
#define	FRU_UNIT_TO_EVCODE(type, unit)	(type_to_code1[type] << (unit - 1))

/*LINTED table used in scsb.o and system utilities*/
static uchar_t	*scb_reg_index;
/*LINTED table used in scsb.o and system utilities*/
static uchar_t	*scb_numregs;
/*LINTED table used in scsb.o and system utilities*/
static uchar_t	*scb_fru_offset;
/*LINTED table used in scsb.o and system utilities*/
static uchar_t	*scb_sys_offset;

/*
 * --------------------
 * Common TABLES
 * --------------------
 */

/*
 * FRU type to unit 1 event_code, see FRU_UNIT_TO_EVCODE() macro above.
 * Table order is dependent on scsb_utype_t definition in mct_topology.h
 */
/*LINTED table used in scsb.o and system utilities*/
static uint32_t type_to_code1[] = {
	SCTRL_EVENT_SLOT1,
	SCTRL_EVENT_PDU1,
	SCTRL_EVENT_PS1,
	SCTRL_EVENT_DISK1,
	SCTRL_EVENT_FAN1,
	SCTRL_EVENT_ALARM,
	SCTRL_EVENT_SCB,
	SCTRL_EVENT_SSB,
	SCTRL_EVENT_CFTM,
	SCTRL_EVENT_CRTM,
	SCTRL_EVENT_PRTM
};

/*
 * --------------------
 * P0.6 and P1.0 TABLES
 * --------------------
 */

/*
 * MonteCarlo: Programming Inteface Specifications Version 0.9
 * 10/27/99
 * NOTE: P0.6 FANs and PDUs were different
 */
/*LINTED table used in scsb.o and system utilities*/
static uchar_t scb_10_reg_index[] = {
	0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,		/* 00 - 07 */
	0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,		/* 08 - 15 */
	0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,		/* 16 - 23 */
	0xD8, 0xD9, 0xDA, 0xDB, 0x00, 0x00, 0xDC, 0x00,		/* 24 - 31 */
	0xDC, 0xDD, 0xDE, 0xDF, 0xD8, 0xDC, 0x00, 0x00,		/* 32 - 39 */
};

/*LINTED table used in scsb.o and system utilities*/
static uchar_t scb_10_numregs[] = {
	2, 4, 4, 8, 2, 2, 1, 2, 6, 4, 4, 32
};


/*
 * MCT_MAX_FRUS * REG_GROUPS_NUM
 *
 * FRU order:
 *	 0 -  9:	Slots 1 - 10
 *	10 - 11:	PDU 1 - 2
 *	12 - 13:	PS 1 - 2
 *	14 - 16:	Disk 1 - 3
 *	17 - 19:	Fan 1 - 3
 *	20:		Alarm Card
 *	21:		SCB
 *	22:		SSB
 *	23:		CRTM
 *	24:		CFTM
 *	25:		PRTM
 *	26:		PWRDWN
 *	27:		REPLACE
 *	28:		ALARM_INT
 *	29 - 31:	Unused
 *
 * A register base group offset is added to the register base value to
 * find the index into the reg_index table.
 * Example: LED_NOK_BASE + '1' = register for slots 7-10 NOK LEDs
 * This offset is encoded in the upper nibble in the following table
 * of register offsets per FRU/EVENT.
 * The register base group definitions are:
 *	base group		offset group
 *	----------------------	------------
 *	SCTRL_LED_NOK_BASE	G1
 *	SCTRL_LED_OK_BASE	G1
 *	SCTRL_RESET_BASE	G1
 *	SCTRL_BLINK_OK_BASE	G1
 *	SCTRL_BHLTHY_BASE	G1
 *	SCTRL_SYSCFG_BASE	G2
 *	SCTRL_INTSRC_BASE	G3
 *	SCTRL_INTMASK_BASE	G3
 *	SCTRL_SYS_CMD_BASE	G4
 *
 * See FRU_OFFSET() macro
 */
/*LINTED table used in scsb.o and system utilities*/
static uchar_t	scb_10_fru_offset[] = {
	/* Register Group 1 */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,	/* SLOT    1-6	*/
	0x10, 0x11, 0x12, 0x13,			/* SLOT    7-10	*/
	0x35, 0x15, 0x21, 0x22,			/* PDU/PS  1-2	*/
	0x23, 0x24, 0x25,			/* Disks   1-3	*/
	0x33, 0x34, 0x35,			/* Fans    1-3	*/
	0xFF, 0x20, 0xFF,		/* Alarm Card, SCB, SSB	*/
	0xFF, 0xFF, 0xFF,		/* CRTM, CFTM, PRTM	*/
	0xFF, 0xFF, 0xFF,		/* PWRDWN, SCBRR, ACINT */
	0xFF, 0xFF, 0xFF,		/* Unused		*/
	/* Register Group 2 */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,	/* SLOT    1-6	*/
	0x10, 0x11, 0x12, 0x13,			/* SLOT    7-10	*/
	0x25, 0x27, 0x30, 0x31,			/* PDU/PS  1-2	*/
	0x40, 0x41, 0x42,			/* Disks   1-3	*/
	0x32, 0x33, 0x34,			/* Fans    1-3	*/
	0x50, 0xFF, 0x35,		/* Alarm Card, SCB, SSB	*/
	0x43, 0x44, 0x45,		/* CRTM, CFTM, PRTM	*/
	0xFF, 0xFF, 0xFF,		/* PWRDWN, SCBRR, ACINT */
	0x24, 0x26, 0x20,		/* STAT0, STAT1, MPID0	*/
	/* Register Group 3 */
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36,	/* SLOT    1-6	*/
	0x37, 0x26, 0x27, 0x16,			/* SLOT    7-10	*/
	0xFF, 0xFF, 0x10, 0x11,			/* PDU/PS  1-2	*/
	0x20, 0x21, 0x22,			/* Disks   1-3	*/
	0x12, 0x13, 0x14,			/* Fans    1-3	*/
	0x30, 0x04, 0x15,		/* Alarm Card, SCB, SSB	*/
	0x23, 0x24, 0x25,		/* CRTM, CFTM, PRTM	*/
	0x00, 0x02, 0x03,		/* PWRDWN, SCBRR, ACINT */
	0xFF, 0xFF, 0xFF,		/* Unused		*/
};

/*LINTED table used in scsb.o and system utilities*/
static uchar_t	scb_10_sys_offset[] = {
	0x00, 0x01, 0x06, 0x07, 0x10, 0x11, 0x12, 0x13,
	0x15, 0x16, 0xFF, 0x02, 0x03, 0x04, 0x05, 0x14,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x26, 0x00, 0x07,
};

/*LINTED table used in scsb.o and system utilities*/
static uchar_t	scb_10_int_masks[] = {
	0x11, 0x2F, 0x3F, 0xFF, 0x00, 0x00,
};


/*
 * --------------------
 * P1.5 and P2.0 TABLES
 * --------------------
 */

/*
 * MonteCarlo: Programming Inteface Specifications
 * Chapter 12 from the MonteCarlo System Specification
 * 02/08/00: Chapter update from Carl Meert
 */
/*LINTED table used in scsb.o and system utilities*/
static uchar_t scb_15_reg_index[] = {
	0xE0, 0xE1, 0xC0, 0xC1, 0xC2, 0xC2, 0xC3, 0xC4,		/* 00 - 07 */
	0xC5, 0xC5, 0xE2, 0xE3, 0xC6, 0xC7, 0xC8, 0xCF,		/* 08 - 15 */
	0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0x00, 0x00,		/* 16 - 23 */
	0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,		/* 24 - 31 */
	0xD8, 0xD9, 0xDA, 0xDB, 0xD2, 0xD8, 0x00, 0x00,		/* 32 - 39 */
};

/*LINTED table used in scsb.o and system utilities*/
static uchar_t scb_15_numregs[] = {
	2, 3, 3, 6, 2, 3, 1, 2, 4, 6, 6, 48
};

/*LINTED table used in scsb.o and system utilities*/
static uchar_t	scb_15_fru_offset[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,	/* SLOT    1-6	*/
	0x06, 0x07, 0x16, 0x17,			/* SLOT    7-10	*/
	0x11, 0x13, 0x26, 0x27,			/* PDU/PS  1-2	*/
	0x23, 0x24, 0x25,			/* Disks   1-3	*/
	0x20, 0x21, 0xFF,			/* Fans    1-3	*/
	0x30, 0x15, 0x33,		/* Alarm Card, SCB, SSB	*/
	0x31, 0x14, 0x32,		/* CRTM, CFTM, PRTM	*/
	0x34, 0xFF, 0x36,		/* PWRDWN, SCBRR, ACINT */
	0xFF, 0xFF, 0xFF,		/* Unused		*/
};

/*LINTED table used in scsb.o and system utilities*/
static uchar_t	scb_15_sys_offset[] = {
	0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0x34, 0x35, 0x36, 0x37, 0x10, 0x12, 0x00, 0x07
};

/*LINTED table used in scsb.o and system utilities*/
static uchar_t	scb_15_int_masks[] = {
	0xFF, 0x00, 0xFF, 0x1A, 0xFB, 0x7F,
};

#define	SCSB_NO_OF_BOARDS  1

/*
 * scsb_state values
 * outside _KERNEL for smctrl test utility
 */
#define	SCSB_DOWN			0x0000	/* never really used */
#define	SCSB_UP				0x0001
#define	SCSB_OPEN			0x0002
#define	SCSB_EXCL			0x0004
#define	SCSB_APP_SLOTLED_CTRL		0x0008
#define	SCSB_KS_UPDATE			0x0010
#define	SCSB_FROZEN			0x0020
#define	SCSB_DEBUG_MODE			0x0040
#define	SCSB_DIAGS_MODE			0x0080
#define	SCSB_UNUSED_08			0x0100
#define	SCSB_PSM_INT_ENABLED		0x0200
#define	SCSB_UMUTEX			0x0400
#define	SCSB_CONDVAR			0x0800
#define	SCSB_SCB_PRESENT		0x1000
#define	SCSB_SSB_PRESENT		0x2000
#define	SCSB_UNUSED_14			0x4000
#define	SCSB_UNUSED_15			0x8000
#define	SCSB_MINOR_NODE			0x00010000
#define	SCSB_PROP_CREATE		0x00020000
#define	SCSB_IMUTEX			0x00040000
#define	SCSB_I2C_PHANDLE		0x00080000
#define	SCSB_I2C_TRANSFER		0x00100000
#define	SCSB_TOPOLOGY			0x00200000
#define	SCSB_KSTATS			0x00400000
#define	SCSB_IS_TONGA			0x00800000
#define	SCSB_P10_PROM			0x01000000
#define	SCSB_P15_PROM			0x02000000
#define	SCSB_P20_PROM			0x04000000
#define	SCSB_P2X_PROM			0x08000000
#define	SCSB_P06_PROM			0x10000000
#define	SCSB_P06_INTR_ON		0x20000000
#define	SCSB_P06_NOINT_KLUGE		0x40000000
#define	SCSB_IN_INTR			0x80000000
#define	SCSB_HSC_INIT			0x0001
#define	SCSB_ENUM_ENABLED		0x0002
#define	SCSB_ALARM_CARD_PRES		0x0004
#define	SCSB_ALARM_CARD_IN_USE		0x0008
#define	SCSB_AC_SLOT_INTR_DONE		0x0010
#define	SCSB_HSC_CTC_PRES		0x0020
#define	SCSB_HSC_UNUSED_06		0x0040
#define	SCSB_HSC_UNUSED_07		0x0080
#define	SCSB_HSC_UNUSED_08		0x0100
#define	SCSB_HSC_UNUSED_09		0x0200
#define	SCSB_HSC_UNUSED_10		0x0400
#define	SCSB_HSC_UNUSED_11		0x0800
#define	SCSB_HSC_UNUSED_12		0x1000
#define	SCSB_HSC_UNUSED_13		0x2000
#define	SCSB_HSC_UNUSED_14		0x4000
#define	SCSB_HSC_UNUSED_15		0x8000

#ifdef	_KERNEL

/*
 * The System Controller Board uses the Xilinx to control the I2C bus.
 * The address should really go to scsb.conf file.
 * The I2C address of the System Controller Board
 */
#define	SCSB_I2C_ADDR		0x80
#define	SCSB_I2C_ADDR_MASK 	0xFF

#define	SCSB_DEVICE_NAME	"scsb"
#define	SCSB_INTR_PIL	4

/*
 * definitions for Interrupt Event Code handling
 */
#define	EVC_FIFO_SIZE	8
#define	EVC_PROCS_MAX	16
/*
 * return values for check_event_procs()
 */
#define	EVC_NO_EVENT_CODE	1
#define	EVC_NO_CURR_PROC	2
#define	EVC_NEW_EVENT_CODE	3
#define	EVC_OR_EVENT_CODE	4
#define	EVC_FAILURE		5
/*
 * scsb_queue_ops() definitions
 *   Operations:
 */
#define	QPROCSOFF		1
#define	QPUT_INT32		2
#define	QFIRST_AVAILABLE	3
#define	QFIRST_OPEN		4
#define	QFIND_QUEUE		5
/*
 *   Return values:
 *   0 - 15 are valid clone numbers used as index to clone_devs[]
 *   and returned for some operations instead of QOP_OK.
 */
#define	QOP_OK		16
#define	QOP_FAILED	-1

/*
 * minor_t definitions
 *   bits 2-0      SCB instance 0-7
 *   bit    3      Clone device for sm_open()
 *   bits 7-4      Cloned device numbers for a total of 15: 0x1# - 0xf#
 *		   Must start with '1'  to avoid conflict with:
 *			0x00 non-clone device node for instance 0
 *			0x08 the clone device node for instance 0
 * the new minor_t for the clone is all of the above.
 */
#define	SCSB_INSTANCE_MASK	0x07
#define	SCSB_CLONE		0x08
#define	SCSB_CLONES_MASK	0xf0
#define	SCSB_CLONES_SHIFT	4
#define	SCSB_CLONES_FIRST	1
#define	SCSB_CLONES_MAX		16
#define	SCSB_GET_CLONE(minor)	((minor&SCSB_CLONES_MASK)>>SCSB_CLONES_SHIFT)
#define	SCSB_GET_INSTANCE(minor) \
				(minor&SCSB_INSTANCE_MASK)
#define	SCSB_MAKE_MINOR(inst, clnum) \
				(inst|(clnum<<SCSB_CLONES_SHIFT)|SCSB_CLONE)

typedef struct clone_dev {
	queue_t		*cl_rq;
	minor_t		cl_minor;
	uint32_t	cl_flags;
} clone_dev_t;

typedef struct {
	uint32_t	scsb_instance;
	uint32_t	scsb_state;
	uint32_t	scsb_hsc_state;
	int		ac_slotnum;	/* Alarm Card Slot Number */
	kmutex_t	scsb_mutex;
	kcondvar_t	scsb_cv;
	uint32_t	scsb_opens;
	dev_info_t	*scsb_dev;
	i2c_client_hdl_t scsb_phandle;	/* i2c private handle from i2c nexus */
	mblk_t		*scsb_mp;	/* reserved for interrupt processing */
	i2c_transfer_t	*scsb_i2ctp;	/* pointer to read/write structure */
	uchar_t		scsb_data_reg[SCSB_DATA_REGISTERS];
	int		scsb_i2c_addr;	/* i2c addr. */
	queue_t		*scsb_rq;	/* read q for scsb_instance */
	timeout_id_t	scsb_btid;	/* qbufcall, or qtimeout id */
	kmutex_t	scsb_imutex;
	ddi_iblock_cookie_t scsb_iblock;
	kstat_t		*ks_leddata;
	kstat_t		*ks_state;
	kstat_t		*ks_topology;
	kstat_t		*ks_evcreg;
	uint32_t	scsb_i2c_errcnt;
	boolean_t	scsb_err_flag;	/* latch err until kstat read */
	boolean_t	scsb_kstat_flag;	/* do i2c trans for kstat */
	uint32_t	scsb_clopens;
	clone_dev_t	clone_devs[SCSB_CLONES_MAX];
} scsb_state_t;

int	scsb_led_get(scsb_state_t *, scsb_uinfo_t *, scsb_led_t led_type);
int	scsb_led_set(scsb_state_t *, scsb_uinfo_t *, scsb_led_t led_type);
int	scsb_reset_unit(scsb_state_t *, scsb_uinfo_t *);
int	scsb_bhealthy_slot(scsb_state_t *, scsb_uinfo_t *);
int	scsb_slot_occupancy(scsb_state_t *, scsb_uinfo_t *);

#if defined(DEBUG)
extern void prom_printf(const char *, ...);
void	scsb_debug_prnt(char *, uintptr_t, uintptr_t,
	uintptr_t, uintptr_t, uintptr_t);

#define	DEBUG0(fmt)\
	scsb_debug_prnt(fmt, 0, 0, 0, 0, 0);
#define	DEBUG1(fmt, a1)\
	scsb_debug_prnt(fmt, (uintptr_t)(a1), 0, 0, 0, 0);
#define	DEBUG2(fmt, a1, a2)\
	scsb_debug_prnt(fmt, (uintptr_t)(a1), (uintptr_t)(a2), 0, 0, 0);
#define	DEBUG3(fmt, a1, a2, a3)\
	scsb_debug_prnt(fmt, (uintptr_t)(a1), (uintptr_t)(a2),\
		(uintptr_t)(a3), 0, 0);
#define	DEBUG4(fmt, a1, a2, a3, a4)\
	scsb_debug_prnt(fmt, (uintptr_t)(a1), (uintptr_t)(a2),\
		(uintptr_t)(a3), (uintptr_t)(a4), 0);
#else
#define	DEBUG0(fmt)
#define	DEBUG1(fmt, a1)
#define	DEBUG2(fmt, a1, a2)
#define	DEBUG3(fmt, a1, a2, a3)
#define	DEBUG4(fmt, a1, a2, a3, a4)
#endif


#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _MONTECARLO_SYS_SCSB_H */
