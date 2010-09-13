/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1996-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_STARFIRE_H
#define	_STARFIRE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* I/O space definitions */
#define	STARFIRE_IO_BASE 0x10000000000ULL

/* UPA Port Space (UPS) definitions */
#define	STARFIRE_UPS_MID_SHIFT 33	/* MID is 7 bits */
#define	STARFIRE_UPS_BRD_SHIFT 36
#define	STARFIRE_UPS_BUS_SHIFT 6

/* Starfire Interconnect Space (IS) definitions */
#define	STARFIRE_IS_MC_BASE	0x10e80000000ULL /* MC Register Space */


/* Port Specific Interconnect Space (PSI) */
#define	STARFIRE_PSI_BASE \
		0x100f8000000ULL	/* put mid in [39:33] */
#define	STARFIRE_PSI_PCREG_OFF \
		0x4000000ULL		/* PSI offset for PC regs */
#define	STARFIRE_BRD_TO_PSI(board) \
		(STARFIRE_PSI_BASE | \
			(((uint64_t)board) << STARFIRE_UPS_BRD_SHIFT))


/* Starfire BootBus Space (BS) definitions */
#define	STARFIRE_PSI_BS_BASE \
		STARFIRE_PSI_BASE	/* BS at start of PSI Space */

#define	STARFIRE_UPAID2PSI_BS(upaid) \
		(STARFIRE_PSI_BS_BASE | \
		((u_longlong_t)STARFIRE_UPAID2HWMID(upaid) << \
			STARFIRE_UPS_MID_SHIFT))

#define	STARFIRE_DEV2UPAID(b, p, i) \
		((((i) & 0x1) << 6) | \
		(((b) & 0xf) << 2) | \
		((p) & 0x3))

/* Starfire Port Controller Register offsets */
#define	STARFIRE_PC_CONF		0x000000UL /* Configuration Reg */
#define	STARFIRE_PC_COMP_ID		0x000010UL /* Component ID Reg */
#define	STARFIRE_PC_BUS_CONF		0x000020UL /* Bus Configuration Reg */
#define	STARFIRE_PC_TO_HOLD_CONF	0x000030UL /* Timeout/Hold Config Reg */
#define	STARFIRE_PC_CIC_WRITE_DATA	0x000040UL /* CIC Write Data Reg */
#define	STARFIRE_PC_FORCE_PARITY_ERR	0x000050UL /* Force Parity Err Reg */
#define	STARFIRE_PC_ERR_0_MASK		0x000060UL /* Err 0 Mask Reg */
#define	STARFIRE_PC_ERR_1_MASK		0x000070UL /* Err 1 Mask Reg */
#define	STARFIRE_PC_ERR_0		0x000080UL /* Err 0 Reg */
#define	STARFIRE_PC_ERR_1		0x000090UL /* Err 1 Reg */
#define	STARFIRE_PC_ERR_DATA_SRC	0x0000a0UL /* Err Data Src Reg */
#define	STARFIRE_PC_ERR_DATA_LOW	0x0000b0UL /* Err Data Lower Reg */
#define	STARFIRE_PC_ERR_DATA_HI		0x0000c0UL /* Err Data Upper Reg */
#define	STARFIRE_PC_PORT_ID		0x0000d0UL
#define	STARFIRE_PC_PERF_COUNT_0	0x0000e0UL
#define	STARFIRE_PC_PERF_COUNT_1	0x0000f0UL
#define	STARFIRE_PC_PERF_COUNT_CNTRL	0x000100UL
#define	STARFIRE_PC_BLOCK		0x0001c0UL /* 512 Byte scr area */
#define	STARFIRE_PC_INT_MAP		0x000200UL /* 32 regs 00.0200-00.03f0 */
#define	STARFIRE_PC_MADR		0x000400UL /* 16 regs 00.0400-00.04f0 */

/* Starfire PC definitions/macros */
#define	STARFIRE_PC_MADR_BOARD_SHIFT	4
#define	STARFIRE_PC_MADR_ADDR(bb, rb, p) \
		(STARFIRE_BRD_TO_PSI(bb) | \
		((uint64_t)(p) << STARFIRE_UPS_MID_SHIFT) | \
		((uint64_t)(rb) << STARFIRE_PC_MADR_BOARD_SHIFT) | \
		STARFIRE_PSI_PCREG_OFF | \
		STARFIRE_PC_MADR)

/* Starfire BB (BootBus) definitions/macros */
#define	STARFIRE_BB_SYSRESET_CNTRL	0x800000ULL
#define	STARFIRE_BB_PAUSE_FLUSH		0x800016ULL

#define	STARFIRE_BB_PC_PAUSE(i)		((uchar_t)(1 << (i)))
#define	STARFIRE_BB_PC_FLUSH(i)		((uchar_t)(1 << ((i)+2)))
#define	STARFIRE_BB_PC_IDLE(i)		((uchar_t)(1 << ((i)+4)))

#define	STARFIRE_BB_SYSRESET(i)		((uchar_t)(1 << (i)))

#define	STARFIRE_BB_PC_ADDR(bb, p, io) \
		(STARFIRE_UPAID2PSI_BS(STARFIRE_DEV2UPAID((bb), (p), (io))) | \
		STARFIRE_BB_PAUSE_FLUSH)
#define	STARFIRE_BB_RESET_ADDR(bb, p) \
		(STARFIRE_UPAID2PSI_BS(STARFIRE_DEV2UPAID((bb), (p), 0)) | \
		STARFIRE_BB_SYSRESET_CNTRL)

/* Starfire Memory Controller Register offsets */
#define	STARFIRE_MC_ASR			0x000400U	/* Addr Select Reg */
#define	STARFIRE_MC_DIMMTYPE		0x00c800U	/* DIMM Type Code Reg */
#define	STARFIRE_MC_IDLE		0x00cc00U	/* Idle MC Reg */

/* Starfire MC definitions/macros */
#define	STARFIRE_MC_MEM_PRESENT_MASK	0x80000000U
#define	STARFIRE_MC_MEM_BASEADDR_MASK	0x7fff0000U
#define	STARFIRE_MC_IDLE_MASK		0x00008000U
#define	STARFIRE_MC_MASK_MASK		0x00007f00U
#define	STARFIRE_MC_DIMMSIZE_MASK	0x0000001fU
#define	STARFIRE_MC_INTERLEAVE_MASK	0x00000001U
#define	STARFIRE_MC_MASK_SHIFT		18
#define	STARFIRE_MC_BASE_SHIFT		10
#define	STARFIRE_MC_ADDR_HIBITS		0x1fe00000000ULL
#define	STARFIRE_MC_ASR_ADDR(reg)	((reg) | (uint64_t)STARFIRE_MC_ASR)
#define	STARFIRE_MC_IDLE_ADDR(reg)	((reg) | (uint64_t)STARFIRE_MC_IDLE)
#define	STARFIRE_MC_DIMMTYPE_ADDR(reg)	((reg) | (uint64_t)STARFIRE_MC_DIMMTYPE)
#define	STARFIRE_MC_ASR_ADDR_BOARD(b) \
		(((uint64_t)(b) << STARFIRE_UPS_BRD_SHIFT) | \
		STARFIRE_IS_MC_BASE | \
		(uint64_t)STARFIRE_MC_ASR)

/*
 * Memory boards on Starfire are aligned on 8GB
 * boundaries, i.e. the physical address space
 * is not physically contiguous.
 */
#define	STARFIRE_MC_MEMBOARD_SHIFT	33
#define	STARFIRE_MC_MEMBOARD_ALIGNMENT	\
		(UINT64_C(1) << STARFIRE_MC_MEMBOARD_SHIFT)

/*
 * Starfire has a special regspec for the "reg" property of the
 * mem-unit node since this node is homegrown.
 */
struct sf_memunit_regspec {
	uint_t	regspec_addr_hi;
	uint_t	regspec_addr_lo;
	uint_t	regspec_size_hi;
	uint_t	regspec_size_lo;
};

/*
 * Conversion macros
 */

/*
 * Starfire hardware version of the upaid (commonly known as
 * HWMID) is different from the software version (also known as upaid).
 *  HW version BBBBIPp   == SW version IBBBBPp
 */
#define	STARFIRE_UPAID2HWMID(upaid) (((upaid & 0x3C) << 1) | \
				((upaid & 0x40) >> 4) | (upaid & 0x3))


/* Xfire UPA ID to UPA Port Specific Space */
#define	STARFIRE_UPAID2UPS(upaid) \
		(((u_longlong_t)STARFIRE_UPAID2HWMID(upaid) << \
				STARFIRE_UPS_MID_SHIFT) | STARFIRE_IO_BASE)

/*
 * Macro to convert our 7 bits HW MID to 7 bits SW MID
 * That is "BBBBIPp" to "IBBBBPp".
 */
#define	STARFIRE_HWMID2SWMID(mid) ((mid & 0x3) | ((mid & 0x78) >> 1) | \
					((mid & 0x4) << 4))

/*
 * Macro to convert our 7 bits UPAid to Sun's 5 bit HW Interrupt
 * group number required in some hardware registers (sysios).
 * That is "IBBBBPp" to "BBBBp", where "BBBB" is the board number,
 * "IP" is the PC id and "p" is the port number.
 */
#define	STARFIRE_UPAID2HWIGN(upaid) \
		(((upaid & 0x3C) >> 1) | (upaid & 0x1))

/*
 * Macro to convert our UPAid to a 7 bit Starfire version of the
 * interrupt group number. This so-called IGN is part of
 * the interrupt vector number read by the CPU serving this interrupt.
 * Thanks to the warp minds of our hardware guys, it is in this
 * convoluted weird format. Note that the interrupt vector number is
 * then used to index into the interrupt dispatch table to get its
 * interrupt handler.
 * Convert "IBBBBPp" to "XPBBBBp" where "BBBB" is the 4bit board #,
 * "IP" is the 2 bit PC id, "p" is the port # and "X" is ~I.
 */
#define	STARFIRE_UPAID2IGN(upaid)  (STARFIRE_UPAID2HWIGN(upaid) | \
			((upaid & 0x2) << 4) |  \
			((upaid & 0x40) ^ 0x40))

/*
 * Starfire platform specific routines currently only defined
 * in starfire.c and referenced by DR.
 */
extern int	plat_max_boards();
extern int	plat_max_cpu_units_per_board();
extern int	plat_max_mem_units_per_board();
extern int	plat_max_io_units_per_board();

/*
 * Starfire platform specific interrupt translation routines
 */
extern void pc_ittrans_init(int, caddr_t *);
extern void pc_ittrans_uninit(caddr_t);
extern int pc_translate_tgtid(caddr_t, int, volatile uint64_t *);
extern void pc_ittrans_cleanup(caddr_t, volatile uint64_t *);

/*
 * Maximum number of system boards supported in a Starfire.
 */
#define	STARFIRE_MAX_BOARDS	16

/*
 * We reserve some "fake" DMV values for Starfire IDN.  These are treated
 * as hardware interrupt numbers, but they don't correspond to an actual UPA
 * port; they can thus be allocated as "well-known" numbers for IDN purposes.
 */
#define	STARFIRE_DMV_EXTRA	4
#define	STARFIRE_DMV_HWINT	(MAX_UPA+STARFIRE_DMV_EXTRA)
#define	STARFIRE_DMV_IDN_BASE	(MAX_UPA)


#ifdef	__cplusplus
}
#endif

#endif	/* _STARFIRE_H */
