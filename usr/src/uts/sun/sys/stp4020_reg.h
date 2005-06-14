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
 * Copyright (c) 1995-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _STP4020_REG_H
#define	_STP4020_REG_H

#pragma ident	"%W%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * this is the header file that describes the registers for the STP4020,
 *	a PCMCIA bus controller that supports two Type-3 PCMCIA cards
 */

/*
 * define some general constants that will probably never change
 */
#define	DRSOCKETS	2	/* number of sockets per STP4020 */
#define	DRWINDOWS	3	/* number of windows per socket */
#define	DRT_NUMWINDOWS	(DRSOCKETS*DRWINDOWS) /* total number of windows */

/*
 * PCMCIA ASIC Address Map
 *	define as constants for convenience
 */
#define	DRMAP_PROM		0 /* the Forth PROM */
#define	DRMAP_CARD0_WIN0	1 /* PC Card 0, Window 0 */
#define	DRMAP_CARD0_WIN1	2 /* PC Card 0, Window 1 */
#define	DRMAP_CARD0_WIN2	3 /* PC Card 0, Window 2 */
#define	DRMAP_ASIC_CSRS		4 /* ASIC Control Status Registers */
#define	DRMAP_CARD1_WIN0	5 /* PC Card 1, Window 0 */
#define	DRMAP_CARD1_WIN1	6 /* PC Card 1, Window 1 */
#define	DRMAP_CARD1_WIN2	7 /* PC Card 1, Window 2 */

/*
 * Socket interface control register definitions
 *
 * Each PCMCIA socket has two interface control registers and two inteface
 *	status registers associated with it.
 *
 * The interface control registers are used to specify the various interrupt
 *	enables, reset the PC card, perform various power management
 *	fucntions on the PC card, and control a few miscellaneous functions
 *	of the socket.
 *
 * The interface status registers are used to report the current status of
 *	various interrupt and status signals on the PC card and socket, as
 *	well as to clear pending interrupts by writing to the status bit
 *	that is set and indicating an interrupt.  Note that some signals
 *	in interface status register 0 change meaning depending on whether
 *	the socket is configured for an interface type of memory-only or
 *	memory and I/O.
 */

/*
 * bit definitions for socket interface control register 0
 *	note that bits 0x00020, 0x04000 and 0x08000 are reserved
 */
#define	DRCTL_PROMEN	0x02000	/* FCode PROM enable */

/*
 * card status change interrupt level control; we can route a status
 *	change interrupt to one of two interrupt levels on the SBus
 */
#define	DRCTL_SCILVL	0x01000	/* card status change interrupt level (SBus) */
#define	DRCTL_SCILVL_SB0	0x00000	/* interrupt on *SB_INT[0] */
#define	DRCTL_SCILVL_SB1	0x01000	/* interrupt on *SB_INT[1] */

#define	DRCTL_CDIE	0x00800	/* card detect interrupt enable */
#define	DRCTL_BVD2IE	0x00400	/* battery voltage detect 2 interrupt enable */
#define	DRCTL_BVD1IE	0x00200	/* battery voltage detect 1 interrupt enable */
#define	DRCTL_RDYIE	0x00100	/* ready/busy interrupt enable */
#define	DRCTL_WPIE	0x00080	/* write protect interrupt enable */
#define	DRCTL_CTOIE	0x00040	/* PC card timeout interrupt enable */
#define	DRCTL_IOIE	0x00010	/* I/O (*IRQ) interrupt enable */

#define	DRT_CHANGE_DEFAULT (DRCTL_CDIE|DRCTL_SCILVL_SB1)
#define	DRT_SBM_DEFAULT	   (SBM_CD)
#define	DRT_CHANGE_MASK		(DRCTL_CDIE|DRCTL_BVD2IE|DRCTL_BVD1IE|\
				DRCTL_RDYIE|DRCTL_WPIE|DRCTL_CTOIE)

/*
 * I/O (*IRQ) interrupt level control; we can route a PC card I/O interrupt
 *	to one of two interrupt levels on the SBus
 */
#define	DRCTL_IOILVL	0x00008	/* I/O (*IRQ) interrupt level (SBus) */
#define	DRCTL_IOILVL_SB0	0x00000	/* interrupt on *SB_INT[0] */
#define	DRCTL_IOILVL_SB1	0x00008	/* interrupt on *SB_INT[1] */

#define	DRCTL_SPKREN	0x00004	/* *SPKR_OUT enable */
#define	DRCTL_RESET	0x00002	/* PC card reset */
#define	DRCTL_IFTYPE	0x00001	/* PC card interface type */
#define	DRCTL_IFTYPE_MEM	0x00000	/* MEMORY only */
#define	DRCTL_IFTYPE_IO		0x00001	/* MEMORY and I/O */

/*
 * bit definitions for socket interface control register 1
 *	note that bit 0x00080 is reserved
 */
#define	DRCTL_LPBKEN	0x08000	/* PC card data loopback enable */
#define	DRCTL_CD1DB	0x04000	/* card detect 1 diagnostic bit */
#define	DRCTL_BVD2DB	0x02000	/* battery voltage detect 2 diagnostic bit */
#define	DRCTL_BVD1DB	0x01000	/* battery voltage detect 1 diagnostic bit */
#define	DRCTL_RDYDB	0x00800	/* ready/busy diagnostic bit */
#define	DRCTL_WPDB	0x00400	/* write protect diagnostic bit */
#define	DRCTL_WAITDB	0x00200	/* *WAIT diagnostic bit */
#define	DRCTL_DIAGEN	0x00100	/* diagnostic enable bit */
#define	DRCTL_APWREN	0x00040	/* PC card auto power switch enable */

/*
 * the Vpp controls are two-bit fields which specify which voltage
 *	should be switched onto Vpp for this socket
 * both of the "no connect" states are equal
 */
#define	DRCTL_VPP2EN	0x00030	/* Vpp2 power enable */
#define	DRCTL_VPP2_OFF	0x00000	/* no connect */
#define	DRCTL_VPP2_VCC	0x00010	/* Vcc switched onto Vpp2 */
#define	DRCTL_VPP2_VPP	0x00020	/* Vpp switched onto Vpp2 */
#define	DRCTL_VPP2_ZIP	0x00030	/* no connect */

#define	DRCTL_VPP1EN	0x0000c	/* Vpp1 power enable */
#define	DRCTL_VPP1_OFF	0x00000	/* no connect */
#define	DRCTL_VPP1_VCC	0x00004	/* Vcc switched onto Vpp1 */
#define	DRCTL_VPP1_VPP	0x00008	/* Vpp switched onto Vpp1 */
#define	DRCTL_VPP1_ZIP	0x0000c	/* no connect */

#define	DRCTL_MSTPWR	0x00002	/* PC card master power enable */
#define	DRCTL_PCIFOE	0x00001	/* PC card interface output enable */

/*
 * Socket interface status register definitions
 *
 * bit definitions for socket interface status register 0 when
 *	the socket is in memory-only mode
 */
#define	DRSTAT_ZERO	0x08000	/* always reads back as zero */
#define	DRSTAT_SCINT	0x04000	/* status change interrupt posted */
#define	DRSTAT_CDCHG	0x02000	/* card detect status change */
#define	DRSTAT_BVD2CHG	0x01000	/* battery voltage detect 2 status change */
#define	DRSTAT_BVD1CHG	0x00800	/* battery voltage detect 1 status change */
#define	DRSTAT_BVDCHG	(DRSTAT_BVD1CHG|DRSTAT_BVD1CHG)
#define	DRSTAT_RDYCHG	0x00400	/* ready/busy status change */
#define	DRSTAT_WPCHG	0x00200	/* write protect status change */
#define	DRSTAT_PCTO	0x00100	/* PC card access timeout */

#define	DRSTAT_LIVE	0x000ff	/* live status bit mask */
#define	DRSTAT_CD2ST	0x00080	/* card detect 2 live status */
#define	DRSTAT_CD1ST	0x00040	/* card detect 1 live status */
#define	DRSTAT_CD_MASK	(DRSTAT_CD1ST|DRSTAT_CD2ST)
#define	DRSTAT_PRESENT_OK	DRSTAT_CD_MASK
#define	DRSTAT_BVD2ST	0x00020	/* battery voltage detect 2 live status */
#define	DRSTAT_BVD1ST	0x00010	/* battery voltage detect 1 live status */
#define	DRSTAT_BVDST		(DRSTAT_BVD1ST|DRSTAT_BVD2ST)
#define	DRSTAT_BATT_LOW		DRSTAT_BVD2ST
#define	DRSTAT_BATT_OK		(DRSTAT_BVD1ST|DRSTAT_BVD2ST)

#define	DRSTAT_RDYST	0x00008	/* ready/busy live status */
#define	DRSTAT_WPST	0x00004	/* write protect live status */
#define	DRSTAT_WAITST	0x00002	/* wait signal live status */
#define	DRSTAT_PWRON	0x00001	/* PC card power status */

/*
 * additional bit definitions for socket interface status register 0 when
 *	the socket is in memory and I/O mode
 *
 * these are just alternate names for the bit definitions described for
 *	this register when the socket is in memory-only mode
 */
#define	DRSTAT_IOINT	0x08000	/* PC card I/O interrupt (*IRQ) posted */
#define	DRSTAT_SPKR	0x00020	/* SPKR (speaker) signal live status */
#define	DRSTAT_STSCHG	0x00010	/* I/O *STSCHG signal live status */
#define	DRSTAT_IOREQ	0x00008	/* I/O *REQ signal live status */
#define	DRSTAT_IOIS16	0x00004	/* IOIS16 signal live status */

/*
 * bit definitions for socket interface status register 1; these are
 *	valid no matter what mode the socket is in
 *
 * note that bits 0x0ffc0 are reserved
 */
#define	DRSTAT_PCTYS_M	0x00030	/* PC card type(s) supported bit mask */
#define	DRSTAT_PCTYS_S	4	/* PC card type(s) supported bit shift */
#define	SET_DRSTAT_PCTYS(x)	(((int)(x) << DRSTAT_PCTYS_S) & DRSTAT_PCTYS_M)
#define	GET_DRSTAT_PCTYS(x)	(((int)(x) & DRSTAT_PCTYS_M) >> DRSTAT_PCTYS_S)

#define	DRSTAT_REV_M	0x0000f	/* STP4020 ASIC revision level bit mask */
#define	DRSTAT_REV_S	0	/* STP4020 ASIC revision level bit shift */
#define	SET_DRSTAT_REV(x)	(((int)(x) << DRSTAT_REV_S) & DRSTAT_REV_M)
#define	GET_DRSTAT_REV(x)	(((int)(x) & DRSTAT_REV_M) >> DRSTAT_REV_S)

/*
 * Socket window control/status register definitions
 *
 * Each PCMCIA socket has three windows associated with it; each of these
 *	windows can be programmed to map in either the AM, CM or IO space
 *	on the PC card.  Each window can also be programmed with a
 *	starting or base address relative to the PC card's address zero.
 *	Each window is a fixed 1Mb in size.
 *
 * Each window has two window control registers associated with it to
 *	control the window's PCMCIA bus timing parameters, PC card address
 *	space that that window maps, and the base address in the
 *	selected PC card's address space.
 */
#define	DRWINSIZE	(1024*1024) /* 1MB */
#define	DRADDRLINES	20	/* for 1MB */

/*
 * bit mask, shift offset and set/clear macro definitions for window
 *	control registers
 *
 * The SET_XXX macros shift their normalized arguments to the correct
 *	position for the window control register and return the shifted
 *	value.
 *
 * The GET_XXX macros take a window control register value and return
 *	the appropriate normalized value.
 */

/*
 * PC card window control register 0
 *	note that bit 0x08000 is reserved
 */
#define	DRWIN_CMDLNG_M	0x07c00	/* command strobe length bit mask */
#define	DRWIN_CMDLNG_S	10	/* command strobe length bit shift */
#define	SET_DRWIN_CMDLNG(x)	(((int)(x) << DRWIN_CMDLNG_S) & DRWIN_CMDLNG_M)
#define	GET_DRWIN_CMDLNG(x)	(((int)(x) & DRWIN_CMDLNG_M) >> DRWIN_CMDLNG_S)

#define	DRWIN_CMDDLY_M	0x00300	/* command strobe delay bit mask */
#define	DRWIN_CMDDLY_S	8	/* command strobe delay bit shift */
#define	SET_DRWIN_CMDDLY(x)	(((int)(x) << DRWIN_CMDDLY_S) & DRWIN_CMDDLY_M)
#define	GET_DRWIN_CMDDLY(x)	(((int)(x) & DRWIN_CMDDLY_M) >> DRWIN_CMDDLY_S)

#define	MEM_SPEED_MIN	100
#define	MEM_SPEED_MAX	1370

/*
 * the ASPSEL bits control which of the three PC card address spaces
 *	this window maps in
 */
#define	DRWIN_ASPSEL_M	0x000c0	/* address space select bit mask */
#define	DRWIN_ASPSEL_AM	0x000	/* attribute memory */
#define	DRWIN_ASPSEL_CM	0x040	/* common memory */
#define	DRWIN_ASPSEL_IO	0x080	/* I/O */

#define	DRWIN_BASE_M	0x0003f	/* base address bit mask */
#define	DRWIN_BASE_S	0	/* base address bit shift */
#define	SET_DRWIN_BASE(x)	(((int)(x) << DRWIN_BASE_S) & DRWIN_BASE_M)
#define	GET_DRWIN_BASE(x)	(((int)(x) & DRWIN_BASE_M) >> DRWIN_BASE_S)
#define	ADDR2PAGE(x)	((x) >> 20)

/*
 * PC card window control register 1
 *	note that bits 0x0ffe0 are reserved
 */
#define	DRWIN_RECDLY_M	0x00018	/* recovery delay bit mask */
#define	DRWIN_RECDLY_S	3	/* recovery delay bit shift */
#define	SET_DRWIN_RECDLY(x)	(((int)(x) << DRWIN_RECDLY_S) & DRWIN_RECDLY_M)
#define	GET_DRWIN_RECDLY(x)	(((int)(x) & DRWIN_RECDLY_M) >> DRWIN_RECDLY_S)

#define	DRWIN_WAITDLY_M	0x00006	/* *WAIT signal delay bit mask */
#define	DRWIN_WAITDLY_S	1	/* *WAIT signal delay bit shift */
#define	SET_DRWIN_WAITDLY(x)	(((int)(x) << DRWIN_WAITDLY_S) & \
							DRWIN_WAITDLY_M)
#define	GET_DRWIN_WAITDLY(x)	(((int)(x) & DRWIN_WAITDLY_M) >> \
							DRWIN_WAITDLY_S)

#define	DRWIN_WAITREQ_M	0x00001	/* *WAIT signal is required bit mask */
#define	DRWIN_WAITREQ_S	0	/* *WAIT signal is required bit shift */
#define	SET_DRWIN_WAITREQ(x)	(((int)(x) << DRWIN_WAITREQ_S) & \
							DRWIN_WAITREQ_M)
#define	GET_DRWIN_WAITREQ(x)	(((int)(x) & DRWIN_WAITREQ_M) >> \
							DRWIN_WAITREQ_S)

/*
 * STP4020 CSR structures
 *
 * There is one stp4020_regs_t structure per instance, and it refers to
 *	the complete Stp4020 register set.
 *
 * For each socket, there is one stp4020_socket_csr_t structure, which
 *	refers to all the registers for that socket.  That structure is
 *	made up of the window register structures as well as the registers
 *	that control overall socket operation.
 *
 * For each window, there is one stp4020_window_ctl_t structure, which
 *	refers to all the registers for that window.
 */

/*
 * per-window CSR structure
 */
typedef struct stp4020_window_ctl_t {
    volatile	ushort_t	ctl0;		/* window control register 0 */
    volatile	ushort_t	ctl1;		/* window control register 1 */
} stp4020_window_ctl_t;

/*
 * per-socket CSR structure
 */
typedef struct stp4020_socket_csr_t {
    volatile	struct stp4020_window_ctl_t	window[DRWINDOWS];
    volatile	ushort_t	ctl0;		/* socket control register 0 */
    volatile	ushort_t	ctl1;		/* socket control register 1 */
    volatile	ushort_t	stat0;		/* socket status register 0 */
    volatile	ushort_t	stat1;		/* socket status register 1 */
    volatile	uchar_t	filler[12];	/* filler space */
} stp4020_socket_csr_t;

/*
 * per-instance CSR structure
 */
typedef struct stp4020_regs_t {
    struct stp4020_socket_csr_t	socket[DRSOCKETS];	/* socket CSRs */
} stp4020_regs_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _STP4020_REG_H */
