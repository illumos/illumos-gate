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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SGSBBC_PRIV_H
#define	_SYS_SGSBBC_PRIV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Private structures used by the Serengeti SBBC Driver
 *
 * The Serengeti SBBC driver handles communication between the
 * System Controller Software (ScApp) and Solaris via SBBC
 * registers and IOSRAM.
 *
 * This header file contains necessary definitions to enable
 * such communication.
 *
 * Register offsets and definitions can be found in
 * Serengeti Architecture Programmer's Reference
 * Revision 1.3 11/16/1999
 * Section 2.5 to 2.8
 */

#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/sgsbbc.h>

/*
 * SBBC Interrupt registers
 */
#define	SBBC_MAX_INTRS		32

/*
 * Different interrupts
 */
#define	INTERRUPT_ON	0x1	/* bit 0 */
/*
 * EPLD Interrupt Register Offset for communication with the SC
 */
#define	EPLD_INTERRUPT	0x13

/*
 * register numbers for mapping in OBP reg properties
 */
#define	RNUM_SBBC_REGS		1

/*
 * SBBC registers and devices on CPU/memory board
 */
#define	SBBC_REGS_OFFSET	0x800000
#define	SBBC_REGS_SIZE		0x6230
#define	SBBC_EPLD_OFFSET	0x8e0000
#define	SBBC_EPLD_SIZE		0x20
#define	SBBC_SRAM_OFFSET	0x900000
#define	SBBC_SRAM_SIZE		0x20000		/* max. 128KB of SRAM */
/*
 * Register Offsets
 */
#define	SBBC_PCI_INT_STATUS	0x2320
#define	SBBC_PCI_INT_ENABLE	0x2330

/*
 * Port Interrupt Enable Register
 *
 * Field	Bits	Reset	Type	Description
 *			State
 * Resvd	<31:8>	0	R	Reserved
 * PINT1_EN	<7:4>	0	RW	Enables for each of the 4 PCI
 *					interrupt lines for Port Interrupt
 *					Generation register 1.  Bit 7
 *					corresponds to PCI Interrupt D,
 *					bit 4 corresponds to PCI Interrupt A.
 * PINT0_EN	<3:0>	0	RW	Same as above, but for register 0.
 */
#define	SBBC_PCI_ENABLE_INT_A	0x11	/* Enable both PCI Interrupt A */
#define	SBBC_PCI_ENABLE_MASK	0xff	/* Mask for the two enable registers */

#ifdef	DEBUG
#define	SGSBBC_DBG_MASK_MBOX		0x00000001
#define	SGSBBC_DBG_MASK_INTR		0x00000002
#define	SGSBBC_DBG_MASK_EVENT		0x00000004

extern uint_t sgsbbc_debug;
#define	SGSBBC_DBG_ALL	if (sgsbbc_debug)	prom_printf
#define	SGSBBC_DBG_MBOX \
	if (sgsbbc_debug & SGSBBC_DBG_MASK_MBOX) printf
#define	SGSBBC_DBG_INTR \
	if (sgsbbc_debug & SGSBBC_DBG_MASK_INTR) cmn_err
#define	SGSBBC_DBG_EVENT \
	if (sgsbbc_debug & SGSBBC_DBG_MASK_EVENT) cmn_err

#else	/* DEBUG */
#define	SGSBBC_DBG_ALL
#define	SGSBBC_DBG_MBOX
#define	SGSBBC_DBG_INTR
#define	SGSBBC_DBG_EVENT

#endif	/* DEBUG */


typedef struct sbbc_intrs {
	sbbc_intrfunc_t		sbbc_handler;	/* interrupt handler */
	caddr_t			sbbc_arg;	/* interrupt argument */
	ddi_softintr_t		sbbc_intr_id;
	kmutex_t		*sbbc_intr_lock;	/* for state flag */
	uint_t			*sbbc_intr_state;	/* handler state */
	struct sbbc_intrs	*sbbc_intr_next;
	int			registered;
} sbbc_intrs_t;

struct sbbc_epld_regs {
	uchar_t		epld_reg[32];
};

/*
 * device soft state
 */
typedef struct sbbc_softstate {
	struct sbbc_softstate	*prev;
	struct sbbc_softstate	*next;

	struct chosen_iosram    *iosram; /* back reference */
	dev_info_t 		*dip;

	/*
	 * Tunnel Info.
	 */
	void			*sram;

	/*
	 * SBBC Register Info.
	 */
	caddr_t				sbbc_regs;	/* common device regs */
	uint32_t			*port_int_regs; /* interrupt regs */
	struct sbbc_epld_regs		*epld_regs;	/* EPLD regs */
	uint32_t			sram_toc;	/* SRAM TOC */

	/*
	 * device map handles for register mapping
	 */
	ddi_acc_handle_t		sbbc_reg_handle1;
	ddi_acc_handle_t		sbbc_reg_handle2;
	/*
	 * SBBC Interrupts
	 */
	uint_t			inumber;
	ddi_iblock_cookie_t 	iblock;
	ddi_idevice_cookie_t 	idevice;

	sbbc_intrs_t		*intr_hdlrs;

	/*
	 * misc.
	 */
	kmutex_t		sbbc_lock;	/* mutex for this struct */
	uchar_t			suspended;	/* TRUE if instance suspended */
	uchar_t			chosen;		/* TRUE if instance 'chosen' */
	int			sbbc_instance;
	int			sbbc_state;	/* see below */
} sbbc_softstate_t;
/* sbbc iosram state */
#define	SBBC_STATE_INIT 0x0001		/* initialization */
#define	SBBC_STATE_DETACH 0x0002	/* IOSRAM instance being detached */

/*
 * Structure used for tunnel switch
 */
typedef struct {
	dev_info_t	*cur_dip;	/* current dip that we compare to */
	dev_info_t	*new_dip;	/* new dip that fits the condition */
} sbbc_find_dip_t;

/*
 * Routines for mapping and unmapping SBBC internal registers
 */
extern int	sbbc_map_regs(sbbc_softstate_t *);

/*
 * Interrupt related routines
 */
extern int	sbbc_add_intr(sbbc_softstate_t *);
extern void	sbbc_enable_intr(sbbc_softstate_t *);
extern void	sbbc_disable_intr(sbbc_softstate_t *);
extern int	sbbc_send_intr(sbbc_softstate_t *, int);
extern uint_t	sbbc_intr_handler();

extern sbbc_softstate_t	*sbbc_get_soft_state(int);

/*
 * To protect master_chosen
 */
extern kmutex_t chosen_lock;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SGSBBC_PRIV_H */
