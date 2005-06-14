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

#ifndef _STP4020_VAR_H
#define	_STP4020_VAR_H

#pragma ident	"%W%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	DRT_REG_SETS	8

struct drt_window {
	int	drtw_flags;
/* XXX	int	drtw_status; XXX */
	int	drtw_ctl0;
	int	drtw_speed;	/* unprocessed speed */
	ddi_acc_handle_t drtw_handle;
	ddi_acc_hdl_t drtw_modhandle;
	caddr_t drtw_base;	/* address in host memory */
	int	drtw_len;
	caddr_t drtw_addr;	/* address on PC Card */
	caddr_t drtw_reqaddr;	/* requested address */
};
#define	DRW_IO		0x01	/* window is an I/O window */
#define	DRW_MAPPED	0x02	/* window is mapped */
#define	DRW_ENABLED	0x04
#define	DRW_ATTRIBUTE	0x08	/* window points to AM */

struct stpramap {
	struct stpramap *ra_next;
	uint32_t ra_base;
	uint32_t ra_len;
};

typedef struct stpra_request {
				/* general flags */
	uint32_t	ra_flags;
				/* length of resource */
	uint32_t	ra_len;
				/* specific address */
	uint32_t	ra_addr_hi;
	uint32_t	ra_addr_lo;
				/* address mask */
	uint32_t	ra_mask;
				/* bounds on addresses */
	uint32_t	ra_boundbase;
	uint32_t	ra_boundlen;
				/* alignment mask */
	uint32_t	ra_align;
} stpra_request_t;

#define	STP_RA_ALIGN_MASK	0x0001
#define	STP_RA_ALIGN_SIZE	0x0002
#define	STP_RA_ALLOC_POW2	0x0020
#define	STP_RA_ALLOC_SPECIFIED	0x0040

typedef struct stpra_return {
	uint32_t	ra_addr_hi;
	uint32_t	ra_addr_lo;
	uint32_t	ra_len;
	int		ra_error;
} stpra_return_t;



typedef struct drt_socket {
	int	drt_flags;
	int	drt_state;
	int	drt_intmask;
	int	drt_vcc;
	int	drt_vpp1;
	int	drt_vpp2;
	int	drt_irq;	/* high or low */
	struct stpramap *drt_iomap;
	struct drt_window drt_windows[DRWINDOWS];
} drt_socket_t;

#define	DRT_SOCKET_IO		0x01
#define	DRT_CARD_ENABLED	0x02
#define	DRT_CARD_PRESENT	0x04
#define	DRT_BATTERY_DEAD	0x08
#define	DRT_BATTERY_LOW		0x10
#define	DRT_INTR_ENABLED	0x20
#define	DRT_INTR_HIPRI		0x40

#define	DRT_NUM_POWER	3	/* number of power table entries */

typedef
struct drtdev {
	uint32_t pc_flags;
	int	pc_type;
	dev_info_t *pc_devinfo;
	ddi_iblock_cookie_t pc_icookie_hi;
	ddi_idevice_cookie_t pc_dcookie_hi;
	ddi_iblock_cookie_t pc_icookie_lo;
	ddi_idevice_cookie_t pc_dcookie_lo;
	kmutex_t pc_lock;
	kmutex_t pc_intr;
	caddr_t pc_addr;	/* temporary address map */
	int	pc_numsockets;
	int   (*pc_callback)(); /* used to inform nexus of events */
	int	pc_cb_arg;
	int	pc_numpower;
	struct power_entry *pc_power;
	int	pc_numintr;
	ddi_acc_handle_t pc_handle;
	drt_socket_t pc_sockets[DRSOCKETS];
	stp4020_regs_t *pc_csr;
	inthandler_t *pc_handlers;
	uint32_t pc_timestamp;	/* last time touched */
	kmutex_t pc_tslock;
	volatile struct stp4020_socket_csr_t	saved_socket[DRSOCKETS];
} drt_dev_t;

#define	PCF_CALLBACK	0x0001
#define	PCF_INTRENAB	0x0002
#define	PCF_SUSPENDED	0x0004	/* driver has been suspended */
#define	PCF_AUDIO	0x0008	/* allow audio */
#define	PCF_ATTACHING	0x0010	/* driver is attaching so spurious intr */

#define	DRT_DEFAULT_INT_CAPS (SBM_CD|SBM_BVD1|SBM_BVD2|SBM_RDYBSY|SBM_WP)
#define	DRT_DEFAULT_RPT_CAPS DRT_DEFAULT_INT_CAPS
#define	DRT_DEFAULT_CTL_CAPS (0)

#define	PC_CALLBACK(drt, arg, x, e, s) (*drt->pc_callback)(arg, x, e, s)

/*
 * The following two defines are for CPR support
 */
#define	DRT_SAVE_HW_STATE	1
#define	DRT_RESTORE_HW_STATE	2

#ifdef	__cplusplus
}
#endif

#endif	/* _STP4020_VAR_H */
