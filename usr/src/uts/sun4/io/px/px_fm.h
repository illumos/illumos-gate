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

#ifndef _SYS_PX_FM_H
#define	_SYS_PX_FM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PX_ERR_PIL	14
#define	PX_ERR_LOW_PIL  9

/*
 * Error handlers maybe called due to trap or interrupts
 * occured.
 */
#define	PX_TRAP_CALL	0
#define	PX_INTR_CALL	1
#define	PX_LIB_CALL	2

/*
 * Definition of Fire internal error severity -
 * HW Reset     Errors that cause hardware to automatically reset. Software is
 *              being reset along, sticky status bits need to be cleaned up upon
 *              system initialization.
 * Panic        Errors that definitely result in panic'ing the system.
 * Expected     Expected error, do not panic, plus do not send ereport.
 * Protected    Errors SW to determine panic or not, forgivable for safe access.
 *              Set when SW determines this error is forgivable during safe acc.
 * No-panic     Errors that don't directly result in panic'ing the system.
 * No-Error     When an interrupt occured and no errors were seen
 */
#define	PX_HW_RESET		(0x1 << 5)
#define	PX_PANIC		(0x1 << 4)
#define	PX_EXPECTED		(0x1 << 3)
#define	PX_PROTECTED		(0x1 << 2)
#define	PX_NO_PANIC		(0x1 << 1)
#define	PX_NO_ERROR		(0x1 << 0)

#define	PX_HB		(0x1 << 2)
#define	PX_RP		(0x1 << 1)
#define	PX_RC		(0x1 << 0)

/*
 * Generic PCIe Root Port Error Handling
 * This struct must align with px_pec_err_t in sun4v/io/px/px_err.h
 */
typedef struct px_err_pcie {
	uint32_t tx_hdr1;	/* sysino */
	uint32_t tx_hdr2;	/* sysino */
	uint32_t tx_hdr3;	/* ehdl */
	uint32_t tx_hdr4;	/* ehdl */
	uint32_t primary_ue;	/* stick */
	uint32_t rsvd0;		/* stick */
	uint32_t rsvd1;		/* pec_desc */
	uint16_t pci_err_status;
	uint16_t pcie_err_status;
	uint32_t ce_reg;
	uint32_t ue_reg;
	uint32_t rx_hdr1;	/* hdr[0] */
	uint32_t rx_hdr2;	/* hdr[0] */
	uint32_t rx_hdr3;	/* hdr[1] */
	uint32_t rx_hdr4;	/* hdr[1] */
	uint32_t rsvd3;		/* err_src_reg */
	uint32_t rsvd4;		/* root err status */
} px_err_pcie_t;

#define	PX_FM_BLOCK_HOST	(0x1 << 0)
#define	PX_FM_BLOCK_PCIE	(0x1 << 1)
#define	PX_FM_BLOCK_ALL		(PX_FM_BLOCK_HOST | PX_FM_BLOCK_PCIE)

/*
 * Error handling FMA hook
 */
extern void px_bus_enter(dev_info_t *dip, ddi_acc_handle_t handle);
extern void px_bus_exit(dev_info_t *dip, ddi_acc_handle_t handle);
extern int px_fm_attach(px_t *px_p);
extern void px_fm_detach(px_t *px_p);
extern int px_fm_init_child(dev_info_t *, dev_info_t *, int,
    ddi_iblock_cookie_t *);
extern void px_fm_acc_setup(ddi_map_req_t *, dev_info_t *);
extern int px_fm_callback(dev_info_t *, ddi_fm_error_t *, const void *);
extern int px_err_cmn_intr(px_t *, ddi_fm_error_t *, int, int);

/*
 * Fire interrupt handlers
 */
extern uint_t px_err_cb_intr(caddr_t arg);
extern uint_t px_err_dmc_pec_intr(caddr_t arg);
extern uint_t px_err_fabric_intr(px_t *px_p, msgcode_t msg_code,
    pcie_req_id_t rid);

/*
 * Common error handling functions
 */
extern void px_err_safeacc_check(px_t *px_p, ddi_fm_error_t *derr);
extern int px_err_check_eq(dev_info_t *dip);
extern int px_err_check_pcie(dev_info_t *dip, ddi_fm_error_t *derr,
    px_err_pcie_t *regs);
extern void px_err_panic(int err, int msg, int fab_err);
extern void px_rp_en_q(px_t *px_p, pcie_req_id_t fault_bdf,
    uint32_t fault_addr, uint16_t s_status);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_FM_H */
