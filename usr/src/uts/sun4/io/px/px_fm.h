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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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
 *   PX_FATAL_HW: errors that automatically cause Fire HW reset,
 *   PX_FATAL_GOS: errors that causes OS cease to function immediately,
 *   PX_STUCK_FATAL: errors that is likely to spam, causing hang,
 *   PX_FATAL_SW: errors that cause partial OS lose function,
 *   PX_NONFATAL: errors that can be recovered or ignored.
 */
#define	PX_FATAL_HW		0x10
#define	PX_FATAL_GOS		0x8
#define	PX_STUCK_FATAL		0x4
#define	PX_FATAL_SW		0x2
#define	PX_NONFATAL		0x1
#define	PX_OK			DDI_FM_OK
#define	PX_ERR_UNKNOWN		0x80

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
extern int px_handle_lookup(dev_info_t *, int, uint64_t, void *);
extern int px_fm_callback(dev_info_t *, ddi_fm_error_t *, const void *);
extern int px_err_handle(px_t *px_p, ddi_fm_error_t *derr, int caller,
    boolean_t checkjbc);

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

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_FM_H */
