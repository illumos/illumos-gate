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

#ifndef _SYS_PX_FAULT_H
#define	_SYS_PX_FAULT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct px_fh px_fh_t;
enum { PX_FAULT_XBC, PX_FAULT_PEC };

typedef enum {
	PX_ERR_TLU_UE,
	PX_ERR_TLU_CE,
	PX_ERR_TLU_OE,
	PX_ERR_MMU,
	PX_ERR_IMU,
	PX_ERR_ILU,
	PX_ERR_JBC,
	PX_ERR_LPU_LINK,
	PX_ERR_LPU_PHY,
	PX_ERR_LPU_REC_PHY,
	PX_ERR_LPU_TRNS_PHY,
	PX_ERR_LPU_LTSSM,
	PX_ERR_LPU_GIGABLZ
} px_err_id_t;

typedef struct px_fh_desc {
	uint64_t	*fhd_imask_p;	/* bitmask for enabled interrupts   */
	uint64_t	*fhd_lmask_p;	/* bitmask for logged  interrupts   */
	uint64_t	*fhd_cmask_p;	/* bitmask for counted interrupts   */
	int		(*fhd_func)(dev_info_t *dip, px_fh_t *fh_p);

	uint32_t	fhd_log;	/* interrupt log    register offset */
	uint32_t	fhd_en;		/* interrupt enable register offset */
	uint32_t	fhd_st;		/* interrupt status register offset */
	uint32_t	fhd_cl;		/* interrupt clear  register offset */

	char		*fhd_msg_tbl;	/* error messages table  */
} px_fh_desc_t;

extern px_fh_desc_t px_fhd_tbl[];

typedef struct px_fault {
	dev_info_t	*px_fh_dip;
	sysino_t	px_fh_sysino;
	px_fh_t		*px_fh_lst;
	kmutex_t	px_fh_lock;
} px_fault_t;

struct px_fh {
	px_fh_t		*fh_next;
	caddr_t		fh_base;	/* Base offset for registers */
	px_err_id_t	fh_err_id;
	uint64_t	fh_stat;	/* last recorded stat */
	uint64_t	fh_cntrs[64];	/* counter array for interrupts */
};

extern void px_err_rem(px_fault_t *px_fault_p, int id);
extern void px_err_add_fh(px_fault_t *px_fault_p, int id, caddr_t csr_base);
extern int px_err_add_intr(px_t *px_p, px_fault_t *px_fault_p, int id);
extern void px_err_rem_intr(px_t *px_p, int id);

/* XXX need to be moved to individual include files */
extern int px_tlu_ue_intr(dev_info_t *dip, px_fh_t *fh_p);
extern int px_tlu_ce_intr(dev_info_t *dip, px_fh_t *fh_p);
extern int px_tlu_oe_intr(dev_info_t *dip, px_fh_t *fh_p);
extern int px_mmu_intr(dev_info_t *dip, px_fh_t *fh_p);
extern int px_imu_intr(dev_info_t *dip, px_fh_t *fh_p);
extern int px_ilu_intr(dev_info_t *dip, px_fh_t *fh_p);
extern int px_lpu_intr(dev_info_t *dip, px_fh_t *fh_p);
extern int px_cb_intr(dev_info_t *dip, px_fh_t *fh_p);

#define	PX_ERR_PIL  14

#define	px_lpul_intr	px_lpu_intr
#define	px_lpup_intr	px_lpu_intr
#define	px_lpur_intr	px_lpu_intr
#define	px_lpux_intr	px_lpu_intr
#define	px_lpus_intr	px_lpu_intr
#define	px_lpug_intr	px_lpu_intr

#define	M4(pre) \
	&px ## _ ## pre ## _ ## intr_mask, \
	&px ## _ ## pre ## _ ## log_mask, \
	&px ## _ ## pre ## _ ## count_mask, \
	&px ## _ ## pre ## _ ## intr

#define	LR4(pre) NULL, \
	pre ## _ ## MASK, \
	pre ## _ ## AND_STATUS, \
	pre ## _ ## AND_STATUS

#define	LR4_FIXME(pre1, pre2) NULL, \
	pre1 ## _ ## pre2 ## _ ## MASK, \
	pre1 ## _LAYER_ ## pre2 ## _ ## AND_STATUS, \
	pre1 ## _LAYER_ ## pre2 ## _ ## AND_STATUS

#define	TR4(pre) \
	pre ## _ ## LOG_ENABLE, \
	pre ## _ ## INTERRUPT_ENABLE, \
	pre ## _ ## INTERRUPT_STATUS, \
	pre ## _ ## STATUS_CLEAR

#define	R4(pre) \
	pre ## _ ## ERROR_LOG_ENABLE, \
	pre ## _ ## INTERRUPT_ENABLE, \
	pre ## _ ## INTERRUPT_STATUS, \
	pre ## _ ## ERROR_STATUS_CLEAR

/* FMA related */
extern int px_fm_attach(px_t *px_p);
extern void px_fm_detach(px_t *px_p);
extern int px_fm_init_child(dev_info_t *dip, dev_info_t *tdip, int cap,
    ddi_iblock_cookie_t *ibc);
extern void px_fm_acc_setup(ddi_map_req_t *mp, dev_info_t *rdip);
extern int px_fm_err_handler(dev_info_t *dip, ddi_fm_error_t *derr,
    const void *impl_data);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_FAULT_H */
