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

#ifndef	_SYS_PCMU_ERR_H
#define	_SYS_PCMU_ERR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ddifm.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#define	PBM_PRIMARY		1
#define	PBM_SECONDARY		0
#define	PBM_NONFATAL		0
#define	PBM_FATAL		1
#define	FM_LOG_PCI		0
#define	FM_LOG_PBM		1
#define	ECC_MAX_ERRS		6
#define	TARGET_MAX_ERRS		6

/*
 * Since pcmu_pbm_err_handler() is called by various interrupt/trap/callback
 * handlers, it is necessary for it to know where it is being called from.
 * Below are the flags passed to pcmu_pbm_err_handler() to give it knowledge
 * of it's caller.
 */
#define	PCI_TRAP_CALL		0x0
#define	PCI_CB_CALL		0x1
#define	PCI_INTR_CALL		0x2
#define	PCI_BUS_EXIT_CALL	0x3
#define	PCI_ECC_CALL		0x4

extern errorq_t *pcmu_ecc_queue;	/* per-system ecc handling queue */

struct pcmu_errstate {
	char *pcmu_err_class;
	uint16_t pcmu_cfg_stat;
	uint16_t pcmu_cfg_comm;
	uint64_t pcmu_pa;
};

/*
 * pbm errstate use to encompass the state for all errors
 * detected by the pci block
 */
struct pcmu_pbm_errstate {
	char *pbm_err_class;
	int pcbm_pri;
	int pbm_log;
	uint32_t pbm_err;
	uint32_t pbm_multi;
	char *pbm_bridge_type;
	uint64_t pbm_ctl_stat;
	uint64_t pbm_afsr;
	uint64_t pbm_afar;
	uint64_t pbm_va_log;
	uint64_t pbm_err_sl;
	uint64_t pcbm_pcix_stat;
	uint32_t pcbm_pcix_pfar;
	pcmu_errstate_t pcbm_pci;
	char *pcmu_pbm_terr_class;
};

/*
 * ecc errstate used to store all state captured,
 * upon detection of an ecc error.
 */
struct pcmu_ecc_errstate {
	char *ecc_bridge_type;
	pcmu_ecc_t *pecc_p;
	uint64_t ecc_afsr;
	uint64_t ecc_afar;
	uint64_t ecc_offset;
	uint64_t ecc_dev_id;
	uint64_t ecc_dw_offset;
	struct async_flt ecc_aflt;
	pcmu_ecc_intr_info_t ecc_ii_p;
	uint64_t ecc_ctrl;
	int pecc_pri;
	char ecc_unum[UNUM_NAMLEN];
	uint64_t ecc_ena;
	uint64_t ecc_err_addr;
	char *ecc_err_type;
	int pecc_pg_ret;
	nvlist_t *ecc_fmri;
	int ecc_caller;
};

extern int pcmu_fm_init_child(dev_info_t *dip, dev_info_t *tdip, int cap,
		ddi_iblock_cookie_t *ibc);
extern void pcmu_bus_enter(dev_info_t *dip, ddi_acc_handle_t handle);
extern void pcmu_bus_exit(dev_info_t *dip, ddi_acc_handle_t handle);
extern void pcmu_pbm_ereport_post(dev_info_t *dip, uint64_t ena,
		pcmu_pbm_errstate_t *pbm_err);
extern void pcmu_fm_acc_setup(ddi_map_req_t *mp, dev_info_t *rdip);
extern int pcmu_handle_lookup(dev_info_t *dip, int type, uint64_t fme_ena,
		void *afar);
extern void pcmu_fm_create(pcmu_t *pcmu_p);
extern void pcmu_fm_destroy(pcmu_t *pcmu_p);
extern int pcmu_err_callback(dev_info_t *dip, ddi_fm_error_t *derr,
		const void *impl_data);
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCMU_ERR_H */
