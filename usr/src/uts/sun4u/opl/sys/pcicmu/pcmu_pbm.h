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

#ifndef	_SYS_PCMU_PBM_H
#define	_SYS_PCMU_PBM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/ontrap.h>
#include <sys/callb.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following structure represents the pci configuration header
 * for CMU-CH PBM.
 */
typedef struct config_header {
	volatile uint16_t ch_vendor_id;
	volatile uint16_t ch_device_id;
	volatile uint16_t ch_command_reg;
	volatile uint16_t ch_status_reg;
	volatile uint8_t ch_revision_id_reg;
	volatile uint8_t ch_programming_if_code_reg;
	volatile uint8_t ch_sub_class_reg;
	volatile uint8_t ch_base_class_reg;
	volatile uint8_t ch_cache_line_size_reg;
	volatile uint8_t ch_latency_timer_reg;
	volatile uint8_t ch_header_type_reg;
} config_header_t;

#define	PBM_NAMESTR_BUFLEN	64

/*
 * CMU-CH pbm block soft state structure:
 */
struct pcmu_pbm {
	pcmu_t *pcbm_pcmu_p;		/* link back to the soft state */

	volatile uint64_t *pcbm_ctrl_reg;		/* PBM control reg */
	volatile uint64_t *pcbm_async_flt_status_reg;	/* PBM AFSR reg */
	volatile uint64_t *pcbm_async_flt_addr_reg;	/* PBM AFAR reg */
	volatile uint64_t *pcbm_diag_reg;		/* PBM diag reg */

	config_header_t *pcbm_config_header;		/* PBM config header */
	uint64_t pcbm_imr_save;				/* intr map save area */
	ddi_iblock_cookie_t pcbm_iblock_cookie;	/* PBM error intr priority */

	on_trap_data_t *pcbm_ontrap_data;	/* ddi_poke support */
	kmutex_t pcbm_pokeflt_mutex;		/* poke mutex */
	ddi_acc_handle_t pcbm_excl_handle;	/* cautious IO access handle */
	char pcbm_nameinst_str[PBM_NAMESTR_BUFLEN]; /* driver name & inst */
	char *pcbm_nameaddr_str;		/* node name & address */
};

/*
 * Prototypes
 */
extern void pcmu_pbm_create(pcmu_t *pcmu_p);
extern void pcmu_pbm_destroy(pcmu_t *pcmu_p);
extern void pcmu_pbm_configure(pcmu_pbm_t *pcbm_p);
extern void pcmu_pbm_suspend(pcmu_pbm_t *pcbm_p);
extern void pcmu_pbm_resume(pcmu_pbm_t *pcbm_p);
extern void pcmu_pbm_intr_dist(void *arg);
extern int pcmu_pbm_register_intr(pcmu_pbm_t *pcbm_p);
extern int pcmu_pbm_afsr_report(dev_info_t *dip, uint64_t fme_ena,
    pcmu_pbm_errstate_t *pbm_err_p);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCMU_PBM_H */
