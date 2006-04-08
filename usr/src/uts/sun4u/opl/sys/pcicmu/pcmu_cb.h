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

#ifndef	_SYS_PCMU_CB_H
#define	_SYS_PCMU_CB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

enum pcmu_cb_nintr_index {
	CBNINTR_PBM = 0,		/* not shared */
	CBNINTR_UE = 1,			/* shared */
	CBNINTR_CE = 2,			/* shared */
	CBNINTR_POWER_FAIL	= 3,	/* shared */
	CBNINTR_THERMAL		= 4,	/* shared */
	CBNINTR_MAX			/* max */
};

/*
 * control block soft state structure:
 */
struct pcmu_cb {
	pcmu_t *pcb_pcmu_p;
	pcmu_ign_t pcb_ign;		/* interrupt grp# */
	kmutex_t pcb_intr_lock;		/* guards add/rem intr and intr dist */
	uint32_t pcb_no_of_inos;	/* # of actual inos, including PBM */
	uint32_t pcb_inos[CBNINTR_MAX];	/* subset of pcmu_p->pcmu_inos array */
	uint64_t pcb_base_pa;		/* PA of CSR bank, 2nd "reg" */
	uint64_t pcb_map_pa;		/* map reg base PA */
	uint64_t pcb_clr_pa;		/* clr reg base PA */
	uint64_t pcb_obsta_pa;		/* sta reg base PA */
	uint64_t *pcb_imr_save;
	caddr_t pcb_ittrans_cookie;	/* intr tgt translation */
};

#define	PCMU_CB_INO_TO_MONDO(pcb_p, ino)			\
	    ((pcb_p)->pcb_ign << PCMU_INO_BITS |  (ino))

/*
 * Prototypes.
 */
extern void pcmu_cb_create(pcmu_t *pcmu_p);
extern void pcmu_cb_destroy(pcmu_t *pcmu_p);
extern void pcmu_cb_suspend(pcmu_cb_t *cb_p);
extern void pcmu_cb_resume(pcmu_cb_t *cb_p);
extern void pcmu_cb_enable_nintr(pcmu_t *pcmu_p, pcmu_cb_nintr_index_t idx);
extern void pcmu_cb_disable_nintr(pcmu_cb_t *cb_p,
    pcmu_cb_nintr_index_t idx, int wait);
extern void pcmu_cb_clear_nintr(pcmu_cb_t *cb_p, pcmu_cb_nintr_index_t idx);
extern void pcmu_cb_intr_dist(void *arg);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCMU_CB_H */
