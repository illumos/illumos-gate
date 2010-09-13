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

#ifndef	_SYS_PCMU_UTIL_H
#define	_SYS_PCMU_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Prototypes
 */
extern int pcmu_init_child(pcmu_t *, dev_info_t *);
extern int pcmu_uninit_child(pcmu_t *, dev_info_t *);
extern int pcmu_report_dev(dev_info_t *);
extern int get_pcmu_properties(pcmu_t *, dev_info_t *);
extern void free_pcmu_properties(pcmu_t *);
extern int pcmu_get_portid(dev_info_t *);
extern int pcmu_reloc_reg(dev_info_t *, dev_info_t *, pcmu_t *,
    pci_regspec_t *);
extern int pcmu_xlate_reg(pcmu_t *, pci_regspec_t *, struct regspec *);
extern off_t pcmu_get_reg_set_size(dev_info_t *, int);
extern uint_t pcmu_get_nreg_set(dev_info_t *);
extern uint64_t pcmu_get_cfg_pabase(pcmu_t *);
extern int pcmu_cfg_report(dev_info_t *, ddi_fm_error_t *,
    pcmu_errstate_t *, int, uint32_t);

#ifdef DEBUG

extern uint64_t pcmu_debug_flags;

typedef struct pcmu_dflag_to_str {
	uint64_t flag;
	char *string;
} pcmu_dflag_to_str_t;

#define	PCMU_DBG_ATTACH		0x1ull
#define	PCMU_DBG_DETACH		0x2ull
#define	PCMU_DBG_MAP		0x4ull
#define	PCMU_DBG_A_INTX		0x8ull
#define	PCMU_DBG_R_INTX		0x10ull
#define	PCMU_DBG_INIT_CLD	0x20ull
#define	PCMU_DBG_CTLOPS		0x40ull
#define	PCMU_DBG_INTR		0x80ull
#define	PCMU_DBG_ERR_INTR	0x100ull
#define	PCMU_DBG_BUS_FAULT	0x200ull
#define	PCMU_DBG_IB		(0x20ull << 32)
#define	PCMU_DBG_CB		(0x40ull << 32)
#define	PCMU_DBG_PBM		(0x80ull << 32)
#define	PCMU_DBG_CONT		(0x100ull << 32)
#define	PCMU_DBG_OPEN		(0x1000ull << 32)
#define	PCMU_DBG_CLOSE		(0x2000ull << 32)
#define	PCMU_DBG_IOCTL		(0x4000ull << 32)
#define	PCMU_DBG_PWR		(0x8000ull << 32)


#define	PCMU_DBG0(flag, dip, fmt)	\
	pcmu_debug(flag, dip, fmt, 0, 0, 0, 0, 0);

#define	PCMU_DBG1(flag, dip, fmt, a1)	\
	pcmu_debug(flag, dip, fmt, (uintptr_t)(a1), 0, 0, 0, 0);

#define	PCMU_DBG2(flag, dip, fmt, a1, a2)	\
	pcmu_debug(flag, dip, fmt, (uintptr_t)(a1), (uintptr_t)(a2), 0, 0, 0);

#define	PCMU_DBG3(flag, dip, fmt, a1, a2, a3)	\
	pcmu_debug(flag, dip, fmt, (uintptr_t)(a1),	\
		(uintptr_t)(a2), (uintptr_t)(a3), 0, 0);

#define	PCMU_DBG4(flag, dip, fmt, a1, a2, a3, a4)	\
	pcmu_debug(flag, dip, fmt, (uintptr_t)(a1),	\
		(uintptr_t)(a2), (uintptr_t)(a3), \
		(uintptr_t)(a4), 0);

#define	PCMU_DBG5(flag, dip, fmt, a1, a2, a3, a4, a5)	\
	pcmu_debug(flag, dip, fmt, (uintptr_t)(a1),	\
		(uintptr_t)(a2), (uintptr_t)(a3), \
		(uintptr_t)(a4), (uintptr_t)(a5));

extern void pcmu_debug(uint64_t, dev_info_t *, char *,
			uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
#else /* DEBUG */

#define	PCMU_DBG0(flag, dip, fmt)
#define	PCMU_DBG1(flag, dip, fmt, a1)
#define	PCMU_DBG2(flag, dip, fmt, a1, a2)
#define	PCMU_DBG3(flag, dip, fmt, a1, a2, a3)
#define	PCMU_DBG4(flag, dip, fmt, a1, a2, a3, a4)
#define	PCMU_DBG5(flag, dip, fmt, a1, a2, a3, a4, a5)

#endif /* DEBUG */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCMU_UTIL_H */
