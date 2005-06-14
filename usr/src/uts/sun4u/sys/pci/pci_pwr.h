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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_PCI_PWR_H
#define	_SYS_PCI_PWR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/epm.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * An element of this structure type is allocated for
 * each PCI child to track power info.
 */
typedef struct pci_pwr_chld {
	dev_info_t		*dip;	/* node this struct represents */
	int			dev_cap;
					/* The clock capability the device */
					/* reports it  can operate. */
	int			bus_speed;
					/* the speed of the bus for this */
					/* device during E* */
	struct pci_pwr_chld	*next;	/* link to next item on list */
	int			flags;	/* State for entire device */
	int			*comp_pwr; /* state for each component */
	int			num_comps; /* size of comp_pwr */
	int			u01;	/* # comps in UNKNOWN, D0, D1 */
} pci_pwr_chld_t;

/*
 * For each PCI nexus instance that is PM capable, it will have
 * the following structure allocated.
 */
typedef struct pci_pwr {
	/*
	 * cpr and power management support:
	 */
	kmutex_t	pwr_mutex;
	int		current_lvl; /* power level of bus */
	dev_info_t	*pwr_dip;	/* dip of nexus */
	pci_pwr_chld_t	*pwr_info;	/* linked list of children */
	int		pwr_flags;	/* power management flags */
	int		pwr_fp;		/* # requiring full power */
	int		pwr_uk;		/* # at unknown PM state */
	int		pwr_d0;		/* # at d0 PM state */
	int		pwr_d1;		/* # at d1 PM state */
	int		pwr_d2;		/* # at d2 PM state */
	int		pwr_d3;		/* # at d3 PM state */

} pci_pwr_t;

#define	PCI_CLK_SETTLE_TIME	10000 /* settle time before PCI operation */

/*
 * ret this if unable to det slot speed while in slow mode
 */
#define	INVALID_BUS_SPEED	-1

/*
 * XXX Number of components for dip.  This needs to be provided by DDI.
 */
#define	PM_NUMCMPTS(dip)	(DEVI(dip)->devi_pm_num_components)

/*
 * Label for component 0
 */
#define	PCI_PM_COMP_0	0

/*
 * Bus levels returned by pci_pwr_new_lvl(). In addition to
 * PM_LEVEL_B[0-3], a level is needed for variable clock
 * mode.  These levels MUST correspond to the levels specified
 * in the pm-components property.
 */
#define	PM_LEVEL_DYN	1
#define	PM_LEVEL_B3	0
#define	PM_LEVEL_B2	1
#define	PM_LEVEL_B1	2
#define	PM_LEVEL_B0	3

/*
 * PCI clock speeds for slow mode (expressed in KHz)
 */
#define	PCI_1MHZ	1000
#define	PCI_4MHZ	(4 * PCI_1MHZ)

/*
 * Bit values for struct pci_pwr.pwr_flags
 */
#define	PCI_PWR_PARKING		0x01 /* Need to re-enable parking */
#define	PCI_PWR_SLOW_CAPABLE	0x02 /* HW supports reduced clock speeds */
#define	PCI_PWR_B1_CAPABLE	0x04 /* HW supports B1 state */
#define	PCI_PWR_B2_CAPABLE	0x08 /* HW supports B2 state */
#define	PCI_PWR_B3_CAPABLE	0x10 /* HW supports B3 state */
#define	PCI_PWR_COMP_BUSY	0x20 /* component set busy */

/*
 * State flags for each device (struct pci_pwr_chld.flags)
 */
#define	PWR_FP_HOLD		0x01	/* pwr_fp counted for this dev */

/*
 * Arbitrary level that pci_pwr_chld.comp_pwr is initialized
 */
#define	PM_LEVEL_NOLEVEL	-2

#define	PM_CAPABLE(pwr_p)	(pwr_p != NULL)
#define	SLOW_CAPABLE(pwr_p)	((pwr_p->pwr_flags &\
				PCI_PWR_SLOW_CAPABLE) ==\
				PCI_PWR_SLOW_CAPABLE)

/*
 * Binary prop used by suspend/resume if it saved config regs
 */
#define	NEXUS_SAVED "nexus-saved-config-regs"

extern void pci_pwr_component_busy(pci_pwr_t *pwr_p);
extern void pci_pwr_component_idle(pci_pwr_t *pwr_p);
extern int pci_pwr_current_lvl(pci_pwr_t *pwr_p);
extern int pci_pwr_new_lvl(pci_pwr_t *pwr_p);
extern int pci_pwr_ops(pci_pwr_t *pwr_p, dev_info_t *dip, void *impl_arg,
    pm_bus_power_op_t op, void *arg, void *result);
extern pci_pwr_chld_t *pci_pwr_get_info(pci_pwr_t *pwr_p, dev_info_t *);
extern void pci_pwr_create_info(pci_pwr_t *pwr_p, dev_info_t *);
extern void pci_pwr_rm_info(pci_pwr_t *pwr_p, dev_info_t *);
extern void pci_pwr_add_components(pci_pwr_t *pwr_p, dev_info_t *dip,
    pci_pwr_chld_t *p);
extern void pci_pwr_resume(dev_info_t *dip, pci_pwr_t *pwr_p);
extern void pci_pwr_suspend(dev_info_t *dip, pci_pwr_t *pwr_p);
extern void pci_pwr_component_busy(pci_pwr_t *p);
extern void pci_pwr_component_idle(pci_pwr_t *p);
extern void pci_pwr_change(pci_pwr_t *pwr_p, int current, int new);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_PWR_H */
