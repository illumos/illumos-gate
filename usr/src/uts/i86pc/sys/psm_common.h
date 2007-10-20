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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PSM_COMMON_H
#define	_SYS_PSM_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>

#include <sys/sunddi.h>
#include <sys/ddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci.h>
#include <sys/debug.h>

#ifdef	__cplusplus
extern "C" {
#endif


/* private data used in psm_common */
typedef struct acpi_prs_private {
	uchar_t		prs_irqflags;
	uchar_t		prs_type;
} acpi_prs_private_t;


typedef struct acpi_psm_lnk {
	ACPI_HANDLE	lnkobj;
	acpi_prs_private_t acpi_prs_prv;
	uchar_t		device_status;
} acpi_psm_lnk_t;

typedef void (*intr_exit_fn_t)(int prev_ipl, int irq);

/*
 * status definition for device_status (as returned by _STA)
 */
#define	STA_PRESENT	0x1
#define	STA_ENABLE	0x2


/*
 * irq_cache_t: Entry for irq cache to map pci bus/dev/ipin or ACPI object
 * referencing an interrupt link device the configured irq for the device.
 * It is assumed that the acpi object that references the link device is
 * the same for all devices that reference the same link device.
 */
typedef struct irq_cache {
	uchar_t bus, dev;
	uchar_t ipin;
	uchar_t irq;
	iflag_t flags;
	ACPI_HANDLE	lnkobj;
} irq_cache_t;


typedef struct acpi_irqlist {
	acpi_prs_private_t acpi_prs_prv;
	iflag_t intr_flags;
	uint32_t *irqs;
	int num_irqs;
	struct acpi_irqlist *next;
} acpi_irqlist_t;


#define	MAX_ISA_IRQ 15

#define	ELCR_PORT1	0x4D0
#define	ELCR_PORT2	0x4D1

#define	ELCR_LEVEL(elcrval, irq)	(elcrval & (0x1 << irq))
#define	ELCR_EDGE(elcrval, irq)		((elcrval & (0x1 << irq)) == 0)


#define	ACPI_PSM_SUCCESS	0
#define	ACPI_PSM_FAILURE	-1
#define	ACPI_PSM_PARTIAL 	-2

/* verbose flags definitions */
#define	PSM_VERBOSE_IRQ_FLAG			0x00000001
#define	PSM_VERBOSE_POWEROFF_FLAG		0x00000002
#define	PSM_VERBOSE_POWEROFF_PAUSE_FLAG		0x00000004

extern int acpi_psm_init(char *module_name, int verbose_flags);

extern void build_reserved_irqlist(uchar_t *reserved_irqs_table);

extern int acpi_translate_pci_irq(dev_info_t *dip, int ipin, int *pci_irqp,
    iflag_t *intr_flagp, acpi_psm_lnk_t *acpipsmlnkp);

extern int acpi_set_irq_resource(acpi_psm_lnk_t *acpipsmlnkp, int irq);

extern int acpi_get_current_irq_resource(acpi_psm_lnk_t *acpipsmlnkp,
    int *pci_irqp, iflag_t *intr_flagp);

extern int acpi_irqlist_find_irq(acpi_irqlist_t *irqlistp, int irq,
    iflag_t *intr_flagp);

extern void acpi_free_irqlist(acpi_irqlist_t *irqlistp);

extern int acpi_get_possible_irq_resources(acpi_psm_lnk_t *acpipsmlnkp,
    acpi_irqlist_t **irqlistp);

extern void acpi_new_irq_cache_ent(int bus, int dev, int ipin, int pci_irq,
    iflag_t *intr_flagp, acpi_psm_lnk_t *acpipsmlnkp);

extern int acpi_get_irq_cache_ent(uchar_t bus, uchar_t dev, int ipin,
    int *pci_irqp, iflag_t *intr_flagp);

extern void acpi_restore_link_devices(void);

extern int acpi_poweroff(void);

extern void psm_set_elcr(int vecno, int val);
extern int psm_get_elcr(int vecno);
extern intr_exit_fn_t psm_intr_exit_fn(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PSM_COMMON_H */
