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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_PCI_COUNTERS_H
#define	_SYS_PCI_COUNTERS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	NUM_OF_PICS	2

/*
 * used to build array of event-names and pcr-mask values
 */
typedef struct pci_kev_mask {
	char *event_name;
	uint64_t pcr_mask;
} pci_kev_mask_t;

typedef struct pci_ksinfo {
	uint8_t	pic_no_evs;	/* number of events */
	uint8_t	pic_shift[NUM_OF_PICS];
	kstat_t	*pic_name_ksp[NUM_OF_PICS];
} pci_ksinfo_t;

typedef struct pci_cntr_addr {
	uint64_t	*pcr_addr;
	uint64_t	*pic_addr;
} pci_cntr_addr_t;

typedef struct pci_cntr_pa {
	uint64_t	pcr_pa;
	uint64_t	pic_pa;
} pci_cntr_pa_t;

extern void pci_create_name_kstat(char *, pci_ksinfo_t *, pci_kev_mask_t *);
extern void pci_delete_name_kstat(pci_ksinfo_t *);

extern kstat_t *pci_create_cntr_kstat(pci_t *, char *, int,
	int (*update)(kstat_t *, int), void *);

extern int pci_cntr_kstat_update(kstat_t *, int);
extern int pci_cntr_kstat_pa_update(kstat_t *, int);

extern void pci_kstat_create(pci_t *);
extern void pci_kstat_destroy(pci_t *);
extern void pci_rem_upstream_kstat(pci_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_COUNTERS_H */
