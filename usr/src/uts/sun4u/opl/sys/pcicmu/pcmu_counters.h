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

#ifndef	_SYS_PCMU_COUNTERS_H
#define	_SYS_PCMU_COUNTERS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	NUM_OF_PICS	2

/*
 * used to build array of event-names and pcr-mask values
 */
typedef struct pcmu_kev_mask {
	char *event_name;			/* Event name */
	uint64_t pcr_mask;			/* PCR mask */
} pcmu_kev_mask_t;

typedef struct pcmu_ksinfo {
	uint8_t	pic_no_evs;			/* number of events */
	uint8_t	pic_shift[NUM_OF_PICS];		/* PIC shift */
	kstat_t	*pic_name_ksp[NUM_OF_PICS];	/* kstat names */
} pcmu_ksinfo_t;

typedef struct pcmu_cntr_addr {
	uint64_t	*pcr_addr;
	uint64_t	*pic_addr;
} pcmu_cntr_addr_t;

typedef struct pcmu_cntr_pa {
	uint64_t	pcr_pa;
	uint64_t	pic_pa;
} pcmu_cntr_pa_t;

/*
 * Prototypes.
 */
extern void pcmu_create_name_kstat(char *, pcmu_ksinfo_t *, pcmu_kev_mask_t *);
extern void pcmu_delete_name_kstat(pcmu_ksinfo_t *);
extern kstat_t *pcmu_create_cntr_kstat(pcmu_t *, char *, int,
	int (*update)(kstat_t *, int), void *);
extern int pcmu_cntr_kstat_update(kstat_t *, int);
extern int pcmu_cntr_kstat_pa_update(kstat_t *, int);
extern void pcmu_kstat_create(pcmu_t *);
extern void pcmu_kstat_destroy(pcmu_t *);
extern void pcmu_rem_upstream_kstat(pcmu_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCMU_COUNTERS_H */
