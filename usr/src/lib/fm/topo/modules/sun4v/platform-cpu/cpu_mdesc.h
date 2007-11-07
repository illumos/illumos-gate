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

#ifndef	_CPU_MDESC_H
#define	_CPU_MDESC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/topo_mod.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Node/Field names in the PRI/MD
 */
#define	MD_STR_ID		"id"
#define	MD_STR_PID		"pid"
#define	MD_STR_CPU_SERIAL	"serial#"
#define	MD_STR_CPU		"cpu"
#define	MD_STR_COMPONENT	"component"
#define	MD_STR_TYPE		"type"
#define	MD_STR_PROCESSOR	"processor"
#define	MD_STR_STRAND		"strand"
#define	MD_STR_FRU		"fru"
#define	MD_STR_NAC		"nac"
#define	MD_STR_SERIAL		"serial_number"
#define	MD_STR_PART		"part_number"
#define	MD_STR_DASH		"dash_number"

#define	MD_FRU_DEF		"MB"
#define	MD_STR_BLANK		""

typedef struct md_cpumap {
	uint32_t cpumap_id;		/* virtual cpuid/strandid */
	uint32_t cpumap_pid;		/* physical cpuid/strandid */
	uint64_t cpumap_serialno;	/* cpu serial number */
	int cpumap_chipidx;		/* chip idx */
} md_cpumap_t;

typedef struct md_fru {
	char *nac;			/* FRU or nac */
	char *serial;			/* FRU serial */
	char *part;			/* FRU part number */
	char *dash;			/* FRU dash */
} md_fru_t;

typedef struct md_proc {
	int32_t id;			/* physiscal id of the CMP processor */
	uint64_t serialno;		/* processor serial number */
	md_fru_t *fru;			/* FRU info */
} md_proc_t;

typedef struct md_info {
	md_proc_t *procs;		/* list of processors */
	uint32_t nprocs;		/* size */
	md_cpumap_t *cpus;		/* List of cpu maps */
	uint32_t ncpus;			/* size */
} md_info_t;


extern int cpu_mdesc_init(topo_mod_t *mod, md_info_t *chip);
extern void cpu_mdesc_fini(topo_mod_t *mod, md_info_t *chip);

extern int cpu_get_serialid_mdesc(md_info_t *chip, uint32_t cpuid,
					uint64_t *serialno);
extern md_cpumap_t *cpu_find_cpumap(md_info_t *chip, uint32_t cpuid);
extern md_proc_t *cpu_find_proc(md_info_t *chip, uint32_t procid);

#ifdef __cplusplus
}
#endif

#endif	/* _CPU_MDESC_H */
