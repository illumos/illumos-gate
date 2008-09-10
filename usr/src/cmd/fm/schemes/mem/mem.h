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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MEM_H
#define	_MEM_H

#include <sys/types.h>
#include <sys/nvpair.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * FMRI plugin for the `mem' scheme.
 *
 * The mem scheme can be used to name individual memory modules, as well as
 * groups of memory modules, also known as banks.  The name `dimm' is used as a
 * synonym for individual memory modules, for no good reason.  Mem FMRIs can
 * be further refined with the addition of a member which identifies a
 * particular physical page within the bank or DIMM.  The named page is as
 * viewed by the VM system, and may thus span multiple memory modules.  It will,
 * however, be at least partially contained by the named bank or DIMM.
 *
 * Memory modules are identified by two things - their physical position, or
 * slot, in the machine, and their serial number.  DIMMs are identified by this
 * tuple on platforms which support the retrieval of serial numbers.  Platforms
 * which don't have this support rely on the slot number, with the corresponding
 * degradation in their ability to detect hardware changees.
 *
 * The physical location is embodied by the unum, which is highly specific to
 * each platform, and bears a passing resemblance to the name of the slot, as
 * printed on the actual hardware.  The unum is mapped to a DIMM-specific
 * device, which is then read to determine the serial number.  See mem_disc.c
 * for details of the process by which unums are mapped to devices, and
 * mem_read.c for the code which actually retrieves the serial number from the
 * device.
 *
 * Banks are also identified by unums, which must be broken apart into the
 * unums which identify each constituent memory module.  Serial numbers are
 * retrieved for banks - one per member module - in the same way as for
 * individual modules.  See mem_unum.c for the code which bursts bank unums.
 *
 * Serial number retrieval, on platforms which support it, is very expensive
 * (on the order of several tenths of a second, which adds up in a hurry on
 * larger machines).  So, while we pre-generate the list of DIMM device paths,
 * we only read their serial numbers when requested by plugin consumers.  To
 * further reduce the perceived cost, we don't re-read until/unless we detect
 * that a DR operation has taken place.
 *
 * Using the facilities described above, the plugin implements the following
 * entry points: (see mem.c)
 *
 *   - nvl2str: The printed representation of the named bank or DIMM is
 *     generated.  No attempt is made to determine whether or not the named
 *     item is still present in the system.
 *
 *   - expand: For platforms which do not include bank or DIMM
 *     serial numbers in their ereports, this entry point will read the
 *     serial number(s) for the named item, and will add it/them to the passed
 *     FMRI.  Errors will be returned if the FMRI (unum) was unparseable, or if
 *     the serial number could not be retrieved.
 *
 *   - present: Given a mem-schemed FMRI with a serial number, this entry
 *     point will attempt to determine whether the bank or module named in the
 *     FMRI is still present in the system at the same location.  Programmer
 *     errors (invalid FMRIs) will be signalled to the caller.  Warnings will
 *     be emitted for otherwise-valid FMRIs whose serial numbers could not be
 *     read, with the caller told that the FMRI is not present.
 *
 *   - contains: Used to determine whether a given bank contains a given DIMM.
 *     No attempt is made to determine whether the module named by the FMRIs are
 *     actually present in the system.  Programmer errors (invalidd FMRIs) will
 *     be returned to the caller.  Warnings will be emitted for otherwise-valid
 *     FMRIs whose relationship could not be determined, with the caller told
 *     that there is no relationship.
 */

/*
 * 18+nul for SPD, 6+nul for SEEPROM, 15+nul max for Serengeti, Starcat, LW8.
 * 18 for Sun Partnumber, 18 partner partnumber, 12 serialnumber for OPL.
 */
#define	MEM_SERID_MAXLEN	64
#define	MAX_DIMMS_PER_BANK	4

typedef struct mem_dimm_map {
	struct mem_dimm_map *dm_next;	/* The next DIMM map */
	char *dm_label;			/* The UNUM for this DIMM */
	char *dm_device;		/* Path to I2C device for DIMM */
	char dm_serid[MEM_SERID_MAXLEN]; /* Cached serial number */
	char *dm_part;			/* DIMM part number */
	uint64_t dm_drgen;		/* DR gen count for cached S/N */
} mem_dimm_map_t;

typedef struct mem_bank_map {
	struct mem_bank_map *bm_next;	/* the next bank map overall */
	struct mem_bank_map *bm_grp;	/* next bank map in group */
	uint64_t	bm_mask;
	uint64_t	bm_match;
	uint16_t	bm_shift;	/* dimms-per-reference shift */
	mem_dimm_map_t *bm_dimm[MAX_DIMMS_PER_BANK];
} mem_bank_map_t;

typedef struct mem_grp {
	struct mem_grp *mg_next;
	size_t		mg_size;
	mem_bank_map_t *mg_bank;
} mem_grp_t;

typedef struct mem_seg_map {
	struct mem_seg_map *sm_next;	/* the next segment map */
	uint64_t	sm_base;	/* base address for this segment */
	uint64_t	sm_size;	/* size for this segment */
	mem_grp_t	*sm_grp;
} mem_seg_map_t;


typedef struct mem {
	mem_dimm_map_t *mem_dm;		/* List supported DIMMs */
	uint64_t mem_memconfig;		/* HV memory-configuration-id# */
	mem_seg_map_t *mem_seg;		/* list of defined segments */
	mem_bank_map_t *mem_bank;
	mem_grp_t *mem_group;		/* groups of banks for a segment */
} mem_t;

extern int mem_discover(void);
extern int mem_get_serid(const char *, char *, size_t);
extern int mem_get_serids_by_unum(const char *, char ***, size_t *);
extern void mem_expand_opt(nvlist_t *, char *, char **);

extern int mem_unum_burst(const char *, char ***, size_t *);
extern int mem_unum_contains(const char *, const char *);
extern int mem_unum_rewrite(nvlist_t *, nvlist_t **);

extern void mem_strarray_free(char **, size_t);

extern mem_t mem;

#ifdef __cplusplus
}
#endif

#endif /* _MEM_H */
