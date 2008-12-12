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

#ifndef _GMEM_DIMM_H
#define	_GMEM_DIMM_H


/*
 * Memory modules are described by the gmem_dimm general-purpose state
 * structure.
 *
 * Data structure	P?  Case? Notes
 * ----------------	--- ----- ----------------------------------------------
 * gmem_dimm_t		Yes No    Name is derived from the serial ("dimm_%s")
 * gmem_case_ptr_t	Yes Yes   Name is case's UUID
 * dimm_asru		Yes No    Name is derived from the serial
 *                                ("dimm_asru_%s")
 * dimm_serial		No  No    Pointer into ASRU - relinked during restore
 */

#include <gmem_mem.h>
#include <values.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * GMEM_MAX_CKWDS denotes the highest number, across all covered
 * SPARC architectures, of checkwords per cache line.
 */

#define	GMEM_MAX_CKWDS	8
#define	FINDRSC		0
#define	FINDFRU		1
#define	FINDASRU	2

#define	DIMM_MKVERSION(version)	(version)

#define	GMEM_DIMM_VERSION_0	DIMM_MKVERSION(0)
#define	GMEM_DIMM_VERSION	GMEM_DIMM_VERSION_0

#define	GMEM_DIMM_VERSIONED(dimm)	((dimm)->dimm_version)

#define	GMEM_DIMM_STAT_PREFIX		"DIMM_"

typedef struct gmem_dimm_pers {
	gmem_header_t dimmp_header;	/* Nodetype must be GMEM_NT_DIMM */
	uint_t dimmp_version;
	gmem_fmri_t dimmp_asru;		/* ASRU for this DIMM */
	uint_t dimmp_flags;		/* GMEM_MEM_F_* */
	uint_t dimmp_nretired;		/* # ret'd pages for CEs in DIMM */
} gmem_dimm_pers_t;

/*
 * Index block for MQSC rules 4A and 4B correlation of memory CEs
 * on a single DIMM. "Unit Position" refers to bit or nibble depending
 * on the memory ECC.  This structure is not persisted.
 */

typedef struct gmem_mq {
	gmem_list_t mq_l;		/* pointers to prev and next */
	uint64_t mq_tstamp;		/* timestamp of ereport in secs */
	uint16_t mq_ckwd;		/* phys addr mod 64 */
	uint64_t mq_phys_addr;		/* from ereport */
	uint16_t mq_unit_position;	/* bit for sun4u, nibble for sun4v */
	int16_t mq_dram;		/* by table lookup from unit pos */
	fmd_event_t *mq_ep;		/* ereport - for potential fault */
	char *mq_serdnm;		/* serd eng to retain CE events */
} gmem_mq_t;

struct gmem_dimm {
	gmem_dimm_pers_t dimm_pers;
	char *dimm_serial;		/* Dimm serial number */
	gmem_case_t dimm_case;		/* Open CE case against this DIMM */
	fmd_stat_t dimm_retstat;	/* retirement statistics, this DIMM */
	gmem_list_t
	    mq_root[GMEM_MAX_CKWDS];	/* per-checkword CEs to correlate */
};

#define	GMEM_MQ_TIMELIM		(72*60*60)	/* 72 hours */
#define	GMEM_MQ_SERDT		MAXINT		/* Never expected to fire */
#define	GMEM_MQ_SERDN		2		/* Dup CEs not allowed */

#define	GMEM_DIMM_MAXSIZE sizeof (gmem_dimm_pers_t)
#define	GMEM_DIMM_MINSIZE sizeof (gmem_dimm_pers_t)

#define	dimm_header		dimm_pers.dimmp_header
#define	dimm_nodetype		dimm_pers.dimmp_header.hdr_nodetype
#define	dimm_bufname		dimm_pers.dimmp_header.hdr_bufname
#define	dimm_version		dimm_pers.dimmp_version
#define	dimm_asru		dimm_pers.dimmp_asru
#define	dimm_asru_nvl		dimm_pers.dimmp_asru.fmri_nvl
#define	dimm_flags		dimm_pers.dimmp_flags
#define	dimm_nretired		dimm_pers.dimmp_nretired

extern gmem_dimm_t *gmem_dimm_lookup(fmd_hdl_t *, nvlist_t *);
extern gmem_dimm_t *gmem_dimm_create(fmd_hdl_t *, nvlist_t *);
extern nvlist_t *gmem_dimm_fru(gmem_dimm_t *);
extern int gmem_dimm_thresh_reached(fmd_hdl_t *, gmem_dimm_t *, uint64_t,
    uint16_t);
extern nvlist_t *gmem_find_dimm_fru(fmd_hdl_t *, char *);
extern nvlist_t *gmem_find_dimm_rsc(fmd_hdl_t *, char *);
extern nvlist_t *gmem_find_dimm_asru(fmd_hdl_t *, char *);
extern int gmem_dimm_present(fmd_hdl_t *, nvlist_t *asru);
extern void gmem_dimm_dirty(fmd_hdl_t *, gmem_dimm_t *);
extern void *gmem_dimm_restore(fmd_hdl_t *, fmd_case_t *, gmem_case_ptr_t *);
extern void gmem_dimm_destroy(fmd_hdl_t *, gmem_dimm_t *);
extern void gmem_dimm_validate(fmd_hdl_t *);
extern void gmem_dimm_gc(fmd_hdl_t *);
extern void gmem_dimm_fini(fmd_hdl_t *);

#ifdef __cplusplus
}
#endif

#endif /* _GMEM_DIMM_H */
