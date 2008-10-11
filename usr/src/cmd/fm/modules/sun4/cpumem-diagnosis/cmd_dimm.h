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

#ifndef _CMD_DIMM_H
#define	_CMD_DIMM_H

/*
 * Memory modules are described by the cmd_dimm general-purpose state structure.
 * Whereas banks are primarily used to track UEs, this structure is used to
 * track CEs, which can be associated with individual modules.  Each memory
 * module is part of a bank, and will have a link to the bank if the bank is
 * known to the diagnosis engine.  Banks will be known if UEs have occurred.
 *
 * Data structures:
 *
 *     ,--------.       ,--------.
 *     |dimm    | <---- |case_ptr| (CMD_PTR_DIMM_CASE)
 *     |        |       `--------'
 *     |,-------|       ,-------------.
 *  ,->||asru_t | ----> |packed nvlist|
 *  |  |`-------|       `-------------'
 *  `--| unum   |
 *     | bank   | ----> bank buffer
 *     `--------'
 *
 * Data structure	P?  Case? Notes
 * ----------------	--- ----- ----------------------------------------------
 * cmd_dimm_t		Yes No    Name is derived from the unum ("dimm_%s")
 * cmd_case_ptr_t	Yes Yes   Name is case's UUID
 * dimm_asru		Yes No    Name is derived from the unum ("dimm_asru_%d")
 * dimm_unum		No  No    Pointer into ASRU - relinked during restore
 * dimm_bank		No  No    Recreated during restore
 */

#include <cmd_mem.h>
#include <values.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * CMD_MAX_CKWDS denotes the highest number, across all covered
 * SPARC architectures, of checkwords per cache line.
 */

#define	CMD_MAX_CKWDS	4

/*
 * The DIMM structure started life without a version number.  Making things more
 * complicated, the version number in the new struct occupies the space used for
 * the case pointer in the non-versioned struct.  We therefore have to use
 * somewhat unorthodox version numbers so as to allow us to easily tell the
 * difference between a version number and a case pointer.  Case pointers will
 * be zero or (this being SPARC), a value with the bottom two bits clear.  Our
 * version numbers will begin with 0x11, and will increase by 0x10 each time.
 */

#define	DIMM_MKVERSION(version)	((version) << 4 | 1)

#define	CMD_DIMM_VERSION_1	DIMM_MKVERSION(1)	/* 17 */
#define	CMD_DIMM_VERSION	CMD_DIMM_VERSION_1

#define	CMD_DIMM_VERSIONED(dimm)	((dimm)->dimm_version & 1)

#define	CMD_DIMM_STAT_PREFIX		"d"	/* d = dimm */

typedef struct cmd_dimm_0 {
	cmd_header_t dimm0_header;	/* Nodetype must be CMD_NT_DIMM */
	fmd_case_t *dimm0_case;		/* Open CE case against this DIMM */
	cmd_fmri_t dimm0_asru;		/* ASRU for this DIMM */
	const char *dimm0_unum;		/* This DIMM's name */
	uint_t dimm0_wrnthresh;		/* # of pages retired before warning */
	uint_t dimm0_nretired;		/* # ret'd pages for CEs in DIMM */
	cmd_bank_t *dimm0_bank;		/* This DIMM's bank (if discovered) */
} cmd_dimm_0_t;

typedef struct cmd_dimm_pers {
	cmd_header_t dimmp_header;	/* Nodetype must be CMD_NT_DIMM */
	uint_t dimmp_version;
	cmd_fmri_t dimmp_asru;		/* ASRU for this DIMM */
	uint_t dimmp_flags;		/* CMD_MEM_F_* */
	uint_t dimmp_nretired;		/* # ret'd pages for CEs in DIMM */
} cmd_dimm_pers_t;

/*
 * Index block for MQSC rules 4A and 4B correlation of memory CEs
 * on a single DIMM. "Unit Position" refers to bit or nibble depending
 * on the memory ECC.  This structure is not persisted.
 */

typedef struct cmd_mq {
	cmd_list_t mq_l;		/* pointers to prev and next */
	uint64_t mq_tstamp;		/* timestamp of ereport in secs */
	uint16_t mq_ckwd;		/* phys addr mod 64 */
	uint64_t mq_phys_addr;		/* from ereport */
	uint16_t mq_unit_position;	/* bit for sun4u, nibble for sun4v */
	uint16_t mq_dram;		/* by table lookup from unit pos */
	fmd_event_t *mq_ep;		/* ereport - for potential fault */
	char *mq_serdnm;		/* serd eng to retain CE events */
} cmd_mq_t;

struct cmd_dimm {
	cmd_dimm_pers_t dimm_pers;
	cmd_bank_t *dimm_bank;		/* This DIMM's bank (if discovered) */
	const char *dimm_unum;		/* This DIMM's name */
	cmd_case_t dimm_case;		/* Open CE case against this DIMM */
	fmd_stat_t dimm_retstat;	/* retirement statistics, this DIMM */
	cmd_list_t
	    mq_root[CMD_MAX_CKWDS];	/* per-checkword CEs to correlate */
};

#define	CMD_MQ_SERDT	MAXINT		/* Never expected to fire */
#define	CMD_MQ_SERDN	2		/* Dup CEs not allowed */

#define	CMD_DIMM_MAXSIZE \
	MAX(sizeof (cmd_dimm_0_t), sizeof (cmd_dimm_pers_t))
#define	CMD_DIMM_MINSIZE \
	MIN(sizeof (cmd_dimm_0_t), sizeof (cmd_dimm_pers_t))

#define	dimm_header		dimm_pers.dimmp_header
#define	dimm_nodetype		dimm_pers.dimmp_header.hdr_nodetype
#define	dimm_bufname		dimm_pers.dimmp_header.hdr_bufname
#define	dimm_version		dimm_pers.dimmp_version
#define	dimm_asru		dimm_pers.dimmp_asru
#define	dimm_asru_nvl		dimm_pers.dimmp_asru.fmri_nvl
#define	dimm_flags		dimm_pers.dimmp_flags
#define	dimm_nretired		dimm_pers.dimmp_nretired

extern cmd_dimm_t *cmd_dimm_lookup(fmd_hdl_t *, nvlist_t *);
extern cmd_dimm_t *cmd_dimm_create(fmd_hdl_t *, nvlist_t *);

extern nvlist_t *cmd_dimm_fru(cmd_dimm_t *);
extern nvlist_t *cmd_dimm_create_fault(fmd_hdl_t *, cmd_dimm_t *, const char *,
    uint_t);
#ifdef sun4v
extern nvlist_t *cmd_mem2hc(fmd_hdl_t *, nvlist_t *);
#endif /* sun4v */

extern nvlist_t *cmd_dimm_fmri_derive(fmd_hdl_t *, uint64_t, uint16_t,
    uint64_t);
extern int cmd_dimm_thresh_reached(fmd_hdl_t *, cmd_dimm_t *, uint64_t,
    uint16_t);

extern void cmd_dimm_dirty(fmd_hdl_t *, cmd_dimm_t *);
extern void *cmd_dimm_restore(fmd_hdl_t *, fmd_case_t *, cmd_case_ptr_t *);
extern void cmd_dimm_destroy(fmd_hdl_t *, cmd_dimm_t *);
extern void cmd_dimm_validate(fmd_hdl_t *);
extern void cmd_dimm_gc(fmd_hdl_t *);
extern void cmd_dimm_fini(fmd_hdl_t *);

extern void cmd_dimmlist_free(fmd_hdl_t *);

#ifdef __cplusplus
}
#endif

#endif /* _CMD_DIMM_H */
