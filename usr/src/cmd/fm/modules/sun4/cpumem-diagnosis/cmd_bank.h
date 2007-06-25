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

#ifndef _CMD_BANK_H
#define	_CMD_BANK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Collections of memory modules are known as banks, and are described by
 * the cmd_bank general-purpose state structure.  The bank structure --
 * cmd_bank_t -- is itself comprised of a persistent (cmd_bank_pers_t) and
 * dynamic (the rest of cmd_bank_t) portions.  While we'd prefer to associate
 * errors with individual modules, some errors (UEs) may only be attributed to
 * a bank of modules.  This structure is used to track the UEs.  Links are made
 * (via bank_dimms) to the known memory modules that comprise the bank.  Note
 * that memory modules are discovered lazily - as ereports naming them are
 * processed.  As such, the bank_dimms list may be empty, or may only list a
 * subset of the modules in the bank.
 *
 * Data structures:
 *
 *     ,--------.       ,--------.
 *     |bank    | <---- |case_ptr| (CMD_PTR_BANK_CASE)
 *     |        |       `--------'
 *     |,-------|       ,-------------.
 *  ,->||asru_t | ----> |packed nvlist|
 *  |  |`-------|       `-------------'
 *  `--| unum   |       ,---------.       ,---------.
 *     | dimms  | ----> |bank_memb| ----> |bank_memb| ----> ...
 *     `--------'       `---------'       `---------'
 *                           |                 |
 *                           V                 V
 *                      dimm buffer       dimm buffer
 *
 * Data structure	P?  Case? Notes
 * ----------------	--- ----- -------------------------------------
 * cmd_bank_pers_t	Yes No    Name is unum-derived ("bank_%s")
 * cmd_case_ptr_t	Yes Yes   Name is case's UUID
 * bank_asru		Yes No    Name is unum-derived ("bank_asru_%d")
 * bank_unum		No  No    Pointer into ASRU - relinked during restore
 * bank_dimms		No  No    Recreated during restore
 */

#include <cmd_mem.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Tracks the discovered DIMMs that make up a given bank.  Only DIMMs that have
 * experienced errors independently of the bank will be included in this list.
 */
typedef struct cmd_bank_memb {
	cmd_list_t bm_list;		/* Memory module list */
	cmd_dimm_t *bm_dimm;		/* This memory module */
} cmd_bank_memb_t;

/*
 * The bank structure started life without a version number.  Making things more
 * complicated, the version number in the new struct occupies the space used for
 * the case pointer in the non-versioned struct.  We therefore have to use
 * somewhat unorthodox version numbers so as to allow us to easily tell the
 * difference between a version number and a case pointer.  Case pointers will
 * be zero or (this being SPARC), a value with the bottom two bits clear.  Our
 * version numbers will begin with 0x11, and will increase by 0x10 each time.
 */

#define	BANK_MKVERSION(version)	((version) << 4 | 1)

#define	CMD_BANK_VERSION_1	BANK_MKVERSION(1)	/* 17 */
#define	CMD_BANK_VERSION	CMD_DIMM_VERSION_1

#define	CMD_BANK_VERSIONED(bank)	((bank)->bank_version & 1)

#define	CMD_BANK_STAT_PREFIX		"b"	/* b = bank */

typedef struct cmd_bank_0 {
	cmd_header_t bank0_header;	/* Nodetype must be CMD_NT_BANK */
	fmd_case_t *bank0_case;		/* Open UE case against this bank */
	cmd_fmri_t bank0_asru;		/* ASRU for this bank */
	const char *bank0_unum;		/* This bank's name (ptr into ASRU) */
	cmd_list_t bank0_dimms;		/* List of discovered DIMMs in bank */
	uint_t bank0_wrnthresh;		/* # of pages retired before warning */
	uint_t bank0_nretired;		/* # ret'd pages for UEs in bank */
} cmd_bank_0_t;

/* Portion of the bank structure which must be persisted */
typedef struct cmd_bank_pers {
	cmd_header_t bankp_header;	/* Nodetype must be CMD_NT_BANK */
	uint_t bankp_version;		/* Version of this persistent buffer */
	cmd_fmri_t bankp_asru;		/* ASRU for this bank */
	uint_t bankp_flags;		/* CMD_MEM_F_* */
	uint_t bankp_nretired;		/* # ret'd pages for UEs in bank */
} cmd_bank_pers_t;

/* Persistent and dynamic bank data */
struct cmd_bank {
	cmd_bank_pers_t bank_pers;	/* Persistent data for this bank */
	const char *bank_unum;		/* This bank's name (ptr into ASRU) */
	cmd_list_t bank_dimms;		/* List of discovered DIMMs in bank */
	cmd_case_t bank_case;		/* Open UE case against this bank */
	fmd_stat_t bank_retstat;	/* Publicizes num of page retirements */
};

#define	CMD_BANK_MAXSIZE \
	MAX(sizeof (cmd_bank_0_t), sizeof (cmd_bank_pers_t))
#define	CMD_BANK_MINSIZE \
	MIN(sizeof (cmd_bank_0_t), sizeof (cmd_bank_pers_t))

#define	bank_header		bank_pers.bankp_header
#define	bank_nodetype		bank_pers.bankp_header.hdr_nodetype
#define	bank_bufname		bank_pers.bankp_header.hdr_bufname
#define	bank_version		bank_pers.bankp_version
#define	bank_asru		bank_pers.bankp_asru
#define	bank_asru_nvl		bank_pers.bankp_asru.fmri_nvl
#define	bank_flags		bank_pers.bankp_flags
#define	bank_nretired		bank_pers.bankp_nretired

extern cmd_bank_t *cmd_bank_lookup(fmd_hdl_t *, nvlist_t *);
extern cmd_bank_t *cmd_bank_create(fmd_hdl_t *, nvlist_t *);

extern nvlist_t *cmd_bank_fru(cmd_bank_t *);
extern nvlist_t *cmd_bank_create_fault(fmd_hdl_t *, cmd_bank_t *, const char *,
    uint_t);

extern void cmd_bank_add_dimm(fmd_hdl_t *, cmd_bank_t *, cmd_dimm_t *);
extern void cmd_bank_remove_dimm(fmd_hdl_t *, cmd_bank_t *, cmd_dimm_t *);

extern void cmd_bank_dirty(fmd_hdl_t *, cmd_bank_t *);
extern void *cmd_bank_restore(fmd_hdl_t *, fmd_case_t *, cmd_case_ptr_t *);
extern void cmd_bank_destroy(fmd_hdl_t *, cmd_bank_t *);
extern void cmd_bank_validate(fmd_hdl_t *);
extern void cmd_bank_gc(fmd_hdl_t *);
extern void cmd_bank_fini(fmd_hdl_t *);

#ifdef __cplusplus
}
#endif

#endif /* _CMD_BANK_H */
