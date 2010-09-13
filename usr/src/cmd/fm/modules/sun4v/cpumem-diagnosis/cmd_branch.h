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

#ifndef _CMD_BRANCH_H
#define	_CMD_BRANCH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Memory modules are described by the cmd_branch general-purpose state
 * structure.  This structure is used to track FBR errors
 *
 * Data structures:
 *
 *     ,--------.       ,--------.
 *     |branch  | <---- |case_ptr| (CMD_PTR_BRANCH_CASE)
 *     |        |       `--------'
 *     |,-------|       ,-------------.
 *  ,->||asru_t | ----> |packed nvlist|
 *  |  |`-------|       `-------------'
 *  `--|        |
 *     | dimms  | ----> cmd_branch_memb_t -----> cmd_branch_memb_t -----> ...
 *     `--------'            |                        |
 *                      cmd_dimm_t                cmd_dimm_t
 *
 * Data structure	P?  Case? Notes
 * ----------------	--- ----- ----------------------------------------------
 * cmd_branch_pers_t	Yes No    Name is derived from the unum ("branch_%s")
 * cmd_case_ptr_t	Yes Yes   Name is case's UUID
 * branch_asru		Yes No    Name is derived from the unum
 *                                ("branch_asru_%d")
 * branch_unum		No  No    Pointer into ASRU - relinked during restore
 * branch_dimms		No  No    Recreated during restore
 */

#include <cmd_mem.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	MAX_CHANNELS_ON_CHIP	4
#define	MAX_DIMMS_IN_CHANNEL	4
#define	BTK_MAX_CHANNEL		2
#define	CMD_BOARDS_CERT		30

typedef struct cmd_branch_memb {
	cmd_list_t bm_list;
	cmd_dimm_t *dimm;
} cmd_branch_memb_t;

#define	CMD_BRANCH_VERSION_0	0
#define	CMD_BRANCH_VERSION	CMD_BRANCH_VERSION_0

typedef struct cmd_branch_pers {
	cmd_header_t branchp_header;	/* Nodetype must be CMD_NT_BRANCH */
	uint_t branchp_version;
	cmd_fmri_t branchp_asru;	/* ASRU for this BRANCH */
	uint_t branchp_flags;		/* CMD_MEM_F_* */
} cmd_branch_pers_t;

struct cmd_branch {
	cmd_branch_pers_t branch_pers;
	const char *branch_unum;	/* This BRANCH's name */
	cmd_case_t branch_case;		/* Open link errors case against */
					/* this BRANCH */
	cmd_list_t branch_dimms;	/* This BRANCH's dimms */
};

#define	CMD_BRANCH_MAXSIZE	sizeof (cmd_branch_pers_t)
#define	CMD_BRANCH_MINSIZE	sizeof (cmd_branch_pers_t)

#define	branch_header		branch_pers.branchp_header
#define	branch_nodetype		branch_pers.branchp_header.hdr_nodetype
#define	branch_bufname		branch_pers.branchp_header.hdr_bufname
#define	branch_version		branch_pers.branchp_version
#define	branch_asru		branch_pers.branchp_asru
#define	branch_asru_nvl		branch_pers.branchp_asru.fmri_nvl
#define	branch_flags		branch_pers.branchp_flags

extern cmd_branch_t *cmd_branch_lookup(fmd_hdl_t *, nvlist_t *);
extern cmd_branch_t *cmd_branch_create(fmd_hdl_t *, nvlist_t *);
extern cmd_branch_t *cmd_branch_lookup_by_unum(fmd_hdl_t *, const char *);

extern void cmd_branch_create_fault(fmd_hdl_t *, cmd_branch_t *,
    const char *, nvlist_t *);
extern void cmd_branch_add_dimm(fmd_hdl_t *, cmd_branch_t *, cmd_dimm_t *);
extern void cmd_branch_remove_dimm(fmd_hdl_t *, cmd_branch_t *, cmd_dimm_t *);


extern void *cmd_branch_restore(fmd_hdl_t *, fmd_case_t *, cmd_case_ptr_t *);
extern void cmd_branch_destroy(fmd_hdl_t *, cmd_branch_t *);
extern void cmd_branch_validate(fmd_hdl_t *);
extern void cmd_branch_gc(fmd_hdl_t *);
extern void cmd_branch_fini(fmd_hdl_t *);
extern void cmd_branch_dirty(fmd_hdl_t *, cmd_branch_t *);


#ifdef __cplusplus
}
#endif

#endif /* _CMD_BRANCH_H */
