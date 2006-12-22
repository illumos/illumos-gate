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

#ifndef _CMD_PAGE_H
#define	_CMD_PAGE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routines for the creation of page retirement faults and for the management of
 * page-related state.
 */

#include <cmd_state.h>
#include <cmd_fmri.h>

#include <fm/fmd_api.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	PAGE_MKVERSION(version)	((version) << 4 | 1)

#define	CMD_PAGE_VERSION_1	PAGE_MKVERSION(1)	/* 17 */
#define	CMD_PAGE_VERSION	CMD_PAGE_VERSION_1

#define	CMD_PAGE_VERSIONED(page)	((page)->page_version & 1)

typedef struct cmd_page_0 {
	cmd_header_t page0_header;	/* Nodetype must be CMD_NT_PAGE */
	fmd_case_t *page0_case;		/* Open ret. case against this page */
	cmd_fmri_t page0_asru;		/* ASRU for this page */
	uint64_t page0_physbase;	/* Base phys addr for this page */
} cmd_page_0_t;

typedef struct cmd_page_pers {
	cmd_header_t pagep_header;	/* Nodetype must be CMD_NT_PAGE */
	uint_t pagep_version;
	cmd_fmri_t pagep_asru;		/* ASRU for this DIMM */
	uint64_t pagep_physbase;	/* base phys addr for page */
	uint_t pagep_flags;		/* CMD_MEM_F_* */
} cmd_page_pers_t;

typedef struct cmd_page {
	cmd_page_pers_t page_pers;
	cmd_case_t page_case;		/* Open CE case against this page */
} cmd_page_t;

#define	CMD_PAGE_MAXSIZE \
	MAX(sizeof (cmd_page_0_t), sizeof (cmd_page_pers_t))
#define	CMD_PAGE_MINSIZE \
	MIN(sizeof (cmd_page_0_t), sizeof (cmd_page_pers_t))

#define	page_header		page_pers.pagep_header
#define	page_nodetype		page_pers.pagep_header.hdr_nodetype
#define	page_bufname		page_pers.pagep_header.hdr_bufname
#define	page_version		page_pers.pagep_version
#define	page_asru		page_pers.pagep_asru
#define	page_asru_nvl		page_pers.pagep_asru.fmri_nvl
#define	page_flags		page_pers.pagep_flags
#define	page_physbase		page_pers.pagep_physbase
#define	page_list		page_header.hdr_list

/*
 * Page retirement
 *
 * When a page is to be retired, these routines are called to generate and
 * manage a fault.memory.page against the page.
 */
extern void cmd_page_fault(fmd_hdl_t *, nvlist_t *, nvlist_t *, fmd_event_t *,
    uint64_t);
extern void cmd_page_close(fmd_hdl_t *, void *);

extern cmd_page_t *cmd_page_create(fmd_hdl_t *, nvlist_t *, uint64_t);
extern cmd_page_t *cmd_page_lookup(uint64_t);

extern void cmd_page_dirty(fmd_hdl_t *, cmd_page_t *);
extern void *cmd_page_restore(fmd_hdl_t *, fmd_case_t *, cmd_case_ptr_t *);
extern void cmd_page_validate(fmd_hdl_t *);
extern void cmd_page_destroy(fmd_hdl_t *, cmd_page_t *);
extern void cmd_page_fini(fmd_hdl_t *);

#ifdef __cplusplus
}
#endif

#endif /* _CMD_PAGE_H */
