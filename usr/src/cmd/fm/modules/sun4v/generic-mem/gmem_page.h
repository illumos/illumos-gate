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

#ifndef _GMEM_PAGE_H
#define	_GMEM_PAGE_H


/*
 * Routines for the creation of page retirement faults and for the management of
 * page-related state.
 */

#include <gmem_state.h>
#include <gmem_fmri.h>

#include <fm/fmd_api.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	PAGE_MKVERSION(version)	(version)

#define	CMD_PAGE_VERSION_0	PAGE_MKVERSION(0)
#define	CMD_PAGE_VERSION	CMD_PAGE_VERSION_0

#define	CMD_PAGE_VERSIONED(page)	((page)->page_version)

typedef struct gmem_page_pers {
	gmem_header_t pagep_header;	/* Nodetype must be CMD_NT_PAGE */
	uint_t pagep_version;
	gmem_fmri_t pagep_asru;		/* ASRU for this DIMM */
	uint64_t pagep_physbase;	/* base phys addr for page */
	uint64_t pagep_offset;		/* page offset */
	uint_t pagep_flags;		/* CMD_MEM_F_* */
} gmem_page_pers_t;

typedef struct gmem_page {
	gmem_page_pers_t page_pers;
	gmem_case_t page_case;		/* Open CE case against this page */
} gmem_page_t;

#define	CMD_PAGE_MAXSIZE sizeof (gmem_page_pers_t)
#define	CMD_PAGE_MINSIZE sizeof (gmem_page_pers_t)

#define	page_header		page_pers.pagep_header
#define	page_nodetype		page_pers.pagep_header.hdr_nodetype
#define	page_bufname		page_pers.pagep_header.hdr_bufname
#define	page_version		page_pers.pagep_version
#define	page_asru		page_pers.pagep_asru
#define	page_asru_nvl		page_pers.pagep_asru.fmri_nvl
#define	page_flags		page_pers.pagep_flags
#define	page_physbase		page_pers.pagep_physbase
#define	page_offset		page_pers.pagep_offset
#define	page_list		page_header.hdr_list

/*
 * Page retirement
 *
 * When a page is to be retired, these routines are called to generate and
 * manage a fault.memory.page against the page.
 */
extern int gmem_page_fault(fmd_hdl_t *, nvlist_t *, nvlist_t *, fmd_event_t *,
    uint64_t, uint64_t);
extern void gmem_page_close(fmd_hdl_t *, void *);

extern gmem_page_t *gmem_page_create(fmd_hdl_t *, nvlist_t *, uint64_t,
    uint64_t);
extern gmem_page_t *gmem_page_lookup(uint64_t);

extern void gmem_page_dirty(fmd_hdl_t *, gmem_page_t *);
extern void *gmem_page_restore(fmd_hdl_t *, fmd_case_t *, gmem_case_ptr_t *);
extern void gmem_page_validate(fmd_hdl_t *);
extern void gmem_page_destroy(fmd_hdl_t *, gmem_page_t *);
extern void gmem_page_fini(fmd_hdl_t *);

#ifdef __cplusplus
}
#endif

#endif /* _GMEM_PAGE_H */
