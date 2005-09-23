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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
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
#include <cmd_mem.h>

#include <fm/fmd_api.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cmd_page {
	cmd_header_t page_header;	/* Nodetype must be CMD_NT_PAGE */
	fmd_case_t *page_case;		/* Open ret. case against this page */
	cmd_fmri_t page_asru;		/* ASRU for this page */
	uint64_t page_physbase;		/* Base phys addr for this page */
} cmd_page_t;

#define	page_list		page_header.hdr_list
#define	page_nodetype		page_header.hdr_nodetype
#define	page_bufname		page_header.hdr_bufname
#define	page_asru_nvl		page_asru.fmri_nvl

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

extern void *cmd_page_restore(fmd_hdl_t *, fmd_case_t *, cmd_case_ptr_t *);
extern void cmd_page_validate(fmd_hdl_t *);
extern void cmd_page_destroy(fmd_hdl_t *, cmd_page_t *);
extern void cmd_page_fini(fmd_hdl_t *);

#ifdef __cplusplus
}
#endif

#endif /* _CMD_PAGE_H */
