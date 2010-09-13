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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _CMD_DP_PAGE_H
#define	_CMD_DP_PAGE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <cmd.h>
#include <cmd_page.h>
#include <cmd_dp.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cmd_dp_defer {
	cmd_header_t dp_defer_hdr;
	cmd_page_t *dp_defer_page;	/* ptr to cmd_page_t of deferred page */
	int dp_defer_mcids[DP_MAX_MCS]; /* mem ctrl ids for AFARs seen */
} cmd_dp_defer_t;

extern void cmd_dp_page_defer(fmd_hdl_t *, nvlist_t *, fmd_event_t *,
    uint64_t);
extern void cmd_dp_page_replay(fmd_hdl_t *);
extern void cmd_dp_page_restore(fmd_hdl_t *, cmd_page_t *);
extern void cmd_dp_page_validate(fmd_hdl_t *);
extern int cmd_dp_page_isdeferred(fmd_hdl_t *, cmd_page_t *);

#ifdef __cplusplus
}
#endif

#endif /* _CMD_DP_PAGE_H */
