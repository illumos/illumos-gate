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

#ifndef _CMD_HC_SUN4V_H
#define	_CMD_HC_SUN4V_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/fmd_api.h>
#include <sys/nvpair.h>
#include <cmd_cpu.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	CPUBOARD	"MB/CPU"
#define	EMPTY_STR	"-"

extern nvlist_t *cmd_fault_add_location(fmd_hdl_t *, nvlist_t *, const char *);
extern nvlist_t *cmd_boardfru_create_fault(fmd_hdl_t *, nvlist_t *,
    const char *, uint_t, char *);
extern nvlist_t *init_mb(fmd_hdl_t *);
extern nvlist_t *cmd_find_dimm_by_sn(fmd_hdl_t *, char *, char *);
extern char *cmd_getfru_loc(fmd_hdl_t *, nvlist_t *);
extern int cmd_count_components(const char *, char sep);
extern int cmd_breakup_components(char *, char *, nvlist_t **);
extern nvlist_t *cmd_mkboard_fru(fmd_hdl_t *, char *, char *, char *);

#ifdef __cplusplus
}
#endif

#endif /* _CMD_HC_SUN4V_H */
