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

/*
 * Copyright 2019 Joyent, Inc.
 */

#ifndef	_PSEXP_H
#define	_PSEXP_H

#include <sys/types.h>
#include <procfs.h>
#include <regex.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include "idtab.h"

#define	PSEXP_EXACT	0x1	/* Match must be exact (entire string) */

typedef struct psexp {
	idtab_t ps_euids;	/* Table of effective uids to match */
	idtab_t ps_ruids;	/* Table of real uids to match */
	idtab_t ps_rgids;	/* Table of real gids to match */
	idtab_t ps_ppids;	/* Table of parent process-ids to match */
	idtab_t ps_pgids;	/* Table of process group-ids to match */
	idtab_t ps_sids;	/* Table of process session-ids to match */
	idtab_t ps_ttys;	/* Table of tty dev_t values to match */
	idtab_t ps_projids;	/* Table of project ids to match */
	idtab_t ps_taskids;	/* Table of task ids to match */
	idtab_t ps_zoneids;	/* Table of zone ids to match */
	idtab_t ps_ctids;	/* Table of contract ids to match */
	const char *ps_pat;	/* Uncompiled fname/argv regexp pattern */
	regex_t ps_reg;		/* Compiled fname/argv regexp */
} psexp_t;

extern void psexp_create(psexp_t *);
extern void psexp_destroy(psexp_t *);
extern int psexp_compile(psexp_t *);
extern int psexp_match(psexp_t *, psinfo_t *, const char *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _PSEXP_H */
