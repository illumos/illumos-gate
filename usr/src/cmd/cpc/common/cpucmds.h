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

#ifndef	_CPUCMDS_H
#define	_CPUCMDS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "libcpc_impl.h"

extern cpc_set_t *cpc_strtoset(cpc_t *cpc, const char *spec, int smt);
extern cpc_errhndlr_t *strtoset_errfn;
extern int capabilities(cpc_t *cpc, FILE *);
extern int smt_limited_cpc_hw(cpc_t *cpc);
extern void zerotime(void);
extern float mstimestamp(hrtime_t hrt);

/*
 * Request sets can be manipulated in collections called setgroups.
 */
typedef struct __cpc_setgrp cpc_setgrp_t;

extern cpc_setgrp_t *cpc_setgrp_new(cpc_t *cpc, int smt);
extern cpc_setgrp_t *cpc_setgrp_newset(cpc_setgrp_t *sgrp,
    const char *spec, int *errcnt);
extern int cpc_setgrp_getbufs(cpc_setgrp_t *sgrp, cpc_buf_t ***data1,
    cpc_buf_t ***data2, cpc_buf_t ***scratch);
extern cpc_setgrp_t *cpc_setgrp_clone(cpc_setgrp_t *sgrp);
extern void cpc_setgrp_free(cpc_setgrp_t *sgrp);

extern cpc_set_t *cpc_setgrp_getset(cpc_setgrp_t *sgrp);
extern const char *cpc_setgrp_getname(cpc_setgrp_t *sgrp);
extern const char *cpc_setgrp_gethdr(cpc_setgrp_t *sgrp);
extern int cpc_setgrp_numsets(cpc_setgrp_t *sgrp);
extern cpc_set_t *cpc_setgrp_nextset(cpc_setgrp_t *sgrp);
extern void cpc_setgrp_reset(cpc_setgrp_t *to);
extern void cpc_setgrp_accum(cpc_setgrp_t *accum, cpc_setgrp_t *sgrp);
extern int cpc_setgrp_sysonly(cpc_setgrp_t *sgrp);
extern int cpc_setgrp_has_sysonly(cpc_setgrp_t *sgrp);

#ifdef __cplusplus
}
#endif

#endif	/* _CPUCMDS_H */
