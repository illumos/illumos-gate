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
 * PPPoE Server-mode daemon option parsing.
 *
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef PPPOED_H
#define	PPPOED_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include "common.h"

#ifdef	__cplusplus
extern "C" {
#endif

/* Functions in options.c */
extern void parse_options(int tunfd, int argc, char **argv);
extern int locate_service(poep_t *poep, int plen, const char *iname,
    ppptun_atype *pap, uint32_t *outp, void **srvp);
extern int launch_service(int tunfd, poep_t *poep, void *srvp,
    struct ppptun_control *ptc);
extern void dump_configuration(FILE *fp);

#ifdef	__cplusplus
}
#endif

#endif /* PPPOED_H */
