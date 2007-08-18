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

#ifndef	_ERRFP_H
#define	_ERRFP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Headers and definitions for support functions that are shared by
 * the ipsec utilities ipseckey and ikeadm.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdarg.h>

/*
 * Function Prototypes
 */

#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname	errfp		_errfp
#pragma	redefine_extname	verrfp		_verrfp
#pragma	redefine_extname	errxfp		_errxfp
#pragma	redefine_extname	verrxfp		_verrxfp
#pragma	redefine_extname	warnfp		_warnfp
#pragma	redefine_extname	vwarnfp		_vwarnfp
#pragma	redefine_extname	warnxfp		_warnxfp
#pragma	redefine_extname	vwarnxfp	_vwarnxfp
#else
#define	errfp		_errfp
#define	verrfp		_verrfp
#define	errxfp		_errxfp
#define	verrxfp		_verrxfp
#define	warnfp		_warnfp
#define	vwarnfp		_vwarnfp
#define	warnxfp		_warnxfp
#define	vwarnxfp	_vwarnxfp
#endif

/* Program exit and warning calls */
extern void errfp(FILE *, int, const char *, ...);
extern void verrfp(FILE *, int, const char *, va_list);
extern void errxfp(FILE *, int, const char *, ...);
extern void verrxfp(FILE *, int, const char *, va_list);
extern void warnfp(FILE *, const char *, ...);
extern void vwarnfp(FILE *, const char *, va_list);
extern void warnxfp(FILE *, const char *, ...);
extern void vwarnxfp(FILE *, const char *, va_list);

#ifdef __cplusplus
}
#endif

#endif	/* _ERRFP_H */
