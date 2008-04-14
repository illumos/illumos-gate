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
 * Copyright 2008 Sun Microsystems, Inc.
 * All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LINPACK_H
#define	_LINPACK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	DP
#define	PREC	"double"
#define	LINPACK	dlinpack_test
#define	LINSUB	dlinsub
#define	MATGEN	dmatgen
#define	GEFA	dgetrf_64
#define	GESL	dgetrs_64
#define	AXPY	daxpy
#define	SCAL	dscal
#define	IAMAX	diamax
#define	EPSLON	depslon
#define	MXPY	dmxpy
#define	REAL	double
#define	LP_ZERO	0.0e0
#define	LP_ONE	1.0e0

#else

#define	PREC	"single"
#define	LINPACK	slinpack_test
#define	LINSUB	slinsub
#define	MATGEN	smatgen
#define	GEFA	sgetrf_64
#define	GESL	sgetrs_64
#define	AXPY	saxpy
#define	SCAL	sscal
#define	IAMAX	siamax
#define	EPSLON	sepslon
#define	MXPY	smxpy
#define	REAL	float
#define	LP_ZERO	0.0
#define	LP_ONE	1.0

#endif

struct LinpVals {
	REAL  residn;
	REAL  resid;
	REAL  eps;
	REAL  x11;
	REAL  xn1;
};

#undef FPS_LAPA_LIB8
#undef FPS_LAPA_LIB10
#undef FPS_LAPA_LIB11
#undef FPS_LAPA_LIB12
#undef FPS_LAPA_UNK


/* SS12 */
#if (__SUNPRO_C == 0x590)
#define	FPS_LAPA_LIB12

/* SS11 */
#elif (__SUNPRO_C == 0x580)
#define	FPS_LAPA_LIB11

/* SOS10 */
#elif (__SUNPRO_C == 0x570)
#define	FPS_LAPA_LIB10

/* SOS8 */
#elif (__SUNPRO_C == 0x550)
#define	FPS_LAPA_LIB8

#else
#define	FPS_LAPA_UNK
#endif

#ifdef __sparc

/* V9B V9 or V8 arch */
#ifdef V9B
#ifdef FPS_LAPA_LIB8
#include <singdoub64v9b_sos8.h>
#endif

#ifdef FPS_LAPA_LIB10
#include <singdoub64v9b_sos10.h>
#endif

#ifdef FPS_LAPA_LIB11
#include <singdoub64v9b_sos11.h>
#endif

#ifdef FPS_LAPA_LIB12
#include <singdoub64v9b_ss12.h>
#endif

#else

#ifdef FPS_LAPA_LIB8
#include <singdoub64_sos8.h>
#endif

#ifdef FPS_LAPA_LIB10
#include <singdoub64_sos10.h>
#endif

/* This is NOT a typo. singdoub64_sos10.h works with SOS11 */
#ifdef FPS_LAPA_LIB11
#include <singdoub64_sos10.h>
#endif

#ifdef FPS_LAPA_LIB12
#include <singdoub64_ss12.h>
#endif

#endif /* V9B */

#endif

#ifdef __cplusplus
}
#endif

#endif /* _LINPACK_H */
