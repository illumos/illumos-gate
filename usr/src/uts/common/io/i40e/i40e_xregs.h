/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

#ifndef _I40E_XREGS_H
#define	_I40E_XREGS_H

/*
 * This file contains extra register definitions and other things that would
 * nominally come from the Intel common code, but do not due to bugs, erratum,
 * etc. Ideally we'll get to a point where we can remove this file.
 */
#include "i40e_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The MSPDC register is missing from the current datasheet.
 */
#define	I40E_GLPRT_MSPDC(_i)		(0x00300060 + ((_i) * 8)) /* _i=0...3 */
#define	I40E_GLPRT_MSDPC_MAX_INDEX	3
#define	I40E_GLPRT_MSPDC_MSPDC_SHIFT	0
#define	I40E_GLPRT_MSPDC_MSPDC_MASK	\
	I40E_MASK(0xFFFFFFFF, I40E_GLPRT_MSPDC_MSPDC_SHIFT)

/*
 * The RXERR* registers are technically correct from the perspective of their
 * addreses; however, the other associated constants are not correct. Instead,
 * we have new definitions here in the interim.
 */

#define	I40E_X_GL_RXERR1_L(_i)		(0x00318000 + ((_i) * 8))

#define	I40E_X_GL_RXERR2_L(_i)		(0x0031c000 + ((_i) * 8))

#ifdef __cplusplus
}
#endif

#endif /* _I40E_XREGS_H */
