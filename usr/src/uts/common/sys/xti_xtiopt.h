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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_XTI_XTIOPT_H
#define	_SYS_XTI_XTIOPT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * OPTIONS ON XTI LEVEL
 *
 * Note:
 * Unfortunately, XTI specification test assertions require exposing in
 * headers options that are not implemented. They also require exposing
 * Internet and OSI related options as part of inclusion of <xti.h>
 */

/* XTI level */

#define	XTI_GENERIC	0xfffe

/*
 * XTI-level Options
 */

#define	XTI_DEBUG		0x0001 /* enable debugging */
#define	XTI_LINGER		0x0080 /* linger on close if data present */
#define	XTI_RCVBUF		0x1002 /* receive buffer size */
#define	XTI_RCVLOWAT		0x1004 /* receive low water mark */
#define	XTI_SNDBUF		0x1001 /* send buffer size */
#define	XTI_SNDLOWAT		0x1003 /* send low-water mark */


/*
 * Structure used with linger option.
 */

struct t_linger {
	t_scalar_t	l_onoff;	/* option on/off */
	t_scalar_t	l_linger;	/* linger time */
};


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_XTI_XTIOPT_H */
