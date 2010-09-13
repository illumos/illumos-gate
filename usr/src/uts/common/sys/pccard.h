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
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * PCMCIA PC Card client driver master header file
 *
 * All PC Card client drivers must include this header file
 */

#ifndef _PCCARD_H
#define	_PCCARD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kmem.h>

#ifdef	_KERNEL
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/devops.h>
#endif	/* _KERNEL */

#include <sys/dditypes.h>
#include <sys/modctl.h>

#include <sys/pctypes.h>
#include <sys/cs_types.h>
#include <sys/cis.h>
#include <sys/cis_handlers.h>
#include <sys/cs.h>

#ifdef	__cplusplus
}
#endif

#endif	/* _PCCARD_H */
