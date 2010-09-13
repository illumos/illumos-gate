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
 * Copyright (c) 1996-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_UNCTRL_H
#define	_UNCTRL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * unctrl.h
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * $Header: /rd/src/libc/xcurses/rcs/unctrl.h 1.2 1995/05/25 17:57:16 ant Exp $
 */

#include <sys/isa_defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_CHTYPE
#define	_CHTYPE
#if defined(_LP64)
typedef unsigned int	chtype;
#else
typedef unsigned long	chtype;
#endif
#endif

extern char *unctrl(chtype);

#ifdef	__cplusplus
}
#endif

#endif	/* _UNCTRL_H */
