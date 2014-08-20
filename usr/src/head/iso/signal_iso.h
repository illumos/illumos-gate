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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright (c) 1998-1999, by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * An application should not include this header directly.  Instead it
 * should be included only through the inclusion of other Sun headers.
 *
 * The contents of this header is limited to identifiers specified in the
 * C Standard.  Any new identifiers specified in future amendments to the
 * C Standard must be placed in this header.  If these new identifiers
 * are required to also be in the C++ Standard "std" namespace, then for
 * anything other than macro definitions, corresponding "using" directives
 * must also be added to <signal.h>.
 */

#ifndef _ISO_SIGNAL_ISO_H
#define	_ISO_SIGNAL_ISO_H

#include <sys/iso/signal_iso.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if __cplusplus >= 199711L
namespace std {
#endif

typedef int	sig_atomic_t;

#ifdef __cplusplus
extern "C" SIG_PF signal(int, SIG_PF);
#else
extern void (*signal(int, void (*)(int)))(int);
#endif
extern int raise(int);

#if __cplusplus >= 199711L
}
#endif /* end of namespace std */

#ifdef	__cplusplus
}
#endif

#endif	/* _ISO_SIGNAL_ISO_H */
