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
 * Copyright 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * bsd/bsd.h: Interface definitions to BSD compatibility functions for SVR4.
 */

#ifndef _BSD_BSD_H
#define _BSD_BSD_H

#include <signal.h>


#ifndef __cplusplus
typedef void (*SIG_PF) (int);
#endif

#ifdef __cplusplus
extern "C" SIG_PF bsd_signal(int a, SIG_PF b);
#else
extern void (*bsd_signal(int, void (*) (int))) (int);
#endif
extern void bsd_signals(void);

#endif
