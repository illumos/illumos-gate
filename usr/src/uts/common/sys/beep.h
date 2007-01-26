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

#ifndef _SYS_BEEP_H
#define	_SYS_BEEP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Interface to the system beeper.
 *
 * (This is the API, not the hardware interface.)
 */

#ifdef __cplusplus
extern "C" {
#endif

#if	defined(_KERNEL)
enum beep_type { BEEP_DEFAULT = 0, BEEP_CONSOLE = 1, BEEP_TYPE4 = 2 };

void beep(enum beep_type);
void beep_polled(enum beep_type);
void beeper_on(enum beep_type);
void beeper_off(void);
int  beeper_freq(enum beep_type, int);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_BEEP_H */
