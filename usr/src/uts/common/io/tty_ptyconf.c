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
 * Copyright (c) 1987 by Sun Microsystems, Inc.
 */

#ident	"%Z%%M%	%I%	%E% SMI"
		/* SunOS-4.1 1.2	*/

/*
 * Pseudo-terminal driver.
 *
 * Configuration dependent variables
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/termios.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/kmem.h>
#include <sys/tty.h>
#include <sys/ptyvar.h>

#ifndef	NOLDPTY
#define	NOLDPTY	48		/* crude XXX */
#endif

int	npty = NOLDPTY;

struct	pty *pty_softc;

struct pollhead ptcph;		/* poll head for ptcpoll() use */

/*
 * Allocate space for data structures at runtime.
 */
void
pty_initspace(void)
{
	pty_softc = (struct pty *)
		kmem_zalloc(npty * sizeof (struct pty), KM_SLEEP);
}
