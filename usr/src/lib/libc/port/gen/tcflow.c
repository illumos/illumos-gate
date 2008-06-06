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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak _tcflow = tcflow

#include "lint.h"
#include <sys/termios.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * suspend transmission or reception of input or output
 */

/*
 * TCOOFF (0) -> suspend output
 * TCOON  (1) -> restart suspend output
 * TCIOFF (2) -> suspend input
 * TCION  (3) -> restart suspend input
 */

int
tcflow(int fildes, int action)
{
	return (ioctl(fildes, TCXONC, action));

}
