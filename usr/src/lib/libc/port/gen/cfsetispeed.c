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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma weak cfsetispeed = _cfsetispeed
#include "synonyms.h"
#include <sys/types.h>
#include <sys/termios.h>

/*
 * sets the input baud rate stored in c_cflag to speed
 */

int
cfsetispeed(struct termios *termios_p, speed_t speed)
{
	/*
	 * If the input speed is zero, set it to output speed
	 */
	if (speed == 0) {
		speed = termios_p->c_cflag & CBAUD;
		if (termios_p->c_cflag & CBAUDEXT)
			speed += (CBAUD + 1);
	}

	if ((speed << 16) > CIBAUD) {
		termios_p->c_cflag |= CIBAUDEXT;
		speed -= ((CIBAUD >> 16) + 1);
	} else
		termios_p->c_cflag &= ~CIBAUDEXT;
	termios_p->c_cflag =
	    (termios_p->c_cflag & ~CIBAUD) | ((speed << 16) & CIBAUD);
	return (0);
}
