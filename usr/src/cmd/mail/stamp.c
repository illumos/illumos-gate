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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"        /* SVr4.0 1.5 */

#include "mail.h"
/*
	If the mailfile still exists (it may have been deleted),
	time-stamp it; so that our re-writing of mail back to the
	mailfile does not make shell think that NEW mail has arrived
	(by having the file times change).
*/
void stamp()
{
	if ((access(mailfile, A_EXIST) == A_OK) && (utimep->modtime != -1))
		if (utime(mailfile, utimep) != A_OK)
			errmsg(E_FILE,"Cannot time-stamp mailfile");
}
