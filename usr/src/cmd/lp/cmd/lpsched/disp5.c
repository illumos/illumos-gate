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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "dispatch.h"
#include <syslog.h>

extern int		Net_fd;

extern MESG *		Net_md;

/**
 ** s_child_done()
 **/

void
s_child_done(char *m, MESG *md)
{
	long			key;
	short			slot;
	short			status;
	short			err;


	getmessage (m, S_CHILD_DONE, &key, &slot, &status, &err);
	syslog(LOG_DEBUG, "s_child_done(%d, %d, %d, %d)", key, slot, status,
	       err);

	if ((0 <= slot) && (slot < ET_Size) && (Exec_Table[slot].key == key) &&
	    (Exec_Table[slot].md == md)) {
		/*
		 * Remove the message descriptor from the listen
		 * table, then forget about it; we don't want to
		 * accidently match this exec-slot to a future,
		 * unrelated child.
		 */
		DROP_MD (Exec_Table[slot].md);
		Exec_Table[slot].md = 0;

		Exec_Table[slot].pid = -99;
		Exec_Table[slot].status = status;
		Exec_Table[slot].Errno = err;
		DoneChildren++;

	}

	return;
}
