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
 *      Copyright (c) 1997, by Sun Microsystems, Inc.
 *      All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4	*/

/*LINTLIBRARY*/

#include	<sys/types.h>
#include	<stdlib.h>
#include	"curses_inc.h"

/*
 *	Delete a key table
 */

void
delkeymap(TERMINAL *terminal)
{
	_KEY_MAP	**kpp, *kp;
	int		numkeys = terminal->_ksz;

	/* free key slots */
	for (kpp = terminal->_keys; numkeys-- > 0; kpp++) {
		kp = *kpp;
		if (kp->_sends == ((char *) (kp + sizeof (_KEY_MAP))))
			free(kp);
	}

	if (terminal->_keys != NULL) {
		free(terminal->_keys);
		if (terminal->internal_keys != NULL)
			free(terminal->internal_keys);
	}
	_blast_keys(terminal);
}
