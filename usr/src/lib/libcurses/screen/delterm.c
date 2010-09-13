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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include "curses_inc.h"

/*
 * Relinquish the storage associated with "terminal".
 */
extern	TERMINAL	_first_term;
extern	char		_called_before;
extern	char		_frst_tblstr[];

int
delterm(TERMINAL *terminal)
{
	if (!terminal)
		return (ERR);
	(void) delkeymap(terminal);
	if (terminal->_check_fd >= 0)
		(void) close(terminal->_check_fd);

	if (terminal->_pairs_tbl)
		free(terminal->_pairs_tbl);
	if (terminal->_color_tbl)
		free(terminal->_color_tbl);
#ifdef	_VR3_COMPAT_CODE
	if (terminal->_acs32map)
		free(terminal->_acs32map);
#else	/* _VR3_COMPAT_CODE */
	if (terminal->_acsmap)
		free(terminal->_acsmap);
#endif	/* _VR3_COMPAT_CODE */

	if (terminal == &_first_term) {
		/* next setupterm can re-use static areas */
		_called_before = FALSE;
		if (terminal->_strtab != _frst_tblstr)
			free(terminal->_strtab);
	} else {
		free(terminal->_bools);
		free(terminal->_nums);
		free(terminal->_strs);
		free(terminal->_strtab);
		free(terminal);
	}

	return (OK);
}
