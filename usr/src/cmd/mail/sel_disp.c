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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI" 

#include "mail.h"

/*
 * If in default display mode from printmail(), selectively output
 * header lines. Any recognized header lines will have flag stored in
 * header[] structure. Other header lines which should be displayed in
 * the default output mode will be listed in the seldisp[] array.
 * This can all be overridden via the 'P' command at the ? prompt.
 */
int
sel_disp(int type, int hdrtype, char *s)
{
	static char pn[] = "sel_disp";
	char		*p;
	static	int	sav_lastrc = 0;
	int		i, rc = 0;

	if (sending || Pflg || (type != TTY)) {
		return (0);
	}

	switch (hdrtype) {
	case H_CONT:
		rc = sav_lastrc;
		break;
	case H_NAMEVALUE:
		for (i=0,p=seldisp[i]; p; p=seldisp[++i]) {
			if (casncmp(s, p, strlen(p)) == 0) {
				break;
			}
		}
		if (p == (char *)NULL) {
			rc = -1;
		}
		break;
	default:
		if (header[hdrtype].default_display == FALSE) {
			rc = -1;
			break;
		}
	}

	Dout(pn, 2, "type = %d, hdrtype = %d/'%s', rc = %d\n",
		type, hdrtype, header[hdrtype].tag, rc);
	sav_lastrc = rc;	/* In case next one is H_CONT... */
	return (rc);
}
