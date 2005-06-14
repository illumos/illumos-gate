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


/*
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.6 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "wish.h"
#include "typetab.h"

extern char     *nstrcat();
extern long	Dispmodes, Sortmodes;
extern time_t   Prefmodtime;	/* EFT abs k16 */
extern int	Vflag;

void
oh_init()
{
	void	oot_init(), init_modes();

	if (Vflag)
		init_modes();
	oot_get();
	return;
}

void
init_modes()
{
        time_t	oldpref;	/* EFT abs k16 */
	char	*value;
	struct	stat sbuf;
	extern char *Home;
	char	*getepenv();

	/* folders need updating if the pref directory has been touched
	 * since the SORTMODES and DISPLAYMODES have been read.
	 * So, any form that wants to update all the folders on the screen
	 * need only touch $HOME/pref.
	 */
	oldpref = Prefmodtime;
	if (stat(nstrcat(Home, "/pref", NULL), &sbuf) != FAIL) {
		Prefmodtime = sbuf.st_mtime;
		if (oldpref == Prefmodtime)
			return;	/* no need to reread variables if hasn't changed */
	}
#ifdef _DEBUG
	else
		_debug(stderr, "pref stat failed\n");
#endif

	/* get environment settings; if not set, use defaults */

	if (((value = getepenv("DISPLAYMODE")) == NULL) || (value[0] == '\0'))
		Dispmodes = OTT_DOBJ;
	else {
		switch (value[0]) {
		case 'T':	/* object Type */
			Dispmodes = OTT_DOBJ;
			break;
		case 'M':	/* Modification Time */
			Dispmodes = OTT_DMTIME;
			break;
		case 'S':
			Dispmodes = 0;
			break;
		default:
			Dispmodes = strtol(value, NULL, 16);
			break;
		}
	}

	if (((value = getepenv("SORTMODE")) == NULL) || (value[0] == '\0'))
		Sortmodes = OTT_SALPHA;
	else {
		switch (value[0]) {
		case 'A':	/* Alphabetic */
			Sortmodes = OTT_SALPHA;
			break;
		case 'M':	/* Most Recent */
			Sortmodes = OTT_SMTIME;
			break;
		case 'L':	/* Least Recent */
			Sortmodes = OTT_SMTIME|OTT_SREV;
			break;
		case 'O':
			Sortmodes = OTT_SOBJ;
			break;
		default:
			Sortmodes = strtol(value, NULL, 16);
		}
	}
}
