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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * m_cmdname -- MKS specific library routine.
 *
 * Copyright 1985, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Id: m_cmdnam.c 1.16 1993/02/15 14:12:23 fredw Exp $";
#endif
#endif

#include <mks.h>
#include <ctype.h>
#include <string.h>

/*f
 *  MKS private routine to hide o/s dependencies in filenames in argv[0];
 *  cmdname(argv[0]) returns a modified argv[0] which contains only the command
 *  name, prefix, suffix stripped, and lower cased on case-less systems.
 */
LDEFN char *
m_cmdname(cmd)
char *cmd;
{
#if defined(DOS) || defined(OS2) || defined(NT)
	register char *ap;

	/* Lowercase command name on DOS, OS2 and NT. */
	/* The shell needs the whole name lowered. */
	for (ap = cmd; *ap; ap++)
		if (isupper(*ap))
			*ap = _tolower(*ap);

	cmd = basename(cmd);

	/* Strip .com/.exe/.??? suffix on DOS and OS/2 */
	if ((ap = strrchr(cmd, '.')) != NULL)
		*ap = '\0';

	return (cmd);
#else
	return (basename(cmd));
#endif
}
