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
 * MKS interface to XPG message internationalization routines.
 * Copyright 1989, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
** Written by Trevor John Thompson
 */
#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/i18n/rcs/m_strmsg.c 1.5 1992/07/16 19:08:40 tj Exp $";
#endif
#endif

#define	I18N	1	/* InternationalizatioN on */

#include <mks.h>
#include <stdlib.h>

LDEFN char*
m_strmsg(str)
const char* str;
{
	char* cp;
	int id = (int)strtol(str, &cp, 0);

	if (cp[0]!='#' || cp[1]!='#')	/* no "##" delimiter */
		return ((char *)str);
	else
		return (m_textmsg(id, &cp[2], ""));
}
