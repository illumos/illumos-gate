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
 * m_nls.h: mks NLS (National Language Support) header file
 * The client may choose to use a different messaging scheme than the xpg
 * one -- in that case this file will be replaced.
 *
 * Copyright 1992, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * $Header: /rd/h/rcs/m_nls.h 1.5 1995/01/20 01:42:10 fredw Exp $
 */

#ifndef	__M_NLS_H__
#define	__M_NLS_H__

extern char	*m_nlspath(const char* catalog, int mode);

#define	m_textstr(id, str, cls)	#id "##" str
extern void	 m_textdomain(char * str);
extern char	*m_textmsg(int id, const char *str, char *cls);
extern char	*m_strmsg(const char *str);
/*l
 * The following two routines may need to be defined, if you need
 * to do special processing:
 *
 * extern char *m_msgdup(char *m);
 * extern void m_msgfree(char *m);
 */
#define m_msgdup(m) (strdup(m))
#define m_msgfree(m) (free(m))

#endif /*__M_NLS_H__*/
