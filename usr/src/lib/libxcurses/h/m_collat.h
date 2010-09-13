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
 * collate.h will declare all the following routines in their header
 * files -- if they conform to the mks extentions.
 * If they don't conform, then we have to define them ourselves.
 *
 * Copyright 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * $Header: /rd/h/rcs/m_collat.h 1.10 1994/02/02 22:48:30 mark Exp $
 */
#ifndef	__M_M_COLLAT_H__
#define	__M_M_COLLAT_H__

#include <m_i18n.h>

/*
 * MKS i18n extentions for character collation support in POSIX.2
 */


/* m_collel_t: a type used to store collation elements
 * 		This must be an unsigned type.
 * M_MAX_COLLEL: maximum allowable value to be used for m_collel_t
 * M_COLL_ERR  : error value returned by collation functions
 */
/*
 * change this to "unsigned short" when we fix the rest of the code
 * to use M_COLL_ERR 
 */
typedef /* unsigned */ short m_collel_t;	/* Collating element */

#define __M_COLL_ERR	USHRT_MAX
#define __M_COLL_MAX	M_COLL_ERR-1

#undef	m_ismccollel
#define	m_ismccollel(c)	((c) >= M_CSETSIZE)
extern int		m_collequiv (m_collel_t, m_collel_t **);
extern int		m_collrange (m_collel_t,m_collel_t,m_collel_t **);
extern int		m_collorder (m_collel_t **);
extern	int		m_cclass (char *, m_collel_t **);
extern m_collel_t	m_strtocoll (char *);
extern char		*m_colltostr (m_collel_t);
extern m_collel_t	m_getmccoll (const char **);
extern m_collel_t	m_getwmccoll (const wchar_t **);
extern m_collel_t	m_maxcoll (void);

#endif /*__M_M_COLLAT_H__*/
