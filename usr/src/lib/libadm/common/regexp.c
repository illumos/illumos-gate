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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	INIT		char *sp = instring;
#define	GETC()		(*sp++)
#define	PEEKC()		(*sp)
#define	UNGETC(c)	(--sp)
#define	RETURN(pt)	return (pt)
#define	ERROR(c)	return (NULL)

/*
 * Keep these symbols private to the library.
 * The originals, which were exported from libadm by mistake,
 * are now redirected to libgen.so.1 via 'filter' in adm.spec
 */

#define	advance	__advance
#define	compile	__compile
#define	step	__step

#define	loc1	__loc1
#define	loc2	__loc2
#define	locs	__locs
#define	nbra	__nbra

/*
 * We should do the same for these too, but they don't exist in libgen.so.1.
 * We continue to export them from libadm.so.1, even though they are dummies.
 */

int circf;
int sed;

#define	circf	__circf
#define	sed	__sed

#include <regexp.h>
