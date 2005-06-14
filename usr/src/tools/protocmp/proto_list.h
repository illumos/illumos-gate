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
 * Copyright 1993-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	SYM_F		1
#define	PERM_F		2
#define	REF_F		4
#define	TYPE_F		8
#define	NAME_F		16
#define	OWNER_F		32
#define	GROUP_F		64
#define	MAJMIN_F	128

#define	CODE	0
#define	NAME	1
#define	SYM	2
#define	SRC	2
#define	PERM	3
#define	OWNR	4
#define	GRP	5
#define	INO	6
#define	LCNT	7
#define	MAJOR	8
#define	MINOR	9
#define	PROTOS	10
#define	FIELDS	11

extern int read_in_protolist(const char *, elem_list *, int);
