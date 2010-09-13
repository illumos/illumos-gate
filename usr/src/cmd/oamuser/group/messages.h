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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* WARNING: gid %d is reserved.\n */
#define	M_RESERVED		0

/* ERROR: invalid syntax.\nusage:  groupadd [-g gid [-o]] group\n */
#define	M_AUSAGE		1

/* ERROR: invalid syntax.\nusage:  groupdel group\n */
#define	M_DUSAGE		2

/* ERROR: invalid syntax.\nusage:  groupmod -g gid [-o] | -n name group\n */
#define	M_MUSAGE		3

/* ERROR: Cannot update system files - group cannot be %s.\n */
#define	M_UPDATE		4

/* ERROR: %s is not a valid group id.  Choose another.\n */
#define	M_GID_INVALID	5

/* ERROR: %s is already in use.  Choose another.\n */
#define	M_GRP_USED	6

/* ERROR: %s is not a valid group name.  Choose another.\n */
#define	M_GRP_INVALID	7

/* ERROR: %s does not exist.\n */
#define	M_NO_GROUP	8

/* ERROR: Group id %d is too big.  Choose another.\n */
#define	M_TOOBIG	9

/* ERROR: Permission denied.\n */
#define	M_PERM_DENIED	10

/* ERROR: Syntax error in group file at line %d.\n */
#define	M_SYNTAX	11
