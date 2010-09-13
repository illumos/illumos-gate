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

char *errmsgs[] = {
	"WARNING: gid %ld is reserved.\n",
	"ERROR: invalid syntax.\nusage: groupadd [-g gid [-o]] group\n",
	"ERROR: invalid syntax.\nusage: groupdel group\n",
	"ERROR: invalid syntax.\nusage: groupmod -g gid [-o] | -n name group\n",
	"ERROR: Cannot update system files - group cannot be %s.\n",
	"ERROR: %s is not a valid group id.  Choose another.\n",
	"ERROR: %s is already in use.  Choose another.\n",
	"ERROR: %s is not a valid group name.  Choose another.\n",
	"ERROR: %s does not exist.\n",
	"ERROR: Group id %ld is too big.  Choose another.\n",
	"ERROR: Permission denied.\n",
	"ERROR: Syntax error in group file at line %d.\n",
};

int lasterrmsg = sizeof (errmsgs) / sizeof (char *);
