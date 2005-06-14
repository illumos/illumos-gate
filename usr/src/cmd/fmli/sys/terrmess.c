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
 * Copyright  (c) 1986 AT&T
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.2 */

#include	<stdio.h>
#include	"wish.h"
#include	"terror.h"

/*
 * NOTE: these error messages depend upon the order of error numbers in
 * errno.  When that changes, so must this array and the list of defines
 * in terror.h
 */
char	*Errlist[] = {
	nil,
	"Permissions are wrong",
	"File does not exist",
	nil,
	nil,
	"Hardware error",
	nil,
	"Arguments are too long",
	"File has been corrupted",
	"Software error",
	nil,
	"Can't create another process",
	"Out of memory",
	"Permissions are wrong",
	nil,
	nil,
	nil,
	"File already exists",
	nil,
	nil,
	"Improper name",
	"It is a directory",
	nil,
	"Too many files in use on system",
	"Too many files in use by program",
	nil,
	nil,
	nil,
	"System out of disk space",
	nil,
	nil,
	nil,
	nil,
	nil,
	nil,
	nil,
	nil,
};

/*
 * NOTE: this array depends on the numbering scheme in terror.h
 * If you add an element to this array, add it at the end and change
 * terror.h to define the new value. Also, don't forget to change
 * TS_NERRS and add a line to Use_errno.
 */
char	*What[TS_NERRS] = {
	nil,
	"Can't open file",
	"Invalid arguments",
	"Data has been corrupted",
	"Some necessary information is missing",
	"Software failure error",
	"Can't execute the program",
	"Can't create or remove file",
	"Input is not valid",
	"Frame not updated: definition file missing or not readable",
	"Can't open frame: definition file missing or not readable"
};

/*
 * This array indicates whether or not errno may be considered
 * valid when this type of error occurs
 */
bool	Use_errno[TS_NERRS] = {
	FALSE,
	TRUE,
	FALSE,
	FALSE,
	FALSE,
	TRUE,
	TRUE,
	TRUE,
	FALSE,
	FALSE,
	FALSE
};
