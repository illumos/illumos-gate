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
/*	  All Rights Reserved	*/

#include "mail.h"
/*
    NAME
	errmsg - print error message

    SYNOPSIS
	void errmsg(int error_value, char *error_message)

    DESCRIPTION
	Errmsg() prints error messages. If error_message is supplied,
	that is taken as the text for the message, otherwise the
	text for the err_val message is gotten from the errlist[] array.
*/
void errmsg(int err_val, char *err_txt)
{
	static char pn[] = "errmsg";
	error = err_val;
	if (err_txt && *err_txt) {
		fprintf(stderr,"%s: %s\n",program,err_txt);
		Dout(pn, 0, "%s\n",err_txt);
	} else {
		fprintf(stderr,"%s: %s\n",program,errlist[err_val]);
		Dout(pn, 0,"%s\n",errlist[err_val]);
	}
	Dout(pn, 0,"error set to %d\n", error);
}
