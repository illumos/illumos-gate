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


#pragma ident	"%Z%%M%	%I%	%E% SMI"
	 	/* SVr4.0 2.	*/
/*
    NAME
	clr_hinfo, clrhdr - clean out mail header information

    SYNOPSIS
	void clr_hinfo()
	void clrhdr(int hdrtype)

    DESCRIPTION
	Clr_hinfo() cleans out hdrlines[] and other associated data
	in preparation for the next message.

	Clrhdr() does a single hdrlines[].
*/

#include "mail.h"

void
clr_hinfo()
{
	register	int	i;
	static		int	firsttime = 1;
	static char		pn[] = "clr_hinfo";

	Dout(pn, 0, "\n");
	if (firsttime) {
		firsttime = 0;
		return;
	}
	fnuhdrtype = 0;
	orig_aff = orig_rcv = 0;
	for (i = 0; i < H_CONT; i++) {
		clrhdr(i);
	}
	return;
}

void clrhdr(hdrtype)
int	hdrtype;
{
	while (hdrlines[hdrtype].head != (struct hdrs *)NULL) {
		poplist (hdrtype, HEAD);
	}
}
