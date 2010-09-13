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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 *	acctdisk <dtmp >dtacct
 *	reads std.input & converts to tacct.h format, writes to output
 *	input:
 *	uid	name	#blocks
 */

#include <sys/types.h>
#include "acctdef.h"
#include <stdio.h>
#include <stdlib.h>

struct	tacct	tb;
char	ntmp[NSZ+1];

int
main(int argc, char **argv)
{
	int rc;

	tb.ta_dc = 1;
	while ((rc = scanf("%ld\t%s\t%f",
		&tb.ta_uid,
		ntmp,
		&tb.ta_du)) == 3) {

		CPYN(tb.ta_name, ntmp);
		fwrite(&tb, sizeof (tb), 1, stdout);
	}

	if (rc != EOF) {
		fprintf(stderr, "\nacctdisk: incorrect input format.\n");
		exit(1);
	} else {
		exit(0);
	}
}
