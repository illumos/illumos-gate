/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma	weak _addsev = addsev

#include "lint.h"
#include "mtlib.h"
#include "libc.h"
#include <stdlib.h>
#include <pfmt.h>
#include <thread.h>
#include "pfmt_data.h"
#include <sys/types.h>
#include <string.h>
#include <synch.h>

int
addsev(int severity, const char *string)
{
	int i, firstfree;
	void *new;

	/* Cannot redefine standard severity */
	if ((severity <= 4) || (severity > 255))
		return (-1);

	/* Locate severity in table */
	lrw_wrlock(&_rw_pfmt_sev_tab);
	for (i = 0, firstfree = -1; i < __pfmt_nsev; i++) {
		if (__pfmt_sev_tab[i].severity == 0 && firstfree == -1)
			firstfree = i;
		if (__pfmt_sev_tab[i].severity == severity)
			break;
	}

	if (i == __pfmt_nsev) {
		if (string == NULL)	/* Removing non-existing severity */
			return (0);
		if (firstfree != -1)	/* Re-use old entry */
			i = firstfree;
		else {
			/* Allocate new entry */
			new = libc_realloc(__pfmt_sev_tab,
			    sizeof (struct sev_tab) * (__pfmt_nsev + 1));
			if (new == NULL) {
				lrw_unlock(&_rw_pfmt_sev_tab);
				return (-1);
			}
			__pfmt_nsev++;
			__pfmt_sev_tab = new;
		}
	}
	if (string == NULL) {
		if (__pfmt_sev_tab[i].string)
			libc_free(__pfmt_sev_tab[i].string);
		__pfmt_sev_tab[i].severity = 0;
		__pfmt_sev_tab[i].string = NULL;
		lrw_unlock(&_rw_pfmt_sev_tab);
		return (0);
	}
	new = libc_realloc(__pfmt_sev_tab[i].string, strlen(string) + 1);
	if (new == NULL) {
		lrw_unlock(&_rw_pfmt_sev_tab);
		return (-1);
	}
	__pfmt_sev_tab[i].severity = severity;
	__pfmt_sev_tab[i].string = new;
	(void) strcpy(__pfmt_sev_tab[i].string, string);
	lrw_unlock(&_rw_pfmt_sev_tab);
	return (0);
}
