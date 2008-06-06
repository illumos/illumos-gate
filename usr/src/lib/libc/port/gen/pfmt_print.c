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

/*
 * pfmt_print() - format and print
 */
#include "lint.h"
#include "mtlib.h"
#include <pfmt.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <thread.h>
#include <ctype.h>
#include "pfmt_data.h"

/* Catalogue for local messages */
#define	fmt_cat		"uxlibc"
#define	def_colon	": "
#define	def_colonid	2

/* Table of default severities */
static const char *sev_list[] = {
	"SEV = %d",
	"TO FIX",
	"ERROR",
	"HALT",
	"WARNING",
	"INFO"
};

int
__pfmt_print(FILE *stream, long flag, const char *format,
	const char **text_ptr, const char **sev_ptr, va_list args)
{
	const char *ptr;
	char catbuf[DB_NAME_LEN];
	int i, status;
	int length = 0;
	int txtmsgnum = 0;
	int dofmt = (flag & (long)MM_NOSTD) == 0;
	long doact = (flag & (long)MM_ACTION);

	if (format && !(flag & (long)MM_NOGET)) {
		char c;
		ptr = format;
		for (i = 0; i < DB_NAME_LEN - 1 && (c = *ptr++) && c != ':';
		    i++)
			catbuf[i] = c;
		/* Extract the message number */
		if (i != DB_NAME_LEN - 1 && c) {
			catbuf[i] = '\0';
			while (isdigit(c = *ptr++)) {
				txtmsgnum *= 10;
				txtmsgnum += c - '0';
			}
			if (c != ':')
				txtmsgnum = -1;
		}
		else
			txtmsgnum = -1;
		format = __gtxt(catbuf, txtmsgnum, ptr);

	}

	if (text_ptr)
		*text_ptr = format;
	if (dofmt) {
		char label[MAXLABEL];
		int severity, sev, d_sev;
		const char *psev = NULL, *colon;

		lrw_rdlock(&_rw_pfmt_label);
		(void) strlcpy(label, __pfmt_label, MAXLABEL);
		lrw_unlock(&_rw_pfmt_label);

		colon = __gtxt(fmt_cat, def_colonid, def_colon);

		if (label[0] != '\0' && stream) {
			if ((status = fputs(label, stream)) < 0)
				return (-1);
			length += status;
			if ((status = fputs(colon, stream)) < 0)
				return (-1);
			length += status;
		}

		severity = (int)(flag & 0xff);

		if (doact) {
			d_sev = sev = 1;
		} else if (severity <= MM_INFO) {
			sev = severity + 3;
			d_sev = severity + 2;
		} else {
			int i;
			lrw_rdlock(&_rw_pfmt_sev_tab);
			for (i = 0; i < __pfmt_nsev; i++) {
				if (__pfmt_sev_tab[i].severity == severity) {
					psev = __pfmt_sev_tab[i].string;
					d_sev = sev = -1;
					break;
				}
			}
			lrw_unlock(&_rw_pfmt_sev_tab);
			if (i == __pfmt_nsev)
				d_sev = sev = 0;
		}

		if (sev >= 0) {
			psev = __gtxt(fmt_cat, sev, sev_list[d_sev]);
		}

		if (sev_ptr)
			*sev_ptr = psev;

		if (stream) {
			if ((status = fprintf(stream, psev, severity)) < 0)
				return (-1);
			length += status;
			if ((status = fputs(colon, stream)) < 0)
				return (-1);
			length += status;
		} else
			return (-1);
	} else if (sev_ptr)
		*sev_ptr = NULL;

	if (stream) {
		if ((status = vfprintf(stream, format, args)) < 0)
			return (-1);
		length += status;
	} else
		return (-1);

	return (length);
}
