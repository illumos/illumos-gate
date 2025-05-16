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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <ctype.h>
#include <libdiskstatus.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "ds_impl.h"

boolean_t ds_debug;

/*PRINTFLIKE1*/
void
ds_dprintf(const char *fmt, ...)
{
	va_list ap;

	if (!ds_debug)
		return;

	va_start(ap, fmt);
	(void) vprintf(fmt, ap);
	va_end(ap);
}

void
ddump(const char *label, const void *data, size_t length)
{
	int byte_count;
	int i;
#define	LINEBUFLEN 128
	char linebuf[LINEBUFLEN];
	char *linep;
	int bufleft, len;
	const char *start = data;

	if (!ds_debug)
		return;

	if (label != NULL)
		ds_dprintf("%s\n", label);

	linep = linebuf;
	bufleft = LINEBUFLEN;

	for (byte_count = 0; byte_count < length; byte_count += i) {

		(void) snprintf(linep, bufleft, "0x%08x ", byte_count);
		len = strlen(linep);
		bufleft -= len;
		linep += len;

		/*
		 * Inner loop processes 16 bytes at a time, or less
		 * if we have less than 16 bytes to go
		 */
		for (i = 0; (i < 16) && ((byte_count + i) < length); i++) {
			(void) snprintf(linep, bufleft, "%02X", (unsigned int)
			    (unsigned char) start[byte_count + i]);

			len = strlen(linep);
			bufleft -= len;
			linep += len;

			if (bufleft >= 2) {
				if (i == 7)
					*linep = '-';
				else
					*linep = ' ';

				--bufleft;
				++linep;
			}
		}

		/*
		 * If i is less than 16, then we had less than 16 bytes
		 * written to the output.  We need to fixup the alignment
		 * to allow the "text" output to be aligned
		 */
		if (i < 16) {
			int numspaces = (16 - i) * 3;
			while (numspaces-- > 0) {
				if (bufleft >= 2) {
					*linep = ' ';
					--bufleft;
					linep++;
				}
			}
		}

		if (bufleft >= 2) {
			*linep = ' ';
			--bufleft;
			++linep;
		}

		for (i = 0; (i < 16) && ((byte_count + i) < length); i++) {
			int subscript = byte_count + i;
			char ch =  (isprint(start[subscript]) ?
			    start[subscript] : '.');

			if (bufleft >= 2) {
				*linep = ch;
				--bufleft;
				++linep;
			}
		}

		linebuf[LINEBUFLEN - bufleft] = 0;

		ds_dprintf("%s\n", linebuf);

		linep = linebuf;
		bufleft = LINEBUFLEN;
	}

}

const char *
disk_status_errmsg(int error)
{
	switch (error) {
	case EDS_NOMEM:
		return ("memory allocation failure");
	case EDS_CANT_OPEN:
		return ("failed to open device");
	case EDS_NO_TRANSPORT:
		return ("no supported communication protocol");
	case EDS_NOT_SUPPORTED:
		return ("disk status information not supported");
	case EDS_NOT_SIMULATOR:
		return ("not a valid simulator file");
	case EDS_IO:
		return ("I/O error from device");
	default:
		return ("unknown error");
	}
}

int
ds_set_errno(disk_status_t *dsp, int error)
{
	dsp->ds_error = error;
	return (-1);
}
