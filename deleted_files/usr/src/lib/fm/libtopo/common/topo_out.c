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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include "topo_impl.h"
#include "libtopo.h"

unsigned int Topo_out_mask = TOPO_ERR;

static char Topobuf[MAXPATHLEN];
static int Topoidx;

/*PRINTFLIKE2*/
void
topo_out(int flag, char *format, ...)
{
	va_list ap;
	char *errstr = NULL;
	int len;

	if (!(flag & Topo_out_mask))
		return;

	if (*(format + strlen(format) - 1) == ':')
		errstr = topo_strdup(strerror(errno));

	va_start(ap, format);
	/* print out remainder of message */
	len = vsnprintf(&Topobuf[Topoidx], MAXPATHLEN - Topoidx, format, ap);
	if (len >= 0)
		Topoidx += len;

	if (Topoidx >= MAXPATHLEN)
		Topoidx = MAXPATHLEN - 1;

	if (errstr) {
		(void) snprintf(&Topobuf[Topoidx], MAXPATHLEN - Topoidx,
		    " %s\n", errstr);
		topo_free(errstr);
		Topoidx = 0;
	} else if (*(format + strlen(format) - 1) == '\n') {
		Topoidx = 0;
	}

	if (Topoidx == 0 && !(flag & TOPO_BUFONLY) && Outmethod != NULL)
		Outmethod(Topobuf);

	va_end(ap);
}

void
topo_debug_on(uint_t flags)
{
	Topo_out_mask |= flags;
	Topo_out_mask |= TOPO_DEBUG;
}

void
topo_debug_off(void)
{
	Topo_out_mask = TOPO_ERR;
}

int Topo_depth = 0;

void
topo_indent(void)
{
	int ic = Topo_depth;

	while (ic-- > 0)
		topo_out(TOPO_DEBUG, "  ");
}

const char *
topo_errbuf(void)
{
	return (Topobuf);
}

void
topo_set_out_method(void (*outfn)(const char *))
{
	Outmethod = outfn;
}
