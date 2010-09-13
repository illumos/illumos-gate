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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/smbios_impl.h>

#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

smbios_hdl_t *
smb_open_error(smbios_hdl_t *shp, int *errp, int err)
{
	if (shp != NULL)
		smbios_close(shp);

	if (errp != NULL)
		*errp = err;

	return (NULL);
}

const char *
smb_strerror(int err)
{
	return (strerror(err));
}

void *
smb_alloc(size_t len)
{
	return (len ? malloc(len) : NULL);
}

void *
smb_zalloc(size_t len)
{
	void *buf;

	if ((buf = smb_alloc(len)) != NULL)
		bzero(buf, len);

	return (buf);
}

/*ARGSUSED*/
void
smb_free(void *buf, size_t len)
{
	free(buf);
}

/*PRINTFLIKE2*/
void
smb_dprintf(smbios_hdl_t *shp, const char *format, ...)
{
	va_list ap;

	if (!(shp->sh_flags & SMB_FL_DEBUG))
		return;

	(void) fprintf(stderr, "smb DEBUG: ");
	va_start(ap, format);
	(void) vfprintf(stderr, format, ap);
	va_end(ap);
}
