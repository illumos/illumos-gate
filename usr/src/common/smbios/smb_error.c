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

static const char *const _smb_errlist[] = {
	"System does not export an SMBIOS table",	/* ESMB_NOTFOUND */
	"Failed to map SMBIOS table",			/* ESMB_MAPDEV */
	"Failed to locate specified structure",		/* ESMB_NOENT */
	"Failed to allocate memory",			/* ESMB_NOMEM */
	"Failed to read SMBIOS entry point",		/* ESMB_NOHDR */
	"Failed to read SMBIOS structure table",	/* ESMB_NOSTAB */
	"Generic info not available for structure",	/* ESMB_NOINFO */
	"Structure table is shorter than expected",	/* ESMB_SHORT */
	"SMBIOS data structure is corrupted",		/* ESMB_CORRUPT */
	"Requested library version is not supported",	/* ESMB_VERSION */
	"Structure type is not supported by this BIOS",	/* ESMB_NOTSUP */
	"Header is not a valid SMBIOS entry point",	/* ESMB_HEADER */
	"SMBIOS format is too old for processing",	/* ESMB_OLD */
	"SMBIOS format is new and not yet supported",	/* ESMB_NEW */
	"SMBIOS header checksum mismatch",		/* ESMB_CKSUM */
	"Invalid argument specified in library call",	/* ESMB_INVAL */
	"Structure is not of the expected type",	/* ESMB_TYPE */
	"Unknown SMBIOS error"				/* ESMB_UNKNOWN */
};

static const int _smb_nerr = sizeof (_smb_errlist) / sizeof (_smb_errlist[0]);

const char *
smbios_errmsg(int error)
{
	const char *str;

	if (error >= ESMB_BASE && (error - ESMB_BASE) < _smb_nerr)
		str = _smb_errlist[error - ESMB_BASE];
	else
		str = smb_strerror(error);

	return (str ? str : "Unknown error");
}

int
smbios_errno(smbios_hdl_t *shp)
{
	return (shp->sh_err);
}

int
smb_set_errno(smbios_hdl_t *shp, int error)
{
	shp->sh_err = error;
	return (SMB_ERR);
}
