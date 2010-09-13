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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Error code manipulation routines
 */

#include <string.h>
#include <libintl.h>
#include <errno.h>

#include "tnfctl_int.h"
#include "dbg.h"

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif


/*
 * tnfctl_strerror() - this routine returns a pointer to a static string
 * describing the error argument.
 */
const char *
tnfctl_strerror(tnfctl_errcode_t prexstat)
{
	switch (prexstat) {
	case TNFCTL_ERR_NONE:
		return (dgettext(TEXT_DOMAIN, "Success"));
	case TNFCTL_ERR_ACCES:
		return (dgettext(TEXT_DOMAIN, "Permission denied"));
	case TNFCTL_ERR_NOTARGET:
		return (dgettext(TEXT_DOMAIN, "Target process finished"));
	case TNFCTL_ERR_ALLOCFAIL:
		return (dgettext(TEXT_DOMAIN, "Memory allocation failed"));
	case TNFCTL_ERR_INTERNAL:
		return (dgettext(TEXT_DOMAIN, "Internal error"));
	case TNFCTL_ERR_SIZETOOSMALL:
		return (dgettext(TEXT_DOMAIN, "Requested size too small"));
	case TNFCTL_ERR_SIZETOOBIG:
		return (dgettext(TEXT_DOMAIN, "Requested size too big"));
	case TNFCTL_ERR_BADARG:
		return (dgettext(TEXT_DOMAIN, "Bad input argument"));
	case TNFCTL_ERR_NOTDYNAMIC:
		return (dgettext(TEXT_DOMAIN, "Not a dynamic executable"));
	case TNFCTL_ERR_NOLIBTNFPROBE:
		return (dgettext(TEXT_DOMAIN,
				"No libtnfprobe linked in target"));
	case TNFCTL_ERR_BUFEXISTS:
		return (dgettext(TEXT_DOMAIN, "Buffer already exists"));
	case TNFCTL_ERR_NOBUF:
		return (dgettext(TEXT_DOMAIN, "No buffer exists"));
	case TNFCTL_ERR_BADDEALLOC:
		return (dgettext(TEXT_DOMAIN, "Can't deallocate buffer when "
				"tracing is active"));
	case TNFCTL_ERR_NOPROCESS:
		return (dgettext(TEXT_DOMAIN, "Process not found"));
	case TNFCTL_ERR_FILENOTFOUND:
		return (dgettext(TEXT_DOMAIN, "No such file"));
	case TNFCTL_ERR_BUSY:
		return (dgettext(TEXT_DOMAIN,
			"Device busy - kernel or process already tracing"));
	case TNFCTL_ERR_INVALIDPROBE:
		return (dgettext(TEXT_DOMAIN, "Invalid probe specified"));
	case TNFCTL_ERR_USR1:
		return (dgettext(TEXT_DOMAIN, "User error 1"));
	case TNFCTL_ERR_USR2:
		return (dgettext(TEXT_DOMAIN, "User error 2"));
	case TNFCTL_ERR_USR3:
		return (dgettext(TEXT_DOMAIN, "User error 3"));
	case TNFCTL_ERR_USR4:
		return (dgettext(TEXT_DOMAIN, "User error 4"));
	case TNFCTL_ERR_USR5:
		return (dgettext(TEXT_DOMAIN, "User error 5"));
	default:
		return (dgettext(TEXT_DOMAIN,
			"Unknown libtnfctl.so error code"));
	}
}

/*
 * prb_map_to_errocde() - this routine returns maps an internal error code
 * to a tnfctl_errcode_t
 */
tnfctl_errcode_t
_tnfctl_map_to_errcode(prb_status_t prbstat)
{
	tnfctl_errcode_t	err = TNFCTL_ERR_INTERNAL;

	if (prbstat >= PRB_STATUS_MINERRNO &&
		prbstat <= PRB_STATUS_MAXERRNO) {
		if (prbstat == ENOENT)
			err =  TNFCTL_ERR_FILENOTFOUND;
		else if (prbstat == ESRCH)
			err = TNFCTL_ERR_NOPROCESS;
		else if (prbstat == EACCES)
			err = TNFCTL_ERR_ACCES;
		else if (prbstat == EBUSY)
			err = TNFCTL_ERR_BUSY;
	} else {
		if (prbstat == PRB_STATUS_OK)
			err = TNFCTL_ERR_NONE;
		else if (prbstat == PRB_STATUS_ALLOCFAIL)
			err = TNFCTL_ERR_ALLOCFAIL;
	}

	return (err);
}

/*
 * tnfctl_status_map() - this routine converts an errno value into a
 * tnfctl_errcode_t
 */
tnfctl_errcode_t
tnfctl_status_map(int val)
{
	tnfctl_errcode_t err = TNFCTL_ERR_INTERNAL;

	if (val == ENOENT)
		err = TNFCTL_ERR_FILENOTFOUND;
	else if (val == ESRCH)
		err = TNFCTL_ERR_NOPROCESS;
	else if (val == EACCES)
		err = TNFCTL_ERR_ACCES;
	else if (val == EBUSY)
		err = TNFCTL_ERR_BUSY;

	return (err);
}
