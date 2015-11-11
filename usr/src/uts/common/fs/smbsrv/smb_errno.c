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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Translate Unix errno values to NT status, and NT status to
 * DOS-style error class+code (for SMB1)
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_kstat.h>

#include "smbclnt/smb_status2winerr.h"


/*
 * Map Unix errno values to NT status values.
 */

struct errno2status {
	int errnum;
	uint_t status;
};

static const struct errno2status
smb_errno2status_map[] = {
	{ EPERM,	NT_STATUS_ACCESS_DENIED },
	{ ENOENT,	NT_STATUS_NO_SUCH_FILE },
	/* NB: ESRCH is used to represent stream lookup failures. */
	{ ESRCH,	NT_STATUS_OBJECT_NAME_NOT_FOUND },
	{ EINTR,	NT_STATUS_CANCELLED },
	{ EIO,		NT_STATUS_IO_DEVICE_ERROR },
	{ ENXIO,	NT_STATUS_BAD_DEVICE_TYPE },
	/* E2BIG, ENOEXEC */
	{ EBADF,	NT_STATUS_INVALID_HANDLE },
	/* ECHILD, EAGAIN */
	{ ENOMEM,	NT_STATUS_NO_MEMORY },
	{ EACCES,	NT_STATUS_ACCESS_DENIED },
	/* EFAULT, ENOTBLK, EBUSY */
	{ EEXIST,	NT_STATUS_OBJECT_NAME_COLLISION },
	{ EXDEV, 	NT_STATUS_NOT_SAME_DEVICE },
	{ ENODEV,	NT_STATUS_NO_SUCH_DEVICE },
	/* ENOTDIR should be: NT_STATUS_NOT_A_DIRECTORY, but not yet */
	{ ENOTDIR,	NT_STATUS_OBJECT_PATH_NOT_FOUND },
	{ EISDIR,	NT_STATUS_FILE_IS_A_DIRECTORY },
	{ EINVAL,	NT_STATUS_INVALID_PARAMETER },
	{ ENFILE,	NT_STATUS_TOO_MANY_OPENED_FILES },
	{ EMFILE,	NT_STATUS_TOO_MANY_OPENED_FILES },
	{ ENOTTY,	NT_STATUS_INVALID_DEVICE_REQUEST },
	/* ENOTTY, ETXTBSY, EFBIG */
	{ ENOSPC,	NT_STATUS_DISK_FULL },
	/* ESPIPE */
	{ EROFS,	NT_STATUS_ACCESS_DENIED },
	{ EMLINK,	NT_STATUS_TOO_MANY_LINKS },
	{ EPIPE,	NT_STATUS_PIPE_BROKEN },
	/* EDOM */
	/* NB: ERANGE is used to represent lock range I/O conflicts. */
	{ ERANGE,	NT_STATUS_FILE_LOCK_CONFLICT },
	/* ENOMSG, EIDRM, ... */
	{ ENOTSUP,	NT_STATUS_NOT_SUPPORTED },
	{ EDQUOT,	NT_STATUS_DISK_FULL },
	{ EREMOTE, 	NT_STATUS_PATH_NOT_COVERED},
	{ ENAMETOOLONG,	NT_STATUS_OBJECT_NAME_INVALID },
	{ EILSEQ,	NT_STATUS_OBJECT_NAME_INVALID },
	{ ENOTEMPTY,	NT_STATUS_DIRECTORY_NOT_EMPTY },
	{ ENOTSOCK,	NT_STATUS_INVALID_HANDLE },
	{ ESTALE,	NT_STATUS_INVALID_HANDLE },
	{ 0, 0 }
};

uint_t
smb_errno2status(int errnum)
{
	const struct errno2status *es;

	if (errnum == 0)
		return (0);

	for (es = smb_errno2status_map; es->errnum != 0; es++)
		if (es->errnum == errnum)
			return (es->status);

	return (NT_STATUS_INTERNAL_ERROR);
}

/*
 * Map NT Status codes to Win32 API error numbers.
 * But note: we only want the ones below 0xFFFF,
 * which can be returned in SMB with class=DOSERR.
 */
uint16_t
smb_status2doserr(uint_t status)
{
	const struct status2winerr *sw;

	if (status == 0)
		return (0);

	for (sw = smb_status2winerr_map; sw->status != 0; sw++)
		if (sw->status == status && (sw->winerr < 0xFFFF))
			return ((uint16_t)sw->winerr);

	return (ERROR_GEN_FAILURE);
}
