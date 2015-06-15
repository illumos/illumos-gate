/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * These replace NODIRECT functions of the same name in
 * $SRC/lib/smbsrv/libsmb/common/smb_kmod.c including:
 *	smb_kmod_bind, smb_kmod_ioctl, smb_kmod_isbound,
 *	smb_kmod_start, smb_kmod_stop, smb_kmod_unbind.
 *
 * For all the other smb_kmod_... functions, we can just use the
 * libsmb code because those all call smb_kmod_ioctl, for which
 * we have an override here.
 *
 * The replacment functions here just call the libfksmbsrv code
 * directly where the real (in-kernel) versions would be entered
 * via the driver framework (open, close, ioctl).  Aside from that,
 * the call sequences are intentionally the same (where possible).
 * In particular, that makes it possible to debug startup/teardown
 * problems in the user-space version of this code.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioccom.h>
#include <sys/param.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <note.h>

#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_ioctl.h>
#include "smbd.h"

boolean_t smbdrv_opened = B_FALSE;

/*
 * We want to adjust a few things in the standard configuration
 * passed to the "fake" version of the smbsrv kernel module.
 *
 * Reduce the maximum number of connections and workers, just for
 * convenience while debugging.  (Don't want hundreds of threads.)
 */
static void
fksmbd_adjust_config(smb_ioc_header_t *ioc_hdr)
{
	smb_ioc_cfg_t *ioc = (smb_ioc_cfg_t *)ioc_hdr;

	ioc->maxconnections = 10;
	ioc->maxworkers = 20;
	smbd_report("maxconnections=%d, maxworkers=%d",
	    ioc->maxconnections, ioc->maxworkers);
}

boolean_t
smb_kmod_isbound(void)
{
	return (smbdrv_opened);
}

int
smb_kmod_bind(void)
{
	int rc;

	if (smbdrv_opened) {
		smbdrv_opened = B_FALSE;
		(void) fksmbsrv_drv_close();
	}

	rc = fksmbsrv_drv_open();
	if (rc == 0)
		smbdrv_opened = B_TRUE;

	return (rc);
}

void
smb_kmod_unbind(void)
{
	if (smbdrv_opened) {
		smbdrv_opened = B_FALSE;
		(void) fksmbsrv_drv_close();
	}
}

int
smb_kmod_ioctl(int cmd, smb_ioc_header_t *ioc, uint32_t len)
{
	int rc;

	_NOTE(ARGUNUSED(len));

	if (!smbdrv_opened)
		return (EBADF);

	if (cmd == SMB_IOC_CONFIG)
		fksmbd_adjust_config(ioc);

	rc = fksmbsrv_drv_ioctl(cmd, ioc);
	return (rc);
}

/* ARGSUSED */
int
smb_kmod_start(int opipe, int lmshr, int udoor)
{
	smb_ioc_start_t ioc;
	int rc;

	bzero(&ioc, sizeof (ioc));

	/* These three are unused */
	ioc.opipe = -1;
	ioc.lmshrd = -1;
	ioc.udoor = -1;

	/* These are the "door" dispatch callbacks */
	ioc.lmshr_func = NULL; /* not used */
	ioc.opipe_func = NULL; /* not used */
	ioc.udoor_func = (void *)fksmbd_door_dispatch;

	rc = smb_kmod_ioctl(SMB_IOC_START, &ioc.hdr, sizeof (ioc));
	return (rc);
}

void
smb_kmod_stop(void)
{
	smb_ioc_header_t ioc;

	bzero(&ioc, sizeof (ioc));
	(void) smb_kmod_ioctl(SMB_IOC_STOP, &ioc, sizeof (ioc));
}
