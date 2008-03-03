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

/*
 * Structures and type definitions for the SMB module.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ioccom.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>

#include <smbsrv/smb_ioctl.h>

#include "smbd.h"

extern smbd_t smbd;

/*ARGSUSED*/
void *
smbd_nbt_receiver(void *arg)
{
	smb_io_t	smb_io;

	bzero(&smb_io, sizeof (smb_io));
	smb_io.sio_version = SMB_IOC_VERSION;

	(void) ioctl(smbd.s_drv_fd, SMB_IOC_NBT_RECEIVE, &smb_io);
	return (NULL);
}

/*ARGSUSED*/
void *
smbd_nbt_listener(void *arg)
{
	smb_io_t	smb_io;
	pthread_t	tid;

	bzero(&smb_io, sizeof (smb_io));
	smb_io.sio_version = SMB_IOC_VERSION;

	while (ioctl(smbd.s_drv_fd, SMB_IOC_NBT_LISTEN, &smb_io) == 0) {
		smb_io.sio_data.error = pthread_create(&tid, NULL,
		    smbd_nbt_receiver, NULL);
	}
	return (NULL);
}

/*ARGSUSED*/
void *
smbd_tcp_receiver(void *arg)
{
	smb_io_t	smb_io;

	bzero(&smb_io, sizeof (smb_io));
	smb_io.sio_version = SMB_IOC_VERSION;

	(void) ioctl(smbd.s_drv_fd, SMB_IOC_TCP_RECEIVE, &smb_io);
	return (NULL);
}

/*ARGSUSED*/
void *
smbd_tcp_listener(void *arg)
{
	smb_io_t	smb_io;
	pthread_t	tid;

	bzero(&smb_io, sizeof (smb_io));
	smb_io.sio_version = SMB_IOC_VERSION;

	while (ioctl(smbd.s_drv_fd, SMB_IOC_TCP_LISTEN, &smb_io) == 0) {
		smb_io.sio_data.error = pthread_create(&tid, NULL,
		    smbd_tcp_receiver, NULL);
	}
	return (NULL);
}
