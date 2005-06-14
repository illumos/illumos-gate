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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _RMEDIA_H_
#define	_RMEDIA_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * rmedia.h header for libsmedia library
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <synch.h>
#include <rpc/rpc.h>

typedef	struct	rmedia_handle {
	void	*sm_lib_handle;	/* Handle to the module loaded */
	CLIENT	*sm_clnt;
	int32_t	sm_fd;		/* fd that is associated with this handle */
	int32_t	sm_door;	/* door that is associated with this handle */
	int32_t	sm_death_door;	/* door to inform server about client's death */
	int32_t	sm_signature;	/* identifies that handle is valid */
	struct dk_cinfo	sm_dkinfo;
	smdevice_info_t	sm_device_info;
	mutex_t	sm_bufmutex;	/* mutex to make it MT safe. */
	void	*sm_buf;
	int32_t	sm_bufsize;
	int32_t	sm_buffd;
}rmedia_handle_t;


#define	LIBSMEDIA_SIGNATURE	0x1234

#ifdef __cplusplus
}
#endif

#endif /* _RMEDIA_H_ */
