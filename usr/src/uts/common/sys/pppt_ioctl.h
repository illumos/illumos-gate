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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PPPT_IOCTL_H
#define	_SYS_PPPT_IOCTL_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	PPPT_VERSION_1	1

/*
 * map ioctls
 */
#define	PPPT_IOC (('P' << 24) | ('P' << 16) | ('P' << 8))
#define	PPPT_INSTALL_DOOR	(PPPT_IOC|1)	/* to talk to daemon */
#define	PPPT_MESSAGE		(PPPT_IOC|2)	/* data from peer */


typedef struct _pppt_iocdata {
	uint32_t	pppt_version;
	uint32_t	pppt_error;
	uint32_t	pppt_door_fd;
	uint32_t	pppt_buf_size;
	uint64_t	pppt_buf;
} pppt_iocdata_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PPPT_IOCTL_H */
