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

#ifndef _SMB_IOCTL_H_
#define	_SMB_IOCTL_H_

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <smbsrv/smbinfo.h>

#define	SMB_IOC_VERSION		0x534D4201	/* SMB1 */

#define	SMB_IOC_BASE		(('S' << 16) | ('B' << 8))

#define	SMB_IOC_CONFIG		_IOW(SMB_IOC_BASE, 1, int)
#define	SMB_IOC_START		_IOW(SMB_IOC_BASE, 2, int)
#define	SMB_IOC_NBT_LISTEN	_IOW(SMB_IOC_BASE, 3, int)
#define	SMB_IOC_TCP_LISTEN	_IOW(SMB_IOC_BASE, 4, int)
#define	SMB_IOC_NBT_RECEIVE	_IOW(SMB_IOC_BASE, 5, int)
#define	SMB_IOC_TCP_RECEIVE	_IOW(SMB_IOC_BASE, 6, int)
#define	SMB_IOC_GMTOFF		_IOW(SMB_IOC_BASE, 7, int)

#pragma	pack(1)

typedef struct {
	uint32_t	sio_version;
	uint32_t	sio_crc;

	union {
		int32_t		gmtoff;
		int		error;
		smb_kmod_cfg_t	cfg;

		struct smb_io_start {
			int	opipe;
			int	lmshrd;
			int	udoor;
		} start;
	} sio_data;
} smb_io_t;

#pragma	pack()

uint32_t smb_crc_gen(uint8_t *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _SMB_IOCTL_H_ */
