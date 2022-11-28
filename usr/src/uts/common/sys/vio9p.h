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
 * Copyright 2022 Oxide Computer Company
 */

#ifndef _SYS_VIO9P_H
#define	_SYS_VIO9P_H

/*
 * VIRTIO 9P DRIVER
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * If the hypervisor supports mount tags through the VIRTIO_9P_F_MOUNT_TAG
 * feature, they will have at most this many bytes:
 */
#define	VIRTIO_9P_TAGLEN		32

/*
 * ioctl(2) support for 9P channel devices:
 */
#define	VIO9P_IOC_BASE			(('9' << 16) | ('P' << 8))
#define	VIO9P_IOC_MOUNT_TAG		(VIO9P_IOC_BASE | 0x01)

/*
 * Buffer size for the VIO9P_IOC_MOUNT_TAG ioctl, which includes one byte
 * beyond the maximum tag length for NUL termination:
 */
#define	VIO9P_MOUNT_TAG_SIZE		(VIRTIO_9P_TAGLEN + 1)

#ifdef __cplusplus
}
#endif

#endif /* _SYS_VIO9P_H */
