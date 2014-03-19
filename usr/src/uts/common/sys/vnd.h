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
 * Copyright (c) 2014 Joyent, Inc. All rights reserved.
 */

#ifndef _SYS_VND_H
#define	_SYS_VND_H

#include <sys/types.h>
#include <sys/vnd_errno.h>
#include <sys/frameio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * We distinguish between normal ioctls and private ioctls we issues to out
 * streams version. Streams ioctls have the upper bit set in the lowest byte.
 * Note that there are no STREAMs ioctls for userland and all definitions
 * related to them are not present in this file.
 */
#define	VND_IOC		(('v' << 24) | ('n' << 16) | ('d' << 8))

/*
 * Attach the current minor instance to a given dlpi datalink identified by a
 * vnd_ioc_name_t argument. This fails if it's already been attached. Note that
 * unlike the other ioctls, this is passed directly as opposed to every other
 * function which is passed as a pointer to the value.
 */
#define	VND_IOC_ATTACH		(VND_IOC | 0x1)

#define	VND_NAMELEN	32

typedef struct vnd_ioc_attach {
	char		via_name[VND_NAMELEN];
	zoneid_t	via_zoneid;
	uint32_t	via_errno;
} vnd_ioc_attach_t;

/*
 * Link the current minor instance into the /devices name space.
 *
 * This ioctl adds entries into /devices with a name of the form z%d:%s vil_zid,
 * vil_name. The device will be namespaced to the zone. The global zone will be
 * able to see all minor nodes. In the zone, only the /dev entries will exist.
 * At this time, a given device can only have one link at a time. Note that a
 * user cannot specify the zone to pass in, rather it is the zone that the
 * device was attached in.
 */
#define	VND_IOC_LINK		(VND_IOC | 0x2)

typedef struct vnd_ioc_link {
	char		vil_name[VND_NAMELEN];
	uint32_t	vil_errno;
} vnd_ioc_link_t;

/*
 * Unlink the opened minor instance from the /devices name space. A zone may use
 * this to unlink an extent entry in /dev; however, they will not be able to
 * link it in again.
 */
#define	VND_IOC_UNLINK		(VND_IOC | 0x3)
typedef struct vnd_ioc_unlink {
	uint32_t viu_errno;
} vnd_ioc_unlink_t;

/*
 * Controls to get and set the current buffer recieve buffer size.
 */
typedef struct vnd_ioc_buf {
	uint64_t	vib_size;
	uint32_t	vib_filler;
	uint32_t	vib_errno;
} vnd_ioc_buf_t;

#define	VND_IOC_GETRXBUF	(VND_IOC | 0x04)
#define	VND_IOC_SETRXBUF	(VND_IOC | 0x05)
#define	VND_IOC_GETMAXBUF	(VND_IOC | 0x06)
#define	VND_IOC_GETTXBUF	(VND_IOC | 0x07)
#define	VND_IOC_SETTXBUF	(VND_IOC | 0x08)
#define	VND_IOC_GETMINTU	(VND_IOC | 0x09)
#define	VND_IOC_GETMAXTU	(VND_IOC | 0x0a)

/*
 * Information and listing ioctls
 *
 * This gets information about all of the active vnd instances. vl_actents is
 * always updated to the number around and vl_nents is the number of
 * vnd_ioc_info_t elements are allocated in vl_ents.
 */
typedef struct vnd_ioc_info {
	uint32_t vii_version;
	zoneid_t vii_zone;
	char vii_name[VND_NAMELEN];
	char vii_datalink[VND_NAMELEN];
} vnd_ioc_info_t;

typedef struct vnd_ioc_list {
	uint_t vl_nents;
	uint_t vl_actents;
	vnd_ioc_info_t *vl_ents;
} vnd_ioc_list_t;

#ifdef _KERNEL

typedef struct vnd_ioc_list32 {
	uint_t vl_nents;
	uint_t vl_actents;
	caddr32_t vl_ents;
} vnd_ioc_list32_t;

#endif	/* _KERNEL */

#define	VND_IOC_LIST		(VND_IOC | 0x20)

/*
 * Framed I/O ioctls
 *
 * Users should use the standard frameio_t as opposed to a vnd specific type.
 * This is a consolidation private ioctl pending futher stability in the form of
 * specific system work.
 */
#define	VND_IOC_FRAMEIO_READ	(VND_IOC | 0x30)
#define	VND_IOC_FRAMEIO_WRITE	(VND_IOC | 0x31)

#ifdef __cplusplus
}
#endif

#endif /* _SYS_VND_H */
