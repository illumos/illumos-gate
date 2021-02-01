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
 * Copyright 2015 Joyent, Inc.
 */

#ifndef _SYS_VXLAN_H
#define	_SYS_VXLAN_H

/*
 * Common VXLAN information
 */

#include <sys/inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Sizes in bytes */
#define	VXLAN_HDR_LEN	8
#define	VXLAN_ID_LEN	3

#define	VXLAN_F_VDI	0x08000000
#define	VXLAN_ID_SHIFT	8

#pragma pack(1)
typedef struct vxlan_hdr {
	uint32_t vxlan_flags;
	uint32_t vxlan_id;
} vxlan_hdr_t;
#pragma pack()

#ifdef __cplusplus
}
#endif

#endif /* _SYS_VXLAN_H */
