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

/* Copyright © 2003-2011 Emulex. All rights reserved.  */

/*
 * Driver private ioctls
 */

#ifndef _OCE_IOCTL_H_
#define	_OCE_IOCTL_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * OCE IOCTLS.
 */

#define	OCE_IOC			((((('O' << 8) + 'C') << 8) + 'E') << 8)

#define	OCE_ISSUE_MBOX		(OCE_IOC | 1)
#define	OCE_QUERY_DRIVER_DATA	(OCE_IOC | 0x10)

#define	OCN_VERSION_SUPPORTED	0x00

#define	MAX_SMAC	32
struct oce_driver_query {
	uint8_t version;
	uint8_t smac_addr[MAX_SMAC][ETHERADDRL];
	uint8_t pmac_addr[ETHERADDRL];
	uint8_t driver_name[32];
	uint8_t driver_version[32];
	uint32_t num_smac;
};


#ifdef __cplusplus
}
#endif

#endif /* _OCE_IOCTL_H_ */
