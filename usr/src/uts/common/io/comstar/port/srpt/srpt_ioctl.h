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

#ifndef _SRPT_IOCTL_H_
#define	_SRPT_IOCTL_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SRP Target Port Provider ioctls.
 */

#define	SRPT_IOC_ENABLE_SVC		1
#define	SRPT_IOC_DISABLE_SVC		2

/*
 * SRP Target pseudo device
 */
#define	SRPT_NODE	"/devices/ib/srpt@0:srpt"

#ifdef __cplusplus
}
#endif

#endif /* _SRPT_IOCTL_H_ */
