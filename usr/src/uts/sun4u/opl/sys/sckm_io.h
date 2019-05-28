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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Copyright 2019 Peter Tribble.
 */

#ifndef	_SYS_SCKM_IO_H
#define	_SYS_SCKM_IO_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This header file defines the interface between the sckmd daemon and
 * the sckmdrv driver.
 */

#include <sys/types.h>

#define	SCKM_IOC	('s' << 8)

enum sckm_ioctl {
	SCKM_IOCTL_GETREQ = SCKM_IOC,
	SCKM_IOCTL_STATUS
};

/*
 * Structure passed by sckmd daemon to the sckmdrv driver during
 * a SCKM_IOCTL_GETREQ ioctl call.
 */
typedef struct sckm_ioctl_getreq {
	uint64_t transid;	/* returned by driver */
	uint32_t type;		/* message type */
	caddr_t buf;		/* user buffer to store msg */
	uint32_t buf_len;	/* size of buf */
} sckm_ioctl_getreq_t;

#if defined(_SYSCALL32)
typedef struct sckm_ioctl_getreq_32 {
	uint64_t transid;	/* returned by driver */
	uint32_t type;		/* message type */
	caddr32_t buf;		/* user buffer to store msg */
	uint32_t buf_len;	/* size of buf */
} sckm_ioctl_getreq32_t;
#endif /* defined(_SYSCALL32) */

/*
 * Structure passed by sckmd daemon to the sckmdrv driver during
 * a SCKM_IOCTL_STATUS ioctl call.
 */
typedef struct sckm_ioctl_status {
	uint64_t transid;		/* set by daemon */
	uint32_t status;		/* execution status */
	uint32_t sadb_msg_errno;	/* PF_KEY errno, if applicable */
	uint32_t sadb_msg_version;	/* PF_KEY version, if applicable */
} sckm_ioctl_status_t;

/*
 * Valid request types returned by the SCKM_IOCTL_GETREQ ioctl.
 */
#define	SCKM_IOCTL_REQ_SADB		0x0	/* SADB message */

/*
 * Valid values for the status field of the sckm_ioctl_status structure.
 */
#define	SCKM_IOCTL_STAT_SUCCESS		0x0	/* operation success */
#define	SCKM_IOCTL_STAT_ERR_PFKEY	0x1	/* PF_KEY error */
#define	SCKM_IOCTL_STAT_ERR_REQ		0x2	/* invalid request */
#define	SCKM_IOCTL_STAT_ERR_VERSION	0x3	/* not supp. PF_KEY version */
#define	SCKM_IOCTL_STAT_ERR_TIMEOUT	0x4	/* no response from PF_KEY */
#define	SCKM_IOCTL_STAT_ERR_OTHER	0x5	/* other daemon error */
#define	SCKM_IOCTL_STAT_ERR_SADB_TYPE	0x6	/* bad SADB msg type */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SCKM_IO_H */
