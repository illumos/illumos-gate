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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SCSI_IMPL_USMP_H
#define	_SYS_SCSI_IMPL_USMP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ioccom.h>
#include <sys/scsi/generic/smp_frames.h>

#define	SAS_WWN_BYTE_SIZE	8

typedef struct usmp_cmd {
	caddr_t		usmp_req;
	caddr_t		usmp_rsp;
	size_t		usmp_reqsize;
	size_t		usmp_rspsize;
	int		usmp_timeout;
} usmp_cmd_t;

#if defined(_SYSCALL32) && defined(_KERNEL)

typedef struct usmp_cmd32 {
	caddr32_t	usmp_req;
	caddr32_t	usmp_rsp;
	size32_t	usmp_reqsize;
	size32_t	usmp_rspsize;
	int		usmp_timeout;
} usmp_cmd32_t;

#define	usmp_cmd32tousmp_cmd(u32, ucmd)				\
	ucmd->usmp_req		= (caddr_t)(uintptr_t)u32->usmp_req;	\
	ucmd->usmp_rsp		= (caddr_t)(uintptr_t)u32->usmp_rsp; 	\
	ucmd->usmp_reqsize	= (size_t)u32->usmp_reqsize;		\
	ucmd->usmp_rspsize	= (size_t)u32->usmp_rspsize;		\
	ucmd->usmp_timeout	= u32->usmp_timeout;

#define	usmp_cmdtousmp_cmd32(ucmd, u32)				\
	u32->usmp_req		= (caddr32_t)(uintptr_t)ucmd->usmp_req;	\
	u32->usmp_rsp		= (caddr32_t)(uintptr_t)ucmd->usmp_rsp;	\
	u32->usmp_reqsize	= (size32_t)ucmd->usmp_reqsize;		\
	u32->usmp_rspsize	= (size32_t)ucmd->usmp_rspsize;		\
	u32->usmp_timeout	= ucmd->usmp_timeout;

#endif	/* _SYSCALL32 && _KERNEL */

#define	USMPFUNC	_IO('S', 01)		/* user smp function */

#define	SMP_DEFAULT_TIMEOUT	60
#define	SMP_MIN_RESPONSE_SIZE	8
#define	SMP_MIN_REQUEST_SIZE		8
#define	SMP_MAX_RESPONSE_SIZE	1032
#define	SMP_MAX_REQUEST_SIZE		1032

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_IMPL_USMP_H */
