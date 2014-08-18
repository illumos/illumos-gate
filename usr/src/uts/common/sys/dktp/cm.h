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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright (c) 1992 Sun Microsystems, Inc.  All Rights Reserved.
 */

#ifndef _SYS_DKTP_CM_H
#define	_SYS_DKTP_CM_H

#include <sys/types.h>
#ifdef	_KERNEL
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/fcntl.h>
#include <sys/open.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#endif	/* _KERNEL */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

#ifndef _SYS_SCSI_SCSI_H
typedef	void *	opaque_t;
#endif

#define	PRF		prom_printf

#define	SET_BP_SEC(bp, X) ((bp)->b_private = (void *) (X))
#define	GET_BP_SEC(bp) ((daddr_t)(bp)->b_private)

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_CM_H */
