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

#ifndef _SYS_SCSI_TARGETS_SMP_H
#define	_SYS_SCSI_TARGETS_SMP_H

#include <sys/types.h>
#include <sys/scsi/scsi.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL)

/*
 * smp_open_flag: field indicating open smp instance.
 *	0 = closed, 1 = shared open, 2 = exclusive open.
 */
#define	SMP_CLOSED	0
#define	SMP_SOPENED	1
#define	SMP_EXOPENED	2

typedef struct smp_state {
	struct smp_device	*smp_sd;	/* pointer to smp_device */
	kmutex_t		smp_mutex;	/* mutex */
	uint32_t		smp_open_flag;	/* open flag */
	kcondvar_t		smp_cv;		/* condition variable */
	uint32_t		smp_busy;	/* busy */
} smp_state_t;

#define	SMP_ESTIMATED_NUM_DEVS	4		/* for soft-state allocation */
#define	SMP_DEFAULT_RETRY_TIMES	5

#define	SMP_FLAG_REQBUF		0x1
#define	SMP_FLAG_RSPBUF		0x2
#define	SMP_FLAG_XFER		0x4

#endif /* defined(_KERNEL) */


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_TARGETS_SMP_H */
