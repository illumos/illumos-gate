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

#ifndef	_SYS_SCSI_SCSI_TYPES_H
#define	_SYS_SCSI_SCSI_TYPES_H


/*
 * Types for SCSI subsystems.
 *
 * This file picks up specific as well as generic type
 * defines, and also serves as a wrapper for many common
 * includes.
 */

#include <sys/types.h>
#include <sys/param.h>


#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _OPAQUE_T
#define	_OPAQUE_T
typedef	void *opaque_t;
#endif  /* _OPAQUE_T */

#ifdef	__cplusplus
}
#endif

#ifdef	_KERNEL
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stat.h>
#include <sys/sunndi.h>
#include <sys/devctl.h>
#endif	/* _KERNEL */

/*
 * Each implementation will have it's own specific set
 * of types it wishes to define.
 */

/*
 * Generally useful files to include
 */
#include <sys/scsi/scsi_params.h>
#include <sys/scsi/scsi_address.h>
#include <sys/scsi/scsi_pkt.h>
#ifdef	_KERNEL
#include <sys/scsi/conf/device.h>
#endif	/* _KERNEL */
#include <sys/scsi/scsi_ctl.h>
#include <sys/scsi/scsi_resource.h>

#ifdef	_KERNEL
#include <sys/scsi/conf/autoconf.h>
#include <sys/scsi/scsi_watch.h>
#include <sys/scsi/scsi_fm.h>
#endif	/* _KERNEL */

#include <sys/scsi/generic/commands.h>
#include <sys/scsi/generic/status.h>
#include <sys/scsi/generic/message.h>
#include <sys/scsi/generic/mode.h>

/*
 * Sun SCSI type definitions
 */
#include <sys/scsi/impl/types.h>

#endif	/* _SYS_SCSI_SCSI_TYPES_H */
