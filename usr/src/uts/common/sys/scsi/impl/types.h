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

#ifndef	_SYS_SCSI_IMPL_TYPES_H
#define	_SYS_SCSI_IMPL_TYPES_H

/*
 * Local Types for SCSI subsystems
 */

#ifdef	_KERNEL

#include <sys/kmem.h>
#include <sys/map.h>
#include <sys/open.h>
#include <sys/uio.h>
#include <sys/sysmacros.h>

#include <sys/buf.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>

#include <sys/conf.h>

#include <sys/scsi/impl/services.h>
#include <sys/scsi/impl/transport.h>
#include <sys/scsi/impl/smp_transport.h>
#include <sys/scsi/impl/scsi_sas.h>

#endif	/* _KERNEL */

#include <sys/scsi/impl/uscsi.h>

#endif	/* _SYS_SCSI_IMPL_TYPES_H */
