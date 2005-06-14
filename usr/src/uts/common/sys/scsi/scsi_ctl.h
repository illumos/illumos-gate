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
 * Copyright 1996-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SCSI_SCSI_CTL_H
#define	_SYS_SCSI_SCSI_CTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/scsi/scsi_types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SCSI Control Information
 *
 * Defines for stating level of reset.
 * RESET_ALL, RESET_TARGET, and RESET_LUN defined for tran_reset (invoked
 * by target/ioctl)
 * RESET_BUS defined for tran_bus_reset (invoked by ioctl)
 */

#define	RESET_ALL	0	/* reset SCSI bus, host adapter, everything */
#define	RESET_TARGET	1	/* reset SCSI target */
#define	RESET_BUS	2	/* reset SCSI bus only */
#define	RESET_LUN	3	/* reset SCSI logical unit */

/*
 * Defines for scsi_reset_notify flag, to register or cancel
 * the notification of external and internal SCSI bus resets.
 */
#define	SCSI_RESET_NOTIFY	0x01	/* register the reset notification */
#define	SCSI_RESET_CANCEL	0x02	/* cancel the reset notification */

/*
 * Define for scsi_get_addr/scsi_get_name first argument.
 */
#define	SCSI_GET_INITIATOR_ID	((struct scsi_device *)NULL)
					/* return initiator-id */

/*
 * Define for scsi_get_name string length.
 * This is needed because MAXNAMELEN is not part of DDI.
 */
#define	SCSI_MAXNAMELEN		MAXNAMELEN

/*
 * Property for customizing hotplug procedure
 */
#define	SCSI_NO_QUIESCE	"scsi-no-quiesce"

#ifdef	_KERNEL

/*
 * Kernel function declarations
 */

/*
 * Capabilities functions
 */

#ifdef	__STDC__
extern int scsi_ifgetcap(struct scsi_address *ap, char *cap, int whom);
extern int scsi_ifsetcap(struct scsi_address *ap, char *cap, int value,
	int whom);
#else	/* __STDC__ */
extern int scsi_ifgetcap(), scsi_ifsetcap();
#endif	/* __STDC__ */

/*
 * Abort and Reset functions
 */

#ifdef	__STDC__
extern int scsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt);
extern int scsi_reset(struct scsi_address *ap, int level);
extern int scsi_reset_notify(struct scsi_address *ap, int flag,
	void (*callback)(caddr_t), caddr_t arg);
extern int scsi_clear_task_set(struct scsi_address *ap);
extern int scsi_terminate_task(struct scsi_address *ap, struct scsi_pkt *pkt);
#else	/* __STDC__ */
extern int scsi_abort(), scsi_reset();
extern int scsi_reset_notify();
extern int scsi_clear_task_set();
extern int scsi_terminate_task();
#endif	/* __STDC__ */

/*
 * Other functions
 */

#ifdef	__STDC__
extern int scsi_clear_aca(struct scsi_address *ap);
extern int scsi_get_bus_addr(struct scsi_device *devp, char *name, int len);
extern int scsi_get_name(struct scsi_device *devp, char *name, int len);
#else	/* __STDC__ */
extern int scsi_clear_aca();
extern int scsi_get_bus_addr();
extern int scsi_get_name();
#endif	/* __STDC__ */

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_SCSI_CTL_H */
