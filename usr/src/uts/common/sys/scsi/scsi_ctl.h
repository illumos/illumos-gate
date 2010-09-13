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

#ifndef	_SYS_SCSI_SCSI_CTL_H
#define	_SYS_SCSI_SCSI_CTL_H

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
int	scsi_ifgetcap(struct scsi_address *ap, char *cap, int whom);
int	scsi_ifsetcap(struct scsi_address *ap, char *cap, int value, int whom);

/*
 * Abort and Reset functions
 */
int	scsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt);
int	scsi_reset(struct scsi_address *ap, int level);
int	scsi_reset_notify(struct scsi_address *ap, int flag,
	    void (*callback)(caddr_t), caddr_t arg);
int	scsi_clear_task_set(struct scsi_address *ap);
int	scsi_terminate_task(struct scsi_address *ap, struct scsi_pkt *pkt);

/*
 * Other functions
 */
int	scsi_clear_aca(struct scsi_address *ap);
int	scsi_ua_get_reportdev(struct scsi_device *sd, char *ba, int len);
int	scsi_ua_get(struct scsi_device *sd, char *ua, int len);
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_SCSI_CTL_H */
